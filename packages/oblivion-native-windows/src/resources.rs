//! Durable authority for one backend generation's external effects. The
//! receipt contains identities and network metadata, never credentials or RAM.
#![cfg(any(windows, test))]
use crate::network_model::Plan;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const LIMIT: usize = 16384;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEvidence {
    pub volume: u64,
    pub file: [u8; 16],
    pub bytes: u64,
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub runtime_id: String,
    pub generation: String,
    pub config_sha256: String,
    pub source_sha256: String,
    pub client_sid: String,
    pub storage_sid: String,
}

impl Binding {
    fn validate(&self) -> Result<()> {
        if [&self.runtime_id, &self.generation].iter().any(|value| {
            !oblivion_wire::control::valid_id(value) || value.bytes().all(|byte| byte == b'0')
        }) || !oblivion_bundle::hash(&self.config_sha256)
            || !oblivion_bundle::hash(&self.source_sha256)
            || [&self.client_sid, &self.storage_sid].iter().any(|value| {
                !value.starts_with("S-1-")
                    || value.len() > 184
                    || !value[2..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'-')
            })
        {
            return Err(Error("invalid_resource_binding"));
        }
        Ok(())
    }

    fn same_runtime(&self, other: &Self) -> bool {
        self.runtime_id == other.runtime_id
            && self.config_sha256 == other.config_sha256
            && self.client_sid == other.client_sid
            && self.storage_sid == other.storage_sid
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    binding: Binding,
    files: Vec<FileEvidence>,
    network: Option<Plan>,
    clean: bool,
}

impl Record {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > LIMIT {
            return Err(Error("invalid_resource_record"));
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| Error("invalid_resource_record"))?;
        record.binding.validate()?;
        if record.version != 1
            || record.files.len() != 4
            || record.files.iter().enumerate().any(|(index, file)| {
                file.file == [0; 16]
                    || file.bytes == 0
                    || record.files[..index].iter().any(|previous| {
                        previous.volume == file.volume && previous.file == file.file
                    })
            })
        {
            return Err(Error("invalid_resource_record"));
        }
        if let Some(network) = &record.network {
            network.validate()?;
            if network.attachment.runtime_id != record.binding.runtime_id
                || network.generation != record.binding.generation
            {
                return Err(Error("resource_network_binding_changed"));
            }
        }
        Ok(record)
    }

    fn may_replace(&self, next: &Binding) -> Result<()> {
        if !self.clean || !self.binding.same_runtime(next) {
            return Err(Error("runtime_resources_require_recovery"));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
pub(crate) fn verify_retired_receipt(
    bytes: &[u8],
    runtime: &str,
    config_sha256: &str,
    client: &str,
    storage: &str,
    data: FileEvidence,
) -> Result<()> {
    let record = Record::decode(bytes)?;
    let binding = &record.binding;
    if !record.clean
        || binding.runtime_id != runtime
        || binding.config_sha256 != config_sha256
        || binding.client_sid != client
        || binding.storage_sid != storage
        || record.files.last() != Some(&data)
    {
        return Err(Error("runtime_resources_require_recovery"));
    }
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::{Binding, FileEvidence, LIMIT, Plan, Record};
    use crate::config::{CONFIG_LIMIT, RuntimeConfig};
    use crate::files::{self, Asset, CreationParent, Directory};
    use crate::security::Identity;
    use crate::{Error, Result, hcs, network};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_ALWAYS, READ_CONTROL,
    };

    pub struct Context {
        pub binding: Binding,
        path: String,
        storage: Identity,
        _configuration: Asset,
    }

    impl Context {
        /// Read the exact private configuration once, pin it, and admit only
        /// the digest carried by the source-bound supervisor generation.
        pub fn load(
            path: &str,
            binding: Binding,
            storage: &Identity,
        ) -> Result<(Self, RuntimeConfig)> {
            binding.validate()?;
            if binding.storage_sid != storage.sid() {
                return Err(Error("resource_storage_binding_changed"));
            }
            let path = Path::new(path);
            let directory = Directory::open(
                path.parent()
                    .and_then(Path::to_str)
                    .ok_or(Error("invalid_resource_path"))?,
                storage,
                true,
            )?;
            let configuration = directory.asset(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(Error("invalid_resource_path"))?,
                storage,
                true,
            )?;
            let mut bytes = Vec::new();
            configuration
                .reader()?
                .take((CONFIG_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("runtime_configuration_unavailable"))?;
            if format!("{:x}", Sha256::digest(&bytes)) != binding.config_sha256 {
                return Err(Error("runtime_configuration_binding_changed"));
            }
            let config = RuntimeConfig::decode(&bytes)?;
            if config.runtime_id != binding.runtime_id {
                return Err(Error("runtime_configuration_binding_changed"));
            }
            Ok((
                Self {
                    binding,
                    path: path.to_str().ok_or(Error("invalid_resource_path"))?.into(),
                    storage: storage.clone(),
                    _configuration: configuration,
                },
                config,
            ))
        }

        pub fn lock(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<Journal> {
            let lock_path = format!("{}.resources.lock", self.path);
            let parent = CreationParent::open(&lock_path, &self.storage)?;
            let descriptor = self.storage.file_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            let name = lock_path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let file = loop {
                check()?;
                if Instant::now() >= deadline {
                    return Err(Error("resource_owner_lock_timeout"));
                }
                let handle = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                        0,
                        &attributes,
                        OPEN_ALWAYS,
                        FILE_FLAG_OPEN_REPARSE_POINT,
                        null_mut(),
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    break unsafe { File::from_raw_handle(handle) };
                }
                if unsafe { GetLastError() } != ERROR_SHARING_VIOLATION {
                    return Err(Error("resource_owner_lock_unavailable"));
                }
                std::thread::sleep(Duration::from_millis(25));
            };
            files::verify_private(&file, &lock_path, &self.storage)?;
            if file
                .metadata()
                .map_err(|_| Error("resource_owner_lock_unavailable"))?
                .len()
                != 0
            {
                return Err(Error("invalid_resource_owner_lock"));
            }
            parent.verify()?;
            let directory = Directory::open(
                Path::new(&self.path)
                    .parent()
                    .and_then(Path::to_str)
                    .ok_or(Error("invalid_resource_path"))?,
                &self.storage,
                true,
            )?;
            let name = format!(
                "{}.resources.json",
                Path::new(&self.path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(Error("invalid_resource_path"))?
            );
            let path = format!(r"{}\{name}", directory.path());
            let current = match std::fs::symlink_metadata(&path) {
                Ok(_) => Some(directory.asset(&name, &self.storage, true)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(Error("resource_record_unavailable")),
            };
            Ok(Journal {
                directory,
                name,
                current,
                binding: self.binding.clone(),
                storage: self.storage.clone(),
                _lock: file,
                _parent: parent,
            })
        }
    }

    /// This file lock spans the entire backend lifetime, including cleanup.
    /// A lost supervisor cannot race a helper still shutting down after EOF.
    pub struct Journal {
        directory: Directory,
        name: String,
        current: Option<Asset>,
        binding: Binding,
        storage: Identity,
        _lock: File,
        _parent: CreationParent,
    }

    impl Journal {
        pub fn generation(&self) -> &str {
            &self.binding.generation
        }

        fn read(&self) -> Result<Option<Record>> {
            let Some(current) = &self.current else {
                return Ok(None);
            };
            let mut bytes = Vec::new();
            current
                .reader()?
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("resource_record_unavailable"))?;
            Record::decode(&bytes).map(Some)
        }

        pub fn prepare(&mut self, files: Vec<FileEvidence>, network: Option<Plan>) -> Result<()> {
            if let Some(previous) = self.read()? {
                previous.may_replace(&self.binding)?;
            }
            self.save(&Record {
                version: 1,
                binding: self.binding.clone(),
                files,
                network,
                clean: false,
            })
        }

        pub fn clean(&mut self) -> Result<()> {
            let mut record = self.read()?.ok_or(Error("resource_record_unavailable"))?;
            if record.binding != self.binding {
                return Err(Error("resource_binding_changed"));
            }
            record.clean = true;
            self.save(&record)
        }

        fn save(&mut self, record: &Record) -> Result<()> {
            let bytes = serde_json::to_vec(record).map_err(|_| Error("invalid_resource_record"))?;
            Record::decode(&bytes)?;
            self.directory.sync()?;
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).map_err(|_| Error("runtime_entropy_unavailable"))?;
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let mut pending = self
                .directory
                .create_file(&format!("resources-{suffix}.pending"), &self.storage)?;
            pending
                .writer()
                .write_all(&bytes)
                .map_err(|_| Error("resource_record_write_failed"))?;
            pending.finish()?;
            self.directory.sync()?;
            let published = match self.current.take() {
                Some(previous) => pending.replace(previous, &self.storage)?,
                None => pending.move_to(&self.directory, &self.name, &self.storage)?,
            };
            self.current = Some(published);
            self.directory.sync()?;
            // No external effect may begin until the complete receipt is read
            // back through the published object's own retained handle.
            let actual = self.read()?.ok_or(Error("resource_record_unavailable"))?;
            if serde_json::to_vec(&actual).map_err(|_| Error("invalid_resource_record"))? != bytes {
                return Err(Error("resource_record_changed"));
            }
            Ok(())
        }

        pub fn recover(
            &mut self,
            config: &RuntimeConfig,
            stop: &AtomicBool,
            deadline: Instant,
        ) -> Result<()> {
            let record = self.read()?;
            let current = match record {
                Some(record) if record.binding == self.binding => Some(record),
                Some(record) if record.clean && record.binding.same_runtime(&self.binding) => None,
                Some(_) => return Err(Error("resource_binding_changed")),
                None => None,
            };
            let Some(record) = current else {
                // No receipt is not evidence of shutdown. This branch performs
                // no mutations: positively check every external resource absent
                // and all files still strict/ungranted before clearing Recovery.
                hcs::require_absent(&config.vm_id(), deadline, &|| check(stop, deadline))?;
                network::require_absent(&config.runtime_id, &|| check(stop, deadline))?;
                let _files = files::Lease::acquire(config, &self.storage)?;
                return check(stop, deadline);
            };
            if record.network.is_some() != config.network {
                return Err(Error("resource_network_binding_changed"));
            }
            hcs::reconcile(
                &config.vm_id(),
                &config.owner(&self.binding.generation)?,
                deadline,
                &|| check(stop, deadline),
            )?;
            if let Some(network) = &record.network {
                network::reconcile(network, &|| check(stop, deadline))?;
            }
            check(stop, deadline)?;
            if record.clean {
                // Cleanup may have committed its receipt before the supervisor
                // could record Stopped. Re-admit the original ungranted files
                // rather than issue another revoke for an already-clean VM.
                let files = files::Lease::acquire(config, &self.storage)?;
                if files.evidence() != record.files {
                    return Err(Error("runtime_file_evidence_changed"));
                }
                return check(stop, deadline);
            }
            files::reconcile(config, &self.storage, &record.files)?;
            check(stop, deadline)?;
            self.clean()
        }
    }

    fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
        if stop.load(Ordering::Acquire) {
            return Err(Error("resource_recovery_cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(Error("resource_recovery_timeout"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

        struct Area(PathBuf);
        impl Area {
            fn new(identity: &Identity) -> Self {
                let mut random = [0; 16];
                getrandom::getrandom(&mut random).unwrap();
                let suffix = random
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
                let temp = temp.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
                let path = PathBuf::from(temp).join(format!("oblivion-resources-{suffix}"));
                let descriptor = identity.file_descriptor().unwrap();
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor.as_ptr(),
                    bInheritHandle: 0,
                };
                let name = path
                    .as_os_str()
                    .to_str()
                    .unwrap()
                    .encode_utf16()
                    .chain(Some(0))
                    .collect::<Vec<_>>();
                assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
                Self(path)
            }

            fn context(&self, identity: &Identity, generation: &str) -> Context {
                let directory = Directory::open(self.0.to_str().unwrap(), identity, true).unwrap();
                let runtime_id = "1".repeat(32);
                let configuration = RuntimeConfig {
                    version: 1,
                    backend: "hcs-hyperv".into(),
                    runtime_id: runtime_id.clone(),
                    kernel: self.0.join("kernel").to_str().unwrap().into(),
                    initrd: self.0.join("initrd").to_str().unwrap().into(),
                    command_line: format!(
                        "boot=live components quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={runtime_id}"
                    ),
                    disks: vec![
                        crate::config::Disk {
                            path: self.0.join("controller.iso").to_str().unwrap().into(),
                            read_only: true,
                        },
                        crate::config::Disk {
                            path: self.0.join("data.vhdx").to_str().unwrap().into(),
                            read_only: false,
                        },
                    ],
                    cpu_count: 2,
                    memory_mi_b: 2048,
                    control_pipe: format!(r"\\.\pipe\oblivion.{runtime_id}.control"),
                    control_port: 4050,
                    network: false,
                    serial_stdio: false,
                };
                let bytes = serde_json::to_vec(&configuration).unwrap();
                let path = self.0.join("vm.json");
                if !path.exists() {
                    let mut file = directory.create_file("vm.json", identity).unwrap();
                    file.writer().write_all(&bytes).unwrap();
                    file.finish().unwrap();
                }
                Context::load(
                    path.to_str().unwrap(),
                    Binding {
                        runtime_id,
                        generation: generation.into(),
                        config_sha256: format!("{:x}", Sha256::digest(&bytes)),
                        source_sha256: "a".repeat(64),
                        client_sid: identity.sid().into(),
                        storage_sid: identity.sid().into(),
                    },
                    identity,
                )
                .unwrap()
                .0
            }
        }
        impl Drop for Area {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn evidence() -> Vec<FileEvidence> {
            (1..=4)
                .map(|index| FileEvidence {
                    volume: 1,
                    file: [index; 16],
                    bytes: 1024,
                })
                .collect()
        }

        #[test]
        fn native_receipt_survives_atomic_replacement_and_refuses_an_unfinished_generation() {
            let identity = Identity::current().unwrap();
            let area = Area::new(&identity);
            let context = area.context(&identity, &"2".repeat(32));
            let mut journal = context
                .lock(Instant::now() + Duration::from_secs(1), &|| Ok(()))
                .unwrap();
            journal.prepare(evidence(), None).unwrap();
            let first = journal.current.as_ref().unwrap().identity();
            journal.clean().unwrap();
            assert_ne!(journal.current.as_ref().unwrap().identity(), first);
            assert!(journal.read().unwrap().unwrap().clean);
            drop(journal);
            let next = area.context(&identity, &"3".repeat(32));
            let mut journal = next
                .lock(Instant::now() + Duration::from_secs(1), &|| Ok(()))
                .unwrap();
            journal.prepare(evidence(), None).unwrap();
            let original = journal.current.as_ref().unwrap().identity();
            drop(journal);
            let another = area.context(&identity, &"4".repeat(32));
            let mut journal = another
                .lock(Instant::now() + Duration::from_secs(1), &|| Ok(()))
                .unwrap();
            assert_eq!(
                journal.prepare(evidence(), None).unwrap_err().0,
                "runtime_resources_require_recovery"
            );
            assert_eq!(journal.current.as_ref().unwrap().identity(), original);
            assert_eq!(
                journal.read().unwrap().unwrap().binding.generation,
                next.binding.generation
            );
        }

        #[test]
        fn native_backend_lock_remains_exclusive_while_a_receipt_is_replaced() {
            let identity = Identity::current().unwrap();
            let area = Area::new(&identity);
            let context = area.context(&identity, &"2".repeat(32));
            let mut owner = context
                .lock(Instant::now() + Duration::from_secs(1), &|| Ok(()))
                .unwrap();
            owner.prepare(evidence(), None).unwrap();
            owner.clean().unwrap();
            assert_eq!(
                context
                    .lock(Instant::now() + Duration::from_millis(30), &|| Ok(()))
                    .err()
                    .unwrap()
                    .0,
                "resource_owner_lock_timeout"
            );
            let cancelled = AtomicBool::new(true);
            assert_eq!(
                context
                    .lock(Instant::now() + Duration::from_secs(1), &|| check(
                        &cancelled,
                        Instant::now() + Duration::from_secs(1)
                    ))
                    .err()
                    .unwrap()
                    .0,
                "resource_recovery_cancelled"
            );
            drop(owner);
            context
                .lock(Instant::now() + Duration::from_secs(1), &|| Ok(()))
                .unwrap();
        }
    }
}

#[cfg(windows)]
pub use native::{Context, Journal};

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            version: 1,
            binding: Binding {
                runtime_id: "1".repeat(32),
                generation: "2".repeat(32),
                config_sha256: "a".repeat(64),
                source_sha256: "b".repeat(64),
                client_sid: "S-1-5-21-1-2-3-1001".into(),
                storage_sid: "S-1-5-32-544".into(),
            },
            files: (1..=4)
                .map(|value| FileEvidence {
                    volume: 1,
                    file: [value; 16],
                    bytes: 1024,
                })
                .collect(),
            network: None,
            clean: false,
        }
    }

    #[test]
    fn resource_receipt_rejects_aliases_and_foreign_network_generations() {
        let mut record = record();
        let bytes = serde_json::to_vec(&record).unwrap();
        Record::decode(&bytes).unwrap();
        record.files[1] = record.files[0];
        assert!(Record::decode(&serde_json::to_vec(&record).unwrap()).is_err());
        record.files[1].file = [9; 16];
        record.network = Some(Plan::new(&record.binding.runtime_id, &"3".repeat(32), &[]).unwrap());
        assert!(Record::decode(&serde_json::to_vec(&record).unwrap()).is_err());
        record.network.as_mut().unwrap().generation = record.binding.generation.clone();
        Record::decode(&serde_json::to_vec(&record).unwrap()).unwrap();
    }

    #[test]
    fn an_unfinished_generation_cannot_be_overwritten_by_another_boot() {
        let mut record = record();
        let mut next = record.binding.clone();
        next.generation = "3".repeat(32);
        assert!(record.may_replace(&next).is_err());
        record.clean = true;
        record.may_replace(&next).unwrap();
        next.source_sha256 = "c".repeat(64);
        record.may_replace(&next).unwrap();
        next.client_sid = "S-1-5-21-1-2-3-1002".into();
        assert!(record.may_replace(&next).is_err());
    }

    #[test]
    fn atomic_accepts_only_clean_receipts_for_the_reviewed_disk() {
        let mut record = record();
        let disk = *record.files.last().unwrap();
        let verify = |record: &Record, disk| {
            verify_retired_receipt(
                &serde_json::to_vec(record).unwrap(),
                &record.binding.runtime_id,
                &record.binding.config_sha256,
                &record.binding.client_sid,
                &record.binding.storage_sid,
                disk,
            )
        };
        assert!(verify(&record, disk).is_err());
        record.clean = true;
        verify(&record, disk).unwrap();
        assert!(verify(&record, record.files[0]).is_err());
    }
}
