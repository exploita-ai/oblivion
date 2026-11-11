//! Per-user installed-runtime metadata. Interrupted setup resumes only its
//! recorded disk identity; the VHDX is outside replaceable software bundles.
#![cfg(any(windows, test))]

use crate::config::{Disk, RuntimeConfig};
use crate::{Error, Result};
use oblivion_bundle::Binding;
use oblivion_wire::control::valid_id;
use oblivion_wire::runtime_auth::Data;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORD_LIMIT: usize = 8192;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    runtime_id: String,
    bundle: Binding,
    config_sha256: String,
    data_bytes: u64,
    phase: Phase,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Phase {
    Pending {
        disk: PendingDisk,
    },
    Ready {
        data: FileIdentity,
    },
    Updating {
        data: FileIdentity,
        target: Binding,
    },
    Uninstalled {
        data: FileIdentity,
    },
    Atomic {
        data: FileIdentity,
        stage: AtomicStage,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AtomicStage {
    Preparing,
    Deleting {
        config: FileIdentity,
        journal: FileIdentity,
        resources: Option<FileIdentity>,
        resource_lock: FileIdentity,
    },
    Complete,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PendingDisk {
    Uncreated,
    Staged { data: FileIdentity, leaf: String },
    Published { data: FileIdentity },
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    volume: u64,
    file: [u8; 16],
}

impl Record {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > RECORD_LIMIT {
            return Err(Error("invalid_installation_record"));
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| Error("invalid_installation_record"))?;
        if record.version != 1
            || !valid_id(&record.runtime_id)
            || record.runtime_id.bytes().all(|byte| byte == b'0')
            || !oblivion_bundle::hash(&record.config_sha256)
        {
            return Err(Error("invalid_installation_record"));
        }
        record
            .bundle
            .validate()
            .map_err(|_| Error("invalid_installation_record"))?;
        Data::NewDisk {
            runtime_id: record.runtime_id.clone(),
            bytes: record.data_bytes,
        }
        .validate()
        .map_err(|_| Error("invalid_installation_record"))?;
        if let Phase::Updating { target, .. } = &record.phase {
            target
                .validate()
                .map_err(|_| Error("invalid_installation_record"))?;
        }
        if let Some(data) = record.data() {
            if data.file == [0; 16] {
                return Err(Error("invalid_installation_record"));
            }
        }
        if let Phase::Atomic { data, stage } = &record.phase {
            if data.file == [0; 16] {
                return Err(Error("invalid_installation_record"));
            }
            if let AtomicStage::Deleting {
                config,
                journal,
                resources,
                resource_lock,
            } = stage
            {
                let files = [
                    Some(data),
                    Some(config),
                    Some(journal),
                    resources.as_ref(),
                    Some(resource_lock),
                ];
                for (index, file) in files.iter().enumerate() {
                    if file.is_some_and(|file| {
                        file.file == [0; 16] || files[..index].contains(&Some(file))
                    }) {
                        return Err(Error("invalid_installation_record"));
                    }
                }
            }
        }
        if let Phase::Pending { disk } = &record.phase {
            let data = match disk {
                PendingDisk::Uncreated => None,
                PendingDisk::Staged { data, leaf } => {
                    if !data_stage(leaf) {
                        return Err(Error("invalid_installation_record"));
                    }
                    Some(data)
                }
                PendingDisk::Published { data } => Some(data),
            };
            if data.is_some_and(|data| data.file == [0; 16]) {
                return Err(Error("invalid_installation_record"));
            }
        }
        Ok(record)
    }

    fn data(&self) -> Option<&FileIdentity> {
        match &self.phase {
            Phase::Pending { .. } | Phase::Atomic { .. } => None,
            Phase::Ready { data } | Phase::Updating { data, .. } | Phase::Uninstalled { data } => {
                Some(data)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicReview {
    pub runtime_id: String,
    pub data_bytes: u64,
    pub archive: String,
    pub archive_present: bool,
    pub bundle_id: String,
    pub source_sha256: String,
    pub review_id: String,
}

impl AtomicReview {
    pub fn validate(&self) -> Result<()> {
        if !crate::config::drive_file(&self.archive)
            || !self.archive.ends_with("\\data.vhdx")
            || !oblivion_bundle::hash(&self.bundle_id)
            || !oblivion_bundle::hash(&self.source_sha256)
            || !oblivion_bundle::hash(&self.review_id)
        {
            return Err(Error("invalid_atomic_review"));
        }
        Data::NewDisk {
            runtime_id: self.runtime_id.clone(),
            bytes: self.data_bytes,
        }
        .validate()
        .map_err(|_| Error("invalid_atomic_review"))
    }

    fn from_record(record: &Record, archive: String, archive_present: bool) -> Result<Self> {
        let binding = serde_json::to_vec(&(record, &archive, archive_present))
            .map_err(|_| Error("invalid_atomic_review"))?;
        let review = Self {
            runtime_id: record.runtime_id.clone(),
            data_bytes: record.data_bytes,
            archive,
            archive_present,
            bundle_id: record.bundle.bundle_id.clone(),
            source_sha256: record.bundle.source_sha256.clone(),
            review_id: format!("{:x}", Sha256::digest(binding)),
        };
        review.validate()?;
        Ok(review)
    }
}

fn data_stage(value: &str) -> bool {
    value
        .strip_prefix(".data-")
        .and_then(|value| value.strip_suffix(".vhdx"))
        .is_some_and(valid_id)
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub releases_removed: usize,
    pub boot_files_removed: usize,
    pub retained: usize,
    pub in_use: usize,
    pub software_removed: bool,
}

fn configuration(root: &str, runtime_id: &str) -> Result<RuntimeConfig> {
    let config = RuntimeConfig {
        version: 1,
        backend: "hcs-hyperv".into(),
        runtime_id: runtime_id.into(),
        kernel: format!(r"{root}\boot\kernel"),
        initrd: format!(r"{root}\boot\initrd"),
        command_line: format!(
            "boot=live components quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={runtime_id}"
        ),
        disks: vec![
            Disk {
                path: format!(r"{root}\boot\controller.iso"),
                read_only: true,
            },
            Disk {
                path: format!(r"{root}\data.vhdx"),
                read_only: false,
            },
        ],
        cpu_count: 4,
        memory_mi_b: 6144,
        control_pipe: format!(r"\\.\pipe\oblivion.{runtime_id}.control"),
        control_port: 4050,
        network: true,
        serial_stdio: false,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(windows)]
mod native {
    use super::{
        AtomicReview, AtomicStage, Cleanup, FileIdentity, PendingDisk, Phase, RECORD_LIMIT, Record,
        configuration,
    };
    use crate::bundle::VerifiedBundle;
    use crate::config::CONFIG_LIMIT;
    use crate::files::{self, Asset, CreationParent, Directory};
    use crate::security::Identity;
    use crate::supervisor::{self, Lease, Settings};
    use crate::{Error, Result, hcs};
    use oblivion_wire::runtime_auth::Data;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    #[cfg(test)]
    use windows_sys::Win32::Foundation::ERROR_FILE_EXISTS;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    #[cfg(test)]
    use windows_sys::Win32::Storage::FileSystem::CREATE_NEW;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    #[derive(Clone)]
    pub struct Root {
        path: PathBuf,
        storage: Identity,
        client: Identity,
        broker: bool,
    }
    impl Root {
        /// Discovery only: this never creates the directory or changes its ACL.
        pub fn current() -> Result<Self> {
            Self::for_user(&Identity::current()?)
        }
        /// The broker supplies the authenticated caller identity. No client
        /// request or environment variable supplies a root path.
        pub fn for_user(client: &Identity) -> Result<Self> {
            let mut path = null_mut();
            let status =
                unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut path) };
            if status < 0 || path.is_null() {
                return Err(Error("program_data_unavailable"));
            }
            let length = (0..32768).find(|index| unsafe { *path.add(*index) == 0 });
            let text = length.and_then(|length| {
                String::from_utf16(unsafe { std::slice::from_raw_parts(path, length) }).ok()
            });
            unsafe {
                CoTaskMemFree(path.cast());
            }
            Self::new(
                PathBuf::from(text.ok_or(Error("program_data_unavailable"))?)
                    .join("Oblivion")
                    .join(client.sid()),
                Identity::administrators()?,
                client.clone(),
                true,
            )
        }
        /// An explicit test/embedding prefix uses the same private-root checks.
        /// Construction is lexical and has no filesystem side effects.
        pub fn at(path: &Path) -> Result<Self> {
            let identity = Identity::current()?;
            Self::new(path.to_owned(), identity.clone(), identity, false)
        }
        fn new(path: PathBuf, storage: Identity, client: Identity, broker: bool) -> Result<Self> {
            let root = Self {
                path,
                storage,
                client,
                broker,
            };
            if !crate::config::drive_file(&root.file("installation.json")?) {
                return Err(Error("unsupported_installation_path"));
            }
            Ok(root)
        }
        pub fn path(&self) -> &Path {
            &self.path
        }
        pub fn client_identity(&self) -> &Identity {
            &self.client
        }
        pub fn storage_identity(&self) -> &Identity {
            &self.storage
        }
        fn file(&self, leaf: &str) -> Result<String> {
            self.path
                .join(leaf)
                .to_str()
                .map(str::to_owned)
                .ok_or(Error("unsupported_installation_path"))
        }
        fn release(&self, id: &str) -> Result<String> {
            self.file(&format!(r"releases\{id}"))
        }
        fn guard(&self) -> Result<CreationParent> {
            if self.broker
                && !self
                    .storage
                    .permits(unsafe { GetCurrentProcessId() }, false)
                    .unwrap_or(false)
            {
                return Err(Error("windows_administrator_required"));
            }
            match std::fs::symlink_metadata(&self.path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error("runtime_not_installed"));
                }
                Err(_) => return Err(Error("installation_directory_unavailable")),
            }
            if self.broker {
                checked_directory(
                    self.path
                        .parent()
                        .ok_or(Error("unsupported_installation_path"))?,
                    &self.storage,
                    &Identity::from_sid("S-1-5-11")?,
                )?;
            }
            checked_directory(&self.path, &self.storage, &self.client)?;
            if exists(&self.file("releases")?)? {
                checked_directory(&self.path.join("releases"), &self.storage, &self.client)?;
            }
            if exists(&self.file("boot")?)? {
                checked_directory(&self.path.join("boot"), &self.storage, &self.storage)?;
            }
            CreationParent::open(&self.file("installation.json")?, &self.storage)
        }
        fn create(&self) -> Result<()> {
            if self.broker {
                ensure_directory(
                    self.path
                        .parent()
                        .ok_or(Error("unsupported_installation_path"))?,
                    &self.storage,
                    &Identity::from_sid("S-1-5-11")?,
                )?;
            }
            ensure_directory(&self.path, &self.storage, &self.client)
        }
    }

    pub struct Installed {
        root: Root,
        record: Record,
        bundle: VerifiedBundle,
    }
    impl Installed {
        pub fn runtime_id(&self) -> &str {
            &self.record.runtime_id
        }
        pub fn launcher(&self) -> &str {
            self.bundle.cli()
        }
        pub fn helper(&self) -> &str {
            self.bundle.helper()
        }
        pub fn client_identity(&self) -> &Identity {
            self.root.client_identity()
        }
        pub fn storage_identity(&self) -> &Identity {
            self.root.storage_identity()
        }
        pub fn source(&self) -> &str {
            self.bundle.source()
        }
        pub fn manager(&self) -> &str {
            self.bundle.manager()
        }
        pub fn assets(&self) -> &str {
            self.bundle.assets()
        }
        pub fn settings(&self) -> Result<Settings> {
            preflight()?;
            settings(&self.root, &self.record, &self.bundle)
        }
        pub fn acquire(&self, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Lease> {
            supervisor::acquire(&self.settings()?, stop, deadline)
        }
    }

    /// No UAC prompt or implicit privilege acquisition occurs. A non-elevated
    /// installed broker remains a separate, unqualified product boundary.
    pub fn preflight() -> Result<()> {
        if !cfg!(target_arch = "x86_64") {
            return Err(Error("windows_x86_64_required"));
        }
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(Error("windows_elevation_or_broker_required"));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut elevation = TOKEN_ELEVATION::default();
        let mut length = 0;
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut length,
            )
        } == 0
            || elevation.TokenIsElevated == 0
        {
            return Err(Error("windows_elevation_or_broker_required"));
        }
        let capabilities = hcs::capabilities()?;
        if !capabilities.nested_virtualization
            || !capabilities
                .schemas
                .iter()
                .any(|version| version.major == 2 && version.minor >= 2)
        {
            return Err(Error("hcs_nested_virtualization_required"));
        }
        Ok(())
    }

    pub fn install_bundle(
        root: &Root,
        incoming: VerifiedBundle,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Installed> {
        Data::NewDisk {
            runtime_id: "1".repeat(32),
            bytes,
        }
        .validate()
        .map_err(|_| Error("invalid_runtime_data_authority"))?;
        preflight()?;
        check(&stop, deadline)?;
        root.create()?;
        let _root = root.guard()?;
        let _setup = setup_lock(root)?;
        let identity = root.storage.clone();
        let requested = incoming.binding()?;
        let previous = exists(&root.file("installation.json")?)?
            .then(|| read_record(root, &identity))
            .transpose()?;
        let mut record = match previous {
            Some(record)
                if !matches!(
                    &record.phase,
                    Phase::Atomic {
                        stage: AtomicStage::Complete,
                        ..
                    }
                ) =>
            {
                if matches!(&record.phase, Phase::Uninstalled { .. }) {
                    // Reinstall only restores software around the recorded disk.
                    // It must never regain Pending's initialization authority.
                    return update_bundle(root, incoming, stop, deadline);
                }
                if !same_binding(&record.bundle, &requested)? || record.data_bytes != bytes {
                    return Err(Error("installation_resume_requires_matching_bundle"));
                }
                match record.phase {
                    Phase::Pending { .. } => record,
                    Phase::Ready { .. } => {
                        let installed = discover(root)?;
                        let _stopped = supervisor::stopped(
                            &maintenance(root, &record, &record.bundle)?,
                            Arc::clone(&stop),
                            deadline,
                        )?;
                        if root.broker {
                            crate::scm::quiesce(&root.client, Arc::clone(&stop), deadline)?;
                            crate::scm::install(&root.client, Path::new(installed.helper()))?;
                        }
                        return Ok(installed);
                    }
                    _ => return Err(Error("installation_already_present_or_pending")),
                }
            }
            retired => {
                empty_setup(root, retired.is_some())?;
                if retired.is_some() && root.broker {
                    crate::user_command::require_retired_registration_cleared(&root.client)?;
                }
                let runtime_id = random_id()?;
                let config = configuration(
                    root.path()
                        .to_str()
                        .ok_or(Error("unsupported_installation_path"))?,
                    &runtime_id,
                )?;
                let config_bytes = serde_json::to_vec(&config)
                    .map_err(|_| Error("runtime_configuration_encode_failed"))?;
                let record = Record {
                    version: 1,
                    runtime_id,
                    bundle: requested,
                    config_sha256: format!("{:x}", Sha256::digest(&config_bytes)),
                    data_bytes: bytes,
                    phase: Phase::Pending {
                        disk: PendingDisk::Uncreated,
                    },
                };
                if let Some(previous) = retired {
                    locked_registry(root, &previous, &identity)?.save(&record)?;
                } else {
                    create_record(root, &record, &identity)?;
                }
                record
            }
        };
        let (mut registry, _) = registry(root, &identity)?;
        ensure_directory(&root.path.join("releases"), &identity, &root.client)?;
        ensure_directory(&root.path.join("boot"), &identity, &identity)?;
        check(&stop, deadline)?;
        let release = root.release(&record.bundle.bundle_id)?;
        let bundle = if exists(&release)? {
            verified_bundle(root, &record, &identity)?
        } else {
            incoming.publish(&release, &identity, &root.client)?
        };
        prepare_configuration(root, &record, &identity)?;
        let settings = settings(root, &record, &bundle)?;
        // Pending has no user-visible broker or Safe. Cancel only an earlier
        // owned initialization, then reconcile its receipt before reusing data.
        supervisor::prepare_setup(&settings, Arc::clone(&stop), deadline)?;
        for asset in &record.bundle.boot {
            check(&stop, deadline)?;
            let leaf = boot_leaf(asset)?;
            let destination = root.file(&format!(r"boot\{leaf}"))?;
            if exists(&destination)? {
                let boot = Directory::open(&root.file("boot")?, &identity, true)?;
                let existing = boot.asset(leaf, &identity, true)?;
                if !matches_asset(&existing, asset)? {
                    return Err(Error("installed_runtime_boot_changed"));
                }
                continue;
            }
            let source = format!(r"{}\{}", bundle.root(), asset.path.replace('/', r"\"));
            copy_boot(&source, &destination, asset, &identity)?;
        }
        let disk = prepare_disk(root, &mut record, &mut registry, &identity)?;
        let evidence = disk.evidence()?;
        let mut lease = supervisor::initialize(&settings, &evidence, Arc::clone(&stop), deadline)?;
        supervisor::stop(&settings, Arc::clone(&stop), deadline)?;
        lease.close()?;
        let _stopped = supervisor::stopped(&settings, Arc::clone(&stop), deadline)?;
        let evidence = disk.evidence()?;
        let (volume, file) = evidence.file_identity();
        let Phase::Pending {
            disk: PendingDisk::Published { data },
        } = &record.phase
        else {
            return Err(Error("installation_disk_publication_unconfirmed"));
        };
        if (volume, file) != (data.volume, data.file) {
            return Err(Error("installed_data_identity_changed"));
        }
        record.phase = Phase::Ready { data: data.clone() };
        registry.save(&record)?;
        if root.broker {
            crate::scm::install(&root.client, Path::new(bundle.helper()))?;
        }
        Ok(Installed {
            root: root.clone(),
            record,
            bundle,
        })
    }

    struct SetupLock {
        _file: File,
        _parent: CreationParent,
    }

    fn setup_lock(root: &Root) -> Result<SetupLock> {
        exclusive_empty_lock(root, "setup.lock")
    }

    fn exclusive_empty_lock(root: &Root, leaf: &str) -> Result<SetupLock> {
        let path = root.file(leaf)?;
        let parent = CreationParent::open(&path, &root.storage)?;
        let descriptor = root.storage.file_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let name = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                &attributes,
                windows_sys::Win32::Storage::FileSystem::OPEN_ALWAYS,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error(
                if unsafe { GetLastError() }
                    == windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION
                {
                    "installation_setup_in_progress"
                } else {
                    "installation_setup_lock_failed"
                },
            ));
        }
        let file = unsafe { File::from_raw_handle(handle) };
        files::verify_private(&file, &path, &root.storage)?;
        if file
            .metadata()
            .map_err(|_| Error("installation_setup_lock_failed"))?
            .len()
            != 0
        {
            return Err(Error("invalid_installation_setup_lock"));
        }
        parent.verify()?;
        Ok(SetupLock {
            _file: file,
            _parent: parent,
        })
    }

    fn empty_setup(root: &Root, retired: bool) -> Result<()> {
        let directory = Directory::open(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            &root.storage,
            true,
        )?;
        for name in directory.names(256)? {
            if name == "setup.lock" || retired && name == "installation.json" {
                continue;
            }
            // A crash before the first atomic record publication can retain a
            // partial metadata staging file. It is preserved, never adopted.
            if !name
                .strip_prefix("installation-")
                .and_then(|name| name.strip_suffix(".pending"))
                .is_some_and(oblivion_wire::control::valid_id)
            {
                return Err(Error("installation_already_present_or_pending"));
            }
            if directory.asset(&name, &root.storage, true)?.bytes() > RECORD_LIMIT as u64 {
                return Err(Error("installation_already_present_or_pending"));
            }
        }
        Ok(())
    }

    fn prepare_configuration(root: &Root, record: &Record, identity: &Identity) -> Result<()> {
        let path = root.file("vm.json")?;
        if exists(&path)? {
            return verify_config(root, record, identity);
        }
        let bytes = serde_json::to_vec(&configuration(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            &record.runtime_id,
        )?)
        .map_err(|_| Error("runtime_configuration_encode_failed"))?;
        if format!("{:x}", Sha256::digest(&bytes)) != record.config_sha256 {
            return Err(Error("installed_runtime_configuration_changed"));
        }
        let directory = Directory::open(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            identity,
            true,
        )?;
        directory.sync()?;
        let mut stage =
            directory.create_file(&format!("configuration-{}.pending", random_id()?), identity)?;
        stage
            .writer()
            .write_all(&bytes)
            .map_err(|_| Error("runtime_configuration_write_failed"))?;
        stage.finish()?;
        directory.sync()?;
        stage.move_to(&directory, "vm.json", identity)?;
        directory.sync()?;
        verify_config(root, record, identity)
    }

    fn prepare_disk(
        root: &Root,
        record: &mut Record,
        registry: &mut Registry,
        identity: &Identity,
    ) -> Result<crate::disk::CreatedDisk> {
        let Phase::Pending { disk } = &record.phase else {
            return Err(Error("installation_pending"));
        };
        let target = root.file("data.vhdx")?;
        let disk = match disk {
            PendingDisk::Uncreated => {
                if exists(&target)? {
                    return Err(Error("unrecognized_installation_disk"));
                }
                let leaf = format!(".data-{}.vhdx", random_id()?);
                let staged = crate::disk::create(
                    &root.file(&leaf)?,
                    &record.runtime_id,
                    record.data_bytes,
                    identity,
                )?;
                let (volume, file) = staged.evidence()?.file_identity();
                record.phase = Phase::Pending {
                    disk: PendingDisk::Staged {
                        data: FileIdentity { volume, file },
                        leaf,
                    },
                };
                // Bind the actual new FileID durably before its fixed name is
                // visible. An SDK-created but unrecorded partial is never reused.
                registry.save(record)?;
                staged
            }
            PendingDisk::Staged { data, leaf } => {
                let stage = root.file(leaf)?;
                match (exists(&stage)?, exists(&target)?) {
                    (true, false) => crate::disk::resume(
                        &stage,
                        &record.runtime_id,
                        record.data_bytes,
                        (data.volume, data.file),
                        identity,
                    )?,
                    (false, true) => crate::disk::resume(
                        &target,
                        &record.runtime_id,
                        record.data_bytes,
                        (data.volume, data.file),
                        identity,
                    )?,
                    _ => return Err(Error("installation_disk_publication_unconfirmed")),
                }
            }
            PendingDisk::Published { data } => {
                return crate::disk::resume(
                    &target,
                    &record.runtime_id,
                    record.data_bytes,
                    (data.volume, data.file),
                    identity,
                );
            }
        };
        let disk = if disk.evidence()?.path() == target {
            disk
        } else {
            disk.publish(&target, identity)?
        };
        let (volume, file) = disk.evidence()?.file_identity();
        record.phase = Phase::Pending {
            disk: PendingDisk::Published {
                data: FileIdentity { volume, file },
            },
        };
        registry.save(record)?;
        Ok(disk)
    }

    pub fn discover(root: &Root) -> Result<Installed> {
        preflight()?;
        let identity = root.storage.clone();
        let _root = root.guard()?;
        let record = read_record(root, &identity)?;
        let Phase::Ready { data } = &record.phase else {
            return Err(phase_error(&record.phase));
        };
        verify_config(root, &record, &identity)?;
        let actual = files::data_file_identity(&root.file("data.vhdx")?)?;
        if actual != (data.volume, data.file) {
            return Err(Error("installed_data_identity_changed"));
        }
        let bundle = verified_bundle(root, &record, &identity)?;
        verify_boot(root, &record, &identity)?;
        Ok(Installed {
            root: root.clone(),
            record,
            bundle,
        })
    }

    /// Cheap activity/status discovery. This reads only private metadata and the
    /// bounded configuration; it never hashes an ISO, boots or probes HCS.
    pub fn control_id(root: &Root) -> Result<String> {
        let record = control_record(root, true)?;
        Ok(record.runtime_id)
    }
    pub fn control_binding(root: &Root) -> Result<(String, String)> {
        let record = control_record(root, false)?;
        Ok((record.runtime_id, record.bundle.source_sha256))
    }
    fn control_record(root: &Root, ready: bool) -> Result<Record> {
        let identity = root.storage.clone();
        let _root = root.guard()?;
        let record = read_record(root, &identity)?;
        if ready && !matches!(record.phase, Phase::Ready { .. }) {
            return Err(phase_error(&record.phase));
        }
        verify_config(root, &record, &identity)?;
        Ok(record)
    }

    /// Explicit stop/control may address an interrupted setup. This grants no
    /// initialization capability and never clears Pending or Recovery records.
    pub fn owned_settings(root: &Root) -> Result<Settings> {
        let identity = root.storage.clone();
        let _root = root.guard()?;
        let record = read_record(root, &identity)?;
        verify_config(root, &record, &identity)?;
        maintenance(root, &record, &record.bundle)
    }

    /// Update never starts or stops a VM. The exclusive supervisor capability
    /// proves the last owned generation stopped and fences new admission.
    pub fn update_bundle(
        root: &Root,
        incoming: VerifiedBundle,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Installed> {
        let identity = root.storage.clone();
        let _root = root.guard()?;
        let mut record = read_record(root, &identity)?;
        let data = record
            .data()
            .cloned()
            .ok_or_else(|| phase_error(&record.phase))?;
        verify_config(root, &record, &identity)?;
        verify_data(root, &data)?;
        let target = incoming.binding()?;
        if let Phase::Updating {
            target: expected, ..
        } = &record.phase
        {
            if !same_binding(expected, &target)? {
                return Err(Error("installation_update_requires_matching_bundle"));
            }
        }
        let base = maintenance(root, &record, &record.bundle)?;
        let next = maintenance(root, &record, &target)?;
        let mut stopped = supervisor::stopped_update(&base, &next, Arc::clone(&stop), deadline)?;
        if root.broker {
            crate::scm::quiesce(&root.client, Arc::clone(&stop), deadline)?;
        }
        let mut registry = locked_registry(root, &record, &identity)?;
        check(&stop, deadline)?;
        if matches!(record.phase, Phase::Ready { .. }) {
            verify_boot(root, &record, &identity)?;
        }
        // A prior complete publication can be reused only by its full manifest,
        // hashes and identity. A partial/foreign tree is retained and rejected.
        let release = root.release(&target.bundle_id)?;
        let bundle = match std::fs::symlink_metadata(&release) {
            Ok(_) => {
                let existing =
                    VerifiedBundle::open(&release, Some(&target.source_sha256), &identity)?;
                if !same_binding(&existing.binding()?, &target)? {
                    return Err(Error("installed_runtime_bundle_changed"));
                }
                existing
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                incoming.publish(&release, &identity, &root.client)?
            }
            Err(_) => return Err(Error("runtime_release_unavailable")),
        };
        let boot = Directory::open(&root.file("boot")?, &identity, true)?;
        let mut staged = Vec::new();
        for asset in &target.boot {
            check(&stop, deadline)?;
            let leaf = boot_leaf(asset)?;
            let stage = format!("update-{}-{leaf}", target.bundle_id);
            if !exists(&format!(r"{}\{stage}", boot.path()))? {
                let active = boot_asset(&boot, leaf, &identity)?;
                let already_current = match active.as_ref() {
                    Some(file) => matches_asset(file, asset)?,
                    None => false,
                };
                if !already_current {
                    let source = format!(r"{}\{}", bundle.root(), asset.path.replace('/', r"\"));
                    copy_boot(
                        &source,
                        &format!(r"{}\{stage}", boot.path()),
                        asset,
                        &identity,
                    )?;
                }
            }
            let prepared = boot_asset(&boot, &stage, &identity)?;
            if let Some(file) = &prepared {
                if !matches_asset(file, asset)? {
                    return Err(Error("installation_update_staging_changed"));
                }
            }
            staged.push(prepared);
        }
        // All source copies are complete before the durable transition. No
        // Ready installation observes a partly replaced set of boot files.
        record.phase = Phase::Updating {
            data: data.clone(),
            target: target.clone(),
        };
        registry.save(&record)?;
        for ((old, asset), prepared) in record.bundle.boot.iter().zip(&target.boot).zip(staged) {
            check(&stop, deadline)?;
            let leaf = boot_leaf(asset)?;
            if let Some(active) = boot_asset(&boot, leaf, &identity)? {
                if matches_asset(&active, asset)? {
                    if let Some(prepared) = prepared {
                        prepared.removal(&identity)?.remove()?;
                    }
                    continue;
                }
                if !matches_asset(&active, old)? {
                    return Err(Error("installed_runtime_boot_changed"));
                }
                active.removal(&identity)?.remove()?;
            }
            prepared
                .ok_or(Error("installation_update_staging_missing"))?
                .move_to(&boot, leaf, &identity)?;
        }
        boot.sync()?;
        let mut ready = record.clone();
        ready.bundle = target;
        ready.phase = Phase::Ready { data };
        verify_boot(root, &ready, &identity)?;
        stopped.rebind(&next)?;
        registry.save(&ready)?;
        if root.broker {
            // SCM demand-start stays disabled from quiesce until both durable
            // bindings are committed. Keep Stopped held through ImagePath swap.
            crate::scm::install(&root.client, Path::new(bundle.helper()))?;
        }
        Ok(Installed {
            root: root.clone(),
            record: ready,
            bundle,
        })
    }

    pub fn collect(root: &Root, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Cleanup> {
        cleanup(root, false, stop, deadline)
    }

    /// Software only: configuration, runtime identity, supervisor journal and
    /// the exact encrypted data file remain available for explicit reinstall.
    pub fn uninstall(root: &Root, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Cleanup> {
        cleanup(root, true, stop, deadline)
    }

    pub fn atomic_review(root: &Root) -> Result<AtomicReview> {
        let _root = root.guard()?;
        let (registry, record) = registry(root, &root.storage)?;
        let archive = atomic_archive(root, &registry.directory, &record)?;
        AtomicReview::from_record(&record, root.file("data.vhdx")?, archive.is_some())
    }

    /// The elevated request names only the exact locally reviewed installation.
    /// Preparation and completion both remain fenced by its durable record.
    pub fn atomic(
        root: &Root,
        expected: &AtomicReview,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Cleanup> {
        expected.validate()?;
        let _root = root.guard()?;
        let _setup = setup_lock(root)?;
        let identity = &root.storage;
        let mut record = read_record(root, identity)?;
        if record.runtime_id != expected.runtime_id {
            return Err(Error("atomic_review_changed"));
        }
        let data = match &record.phase {
            Phase::Ready { data } | Phase::Uninstalled { data } | Phase::Atomic { data, .. } => {
                data.clone()
            }
            _ => return Err(phase_error(&record.phase)),
        };
        let mut registry = locked_registry(root, &record, identity)?;
        let archive = atomic_archive(root, &registry.directory, &record)?;
        if AtomicReview::from_record(&record, root.file("data.vhdx")?, archive.is_some())?
            != *expected
        {
            return Err(Error("atomic_review_changed"));
        }
        if matches!(
            &record.phase,
            Phase::Atomic {
                stage: AtomicStage::Complete,
                ..
            }
        ) {
            return Ok(Cleanup {
                software_removed: true,
                ..Cleanup::default()
            });
        }

        let mut report = Cleanup {
            software_removed: true,
            ..Cleanup::default()
        };
        if let Some(archive) = archive {
            verify_config(root, &record, identity)?;
            let _stopped = supervisor::stopped(
                &maintenance(root, &record, &record.bundle)?,
                Arc::clone(&stop),
                deadline,
            )?;
            check(&stop, deadline)?;
            if !matches!(&record.phase, Phase::Atomic { .. }) {
                record.phase = Phase::Atomic {
                    data: data.clone(),
                    stage: AtomicStage::Preparing,
                };
                registry.save(&record)?;
            }
            if root.broker {
                crate::scm::quiesce(&root.client, Arc::clone(&stop), deadline)?;
                crate::scm::remove(&root.client)?;
            }
            let resource_guard = exclusive_empty_lock(root, "vm.json.resources.lock")?;
            let (volume, file) = files::data_handle_identity(
                &resource_guard._file,
                &root.file("vm.json.resources.lock")?,
            )?;
            let resource_lock = FileIdentity { volume, file };
            let resources = atomic_resources(root, &registry.directory, &record, &data)?;
            let config = atomic_file_identity(root, "vm.json")?;
            let journal = atomic_file_identity(root, "vm.json.supervision.json")?;
            if let Phase::Atomic {
                stage:
                    AtomicStage::Deleting {
                        config: expected_config,
                        journal: expected_journal,
                        resources: expected_resources,
                        resource_lock: expected_lock,
                    },
                ..
            } = &record.phase
            {
                if (&config, &journal, &resources, &resource_lock)
                    != (
                        expected_config,
                        expected_journal,
                        expected_resources,
                        expected_lock,
                    )
                {
                    return Err(Error("atomic_metadata_identity_changed"));
                }
            } else {
                report = collect_software(root, &record, true, true, &stop, deadline)?;
                if !report.software_removed {
                    return Ok(report);
                }
                record.phase = Phase::Atomic {
                    data: data.clone(),
                    stage: AtomicStage::Deleting {
                        config,
                        journal,
                        resources,
                        resource_lock,
                    },
                };
                registry.save(&record)?;
            }
            check(&stop, deadline)?;
            archive.removal(identity)?.remove()?;
            registry.directory.sync()?;
        }

        let Phase::Atomic {
            stage:
                AtomicStage::Deleting {
                    config,
                    journal,
                    resources,
                    resource_lock,
                },
            ..
        } = &record.phase
        else {
            return Err(Error("atomic_recovery_required"));
        };
        // Deleting is durable evidence that the exact runtime was Stopped and
        // its executable/service were removed. No new runtime can be admitted
        // while this record is present, even if the old journal is gone.
        for (name, expected) in [
            ("vm.json", Some(config)),
            ("vm.json.supervision.json", Some(journal)),
            ("vm.json.resources.json", resources.as_ref()),
            ("vm.json.resources.lock", Some(resource_lock)),
        ] {
            check(&stop, deadline)?;
            if let Some(asset) = boot_asset(&registry.directory, name, identity)? {
                if !expected
                    .is_some_and(|expected| asset.identity() == (expected.volume, expected.file))
                {
                    return Err(Error("atomic_metadata_identity_changed"));
                }
                asset.removal(identity)?.remove()?;
                registry.directory.sync()?;
            }
        }
        for name in ["boot", "releases"] {
            check(&stop, deadline)?;
            if exists(&root.file(name)?)? {
                registry
                    .directory
                    .child(name, identity, true)?
                    .remove(identity)?;
                registry.directory.sync()?;
            }
        }
        record.phase = Phase::Atomic {
            data,
            stage: AtomicStage::Complete,
        };
        registry.save(&record)?;
        Ok(report)
    }

    fn atomic_archive(
        root: &Root,
        directory: &Directory,
        record: &Record,
    ) -> Result<Option<Asset>> {
        let (expected, may_be_absent, must_be_absent) = match &record.phase {
            Phase::Ready { data }
            | Phase::Uninstalled { data }
            | Phase::Atomic {
                data,
                stage: AtomicStage::Preparing,
            } => (data, false, false),
            Phase::Atomic {
                data,
                stage: AtomicStage::Deleting { .. },
            } => (data, true, false),
            Phase::Atomic {
                data,
                stage: AtomicStage::Complete,
            } => (data, true, true),
            _ => return Err(phase_error(&record.phase)),
        };
        let archive = boot_asset(directory, "data.vhdx", &root.storage)?;
        match &archive {
            Some(asset)
                if !must_be_absent && asset.identity() == (expected.volume, expected.file) =>
            {
                verify_config(root, record, &root.storage)?;
            }
            None if may_be_absent => {}
            _ => return Err(Error("installed_data_identity_changed")),
        }
        Ok(archive)
    }

    fn atomic_file_identity(root: &Root, leaf: &str) -> Result<FileIdentity> {
        let (volume, file) = files::data_file_identity(&root.file(leaf)?)?;
        Ok(FileIdentity { volume, file })
    }

    fn atomic_resources(
        root: &Root,
        directory: &Directory,
        record: &Record,
        data: &FileIdentity,
    ) -> Result<Option<FileIdentity>> {
        let Some(asset) = boot_asset(directory, "vm.json.resources.json", &root.storage)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        asset
            .reader()?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("resource_record_unavailable"))?;
        crate::resources::verify_retired_receipt(
            &bytes,
            &record.runtime_id,
            &record.config_sha256,
            root.client.sid(),
            root.storage.sid(),
            crate::resources::FileEvidence {
                volume: data.volume,
                file: data.file,
                bytes: record.data_bytes,
            },
        )?;
        let (volume, file) = asset.identity();
        Ok(Some(FileIdentity { volume, file }))
    }

    fn cleanup(
        root: &Root,
        uninstall: bool,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Cleanup> {
        let identity = root.storage.clone();
        let _root = root.guard()?;
        let mut record = read_record(root, &identity)?;
        if matches!(record.phase, Phase::Updating { .. }) {
            return Err(Error("installation_update_requires_matching_bundle"));
        }
        let data = record
            .data()
            .cloned()
            .ok_or_else(|| phase_error(&record.phase))?;
        verify_config(root, &record, &identity)?;
        verify_data(root, &data)?;
        let _stopped = supervisor::stopped(
            &maintenance(root, &record, &record.bundle)?,
            Arc::clone(&stop),
            deadline,
        )?;
        if root.broker {
            crate::scm::quiesce(&root.client, Arc::clone(&stop), deadline)?;
            if uninstall {
                crate::scm::remove(&root.client)?;
            }
        }
        let mut registry = locked_registry(root, &record, &identity)?;
        if uninstall {
            record.phase = Phase::Uninstalled { data };
            registry.save(&record)?;
        }
        let report = collect_software(root, &record, uninstall, false, &stop, deadline)?;
        if root.broker && !uninstall && matches!(record.phase, Phase::Ready { .. }) {
            let bundle = verified_bundle(root, &record, &identity)?;
            crate::scm::install(&root.client, Path::new(bundle.helper()))?;
        }
        Ok(report)
    }

    fn collect_software(
        root: &Root,
        record: &Record,
        uninstall: bool,
        atomic: bool,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<Cleanup> {
        let identity = &root.storage;
        let mut report = Cleanup::default();
        let executable =
            std::env::current_exe().map_err(|_| Error("current_executable_unavailable"))?;
        let executable = executable
            .to_str()
            .ok_or(Error("current_executable_unavailable"))?;
        let executable =
            files::data_file_identity(executable.strip_prefix(r"\\?\").unwrap_or(executable))?;
        let releases = Directory::open(&root.file("releases")?, identity, true)?;
        for name in releases.names(256)? {
            check(stop, deadline)?;
            if !uninstall && name == record.bundle.bundle_id {
                continue;
            }
            if !oblivion_bundle::hash(&name) {
                report.retained += 1;
                continue;
            }
            let path = root.release(&name)?;
            if atomic {
                let directory = Directory::open(&path, identity, false)?;
                if directory.names(4096)?.is_empty() {
                    directory.remove(identity)?;
                    report.releases_removed += 1;
                    continue;
                }
            }
            let bundle = if atomic {
                VerifiedBundle::open_for_atomic(&path, identity)
            } else {
                VerifiedBundle::open(&path, None, identity)
            };
            match bundle {
                Ok(bundle) if bundle.id() == name && bundle.contains_file(executable) => {
                    // A mapped PE may reject deletion only after DELETE access
                    // was admitted. Preserve the complete invoking release.
                    report.in_use += 1;
                }
                Ok(bundle) if bundle.id() == name => match if atomic {
                    bundle.remove_for_atomic(identity)
                } else {
                    bundle.remove(identity)
                } {
                    Ok(()) => report.releases_removed += 1,
                    Err(Error("runtime_software_in_use")) => report.in_use += 1,
                    Err(_) => report.retained += 1,
                },
                _ => report.retained += 1,
            }
        }
        releases.sync()?;
        if uninstall {
            let boot = Directory::open(&root.file("boot")?, identity, true)?;
            let mut removals = Vec::new();
            for expected in &record.bundle.boot {
                check(stop, deadline)?;
                if let Some(asset) = boot_asset(&boot, boot_leaf(expected)?, identity)? {
                    if !matches_asset(&asset, expected)? {
                        report.retained += 1;
                        continue;
                    }
                    match asset.removal(identity) {
                        Ok(removal) => removals.push(removal),
                        Err(Error("runtime_software_in_use")) => report.in_use += 1,
                        Err(_) => report.retained += 1,
                    }
                }
            }
            for removal in removals {
                match removal.remove() {
                    Ok(()) => report.boot_files_removed += 1,
                    Err(_) => report.retained += 1,
                }
            }
            boot.sync()?;
            let remaining = boot.names(256)?;
            report.retained += remaining
                .iter()
                .filter(|name| {
                    !record
                        .bundle
                        .boot
                        .iter()
                        .any(|asset| asset.path.rsplit('/').next() == Some(name.as_str()))
                })
                .count();
            report.software_removed = releases.names(256)?.is_empty() && remaining.is_empty();
        }
        Ok(report)
    }

    fn phase_error(phase: &Phase) -> Error {
        match phase {
            Phase::Updating { .. } => Error("installation_update_requires_matching_bundle"),
            Phase::Uninstalled { .. } => Error("runtime_software_uninstalled"),
            Phase::Atomic { .. } => Error("runtime_atomic_removal_pending"),
            _ => Error("installation_pending"),
        }
    }
    fn maintenance(
        root: &Root,
        record: &Record,
        binding: &oblivion_bundle::Binding,
    ) -> Result<Settings> {
        Settings::maintenance_for(
            &record.runtime_id,
            Path::new(&format!(
                r"{}\bin\oblivion-vm.exe",
                root.release(&binding.bundle_id)?
            )),
            Path::new(&root.file("vm.json")?),
            &record.config_sha256,
            &binding.source_sha256,
            &root.client,
            &root.storage,
        )
    }
    fn verify_data(root: &Root, data: &FileIdentity) -> Result<()> {
        if files::data_file_identity(&root.file("data.vhdx")?)? != (data.volume, data.file) {
            return Err(Error("installed_data_identity_changed"));
        }
        Ok(())
    }
    fn same_binding(
        left: &oblivion_bundle::Binding,
        right: &oblivion_bundle::Binding,
    ) -> Result<bool> {
        Ok(
            serde_json::to_vec(left).map_err(|_| Error("invalid_runtime_bundle_binding"))?
                == serde_json::to_vec(right)
                    .map_err(|_| Error("invalid_runtime_bundle_binding"))?,
        )
    }
    fn exists(path: &str) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Error("runtime_software_unavailable")),
        }
    }
    fn boot_leaf(asset: &oblivion_bundle::File) -> Result<&str> {
        asset
            .path
            .rsplit('/')
            .next()
            .ok_or(Error("invalid_runtime_bundle_binding"))
    }
    fn boot_asset(directory: &Directory, name: &str, identity: &Identity) -> Result<Option<Asset>> {
        if !exists(&format!(r"{}\{name}", directory.path()))? {
            return Ok(None);
        }
        directory.asset(name, identity, true).map(Some)
    }
    fn matches_asset(asset: &Asset, expected: &oblivion_bundle::File) -> Result<bool> {
        let mut file = asset.reader()?;
        let (bytes, sha256) = hash_stream(&mut file)?;
        Ok(bytes == expected.bytes && sha256 == expected.sha256)
    }
    struct Registry {
        directory: Directory,
        current: Option<Asset>,
        storage: Identity,
    }
    impl Registry {
        fn save(&mut self, record: &Record) -> Result<()> {
            let bytes = serde_json::to_vec(record)
                .map_err(|_| Error("installation_record_encode_failed"))?;
            Record::decode(&bytes)?;
            self.directory.sync()?;
            let identity = &self.storage;
            let mut pending = self
                .directory
                .create_file(&format!("installation-{}.pending", random_id()?), identity)?;
            pending
                .writer()
                .write_all(&bytes)
                .map_err(|_| Error("installation_commit_failed"))?;
            pending.finish()?;
            self.directory.sync()?;
            let previous = self
                .current
                .take()
                .ok_or(Error("installation_record_unavailable"))?;
            self.current = Some(pending.replace(previous, identity)?);
            self.directory.sync()
        }
    }
    fn registry(root: &Root, identity: &Identity) -> Result<(Registry, Record)> {
        let directory = Directory::open(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            identity,
            true,
        )?;
        // Check durable publication support before changing any boot software.
        directory.sync()?;
        let current = directory.asset("installation.json", identity, true)?;
        let mut file = current.reader()?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((RECORD_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("installation_record_unavailable"))?;
        Ok((
            Registry {
                directory,
                current: Some(current),
                storage: identity.clone(),
            },
            Record::decode(&bytes)?,
        ))
    }
    fn locked_registry(root: &Root, expected: &Record, identity: &Identity) -> Result<Registry> {
        let (registry, actual) = registry(root, identity)?;
        if serde_json::to_vec(&actual).map_err(|_| Error("invalid_installation_record"))?
            != serde_json::to_vec(expected).map_err(|_| Error("invalid_installation_record"))?
        {
            return Err(Error("installation_record_changed"));
        }
        Ok(registry)
    }
    fn create_record(root: &Root, record: &Record, identity: &Identity) -> Result<()> {
        let bytes =
            serde_json::to_vec(record).map_err(|_| Error("installation_record_encode_failed"))?;
        Record::decode(&bytes)?;
        let directory = Directory::open(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            identity,
            true,
        )?;
        directory.sync()?;
        let mut file =
            directory.create_file(&format!("installation-{}.pending", random_id()?), identity)?;
        file.writer()
            .write_all(&bytes)
            .map_err(|_| Error("installation_commit_failed"))?;
        file.finish()?;
        directory.sync()?;
        file.move_to(&directory, "installation.json", identity)?;
        directory.sync()
    }

    fn settings(root: &Root, record: &Record, bundle: &VerifiedBundle) -> Result<Settings> {
        Settings::new_for(
            &record.runtime_id,
            Path::new(bundle.helper()),
            Path::new(&root.file("vm.json")?),
            &record.config_sha256,
            &record.bundle.source_sha256,
            &root.client,
            &root.storage,
        )
    }
    fn verified_bundle(
        root: &Root,
        record: &Record,
        identity: &Identity,
    ) -> Result<VerifiedBundle> {
        let bundle = VerifiedBundle::open(
            &root.release(&record.bundle.bundle_id)?,
            Some(&record.bundle.source_sha256),
            identity,
        )?;
        let actual = serde_json::to_vec(&bundle.binding()?)
            .map_err(|_| Error("invalid_runtime_bundle_binding"))?;
        let expected = serde_json::to_vec(&record.bundle)
            .map_err(|_| Error("invalid_runtime_bundle_binding"))?;
        if actual != expected {
            return Err(Error("installed_runtime_bundle_changed"));
        }
        Ok(bundle)
    }
    fn read_record(root: &Root, identity: &Identity) -> Result<Record> {
        Record::decode(&read_private(
            &root.file("installation.json")?,
            RECORD_LIMIT,
            identity,
        )?)
    }
    fn verify_config(root: &Root, record: &Record, identity: &Identity) -> Result<()> {
        let bytes = read_private(&root.file("vm.json")?, CONFIG_LIMIT, identity)?;
        if format!("{:x}", Sha256::digest(&bytes)) != record.config_sha256 {
            return Err(Error("installed_runtime_configuration_changed"));
        }
        let config = crate::config::RuntimeConfig::decode(&bytes)?;
        let expected = configuration(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            &record.runtime_id,
        )?;
        if serde_json::to_vec(&config).map_err(|_| Error("invalid_runtime_configuration"))?
            != serde_json::to_vec(&expected).map_err(|_| Error("invalid_runtime_configuration"))?
        {
            return Err(Error("installed_runtime_configuration_changed"));
        }
        Ok(())
    }
    fn verify_boot(root: &Root, record: &Record, identity: &Identity) -> Result<()> {
        for asset in &record.bundle.boot {
            let leaf = asset
                .path
                .rsplit('/')
                .next()
                .ok_or(Error("invalid_runtime_bundle_binding"))?;
            let path = root.file(&format!(r"boot\{leaf}"))?;
            let _parent = CreationParent::open(&path, identity)?;
            // Metadata identity rejects reparse/hardlink aliases without treating
            // a live VM's temporary ACL grant as installation-wide permissions.
            files::data_file_identity(&path)?;
            let name: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(Error("installed_runtime_boot_unavailable"));
            }
            let mut file = unsafe { File::from_raw_handle(handle) };
            let (bytes, sha256) = hash_stream(&mut file)?;
            if bytes != asset.bytes || sha256 != asset.sha256 {
                return Err(Error("installed_runtime_boot_changed"));
            }
        }
        Ok(())
    }
    fn copy_boot(
        source: &str,
        destination: &str,
        asset: &oblivion_bundle::File,
        identity: &Identity,
    ) -> Result<()> {
        let mut input = File::open(source).map_err(|_| Error("runtime_boot_source_unavailable"))?;
        let (parent, name) = destination
            .rsplit_once('\\')
            .ok_or(Error("invalid_runtime_asset_path"))?;
        let parent = Directory::open(parent, identity, true)?;
        parent.sync()?;
        let mut output = parent.create_file(&format!("boot-{}.pending", random_id()?), identity)?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut bytes = [0; 65536];
        loop {
            let size = input
                .read(&mut bytes)
                .map_err(|_| Error("runtime_boot_copy_failed"))?;
            if size == 0 {
                break;
            }
            count = count
                .checked_add(size as u64)
                .ok_or(Error("runtime_boot_copy_failed"))?;
            if count > asset.bytes {
                return Err(Error("runtime_boot_source_changed"));
            }
            hash.update(&bytes[..size]);
            output
                .writer()
                .write_all(&bytes[..size])
                .map_err(|_| Error("runtime_boot_copy_failed"))?;
        }
        if count != asset.bytes || format!("{:x}", hash.finalize()) != asset.sha256 {
            return Err(Error("runtime_boot_source_changed"));
        }
        output.finish()?;
        parent.sync()?;
        output.move_to(&parent, name, identity)?;
        parent.sync()
    }
    fn hash_stream(input: &mut File) -> Result<(u64, String)> {
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut bytes = [0; 65536];
        loop {
            let size = input
                .read(&mut bytes)
                .map_err(|_| Error("installed_runtime_boot_unavailable"))?;
            if size == 0 {
                break;
            }
            count = count
                .checked_add(size as u64)
                .ok_or(Error("installed_runtime_boot_changed"))?;
            hash.update(&bytes[..size]);
        }
        Ok((count, format!("{:x}", hash.finalize())))
    }
    fn ensure_directory(path: &Path, identity: &Identity, reader: &Identity) -> Result<()> {
        let text = path
            .to_str()
            .ok_or(Error("unsupported_installation_path"))?;
        let parent = CreationParent::ancestors(text)?;
        let descriptor = identity.traversal_for(reader)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let name: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0
            && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
        {
            return Err(Error("private_installation_directory_unavailable"));
        }
        parent.verify()?;
        checked_directory(path, identity, reader)?;
        Ok(())
    }

    fn checked_directory(path: &Path, storage: &Identity, reader: &Identity) -> Result<Directory> {
        let directory = Directory::open(
            path.to_str().ok_or(Error("unsupported_installation_path"))?,
            storage,
            true,
        )?;
        directory.require_traversal(storage, reader)?;
        Ok(directory)
    }
    #[cfg(test)]
    fn create_private(path: &str, identity: &Identity) -> Result<File> {
        let parent = CreationParent::open(path, identity)?;
        let descriptor = identity.file_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let name: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error(match unsafe { GetLastError() } {
                ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => "installation_file_already_exists",
                _ => "installation_file_create_failed",
            }));
        }
        let file = unsafe { File::from_raw_handle(handle) };
        files::verify_private(&file, path, identity)?;
        parent.verify()?;
        Ok(file)
    }
    fn read_private(path: &str, limit: usize, identity: &Identity) -> Result<Vec<u8>> {
        let parent = CreationParent::open(path, identity)?;
        let name: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error(
                if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
                    "runtime_not_installed"
                } else {
                    "installation_record_unavailable"
                },
            ));
        }
        let file = unsafe { File::from_raw_handle(handle) };
        files::verify_private(&file, path, identity)?;
        let mut bytes = vec![];
        file.take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("installation_record_unavailable"))?;
        parent.verify()?;
        if bytes.len() > limit {
            return Err(Error("installation_record_limit"));
        }
        Ok(bytes)
    }
    fn random_id() -> Result<String> {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| Error("runtime_entropy_unavailable"))?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
        if stop.load(Ordering::Acquire) {
            return Err(Error("installation_cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(Error("installation_timeout"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            AtomicReview, AtomicStage, FileIdentity, PendingDisk, Phase, Record, Root, atomic,
            atomic_file_identity, atomic_review, boot_asset, boot_leaf, collect, collect_software,
            checked_directory, configuration, control_id, copy_boot, create_private, create_record,
            empty_setup,
            ensure_directory, maintenance, prepare_disk, random_id, read_record, registry,
            setup_lock, uninstall, update_bundle, verified_bundle,
        };
        use crate::bundle::tests::Fixture;
        use crate::files::{self, Directory, Executable};
        use crate::security::Identity;
        use crate::supervisor;
        use serde_json::json;
        use sha2::{Digest, Sha256};
        use std::io::{Read, Write};
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        struct Area(Root);
        impl Area {
            fn new() -> Self {
                let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
                let temp = temp.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
                let root = Root::at(
                    &std::path::Path::new(temp)
                        .join(format!("oblivion-install-{}", random_id().unwrap())),
                )
                .unwrap();
                assert!(!root.path().exists());
                ensure_directory(root.path(), root.storage_identity(), root.client_identity())
                    .unwrap();
                Self(root)
            }
        }
        impl Drop for Area {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(self.0.path());
            }
        }

        fn pending(area: &Area) -> Record {
            let manifest: oblivion_bundle::Manifest = serde_json::from_str(include_str!(
                "../../oblivion-bundle/tests/fixtures/windows-v2.json"
            ))
            .unwrap();
            let runtime_id = random_id().unwrap();
            let config = serde_json::to_vec(
                &configuration(area.0.path().to_str().unwrap(), &runtime_id).unwrap(),
            )
            .unwrap();
            Record {
                version: 1,
                runtime_id,
                bundle: manifest.binding().unwrap(),
                config_sha256: format!("{:x}", Sha256::digest(config)),
                data_bytes: 4 * 1024 * 1024 * 1024,
                phase: Phase::Pending {
                    disk: PendingDisk::Uncreated,
                },
            }
        }

        #[test]
        fn setup_lock_and_atomic_first_record_preserve_incomplete_metadata_staging() {
            let area = Area::new();
            let identity = Identity::current().unwrap();
            let root = &area.0;
            let owner = setup_lock(root).unwrap();
            assert_eq!(
                setup_lock(root).err().unwrap().0,
                "installation_setup_in_progress"
            );
            let directory =
                Directory::open(root.path().to_str().unwrap(), &identity, true).unwrap();
            let name = format!("installation-{}.pending", random_id().unwrap());
            let mut interrupted = directory.create_file(&name, &identity).unwrap();
            interrupted.writer().write_all(b"{\"version\":").unwrap();
            interrupted.finish().unwrap();
            empty_setup(root, false).unwrap();
            let record = pending(&area);
            create_record(root, &record, &identity).unwrap();
            assert_eq!(
                read_record(root, &identity).unwrap().runtime_id,
                record.runtime_id
            );
            assert_eq!(
                directory.asset(&name, &identity, true).unwrap().identity(),
                interrupted.identity()
            );
            drop(owner);
            setup_lock(root).unwrap();
        }

        #[test]
        fn pending_disk_recovers_exact_identity_after_rename_before_registry_commit() {
            let area = Area::new();
            let identity = Identity::current().unwrap();
            let root = &area.0;
            let mut record = pending(&area);
            create_record(root, &record, &identity).unwrap();
            let (mut registry, _) = registry(root, &identity).unwrap();
            let leaf = format!(".data-{}.vhdx", random_id().unwrap());
            let created = crate::disk::create(
                &root.file(&leaf).unwrap(),
                &record.runtime_id,
                record.data_bytes,
                &identity,
            )
            .unwrap();
            let expected = created.evidence().unwrap().file_identity();
            record.phase = Phase::Pending {
                disk: PendingDisk::Staged {
                    data: FileIdentity {
                        volume: expected.0,
                        file: expected.1,
                    },
                    leaf: leaf.clone(),
                },
            };
            registry.save(&record).unwrap();
            let target = root.file("data.vhdx").unwrap();
            let published = created.publish(&target, &identity).unwrap();
            let mut before = [0; 4096];
            std::fs::File::open(&target)
                .unwrap()
                .read_exact(&mut before)
                .unwrap();
            drop(published);
            let resumed = prepare_disk(root, &mut record, &mut registry, &identity).unwrap();
            assert_eq!(resumed.evidence().unwrap().file_identity(), expected);
            let mut after = [0; 4096];
            std::fs::File::open(&target)
                .unwrap()
                .read_exact(&mut after)
                .unwrap();
            assert_eq!(after, before);
            assert!(!root.path().join(leaf).exists());
            assert!(matches!(
                read_record(root, &identity).unwrap().phase,
                Phase::Pending {
                    disk: PendingDisk::Published { .. }
                }
            ));
        }

        #[test]
        fn pending_disk_refuses_a_replacement_with_the_same_vhdx_uuid_without_overwriting_it() {
            let area = Area::new();
            let identity = Identity::current().unwrap();
            let root = &area.0;
            let mut record = pending(&area);
            create_record(root, &record, &identity).unwrap();
            let (mut registry, _) = registry(root, &identity).unwrap();
            let leaf = format!(".data-{}.vhdx", random_id().unwrap());
            let created = crate::disk::create(
                &root.file(&leaf).unwrap(),
                &record.runtime_id,
                record.data_bytes,
                &identity,
            )
            .unwrap();
            let expected = created.evidence().unwrap().file_identity();
            record.phase = Phase::Pending {
                disk: PendingDisk::Staged {
                    data: FileIdentity {
                        volume: expected.0,
                        file: expected.1,
                    },
                    leaf,
                },
            };
            registry.save(&record).unwrap();
            let original = created
                .publish(&root.file("retained.vhdx").unwrap(), &identity)
                .unwrap();
            let foreign = crate::disk::create(
                &root.file("data.vhdx").unwrap(),
                &record.runtime_id,
                record.data_bytes,
                &identity,
            )
            .unwrap();
            let foreign_id = foreign.evidence().unwrap().file_identity();
            assert_ne!(expected, foreign_id);
            drop(foreign);
            assert_eq!(
                prepare_disk(root, &mut record, &mut registry, &identity)
                    .err()
                    .unwrap()
                    .0,
                "runtime_disk_identity_mismatch"
            );
            assert_eq!(
                files::data_file_identity(&root.file("data.vhdx").unwrap()).unwrap(),
                foreign_id
            );
            assert_eq!(original.evidence().unwrap().file_identity(), expected);
            assert!(matches!(
                read_record(root, &identity).unwrap().phase,
                Phase::Pending {
                    disk: PendingDisk::Staged { .. }
                }
            ));
        }

        #[test]
        fn broker_directory_roles_are_exact_and_old_private_ancestors_are_not_rewritten() {
            let area = Area::new();
            let storage = Identity::administrators().unwrap();
            let caller = Identity::current().unwrap();
            let users = Identity::from_sid("S-1-5-11").unwrap();
            let other = Identity::from_sid("S-1-5-21-100000001-100000002-100000003-1001").unwrap();
            let shared = area.0.path().join("shared");
            let root = Root::new(
                shared.join(caller.sid()),
                storage.clone(),
                caller.clone(),
                true,
            )
            .unwrap();
            root.create().unwrap();
            checked_directory(&shared, &storage, &users).unwrap();
            checked_directory(root.path(), &storage, &caller).unwrap();
            assert!(checked_directory(root.path(), &storage, &users).is_err());
            root.guard().unwrap();
            let releases = root.path().join("releases");
            ensure_directory(&releases, &storage, &other).unwrap();
            assert!(root.guard().is_err());
            assert!(ensure_directory(&releases, &storage, &caller).is_err());
            checked_directory(&releases, &storage, &other).unwrap();
            std::fs::remove_dir(&releases).unwrap();
            ensure_directory(&releases, &storage, &caller).unwrap();
            root.guard().unwrap();
            let boot = root.path().join("boot");
            ensure_directory(&boot, &storage, &caller).unwrap();
            assert!(root.guard().is_err());
            assert!(ensure_directory(&boot, &storage, &storage).is_err());
            checked_directory(&boot, &storage, &caller).unwrap();

            let old = area.0.path().join("old-private-catalog");
            ensure_directory(&old, &storage, &storage).unwrap();
            assert!(ensure_directory(&old, &storage, &caller).is_err());
            checked_directory(&old, &storage, &storage).unwrap();
        }

        #[test]
        fn broker_roots_derive_programdata_and_storage_from_the_authenticated_user_only() {
            let owner = Identity::current().unwrap();
            let root = Root::for_user(&owner).unwrap();
            assert!(root.broker);
            assert_eq!(root.client_identity().sid(), owner.sid());
            assert_eq!(root.storage_identity().sid(), "S-1-5-32-544");
            assert_eq!(root.path().file_name().unwrap(), owner.sid());
            assert_eq!(
                root.path().parent().unwrap().file_name().unwrap(),
                "Oblivion"
            );
            let area = Area::new();
            assert!(!area.0.broker);
            assert_eq!(area.0.storage_identity().sid(), owner.sid());
            assert_eq!(area.0.client_identity().sid(), owner.sid());
        }

        // No VHDX or HCS is fabricated: this filesystem fixture represents the
        // already-recorded file identity, while supervisor Stopped is admitted
        // through its actual private journal and exclusive writer.
        fn prepared(area: &Area, source: &Fixture) -> Record {
            let root = &area.0;
            let identity = Identity::current().unwrap();
            for child in ["releases", "boot"] {
                ensure_directory(&root.path().join(child), &identity, &identity).unwrap();
            }
            let bundle = source.open().unwrap();
            let binding = bundle.binding().unwrap();
            let bundle = bundle
                .publish(
                    &root.release(&binding.bundle_id).unwrap(),
                    &identity,
                    root.client_identity(),
                )
                .unwrap();
            let runtime_id = random_id().unwrap();
            let config = serde_json::to_vec(
                &configuration(root.path().to_str().unwrap(), &runtime_id).unwrap(),
            )
            .unwrap();
            let mut file = create_private(&root.file("vm.json").unwrap(), &identity).unwrap();
            file.write_all(&config).unwrap();
            file.sync_all().unwrap();
            drop(file);
            let mut data = create_private(&root.file("data.vhdx").unwrap(), &identity).unwrap();
            data.write_all(b"Synthetic file-identity fixture; not a VHDX or bootable data.")
                .unwrap();
            data.sync_all().unwrap();
            drop(data);
            let (volume, file) =
                files::data_file_identity(&root.file("data.vhdx").unwrap()).unwrap();
            for asset in &binding.boot {
                copy_boot(
                    &format!(r"{}\{}", bundle.root(), asset.path.replace('/', r"\")),
                    &root
                        .file(&format!(r"boot\{}", boot_leaf(asset).unwrap()))
                        .unwrap(),
                    asset,
                    &identity,
                )
                .unwrap();
            }
            let record = Record {
                version: 1,
                runtime_id,
                bundle: binding,
                config_sha256: format!("{:x}", Sha256::digest(&config)),
                data_bytes: 8 * 1024 * 1024 * 1024,
                phase: Phase::Ready {
                    data: FileIdentity { volume, file },
                },
            };
            create_record(root, &record, &identity).unwrap();
            let mut journal =
                create_private(&root.file("vm.json.supervision.json").unwrap(), &identity).unwrap();
            journal.write_all(&serde_json::to_vec(&json!({"version":1,
                "binding":{"runtime_id":record.runtime_id,"config_sha256":record.config_sha256,"source_sha256":record.bundle.source_sha256,
                    "client_sid":root.client_identity().sid(),"storage_sid":root.storage_identity().sid()},
                "generation":random_id().unwrap(),"phase":"stopped","resident":false,"boot":{"kind":"existing"}})).unwrap()).unwrap();
            journal.sync_all().unwrap();
            record
        }

        #[test]
        fn atomic_keeps_the_disk_until_the_installed_executable_is_released() {
            let area = Area::new();
            let root = &area.0;
            let source = Fixture::version("atomic");
            let record = prepared(&area, &source);
            let identity = &root.storage;
            let data = record.data().unwrap();
            let resource_lock =
                create_private(&root.file("vm.json.resources.lock").unwrap(), identity).unwrap();
            drop(resource_lock);
            let mut receipt =
                create_private(&root.file("vm.json.resources.json").unwrap(), identity).unwrap();
            let evidence: Vec<_> = [1, 2, 3]
                .into_iter()
                .map(|value| crate::resources::FileEvidence {
                    volume: 0,
                    file: [value; 16],
                    bytes: 1,
                })
                .chain([crate::resources::FileEvidence {
                    volume: data.volume,
                    file: data.file,
                    bytes: record.data_bytes,
                }])
                .collect();
            receipt.write_all(&serde_json::to_vec(&json!({"version":1,
                "binding":{"runtime_id":record.runtime_id,"generation":random_id().unwrap(),
                    "config_sha256":record.config_sha256,"source_sha256":record.bundle.source_sha256,
                    "client_sid":root.client.sid(),"storage_sid":identity.sid()},
                "files":evidence,"network":null,"clean":true})).unwrap()).unwrap();
            drop(receipt);
            let bundle = verified_bundle(root, &record, identity).unwrap();
            let executable = Executable::open(bundle.helper(), identity).unwrap();
            drop(bundle);
            let review = atomic_review(root).unwrap();
            let run = |review: &AtomicReview| {
                atomic(
                    root,
                    review,
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(5),
                )
            };
            let partial = run(&review).unwrap();
            assert_eq!(partial.in_use, 1);
            assert!(!partial.software_removed);
            assert!(root.path().join("data.vhdx").is_file());
            assert!(matches!(
                read_record(root, identity).unwrap().phase,
                Phase::Atomic {
                    stage: AtomicStage::Preparing,
                    ..
                }
            ));
            drop(executable);
            assert_eq!(run(&review).err().unwrap().0, "atomic_review_changed");
            assert!(run(&atomic_review(root).unwrap()).unwrap().software_removed);
            assert!(!root.path().join("data.vhdx").exists());
            assert!(!root.path().join("vm.json").exists());
            assert!(!root.path().join("vm.json.supervision.json").exists());
            assert!(!root.path().join("vm.json.resources.json").exists());
            assert!(!root.path().join("vm.json.resources.lock").exists());
            let retired = atomic_review(root).unwrap();
            assert!(!retired.archive_present);
            assert_eq!(retired.runtime_id, record.runtime_id);
            assert!(run(&retired).unwrap().software_removed);
            empty_setup(root, true).unwrap();
        }

        #[test]
        fn atomic_resumes_after_disk_deletion_and_refuses_replaced_metadata() {
            let area = Area::new();
            let root = &area.0;
            let source = Fixture::version("atomic-resume");
            let mut record = prepared(&area, &source);
            let identity = &root.storage;
            let (mut registry, _) = registry(root, identity).unwrap();
            let data = record.data().unwrap().clone();
            let config = atomic_file_identity(root, "vm.json").unwrap();
            let journal = atomic_file_identity(root, "vm.json.supervision.json").unwrap();
            drop(create_private(&root.file("vm.json.resources.lock").unwrap(), identity).unwrap());
            let resource_lock = atomic_file_identity(root, "vm.json.resources.lock").unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now() + Duration::from_secs(5);
            assert!(
                collect_software(root, &record, true, true, &stop, deadline)
                    .unwrap()
                    .software_removed
            );
            record.phase = Phase::Atomic {
                data,
                stage: AtomicStage::Deleting {
                    config,
                    journal,
                    resources: None,
                    resource_lock,
                },
            };
            registry.save(&record).unwrap();
            for name in ["data.vhdx", "vm.json"] {
                registry
                    .directory
                    .asset(name, identity, true)
                    .unwrap()
                    .removal(identity)
                    .unwrap()
                    .remove()
                    .unwrap();
            }
            drop(registry);

            let journal = root.path().join("vm.json.supervision.json");
            let retained = root.path().join("untouched-journal.json");
            std::fs::rename(&journal, &retained).unwrap();
            let mut replacement = create_private(journal.to_str().unwrap(), identity).unwrap();
            replacement.write_all(b"Unrelated file").unwrap();
            drop(replacement);
            let review = atomic_review(root).unwrap();
            assert!(!review.archive_present);
            assert_eq!(
                atomic(root, &review, Arc::clone(&stop), deadline)
                    .err()
                    .unwrap()
                    .0,
                "atomic_metadata_identity_changed"
            );
            assert_eq!(std::fs::read(&journal).unwrap(), b"Unrelated file");
            std::fs::remove_file(&journal).unwrap();
            std::fs::rename(retained, journal).unwrap();
            assert!(
                atomic(root, &review, stop, deadline)
                    .unwrap()
                    .software_removed
            );
            empty_setup(root, true).unwrap();
        }

        #[test]
        fn stopped_update_collection_and_software_only_uninstall_preserve_data_and_unknown_entries()
        {
            let area = Area::new();
            let base = Fixture::version("base");
            let next = Fixture::version("next");
            let record = prepared(&area, &base);
            let identity = Identity::current().unwrap();
            let root = &area.0;
            let config = std::fs::read(root.path().join("vm.json")).unwrap();
            let data = std::fs::read(root.path().join("data.vhdx")).unwrap();
            let installed = update_bundle(
                root,
                next.open().unwrap(),
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
            assert_eq!(installed.runtime_id(), record.runtime_id);
            let helper = installed.bundle.helper().to_owned();
            let current = installed.record.bundle.bundle_id.clone();
            drop(installed);
            let releases =
                Directory::open(&root.file("releases").unwrap(), &identity, true).unwrap();
            let mut unknown = releases.create_file("personal-note", &identity).unwrap();
            unknown
                .writer()
                .write_all(b"Never delete unknown files")
                .unwrap();
            unknown.finish().unwrap();
            drop(unknown);
            let report = collect(
                root,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(
                (report.releases_removed, report.retained, report.in_use),
                (1, 1, 0)
            );
            assert!(
                !std::path::Path::new(&root.release(&record.bundle.bundle_id).unwrap()).exists()
            );
            let running_command = Executable::open(&helper, &identity).unwrap();
            let report = uninstall(
                root,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert!(!report.software_removed);
            assert_eq!(report.in_use, 1);
            assert_eq!(report.boot_files_removed, 3);
            assert!(std::path::Path::new(&root.release(&current).unwrap()).exists());
            assert!(matches!(
                read_record(root, &identity).unwrap().phase,
                Phase::Uninstalled { .. }
            ));
            assert_eq!(
                control_id(root).unwrap_err().0,
                "runtime_software_uninstalled"
            );
            drop(running_command);
            let report = uninstall(
                root,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!((report.releases_removed, report.retained), (1, 1));
            assert!(!report.software_removed);
            assert_eq!(
                std::fs::read(root.path().join(r"releases\personal-note")).unwrap(),
                b"Never delete unknown files"
            );
            std::fs::remove_file(root.path().join(r"releases\personal-note")).unwrap();
            let report = uninstall(
                root,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert!(report.software_removed);
            let preserved = read_record(root, &identity).unwrap();
            assert_eq!(preserved.runtime_id, record.runtime_id);
            assert_eq!(std::fs::read(root.path().join("vm.json")).unwrap(), config);
            assert_eq!(std::fs::read(root.path().join("data.vhdx")).unwrap(), data);
            assert!(root.path().join("vm.json.supervision.json").exists());

            let restored = update_bundle(
                root,
                base.open().unwrap(),
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(restored.runtime_id(), record.runtime_id);
            assert!(matches!(restored.record.phase, Phase::Ready { .. }));
            assert!(restored.record.data() == preserved.data());
            assert_eq!(std::fs::read(root.path().join("vm.json")).unwrap(), config);
            assert_eq!(std::fs::read(root.path().join("data.vhdx")).unwrap(), data);
        }

        #[test]
        fn interrupted_update_accepts_only_its_target_after_the_stopped_journal_was_rebound() {
            let area = Area::new();
            let base = Fixture::version("base");
            let next = Fixture::version("next");
            let foreign = Fixture::version("foreign");
            let mut record = prepared(&area, &base);
            let root = &area.0;
            let identity = Identity::current().unwrap();
            let target = next.open().unwrap();
            let binding = target.binding().unwrap();
            let target = target
                .publish(
                    &root.release(&binding.bundle_id).unwrap(),
                    &identity,
                    root.client_identity(),
                )
                .unwrap();
            let data = record.data().unwrap().clone();
            record.phase = Phase::Updating {
                data,
                target: binding.clone(),
            };
            let (mut registry, _) = registry(root, &identity).unwrap();
            registry.save(&record).unwrap();
            drop(registry);
            let boot = Directory::open(&root.file("boot").unwrap(), &identity, true).unwrap();
            for asset in &binding.boot {
                let leaf = boot_leaf(asset).unwrap();
                let stage = format!("update-{}-{leaf}", binding.bundle_id);
                copy_boot(
                    &format!(r"{}\{}", target.root(), asset.path.replace('/', r"\")),
                    &format!(r"{}\{stage}", boot.path()),
                    asset,
                    &identity,
                )
                .unwrap();
                boot_asset(&boot, leaf, &identity)
                    .unwrap()
                    .unwrap()
                    .removal(&identity)
                    .unwrap()
                    .remove()
                    .unwrap();
                boot_asset(&boot, &stage, &identity)
                    .unwrap()
                    .unwrap()
                    .move_to(&boot, leaf, &identity)
                    .unwrap();
            }
            let base_settings = maintenance(root, &record, &record.bundle).unwrap();
            let target_settings = maintenance(root, &record, &binding).unwrap();
            let mut stopped = supervisor::stopped_update(
                &base_settings,
                &target_settings,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            stopped.rebind(&target_settings).unwrap();
            drop(stopped);
            drop(target);
            assert_eq!(
                update_bundle(
                    root,
                    foreign.open().unwrap(),
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(5)
                )
                .err()
                .unwrap()
                .0,
                "installation_update_requires_matching_bundle"
            );
            assert_eq!(
                control_id(root).unwrap_err().0,
                "installation_update_requires_matching_bundle"
            );
            let installed = update_bundle(
                root,
                next.open().unwrap(),
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(installed.record.bundle.bundle_id, binding.bundle_id);
            assert!(matches!(installed.record.phase, Phase::Ready { .. }));
            assert_eq!(installed.runtime_id(), record.runtime_id);
        }

        #[test]
        fn activity_discovery_is_ready_only_and_needs_no_boot_assets_disk_or_hcs_probe() {
            let area = Area::new();
            let root = &area.0;
            let identity = Identity::current().unwrap();
            let runtime_id = random_id().unwrap();
            let config = serde_json::to_vec(
                &configuration(root.path().to_str().unwrap(), &runtime_id).unwrap(),
            )
            .unwrap();
            let manifest: oblivion_bundle::Manifest = serde_json::from_str(include_str!(
                "../../oblivion-bundle/tests/fixtures/windows-v2.json"
            ))
            .unwrap();
            let mut record = Record {
                version: 1,
                runtime_id: runtime_id.clone(),
                bundle: manifest.binding().unwrap(),
                config_sha256: format!("{:x}", Sha256::digest(&config)),
                data_bytes: 8 * 1024 * 1024 * 1024,
                phase: Phase::Pending {
                    disk: super::PendingDisk::Uncreated,
                },
            };
            create_record(root, &record, &identity).unwrap();
            let (mut registry, _) = registry(root, &identity).unwrap();
            let initial_file =
                files::data_file_identity(&root.file("installation.json").unwrap()).unwrap();
            assert_eq!(control_id(root).unwrap_err().0, "installation_pending");
            let mut configuration =
                create_private(&root.file("vm.json").unwrap(), &identity).unwrap();
            configuration.write_all(&config).unwrap();
            configuration.sync_all().unwrap();
            drop(configuration);
            record.phase = Phase::Ready {
                data: FileIdentity {
                    volume: 1,
                    file: [1; 16],
                },
            };
            registry.save(&record).unwrap();
            assert_ne!(
                files::data_file_identity(&root.file("installation.json").unwrap()).unwrap(),
                initial_file
            );
            assert_eq!(control_id(root).unwrap(), runtime_id);
            assert!(!root.path().join("boot").exists());
            assert!(!root.path().join("data.vhdx").exists());
            assert_eq!(
                create_private(&root.file("installation.json").unwrap(), &identity)
                    .err()
                    .unwrap()
                    .0,
                "installation_file_already_exists"
            );
            assert_eq!(control_id(root).unwrap(), runtime_id);
        }
    }
}
#[cfg(windows)]
pub use native::{
    Installed, Root, atomic, atomic_review, collect, control_binding, control_id, discover,
    install_bundle, owned_settings, preflight, uninstall, update_bundle,
};

#[cfg(test)]
mod tests {
    use super::{AtomicReview, Phase, Record, configuration};
    use serde_json::{Value, json};
    const ID: &str = "0123456789abcdef0123456789abcdef";
    #[test]
    fn generated_configuration_uses_owned_boot_copies_and_a_separate_stable_vhdx() {
        let config = configuration(r"C:\Users\test\AppData\Local\Oblivion", ID).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.disks[1].path,
            r"C:\Users\test\AppData\Local\Oblivion\data.vhdx"
        );
        assert!(!config.disks[1].read_only);
        assert!(config.kernel.contains(r"\boot\"));
        assert!(!config.kernel.contains("releases"));
        assert!(config.network);
        assert!(!config.serial_stdio);
        assert_eq!(config.runtime_id, ID);
    }
    fn record() -> Value {
        let manifest: oblivion_bundle::Manifest = serde_json::from_str(include_str!(
            "../../oblivion-bundle/tests/fixtures/windows-v2.json"
        ))
        .unwrap();
        json!({"version":1,"runtime_id":ID,"bundle":manifest.binding().unwrap(),
            "config_sha256":"3".repeat(64),"data_bytes":8_u64*1024*1024*1024,"phase":{"kind":"pending","disk":{"kind":"uncreated"}}})
    }
    #[test]
    fn atomic_review_changes_with_the_disk_identity_and_presence() {
        let mut value = record();
        value["phase"] = json!({"kind":"ready","data":{"volume":4,"file":vec![1;16]}});
        let archive = r"C:\Oblivion\data.vhdx";
        let record = Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let reviewed = AtomicReview::from_record(&record, archive.into(), true).unwrap();
        assert_ne!(
            reviewed.review_id,
            AtomicReview::from_record(&record, archive.into(), false)
                .unwrap()
                .review_id
        );
        value["phase"]["data"]["file"] = json!(vec![2; 16]);
        let replaced = Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_ne!(
            reviewed.review_id,
            AtomicReview::from_record(&replaced, archive.into(), true)
                .unwrap()
                .review_id
        );
    }
    #[test]
    fn pending_is_a_distinct_current_format_and_never_an_installed_ready_record() {
        let pending = Record::decode(&serde_json::to_vec(&record()).unwrap()).unwrap();
        assert!(matches!(
            pending.phase,
            Phase::Pending {
                disk: super::PendingDisk::Uncreated
            }
        ));
        let mut ready = record();
        ready["phase"] = json!({"kind":"ready","data":{"volume":4,"file":vec![1;16]}});
        assert!(matches!(
            Record::decode(&serde_json::to_vec(&ready).unwrap())
                .unwrap()
                .phase,
            Phase::Ready { .. }
        ));
        ready["phase"] = json!({"kind":"ready"});
        assert_eq!(
            Record::decode(&serde_json::to_vec(&ready).unwrap())
                .err()
                .unwrap()
                .0,
            "invalid_installation_record"
        );
    }
    #[test]
    fn pending_stages_require_an_explicit_original_disk_identity_and_local_stage_leaf() {
        let mut value = record();
        let data = json!({"volume":1,"file":vec![2;16]});
        value["phase"] = json!({"kind":"pending","disk":{"kind":"staged","data":data,"leaf":format!(".data-{}.vhdx","a".repeat(32))}});
        Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        for leaf in [
            r"..\data.vhdx",
            r"C:\other\data.vhdx",
            "data.vhdx",
            ".data-invalid.vhdx",
        ] {
            value["phase"]["disk"]["leaf"] = json!(leaf);
            assert!(Record::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        value["phase"] = json!({"kind":"pending","disk":{"kind":"published","data":data}});
        let decoded = Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(decoded.data().is_none()); // Pending does not grant update/uninstall authority.
        value["phase"]["disk"]["data"]["file"] = json!(vec![0; 16]);
        assert!(Record::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["phase"] = json!({"kind":"pending"});
        assert!(Record::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn update_target_and_uninstalled_states_retain_the_same_data_authority() {
        let mut value = record();
        let data = json!({"volume":4,"file":vec![1;16]});
        value["phase"] = json!({"kind":"updating","data":data,"target":value["bundle"]});
        let updating = Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(updating.phase, Phase::Updating { .. }));
        assert_eq!(updating.data().unwrap().file, [1; 16]);
        value["phase"]["target"]["source_sha256"] = json!("PRIVATE_CANARY");
        assert_eq!(
            Record::decode(&serde_json::to_vec(&value).unwrap())
                .err()
                .unwrap()
                .0,
            "invalid_installation_record"
        );
        value["phase"] = json!({"kind":"uninstalled","data":data});
        let removed = Record::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(removed.phase, Phase::Uninstalled { .. }));
        assert_eq!(removed.runtime_id, ID);
        assert_eq!(removed.data().unwrap().file, [1; 16]);
    }
    #[test]
    fn malformed_or_foreign_record_fields_have_only_static_diagnostics() {
        for (field, value) in [
            ("runtime_id", json!("PRIVATE_CANARY")),
            ("config_sha256", json!("PRIVATE_CANARY")),
            ("PRIVATE_CANARY", json!(true)),
        ] {
            let mut value_record = record();
            value_record[field] = value;
            let error = Record::decode(&serde_json::to_vec(&value_record).unwrap())
                .err()
                .unwrap();
            assert_eq!(error.0, "invalid_installation_record");
            assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
        }
    }
}
