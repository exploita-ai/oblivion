//! Per-user installed-runtime metadata. Pending setup never authorizes a second
//! disk initialization; the VHDX is outside immutable, replaceable bundles.
#![cfg(any(windows, test))]

use crate::config::{Disk, RuntimeConfig};
use crate::{Error, Result};
use oblivion_bundle::Binding;
use oblivion_wire::control::valid_id;
use oblivion_wire::runtime_auth::Data;
use serde::{Deserialize, Serialize};

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
    Pending,
    Ready { data: FileIdentity },
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
        if let Phase::Ready { data } = &record.phase {
            if data.file == [0; 16] {
                return Err(Error("invalid_installation_record"));
            }
        }
        Ok(record)
    }
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
    use super::{FileIdentity, Phase, RECORD_LIMIT, Record, configuration};
    use crate::bundle::VerifiedBundle;
    use crate::config::CONFIG_LIMIT;
    use crate::files::{self, CreatedDiskLeaf, CreationParent};
    use crate::security::Identity;
    use crate::supervisor::{self, Lease, Settings};
    use crate::{Error, Result, hcs};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, GENERIC_READ, GENERIC_WRITE,
        GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

    #[derive(Clone)]
    pub struct Root(PathBuf);
    impl Root {
        /// Discovery only: this never creates the directory or changes its ACL.
        pub fn current() -> Result<Self> {
            let mut path = null_mut();
            let status =
                unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, null_mut(), &mut path) };
            if status < 0 || path.is_null() {
                return Err(Error("local_app_data_unavailable"));
            }
            let length = (0..32768).find(|index| unsafe { *path.add(*index) == 0 });
            let text = length.and_then(|length| {
                String::from_utf16(unsafe { std::slice::from_raw_parts(path, length) }).ok()
            });
            unsafe {
                CoTaskMemFree(path.cast());
            }
            Self::at(
                &PathBuf::from(text.ok_or(Error("local_app_data_unavailable"))?).join("Oblivion"),
            )
        }
        /// An explicit test/embedding prefix uses the same private-root checks.
        /// Construction is lexical and has no filesystem side effects.
        pub fn at(path: &Path) -> Result<Self> {
            let root = Self(path.to_owned());
            if !crate::config::drive_file(&root.file("installation.json")?) {
                return Err(Error("unsupported_installation_path"));
            }
            Ok(root)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
        fn file(&self, leaf: &str) -> Result<String> {
            self.0
                .join(leaf)
                .to_str()
                .map(str::to_owned)
                .ok_or(Error("unsupported_installation_path"))
        }
        fn release(&self, id: &str) -> Result<String> {
            self.file(&format!(r"releases\{id}"))
        }
        fn guard(&self, identity: &Identity) -> Result<CreationParent> {
            match std::fs::symlink_metadata(&self.0) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error("runtime_not_installed"));
                }
                Err(_) => return Err(Error("installation_directory_unavailable")),
            }
            CreationParent::open(&self.file("installation.json")?, identity)
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
        bundle: VerifiedBundle,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Installed> {
        oblivion_wire::runtime_auth::Data::NewDisk {
            runtime_id: "1".repeat(32),
            bytes,
        }
        .validate()
        .map_err(|_| Error("invalid_runtime_data_authority"))?;
        preflight()?;
        check(&stop, deadline)?;
        let identity = Identity::current()?;
        ensure_directory(root.path(), &identity)?;
        let _root = root.guard(&identity)?;
        if std::fs::read_dir(root.path())
            .map_err(|_| Error("installation_directory_unavailable"))?
            .next()
            .transpose()
            .map_err(|_| Error("installation_directory_unavailable"))?
            .is_some()
        {
            return Err(Error("installation_already_present_or_pending"));
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
        let mut record = Record {
            version: 1,
            runtime_id,
            bundle: bundle.binding()?,
            config_sha256: format!("{:x}", Sha256::digest(&config_bytes)),
            data_bytes: bytes,
            phase: Phase::Pending,
        };
        let registry_path = root.file("installation.json")?;
        let mut registry = create_private(&registry_path, &identity)?;
        save(&mut registry, &record)?;
        // Everything after the durable Pending record is a one-shot setup.
        // Failure retains that record; a subsequent run never reinitializes it.
        ensure_directory(&root.0.join("releases"), &identity)?;
        ensure_directory(&root.0.join("boot"), &identity)?;
        check(&stop, deadline)?;
        let bundle = bundle.publish(&root.release(&record.bundle.bundle_id)?, &identity)?;
        for asset in &record.bundle.boot {
            check(&stop, deadline)?;
            let source = format!(r"{}\{}", bundle.root(), asset.path.replace('/', r"\"));
            let leaf = asset
                .path
                .rsplit('/')
                .next()
                .ok_or(Error("invalid_runtime_bundle_binding"))?;
            let destination = root.file(&format!(r"boot\{leaf}"))?;
            copy_boot(&source, &destination, asset, &identity)?;
        }
        let mut config_file = create_private(&root.file("vm.json")?, &identity)?;
        config_file
            .write_all(&config_bytes)
            .and_then(|_| config_file.sync_all())
            .map_err(|_| Error("runtime_configuration_write_failed"))?;
        drop(config_file);
        let settings = settings(root, &record, &bundle)?;
        let mut lease = supervisor::initialize(&settings, bytes, Arc::clone(&stop), deadline)?;
        // First boot proves controller IPC, not an initialized user archive.
        // Stop before inspecting the strict ungranted VHDX identity and commit;
        // subsequent startup always uses ordinary run with the existing disk.
        supervisor::stop(&settings, Arc::clone(&stop), deadline)?;
        lease.close()?;
        let disk = CreatedDiskLeaf::open(&root.file("data.vhdx")?, &identity)?;
        disk.verify(&record.runtime_id, record.data_bytes)?;
        let (volume, file) = disk.identity();
        record.phase = Phase::Ready {
            data: FileIdentity { volume, file },
        };
        save(&mut registry, &record)?;
        Ok(Installed {
            root: root.clone(),
            record,
            bundle,
        })
    }

    pub fn discover(root: &Root) -> Result<Installed> {
        preflight()?;
        let identity = Identity::current()?;
        let _root = root.guard(&identity)?;
        let record = read_record(root, &identity)?;
        let Phase::Ready { data } = &record.phase else {
            return Err(Error("installation_pending"));
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
        let identity = Identity::current()?;
        let _root = root.guard(&identity)?;
        let record = read_record(root, &identity)?;
        if !matches!(record.phase, Phase::Ready { .. }) {
            return Err(Error("installation_pending"));
        }
        verify_config(root, &record, &identity)?;
        Ok(record.runtime_id)
    }

    /// Explicit stop/control may address an interrupted setup. This grants no
    /// initialization capability and never clears Pending or Recovery records.
    pub fn owned_settings(root: &Root) -> Result<Settings> {
        let identity = Identity::current()?;
        let _root = root.guard(&identity)?;
        let record = read_record(root, &identity)?;
        verify_config(root, &record, &identity)?;
        let bundle = verified_bundle(root, &record, &identity)?;
        settings(root, &record, &bundle)
    }

    fn settings(root: &Root, record: &Record, bundle: &VerifiedBundle) -> Result<Settings> {
        Settings::new(
            &record.runtime_id,
            Path::new(bundle.helper()),
            Path::new(&root.file("vm.json")?),
            &record.config_sha256,
            &record.bundle.source_sha256,
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
        let mut output = create_private(destination, identity)?;
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
                .write_all(&bytes[..size])
                .map_err(|_| Error("runtime_boot_copy_failed"))?;
        }
        if count != asset.bytes || format!("{:x}", hash.finalize()) != asset.sha256 {
            return Err(Error("runtime_boot_source_changed"));
        }
        output
            .sync_all()
            .map_err(|_| Error("runtime_boot_copy_failed"))
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
    fn ensure_directory(path: &Path, identity: &Identity) -> Result<()> {
        let text = path
            .to_str()
            .ok_or(Error("unsupported_installation_path"))?;
        let parent = CreationParent::ancestors(text)?;
        let descriptor = identity.file_descriptor()?;
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
        CreationParent::open(
            path.join(".review")
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            identity,
        )?;
        Ok(())
    }
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
                FILE_SHARE_READ | FILE_SHARE_WRITE,
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
    fn save(file: &mut File, record: &Record) -> Result<()> {
        let bytes =
            serde_json::to_vec(record).map_err(|_| Error("installation_record_encode_failed"))?;
        Record::decode(&bytes)?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.set_len(bytes.len() as u64))
            .and_then(|_| file.sync_all())
            .map_err(|_| Error("installation_commit_failed"))
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
            FileIdentity, Phase, Record, Root, configuration, control_id, create_private,
            ensure_directory, random_id, save,
        };
        use crate::security::Identity;
        use sha2::{Digest, Sha256};
        use std::io::Write;

        struct Area(Root);
        impl Area {
            fn new() -> Self {
                let root = Root::at(
                    &std::env::temp_dir()
                        .join(format!("oblivion-install-{}", random_id().unwrap())),
                )
                .unwrap();
                assert!(!root.path().exists());
                ensure_directory(root.path(), &Identity::current().unwrap()).unwrap();
                Self(root)
            }
        }
        impl Drop for Area {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(self.0.path());
            }
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
                "../../oblivion-bundle/tests/fixtures/windows-v1.json"
            ))
            .unwrap();
            let mut record = Record {
                version: 1,
                runtime_id: runtime_id.clone(),
                bundle: manifest.binding().unwrap(),
                config_sha256: format!("{:x}", Sha256::digest(&config)),
                data_bytes: 8 * 1024 * 1024 * 1024,
                phase: Phase::Pending,
            };
            let mut registry =
                create_private(&root.file("installation.json").unwrap(), &identity).unwrap();
            save(&mut registry, &record).unwrap();
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
            save(&mut registry, &record).unwrap();
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
    Installed, Root, control_id, discover, install_bundle, owned_settings, preflight,
};

#[cfg(test)]
mod tests {
    use super::{Phase, Record, configuration};
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
            "../../oblivion-bundle/tests/fixtures/windows-v1.json"
        ))
        .unwrap();
        json!({"version":1,"runtime_id":ID,"bundle":manifest.binding().unwrap(),
            "config_sha256":"3".repeat(64),"data_bytes":8_u64*1024*1024*1024,"phase":{"kind":"pending"}})
    }
    #[test]
    fn pending_is_a_distinct_current_format_and_never_an_installed_ready_record() {
        let pending = Record::decode(&serde_json::to_vec(&record()).unwrap()).unwrap();
        assert!(matches!(pending.phase, Phase::Pending));
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
