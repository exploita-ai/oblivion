//! Current-format development bundles. Checksums identify a paired source build;
//! they do not establish release signing, redistribution approval or hardware support.
use crate::control::Result;
pub(crate) use oblivion_bundle::{Binding, File, Runtime};
use oblivion_bundle::{MAX_MANIFEST, Manifest, hash};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct Bundle {
    pub root: PathBuf,
    manifest: Manifest,
}

#[cfg(target_os = "linux")]
pub(crate) const PACKAGE_ROOT: &str = "/usr/lib/oblivion-desktop";

pub fn packaged_entry() -> Result<bool> {
    #[cfg(target_os = "linux")]
    return Ok(std::env::current_exe()? == Path::new(PACKAGE_ROOT).join("bin/oblivion"));
    #[cfg(not(target_os = "linux"))]
    Ok(false)
}

pub fn launcher_path() -> std::io::Result<PathBuf> {
    // macOS can report the user-facing symlink instead of the bundle binary.
    std::env::current_exe()?.canonicalize()
}

pub(crate) fn platform() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "darwin-arm64";
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "linux-x86_64";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return "linux-arm64";
    #[allow(unreachable_code)]
    "unsupported"
}

pub(crate) fn source_id() -> Result<&'static str> {
    option_env!("OBLIVION_DESKTOP_SOURCE_SHA256")
        .filter(|value| hash(value))
        .ok_or_else(|| "Build and install a current development desktop bundle before using the desktop runtime".into())
}

impl Bundle {
    pub fn read(root: &Path) -> Result<Self> {
        if !root.is_dir() {
            return Err("Use a current desktop bundle directory; arbitrary ISO installation is not supported".into());
        }
        Self::verified(root, Some(source_id()?), platform(), true)
    }

    pub fn current() -> Result<Self> {
        let executable = launcher_path()?;
        let root = executable
            .parent()
            .and_then(Path::parent)
            .ok_or("bundle_directory_missing")?;
        Self::verified(root, Some(source_id()?), platform(), false)
    }

    /// Collection verifies the same current manifest and full inventory, but an
    /// older release has its own source identity rather than this binary's.
    pub(crate) fn stored(root: &Path, identity: &str, expected_platform: &str) -> Result<Self> {
        Self::stored_inventory(root, identity, expected_platform, false)
    }

    pub(crate) fn stored_for_removal(root: &Path, identity: &str, expected_platform: &str) -> Result<Self> {
        Self::stored_inventory(root, identity, expected_platform, true)
    }

    fn stored_inventory(root: &Path, identity: &str, expected_platform: &str, allow_missing: bool) -> Result<Self> {
        let bundle = Self::verify_inventory(root, None, expected_platform, true, allow_missing)?;
        if bundle.id() != identity {
            return Err("installed_desktop_release_changed".into());
        }
        Ok(bundle)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn deployed(root: &Path, binding: &Binding, platform: &str) -> Result<Self> {
        let bundle = Self::verified(root, Some(&binding.source_sha256), platform, false)?;
        if serde_json::to_value(bundle.binding()?)? != serde_json::to_value(binding)? {
            return Err("installed_desktop_release_changed".into());
        }
        bundle.verify_native()?;
        Ok(bundle)
    }

    fn verified(
        root: &Path,
        source: Option<&str>,
        expected_platform: &str,
        runtime: bool,
    ) -> Result<Self> {
        Self::verify_inventory(root, source, expected_platform, runtime, false)
    }

    fn verify_inventory(
        root: &Path,
        source: Option<&str>,
        expected_platform: &str,
        runtime: bool,
        allow_missing: bool,
    ) -> Result<Self> {
        if !root.is_absolute() {
            return Err("unsupported_desktop_bundle_platform".into());
        }
        oblivion_bundle::target(expected_platform)?;
        let root = root.canonicalize()?;
        #[cfg(target_os = "linux")]
        let root_owned = root == Path::new(PACKAGE_ROOT);
        #[cfg(not(target_os = "linux"))]
        let root_owned = false;
        let metadata = fs::symlink_metadata(&root)?;
        owned(&metadata, true, root_owned)?;
        let mut reader = open(&root.join("bundle.json"))?;
        owned(&reader.metadata()?, false, root_owned)?;
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_MANIFEST {
            return Err("desktop_bundle_manifest_limit".into());
        }
        let manifest = Manifest::decode(&bytes, source, expected_platform)?;
        let files: BTreeMap<_, _> = manifest
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let mut expected_directories = BTreeSet::new();
        for file in &manifest.files {
            let mut directory = Path::new(&file.path).parent();
            while let Some(path) = directory.filter(|path| !path.as_os_str().is_empty()) {
                expected_directories.insert(path.to_owned());
                directory = path.parent();
            }
        }
        let mut discovered = BTreeSet::new();
        let mut directories = vec![root.clone()];
        let mut count = 0;
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let info = fs::symlink_metadata(&path)?;
                count += 1;
                if count > 4096 {
                    return Err("desktop_bundle_inventory_limit".into());
                }
                owned(&info, info.is_dir(), root_owned)?;
                if info.is_dir() {
                    if !expected_directories.contains(path.strip_prefix(&root)?) {
                        return Err("desktop_bundle_unlisted_directory".into());
                    }
                    directories.push(path);
                    continue;
                }
                let name = path
                    .strip_prefix(&root)?
                    .to_str()
                    .ok_or("invalid_desktop_bundle_path")?;
                if name == "bundle.json" {
                    continue;
                }
                let file = files.get(name).ok_or("desktop_bundle_unlisted_file")?;
                if info.len() != file.bytes || (info.mode() & 0o111 != 0) != file.executable {
                    return Err("desktop_bundle_file_changed".into());
                }
                if runtime && digest(&path)? != file.sha256 {
                    return Err("desktop_bundle_checksum_failed".into());
                }
                discovered.insert(name.to_owned());
            }
        }
        if !allow_missing && discovered.len() != files.len() {
            return Err("desktop_bundle_file_missing".into());
        }
        Ok(Self { root, manifest })
    }

    pub fn id(&self) -> &str {
        &self.manifest.bundle_id
    }
    pub fn source(&self) -> &str {
        &self.manifest.source_sha256
    }
    pub fn binding(&self) -> Result<Binding> {
        Ok(self.manifest.binding()?)
    }
    pub fn files(&self) -> &[File] {
        &self.manifest.files
    }
    pub fn manifest_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&self.manifest)?)
    }
    pub fn verify_native(&self) -> Result<()> {
        for file in self
            .files()
            .iter()
            .filter(|file| !file.path.starts_with("runtime/"))
        {
            if digest(&self.root.join(&file.path))? != file.sha256 {
                return Err("desktop_bundle_checksum_failed".into());
            }
        }
        Ok(())
    }
    pub fn runtime(&self) -> &Runtime {
        &self.manifest.runtime
    }
    pub fn file(&self, path: &str) -> Result<&File> {
        self.files()
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| "desktop_bundle_file_missing".into())
    }
}

/// Called before launching either the manager or a trusted overlay. It never
/// starts a VM, reads a user profile or changes the controller transport.
pub fn prepare_environment() -> Result<()> {
    let bundle = Bundle::current()?;
    unsafe {
        std::env::set_var("OTUI_ASSET_ROOT", bundle.root.join(&bundle.manifest.assets));
    }
    Ok(())
}

pub(crate) fn digest(path: &Path) -> Result<String> {
    let mut file = open(path)?;
    let mut result = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        result.update(&buffer[..count]);
    }
    Ok(format!("{:x}", result.finalize()))
}

fn open(path: &Path) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    owned(&file.metadata()?, false, false)?;
    Ok(file)
}

fn owned(metadata: &fs::Metadata, directory: bool, root_owned: bool) -> Result<()> {
    if (metadata.uid() != 0 && (root_owned || metadata.uid() != unsafe { libc::getuid() }))
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err("unsafe_desktop_bundle_file".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use oblivion_bundle::relative;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct Fixture {
        pub root: PathBuf,
        pub source: String,
    }
    fn test_platform() -> &'static str {
        if platform() == "unsupported" {
            "linux-x86_64"
        } else {
            platform()
        }
    }
    impl Fixture {
        pub fn new() -> Self {
            let mut random = [0; 16];
            fs::File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let root = PathBuf::from("/tmp")
                .join(format!("oblivion-bundle-{:x}", u128::from_ne_bytes(random)));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let platform = test_platform();
            let native = if platform == "darwin-arm64" {
                "lib/manager/@opentui/core-darwin-arm64/libopentui.dylib"
            } else if platform == "linux-arm64" {
                "lib/manager/@opentui/core-linux-arm64/libopentui.so"
            } else {
                "lib/manager/@opentui/core-linux-x64/libopentui.so"
            };
            let mut files = Vec::new();
            for (index, name) in [
                "bin/oblivion",
                "bin/oblivion-vm",
                "bin/oblivion-manager",
                native,
                "runtime/controller.iso",
                "runtime/kernel",
                "runtime/initrd",
            ]
            .iter()
            .enumerate()
            {
                let path = root.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let bytes = format!("Nonbootable current-source packaging fixture {index}\n");
                fs::write(&path, bytes.as_bytes()).unwrap();
                let executable = name.starts_with("bin/");
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
                )
                .unwrap();
                files.push(File {
                    path: (*name).into(),
                    sha256: digest(&path).unwrap(),
                    bytes: bytes.len() as u64,
                    executable,
                });
            }
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let manifest = Manifest {
                format: "oblivion-desktop".into(),
                version: 1,
                development_only: true,
                bundle_id: String::new(),
                product_version: "1.0.0~devfixture".into(),
                platform: platform.into(),
                backend: if platform == "darwin-arm64" {
                    "apple-vz"
                } else {
                    "qemu-kvm"
                }
                .into(),
                source_sha256: "ab".repeat(32),
                control_protocol: 1,
                assets: "lib/manager".into(),
                runtime: Runtime {
                    image: "runtime/controller.iso".into(),
                    kernel: "runtime/kernel".into(),
                    initrd: "runtime/initrd".into(),
                },
                files,
            };
            let fixture = Self {
                root,
                source: manifest.source_sha256.clone(),
            };
            fixture.save(manifest);
            fixture
        }
        fn save(&self, mut manifest: Manifest) {
            let mut value = serde_json::to_value(&manifest).unwrap();
            value.as_object_mut().unwrap().remove("bundle_id");
            manifest.bundle_id =
                format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()));
            fs::write(
                self.root.join("bundle.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
        }
        pub fn bundle(&self) -> Bundle {
            Bundle::verified(&self.root, Some(&self.source), test_platform(), true).unwrap()
        }
        pub fn change_source(&mut self, source: &str) {
            let mut manifest: Manifest =
                serde_json::from_slice(&fs::read(self.root.join("bundle.json")).unwrap()).unwrap();
            manifest.source_sha256 = source.into();
            self.source = source.into();
            self.save(manifest);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn resolves_the_launcher_when_invoked_through_a_symlink() {
        const EXPECTED: &str = "OBLIVION_TEST_EXPECTED_LAUNCHER_PATH";
        if let Some(expected) = std::env::var_os(EXPECTED) {
            assert_eq!(launcher_path().unwrap(), PathBuf::from(expected));
            return;
        }
        let fixture = Fixture::new();
        let executable = launcher_path().unwrap();
        let entry = fixture.root.join("launcher-link");
        std::os::unix::fs::symlink(&executable, &entry).unwrap();
        let result = std::process::Command::new(entry)
            .args(["--exact", "desktop_bundle::tests::resolves_the_launcher_when_invoked_through_a_symlink"])
            .env(EXPECTED, executable)
            .output()
            .unwrap();
        assert!(result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "{}", String::from_utf8_lossy(&result.stdout));
    }

    #[test]
    fn verifies_exact_source_platform_inventory_and_rejects_tampering() {
        let fixture = Fixture::new();
        let bundle = fixture.bundle();
        assert_eq!(bundle.source(), fixture.source);
        assert!(bundle.binding().unwrap().validate().is_ok());
        assert!(
            Bundle::verified(&fixture.root, Some(&"cd".repeat(32)), test_platform(), true).is_err()
        );
        let bytes = fs::read(fixture.root.join("runtime/kernel")).unwrap();
        fs::write(fixture.root.join("runtime/kernel"), vec![b'X'; bytes.len()]).unwrap();
        assert!(
            Bundle::verified(&fixture.root, Some(&fixture.source), test_platform(), true).is_err()
        );
        fs::write(fixture.root.join("runtime/kernel"), bytes).unwrap();
        fixture.bundle();
        fs::write(
            fixture.root.join("unlisted-profile"),
            b"synthetic fixture only",
        )
        .unwrap();
        assert!(
            Bundle::verified(&fixture.root, Some(&fixture.source), test_platform(), true).is_err()
        );
    }

    #[test]
    fn rejects_symlinks_unknown_fields_and_prior_manifest_formats() {
        let fixture = Fixture::new();
        let path = fixture.root.join("runtime/kernel");
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("initrd", &path).unwrap();
        assert!(
            Bundle::verified(&fixture.root, Some(&fixture.source), test_platform(), true).is_err()
        );
        fs::remove_file(&path).unwrap();
        fs::write(&path, bytes).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.root.join("bundle.json")).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("fallback_iso".into(), serde_json::Value::Bool(true));
        fs::write(
            fixture.root.join("bundle.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(
            Bundle::verified(&fixture.root, Some(&fixture.source), test_platform(), true).is_err()
        );
        assert!(!relative("../outside") && !relative("runtime/./kernel") && !relative("/absolute"));
    }

    #[test]
    fn stored_release_requires_its_current_manifest_identity_and_full_inventory() {
        let mut fixture = Fixture::new();
        fixture.change_source(&"cd".repeat(32));
        let identity = fixture.bundle().id().to_owned();
        assert!(Bundle::stored(&fixture.root, &identity, test_platform()).is_ok());
        assert!(Bundle::stored(&fixture.root, &"aa".repeat(32), test_platform()).is_err());
        fs::create_dir(fixture.root.join("unlisted-empty-directory")).unwrap();
        assert!(Bundle::stored(&fixture.root, &identity, test_platform()).is_err());
        fs::remove_dir(fixture.root.join("unlisted-empty-directory")).unwrap();
        fs::write(fixture.root.join("bin/oblivion-vm"), b"changed helper").unwrap();
        assert!(Bundle::stored(&fixture.root, &identity, test_platform()).is_err());
    }
}
