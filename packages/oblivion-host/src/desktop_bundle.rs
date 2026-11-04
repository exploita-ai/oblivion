//! Current-format development bundles. Checksums identify a paired source build;
//! they do not establish release signing, redistribution approval or hardware support.
use crate::control::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_MANIFEST: usize = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub executable: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    pub image: String,
    pub kernel: String,
    pub initrd: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub bundle_id: String,
    pub source_sha256: String,
    pub boot: [File; 3],
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.bundle_id) || !hash(&self.source_sha256) {
            return Err("invalid_runtime_bundle_binding".into());
        }
        for (file, expected) in
            self.boot
                .iter()
                .zip(["runtime/controller.iso", "runtime/kernel", "runtime/initrd"])
        {
            if file.path != expected
                || file.executable
                || file.bytes == 0
                || file.bytes > 64 * 1024 * 1024 * 1024
                || !hash(&file.sha256)
            {
                return Err("invalid_runtime_bundle_binding".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    version: u8,
    development_only: bool,
    bundle_id: String,
    product_version: String,
    platform: String,
    backend: String,
    source_sha256: String,
    control_protocol: u8,
    assets: String,
    runtime: Runtime,
    files: Vec<File>,
}

pub(crate) struct Bundle {
    pub root: PathBuf,
    manifest: Manifest,
}

pub(crate) fn platform() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "darwin-arm64";
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "linux-x86_64";
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
        let executable = std::env::current_exe()?;
        let root = executable
            .parent()
            .and_then(Path::parent)
            .ok_or("bundle_directory_missing")?;
        Self::verified(root, Some(source_id()?), platform(), false)
    }

    /// Collection verifies the same current manifest and full inventory, but an
    /// older release has its own source identity rather than this binary's.
    pub(crate) fn stored(root: &Path, identity: &str, expected_platform: &str) -> Result<Self> {
        let bundle = Self::verified(root, None, expected_platform, true)?;
        if bundle.id() != identity {
            return Err("installed_desktop_release_changed".into());
        }
        Ok(bundle)
    }

    fn verified(
        root: &Path,
        source: Option<&str>,
        expected_platform: &str,
        runtime: bool,
    ) -> Result<Self> {
        if !root.is_absolute() || !matches!(expected_platform, "darwin-arm64" | "linux-x86_64") {
            return Err("unsupported_desktop_bundle_platform".into());
        }
        let root = root.canonicalize()?;
        let metadata = fs::symlink_metadata(&root)?;
        owned(&metadata, true)?;
        let mut reader = open(&root.join("bundle.json"))?;
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_MANIFEST {
            return Err("desktop_bundle_manifest_limit".into());
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        let mut canonical = serde_json::to_value(&manifest)?;
        canonical
            .as_object_mut()
            .ok_or("invalid_desktop_bundle")?
            .remove("bundle_id");
        let identity = format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical)?));
        let expected_backend = if expected_platform == "darwin-arm64" {
            "apple-vz"
        } else {
            "qemu-kvm"
        };
        if manifest.format != "oblivion-desktop"
            || manifest.version != 1
            || !manifest.development_only
            || manifest.bundle_id != identity
            || manifest.platform != expected_platform
            || manifest.backend != expected_backend
            || !hash(&manifest.source_sha256)
            || source.is_some_and(|source| !hash(source) || manifest.source_sha256 != source)
            || manifest.control_protocol != 1
            || manifest.product_version.is_empty()
            || manifest.product_version.len() > 64
            || !manifest
                .product_version
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_digit)
            || !manifest.product_version.contains("~dev")
            || !manifest
                .product_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+:~-".contains(&byte))
            || manifest.assets != "lib/manager"
            || manifest.runtime.image != "runtime/controller.iso"
            || manifest.runtime.kernel != "runtime/kernel"
            || manifest.runtime.initrd != "runtime/initrd"
            || manifest.files.len() > 1024
        {
            return Err("desktop_bundle_does_not_match_this_build".into());
        }
        let mut files = BTreeMap::new();
        let mut expected_directories = BTreeSet::new();
        let mut previous = "";
        for file in &manifest.files {
            if !relative(&file.path)
                || !hash(&file.sha256)
                || file.bytes > 64 * 1024 * 1024 * 1024
                || file.path.as_str() <= previous
                || files.insert(file.path.as_str(), file).is_some()
            {
                return Err("invalid_desktop_bundle_inventory".into());
            }
            let mut directory = Path::new(&file.path).parent();
            while let Some(path) = directory.filter(|path| !path.as_os_str().is_empty()) {
                expected_directories.insert(path.to_owned());
                directory = path.parent();
            }
            previous = &file.path;
        }
        let native = if expected_platform == "darwin-arm64" {
            "lib/manager/@opentui/core-darwin-arm64/libopentui.dylib"
        } else {
            "lib/manager/@opentui/core-linux-x64/libopentui.so"
        };
        for name in [
            "bin/oblivion",
            "bin/oblivion-vm",
            "bin/oblivion-manager",
            native,
            manifest.runtime.image.as_str(),
            manifest.runtime.kernel.as_str(),
            manifest.runtime.initrd.as_str(),
        ] {
            let file = files.get(name).ok_or("desktop_bundle_file_missing")?;
            if file.bytes == 0 || (name.starts_with("bin/") && !file.executable) {
                return Err("desktop_bundle_file_invalid".into());
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
                owned(&info, info.is_dir())?;
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
        if discovered.len() != files.len() {
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
        Ok(Binding {
            bundle_id: self.id().into(),
            source_sha256: self.source().into(),
            boot: [
                self.file(&self.runtime().image)?.clone(),
                self.file(&self.runtime().kernel)?.clone(),
                self.file(&self.runtime().initrd)?.clone(),
            ],
        })
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
    owned(&file.metadata()?, false)?;
    Ok(file)
}

fn owned(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != unsafe { libc::getuid() }
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

fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.contains('\\')
        && !value.contains('\0')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        && value != "bundle.json"
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
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
