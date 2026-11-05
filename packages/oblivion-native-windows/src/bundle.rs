//! Verified current desktop bundles on Windows. The shared bundle model owns
//! the manifest grammar and binding. This adapter pins the actual inventory,
//! checks ACLs/bytes/hashes and publishes only into a new private directory.
//! Unsigned manifest hashes identify content, not publisher provenance.
use crate::files::{Asset, Directory};
use crate::security::Identity;
use crate::{Error, Result};
use oblivion_bundle::{Binding, MAX_MANIFEST, Manifest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

const MAX_ENTRIES: usize = 4096;

pub struct BootAssets {
    pub image: String,
    pub kernel: String,
    pub initrd: String,
}

struct Paths {
    cli: String,
    helper: String,
    manager: String,
    assets: String,
}

impl Paths {
    fn new(root: &str, manifest: &Manifest) -> Self {
        Self {
            cli: locate(root, "bin/oblivion.exe"),
            helper: locate(root, "bin/oblivion-vm.exe"),
            manager: locate(root, "bin/oblivion-manager.exe"),
            assets: locate(root, &manifest.assets),
        }
    }
}

pub struct VerifiedBundle {
    root: Directory,
    paths: Paths,
    manifest: Manifest,
    binding: Binding,
    manifest_file: Asset,
    manifest_sha256: String,
    files: BTreeMap<String, Asset>,
}

impl VerifiedBundle {
    pub fn open(root: &str, expected_source: Option<&str>, identity: &Identity) -> Result<Self> {
        let root = Directory::open(root, identity, true)?;
        let manifest_file = root.asset("bundle.json", identity, false)?;
        if manifest_file.bytes() > MAX_MANIFEST as u64 {
            return Err(Error("desktop_bundle_manifest_limit"));
        }
        let mut encoded = Vec::new();
        manifest_file
            .reader()?
            .take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|_| Error("desktop_bundle_manifest_unavailable"))?;
        let manifest =
            Manifest::decode(&encoded, expected_source, "windows-x86_64").map_err(Error)?;
        let binding = manifest.binding().map_err(Error)?;
        let manifest_sha256 = format!("{:x}", Sha256::digest(&encoded));
        let expected = manifest
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<BTreeMap<_, _>>();
        let directories = directories(&manifest)?;
        let mut files = BTreeMap::new();
        let mut identities = BTreeSet::from([manifest_file.identity()]);
        let mut pending = vec![(String::new(), root.clone())];
        let mut entries = 0;
        let mut found_manifest = false;
        while let Some((prefix, directory)) = pending.pop() {
            for name in directory.names(MAX_ENTRIES - entries)? {
                entries += 1;
                let relative = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if relative == "bundle.json" {
                    let actual = directory.asset(&name, identity, false)?;
                    if actual.identity() != manifest_file.identity() {
                        return Err(Error("desktop_bundle_file_changed"));
                    }
                    found_manifest = true;
                    continue;
                }
                if directories.contains(&relative) {
                    pending.push((relative, directory.child(&name, identity, false)?));
                    continue;
                }
                let metadata = expected
                    .get(relative.as_str())
                    .ok_or(Error("desktop_bundle_unlisted_entry"))?;
                let asset = directory.asset(&name, identity, false)?;
                if !identities.insert(asset.identity()) {
                    return Err(Error("desktop_bundle_file_alias"));
                }
                transfer(
                    &asset,
                    metadata.bytes,
                    &metadata.sha256,
                    &mut std::io::sink(),
                )?;
                files.insert(relative, asset);
            }
        }
        if !found_manifest || files.len() != manifest.files.len() {
            return Err(Error("desktop_bundle_file_missing"));
        }
        root.verify()?;
        manifest_file.verify()?;
        Ok(Self {
            paths: Paths::new(root.path(), &manifest),
            root,
            manifest,
            binding,
            manifest_file,
            manifest_sha256,
            files,
        })
    }

    /// Publication is visible to the installer only after this returns. On an
    /// error retain the new private tree for explicit inspection; never delete
    /// an existing destination or unknown entries by path.
    pub fn publish(self, destination: &str, identity: &Identity) -> Result<Self> {
        let (parent, name) = destination
            .rsplit_once('\\')
            .ok_or(Error("invalid_runtime_asset_path"))?;
        let parent = Directory::open(parent, identity, true)?;
        parent.sync()?;
        match std::fs::symlink_metadata(destination) {
            Ok(_) => return Err(Error("runtime_release_already_exists")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error("runtime_release_unavailable")),
        }
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|_| Error("runtime_entropy_unavailable"))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let stage = format!(r"{}\.bundle-{suffix}", parent.path());
        let copied = self.copy_into(&stage, identity)?;
        let source = copied.source().to_owned();
        let Self {
            root,
            files,
            manifest_file,
            ..
        } = copied;
        // Rename only the complete tree; interrupted copies never occupy the
        // final bundle ID and never authorize adoption of a partial release.
        drop(files);
        drop(manifest_file);
        let published = root.move_to(&parent, name, identity)?;
        parent.sync()?;
        let result = Self::open(destination, Some(&source), identity);
        drop(published);
        result
    }

    fn copy_into(self, destination: &str, identity: &Identity) -> Result<Self> {
        self.root.verify()?;
        self.manifest_file.verify()?;
        for asset in self.files.values() {
            asset.verify()?;
        }
        let root = Directory::create(destination, identity)?;
        let mut parents = BTreeMap::from([(String::new(), root.clone())]);
        for relative in directories(&self.manifest)? {
            let (parent, name) = split(&relative);
            let directory = parents
                .get(parent)
                .ok_or(Error("desktop_bundle_file_missing"))?
                .create_child(name, identity)?;
            parents.insert(relative, directory);
        }
        let mut files = BTreeMap::new();
        for metadata in &self.manifest.files {
            let (parent, name) = split(&metadata.path);
            let mut target = parents
                .get(parent)
                .ok_or(Error("desktop_bundle_file_missing"))?
                .create_file(name, identity)?;
            transfer(
                self.files
                    .get(&metadata.path)
                    .ok_or(Error("desktop_bundle_file_missing"))?,
                metadata.bytes,
                &metadata.sha256,
                target.writer(),
            )?;
            target.finish()?;
            transfer(
                &target,
                metadata.bytes,
                &metadata.sha256,
                &mut std::io::sink(),
            )?;
            files.insert(metadata.path.clone(), target);
        }
        let mut manifest_file = root.create_file("bundle.json", identity)?;
        transfer(
            &self.manifest_file,
            self.manifest_file.bytes(),
            &self.manifest_sha256,
            manifest_file.writer(),
        )?;
        manifest_file.finish()?;
        transfer(
            &manifest_file,
            self.manifest_file.bytes(),
            &self.manifest_sha256,
            &mut std::io::sink(),
        )?;
        root.verify()?;
        Ok(Self {
            paths: Paths::new(root.path(), &self.manifest),
            root,
            manifest: self.manifest,
            binding: self.binding,
            manifest_file,
            manifest_sha256: self.manifest_sha256,
            files,
        })
    }

    pub fn root(&self) -> &str {
        self.root.path()
    }
    pub fn id(&self) -> &str {
        &self.manifest.bundle_id
    }
    pub fn source(&self) -> &str {
        &self.manifest.source_sha256
    }
    pub fn binding(&self) -> Result<Binding> {
        Ok(self.binding.clone())
    }
    pub fn cli(&self) -> &str {
        &self.paths.cli
    }
    pub fn helper(&self) -> &str {
        &self.paths.helper
    }
    pub fn manager(&self) -> &str {
        &self.paths.manager
    }
    pub fn assets(&self) -> &str {
        &self.paths.assets
    }
    pub fn boot(&self) -> BootAssets {
        BootAssets {
            image: locate(self.root(), &self.manifest.runtime.image),
            kernel: locate(self.root(), &self.manifest.runtime.kernel),
            initrd: locate(self.root(), &self.manifest.runtime.initrd),
        }
    }

    pub(crate) fn contains_file(&self, identity: (u64, [u8; 16])) -> bool {
        self.manifest_file.identity() == identity
            || self.files.values().any(|file| file.identity() == identity)
    }

    /// Only the exact, complete inventory admitted by open() is removable.
    /// Acquire every file's DELETE handle first, so a running executable keeps
    /// its whole release intact instead of producing an incomplete uninstall.
    pub(crate) fn remove(self, identity: &Identity) -> Result<()> {
        let mut parents = BTreeMap::from([(String::new(), self.root.clone())]);
        for relative in directories(&self.manifest)? {
            let (parent, name) = split(&relative);
            let child = parents
                .get(parent)
                .ok_or(Error("desktop_bundle_file_missing"))?
                .child(name, identity, true)?;
            parents.insert(relative, child);
        }
        let mut removals = Vec::with_capacity(self.files.len() + 1);
        for asset in self.files.into_values() {
            removals.push(asset.removal(identity)?);
        }
        removals.push(self.manifest_file.removal(identity)?);
        for removal in removals {
            removal.remove()?;
        }
        // Children first; rmdir-style deletion preserves any unlisted entry
        // inserted after review and reports an incomplete cleanup.
        while let Some((_, directory)) = parents.pop_last() {
            if directory.path() == self.root.path() {
                drop(directory);
                continue;
            }
            directory.remove(identity)?;
        }
        self.root.remove(identity)
    }
}

fn locate(root: &str, relative: &str) -> String {
    format!("{root}\\{}", relative.replace('/', "\\"))
}
fn split(relative: &str) -> (&str, &str) {
    relative.rsplit_once('/').unwrap_or(("", relative))
}

fn directories(manifest: &Manifest) -> Result<BTreeSet<String>> {
    let mut directories = BTreeSet::new();
    for file in &manifest.files {
        let mut path = file.path.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            directories.insert(parent.to_owned());
            if directories.len() > MAX_ENTRIES {
                return Err(Error("desktop_bundle_inventory_limit"));
            }
            path = parent;
        }
    }
    Ok(directories)
}

/// Verification and publication consume the same pinned source and one byte
/// pipeline. A mismatched size/hash never produces a verified bundle result.
fn transfer(
    asset: &Asset,
    expected_bytes: u64,
    expected_sha256: &str,
    writer: &mut impl Write,
) -> Result<()> {
    if asset.bytes() != expected_bytes {
        return Err(Error("desktop_bundle_file_changed"));
    }
    let mut reader = asset.reader()?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| Error("desktop_bundle_read_failed"))?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or(Error("desktop_bundle_file_changed"))?;
        if bytes > expected_bytes {
            return Err(Error("desktop_bundle_file_changed"));
        }
        hash.update(&buffer[..count]);
        writer
            .write_all(&buffer[..count])
            .map_err(|_| Error("desktop_bundle_write_failed"))?;
    }
    if bytes != expected_bytes || format!("{:x}", hash.finalize()) != expected_sha256 {
        return Err(Error("desktop_bundle_checksum_failed"));
    }
    asset.verify()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::VerifiedBundle;
    use crate::files::{CreationParent, Directory, Executable};
    use crate::security::Identity;
    use oblivion_bundle::{File, Manifest, Runtime};
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, READ_CONTROL, WRITE_DAC};

    pub(crate) struct Fixture {
        source: Option<Directory>,
        area: PathBuf,
        identity: Identity,
        manifest: Manifest,
    }

    impl Fixture {
        fn new() -> Self {
            Self::version("")
        }
        pub(crate) fn version(version: &str) -> Self {
            let identity = Identity::current().unwrap();
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let temp = temp.to_str().unwrap();
            let area = PathBuf::from(temp.strip_prefix(r"\\?\").unwrap_or(temp))
                .join(format!("oblivion-bundle-{suffix}"));
            let descriptor = identity.file_descriptor().unwrap();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            let path = wide(area.to_str().unwrap());
            assert_ne!(unsafe { CreateDirectoryW(path.as_ptr(), &attributes) }, 0);
            let root = Directory::open(area.to_str().unwrap(), &identity, true).unwrap();
            let source = root.create_child("source", &identity).unwrap();
            let mut directories =
                std::collections::BTreeMap::from([(String::new(), source.clone())]);
            let mut files = Vec::new();
            for (index, path) in [
                "bin/oblivion.exe",
                "bin/oblivion-vm.exe",
                "bin/oblivion-manager.exe",
                "lib/manager/@opentui/core-win32-x64/opentui.dll",
                "runtime/controller.iso",
                "runtime/kernel",
                "runtime/initrd",
                "licenses/NOTICE",
            ]
            .iter()
            .enumerate()
            {
                let (parent, name) = super::split(path);
                let mut prefix = String::new();
                for segment in parent.split('/') {
                    let next = if prefix.is_empty() {
                        segment.into()
                    } else {
                        format!("{prefix}/{segment}")
                    };
                    if !directories.contains_key(&next) {
                        let created = directories
                            .get(&prefix)
                            .unwrap()
                            .create_child(segment, &identity)
                            .unwrap();
                        directories.insert(next.clone(), created);
                    }
                    prefix = next;
                }
                let bytes = format!(
                    "Non-executable, nonbootable Windows installer fixture {index} {version}\n"
                );
                let mut file = directories
                    .get(parent)
                    .unwrap()
                    .create_file(name, &identity)
                    .unwrap();
                file.writer().write_all(bytes.as_bytes()).unwrap();
                file.finish().unwrap();
                files.push(File {
                    path: (*path).into(),
                    bytes: bytes.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(bytes.as_bytes())),
                    executable: path.starts_with("bin/"),
                });
            }
            files.sort_by(|left, right| left.path.cmp(&right.path));
            let mut manifest = Manifest {
                format: "oblivion-desktop".into(),
                version: 1,
                development_only: true,
                bundle_id: String::new(),
                product_version: "1.0.0~dev-fixture".into(),
                platform: "windows-x86_64".into(),
                backend: "hcs-hyperv".into(),
                source_sha256: format!("{:x}", Sha256::digest(version.as_bytes())),
                control_protocol: 1,
                assets: "lib/manager".into(),
                runtime: Runtime {
                    image: "runtime/controller.iso".into(),
                    kernel: "runtime/kernel".into(),
                    initrd: "runtime/initrd".into(),
                },
                files,
            };
            manifest.bundle_id = manifest.identity().unwrap();
            let mut encoded = source.create_file("bundle.json", &identity).unwrap();
            encoded
                .writer()
                .write_all(&serde_json::to_vec_pretty(&manifest).unwrap())
                .unwrap();
            encoded.finish().unwrap();
            drop(encoded);
            Self {
                source: Some(source),
                area,
                identity,
                manifest,
            }
        }
        fn source(&self) -> &Directory {
            self.source.as_ref().unwrap()
        }
        fn path(&self, relative: &str) -> String {
            super::locate(self.source().path(), relative)
        }
        fn destination(&self) -> String {
            self.area.join("installed").to_str().unwrap().to_owned()
        }
        pub(crate) fn open(&self) -> crate::Result<VerifiedBundle> {
            VerifiedBundle::open(
                self.source().path(),
                Some(&self.manifest.source_sha256),
                &self.identity,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.source.take();
            std::fs::remove_dir_all(&self.area).unwrap();
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    #[test]
    fn verified_inventory_publishes_private_byte_exact_assets_and_keeps_read_only_pins() {
        let fixture = Fixture::new();
        let bundle = fixture.open().unwrap();
        let expected = bundle.binding().unwrap();
        let destination = fixture.destination();
        let published = bundle.publish(&destination, &fixture.identity).unwrap();
        assert_eq!(published.id(), fixture.manifest.bundle_id);
        assert_eq!(published.source(), fixture.manifest.source_sha256);
        assert_eq!(published.binding().unwrap().bundle_id, expected.bundle_id);
        assert_eq!(
            published.boot().image,
            format!(r"{destination}\runtime\controller.iso")
        );
        assert_eq!(
            published.manager(),
            format!(r"{destination}\bin\oblivion-manager.exe")
        );
        assert_eq!(published.cli(), format!(r"{destination}\bin\oblivion.exe"));
        assert_eq!(published.assets(), format!(r"{destination}\lib\manager"));
        for metadata in &fixture.manifest.files {
            assert_eq!(
                std::fs::read(super::locate(&destination, &metadata.path)).unwrap(),
                std::fs::read(fixture.path(&metadata.path)).unwrap()
            );
        }
        CreationParent::open(&format!(r"{destination}\new-leaf"), &fixture.identity).unwrap();
        let executable = Executable::open(published.helper(), &fixture.identity).unwrap();
        executable.verify().unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&published.boot().kernel)
                .is_err()
        );
        assert!(std::fs::rename(&destination, fixture.area.join("renamed")).is_err());
        let reopened =
            VerifiedBundle::open(&destination, Some(published.source()), &fixture.identity)
                .unwrap();
        assert_eq!(reopened.id(), published.id());
    }

    #[test]
    fn source_tampering_or_unlisted_entries_fail_before_destination_creation() {
        for change in [
            "hash",
            "size",
            "missing",
            "extra-file",
            "extra-directory",
            "hardlink",
        ] {
            let fixture = Fixture::new();
            match change {
                "hash" => {
                    let path = fixture.path("runtime/kernel");
                    let length = std::fs::metadata(&path).unwrap().len() as usize;
                    std::fs::write(path, vec![b'X'; length]).unwrap();
                }
                "size" => std::fs::write(fixture.path("runtime/kernel"), b"changed").unwrap(),
                "missing" => std::fs::remove_file(fixture.path("runtime/kernel")).unwrap(),
                "extra-file" => {
                    std::fs::write(fixture.path("unlisted"), b"NOT_BUNDLE_DATA").unwrap()
                }
                "extra-directory" => std::fs::create_dir(fixture.path("unlisted")).unwrap(),
                "hardlink" => {
                    std::fs::hard_link(fixture.path("runtime/kernel"), fixture.area.join("alias"))
                        .unwrap()
                }
                _ => unreachable!(),
            }
            let destination = fixture.destination();
            assert!(
                fixture
                    .open()
                    .and_then(|bundle| bundle.publish(&destination, &fixture.identity))
                    .is_err()
            );
            assert!(!std::path::Path::new(&destination).exists());
        }
    }

    #[test]
    fn existing_destination_and_unknown_data_are_preserved() {
        let fixture = Fixture::new();
        let destination = fixture.destination();
        std::fs::create_dir(&destination).unwrap();
        let unknown = std::path::Path::new(&destination).join("unknown-private-data");
        std::fs::write(&unknown, b"PRESERVE_UNKNOWN_CANARY").unwrap();
        assert!(
            fixture
                .open()
                .unwrap()
                .publish(&destination, &fixture.identity)
                .is_err()
        );
        assert_eq!(std::fs::read(unknown).unwrap(), b"PRESERVE_UNKNOWN_CANARY");
        assert!(std::path::Path::new(&destination).is_dir());
    }

    #[test]
    fn canonical_shared_manifest_rejects_foreign_source_and_sanitizes_decode_errors() {
        let fixture = Fixture::new();
        assert!(
            VerifiedBundle::open(
                fixture.source().path(),
                Some(&"cd".repeat(32)),
                &fixture.identity
            )
            .is_err()
        );
        let mut manifest = serde_json::to_value(&fixture.manifest).unwrap();
        manifest["PRIVATE_UNKNOWN_FIELD_CANARY"] = serde_json::json!("PRIVATE_CONTENT_CANARY");
        std::fs::write(
            fixture.path("bundle.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = fixture.open().err().unwrap();
        assert_eq!(error.0, "invalid_desktop_bundle");
        assert!(!format!("{error:?}").contains("CANARY"));
    }

    #[test]
    fn source_acl_allowing_other_users_to_mutate_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.path("runtime/kernel");
        let file = OpenOptions::new()
            .access_mode(WRITE_DAC | READ_CONTROL)
            .open(&path)
            .unwrap();
        let text = format!(
            "O:{}{}(A;;GW;;;WD)",
            fixture.identity.sid(),
            fixture.identity.sddl()
        );
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(&text).as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let mut present = 0;
        let mut acl = null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut(),
                )
            },
            0
        );
        unsafe {
            LocalFree(descriptor);
        }
        drop(file);
        assert_eq!(
            fixture.open().err().unwrap().0,
            "private_runtime_file_required"
        );
        assert!(!std::path::Path::new(&fixture.destination()).exists());
    }
}
