//! The single current desktop-bundle manifest for native installers. This pure
//! model validates metadata and canonical identity; adapters own filesystem
//! identity, ACLs, checksums and publication. Unsigned hashes are not provenance.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_MANIFEST: usize = 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_FILES: usize = 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    /// Launchable role. Unix also verifies executable mode; Windows verifies
    /// the artifact and ACLs without treating POSIX execute bits as authority.
    pub executable: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub image: String,
    pub kernel: String,
    pub initrd: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub bundle_id: String,
    pub source_sha256: String,
    pub boot: [File; 3],
}
impl Binding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !hash(&self.bundle_id) || !hash(&self.source_sha256) {
            return Err("invalid_runtime_bundle_binding");
        }
        for (file, expected) in self.boot.iter().zip(BOOT) {
            if file.path != expected
                || file.executable
                || file.bytes == 0
                || file.bytes > MAX_FILE_BYTES
                || !hash(&file.sha256)
            {
                return Err("invalid_runtime_bundle_binding");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase", try_from = "String")]
pub enum Channel {
    Dev,
    Rc,
    Stable,
}
impl TryFrom<String> for Channel {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "dev" => Ok(Self::Dev),
            "rc" => Ok(Self::Rc),
            "stable" => Ok(Self::Stable),
            _ => Err("invalid_desktop_bundle_channel"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub version: u8,
    pub channel: Channel,
    pub bundle_id: String,
    pub product_version: String,
    pub platform: String,
    pub backend: String,
    pub source_sha256: String,
    pub control_protocol: u8,
    pub assets: String,
    pub runtime: Runtime,
    pub files: Vec<File>,
}

#[derive(Clone, Copy)]
pub struct Target {
    pub platform: &'static str,
    pub backend: &'static str,
    pub binaries: [&'static str; 3],
    pub native_library: &'static str,
}
const UNIX_BINARIES: [&str; 3] = ["bin/oblivion", "bin/oblivion-vm", "bin/oblivion-manager"];
const WINDOWS_BINARIES: [&str; 3] = [
    "bin/oblivion.exe",
    "bin/oblivion-vm.exe",
    "bin/oblivion-manager.exe",
];
const BOOT: [&str; 3] = ["runtime/controller.iso", "runtime/kernel", "runtime/initrd"];

pub fn target(platform: &str) -> Result<Target, &'static str> {
    let (platform, backend, native_library) = match platform {
        "darwin-arm64" => (
            "darwin-arm64",
            "apple-vz",
            "lib/manager/@opentui/core-darwin-arm64/libopentui.dylib",
        ),
        "linux-x86_64" => (
            "linux-x86_64",
            "qemu-kvm",
            "lib/manager/@opentui/core-linux-x64/libopentui.so",
        ),
        "linux-arm64" => (
            "linux-arm64",
            "qemu-kvm",
            "lib/manager/@opentui/core-linux-arm64/libopentui.so",
        ),
        "windows-x86_64" => (
            "windows-x86_64",
            "hcs-hyperv",
            "lib/manager/@opentui/core-win32-x64/opentui.dll",
        ),
        _ => return Err("unsupported_desktop_bundle_platform"),
    };
    Ok(Target {
        platform,
        backend,
        native_library,
        binaries: if platform == "windows-x86_64" {
            WINDOWS_BINARIES
        } else {
            UNIX_BINARIES
        },
    })
}

impl Manifest {
    pub fn decode(
        bytes: &[u8],
        source: Option<&str>,
        platform: &str,
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAX_MANIFEST {
            return Err("desktop_bundle_manifest_limit");
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_desktop_bundle")?;
        manifest.validate(source, platform)?;
        Ok(manifest)
    }

    pub fn identity(&self) -> Result<String, &'static str> {
        let mut canonical = serde_json::to_value(self).map_err(|_| "invalid_desktop_bundle")?;
        canonical
            .as_object_mut()
            .ok_or("invalid_desktop_bundle")?
            .remove("bundle_id");
        let bytes = serde_json::to_vec(&canonical).map_err(|_| "invalid_desktop_bundle")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self, source: Option<&str>, platform: &str) -> Result<(), &'static str> {
        let target = target(platform)?;
        if self.format != "oblivion-desktop"
            || self.version != 2
            || self.bundle_id != self.identity()?
            || self.platform != target.platform
            || self.backend != target.backend
            || !hash(&self.source_sha256)
            || source.is_some_and(|source| !hash(source) || self.source_sha256 != source)
            || self.control_protocol != 1
            || !product_version(&self.product_version, self.channel)
            || self.assets != "lib/manager"
            || self.runtime.image != BOOT[0]
            || self.runtime.kernel != BOOT[1]
            || self.runtime.initrd != BOOT[2]
            || self.files.is_empty()
            || self.files.len() > MAX_FILES
        {
            return Err("desktop_bundle_does_not_match_this_build");
        }
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        let mut spellings = BTreeMap::new();
        let mut previous = "";
        for file in &self.files {
            if !relative(&file.path)
                || !hash(&file.sha256)
                || file.bytes > MAX_FILE_BYTES
                || file.path.as_str() <= previous
                || files.insert(file.path.as_str(), file).is_some()
            {
                return Err("invalid_desktop_bundle_inventory");
            }
            let mut prefix = String::new();
            let parts: Vec<_> = file.path.split('/').collect();
            for (index, part) in parts.iter().enumerate() {
                if index != 0 {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if target.platform == "windows-x86_64" {
                    if spellings
                        .insert(prefix.to_ascii_lowercase(), prefix.clone())
                        .is_some_and(|old| old != prefix)
                    {
                        return Err("invalid_desktop_bundle_inventory");
                    }
                }
                if index + 1 < parts.len() {
                    directories.insert(prefix.clone());
                }
            }
            previous = &file.path;
        }
        if files.keys().any(|file| directories.contains(*file)) {
            return Err("invalid_desktop_bundle_inventory");
        }
        for path in target
            .binaries
            .into_iter()
            .chain([target.native_library])
            .chain(BOOT)
        {
            let file = files.get(path).ok_or("desktop_bundle_file_missing")?;
            if file.bytes == 0 || (path.starts_with("bin/") && !file.executable) {
                return Err("desktop_bundle_file_invalid");
            }
        }
        Ok(())
    }

    pub fn file(&self, path: &str) -> Result<&File, &'static str> {
        self.files
            .iter()
            .find(|file| file.path == path)
            .ok_or("desktop_bundle_file_missing")
    }
    pub fn binding(&self) -> Result<Binding, &'static str> {
        let binding = Binding {
            bundle_id: self.bundle_id.clone(),
            source_sha256: self.source_sha256.clone(),
            boot: [
                self.file(BOOT[0])?.clone(),
                self.file(BOOT[1])?.clone(),
                self.file(BOOT[2])?.clone(),
            ],
        };
        binding.validate()?;
        Ok(binding)
    }
}

fn product_version(value: &str, channel: Channel) -> bool {
    if value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let base = match channel {
        Channel::Stable => value,
        Channel::Rc => {
            let Some((base, number)) = value.split_once("~rc") else {
                return false;
            };
            if !decimal(number) || number == "0" {
                return false;
            }
            base
        }
        Channel::Dev => {
            let Some((base, suffix)) = value.split_once("~dev") else {
                return false;
            };
            let Some((number, sha)) = suffix.split_once('.') else {
                return false;
            };
            if !decimal(number)
                || number == "0"
                || sha.len() != 12
                || !sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return false;
            }
            base
        }
    };
    let mut parts = base.split('.');
    (0..3).all(|_| parts.next().is_some_and(decimal)) && parts.next().is_none()
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Portable lexical names, independent of the builder's OS. The current format
/// cannot contain drive-relative paths, ADS, DOS devices or trailing aliases.
pub fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.eq_ignore_ascii_case("bundle.json")
        && value
            .bytes()
            .all(|byte| byte >= 32 && byte != 127 && !b"<>:\\|?*\"".contains(&byte))
        && value.split('/').all(|part| {
            let base = part
                .split('.')
                .next()
                .unwrap_or_default()
                .trim_end_matches(' ')
                .to_ascii_lowercase();
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !matches!(base.as_str(), "con" | "prn" | "aux" | "nul")
                && !(base.len() == 4
                    && (base.starts_with("com") || base.starts_with("lpt"))
                    && matches!(base.as_bytes()[3], b'1'..=b'9'))
        })
}
