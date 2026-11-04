use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disk {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub version: u8,
    pub backend: String,
    pub runtime_id: String,
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    pub command_line: String,
    pub disks: Vec<Disk>,
    pub cpu_count: u8,
    pub memory_mi_b: u64,
    pub control_socket: PathBuf,
    pub control_port: u32,
    #[serde(rename = "guestCID")]
    pub guest_cid: u32,
    pub network: bool,
    pub serial_stdio: bool,
}

impl RuntimeConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let file = private_file(path, false)?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("runtime_configuration_unavailable"))?;
        if bytes.len() > 65536 {
            return Err(Error("invalid_runtime_configuration"));
        }
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error("invalid_runtime_configuration"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.backend != "qemu-kvm"
            || !(1..=32).contains(&self.cpu_count)
            || !(1024..=131072).contains(&self.memory_mi_b)
            || self.control_port != 4050
            || !(3..u32::MAX).contains(&self.guest_cid)
            || self.runtime_id.len() != 32
            || !self
                .runtime_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.command_line.len() > 4096
            || self.command_line.contains('\0')
            || self.disks.len() != 2
            || !self.disks[0].read_only
            || self.disks[1].read_only
            || !self.kernel.is_absolute()
            || self.initrd.as_ref().is_some_and(|path| !path.is_absolute())
            || self.disks.iter().any(|disk| !disk.path.is_absolute())
            || !self.control_socket.is_absolute()
            || self.control_socket.as_os_str().len() > 98
        {
            return Err(Error("invalid_runtime_configuration"));
        }
        let parameters: Vec<_> = self.command_line.split_whitespace().collect();
        let identity = format!("oblivion.runtime-id={}", self.runtime_id);
        if parameters
            .iter()
            .filter(|arg| arg.starts_with("oblivion.runtime-id="))
            .count()
            != 1
            || !parameters.contains(&identity.as_str())
            || !parameters.contains(&"oblivion.runtime=1")
            || !parameters.contains(&"console=hvc0")
            || parameters
                .iter()
                .filter(|arg| arg.starts_with("oblivion.runtime-backend="))
                .count()
                != 1
            || !parameters.contains(&"oblivion.runtime-backend=qemu-kvm")
        {
            return Err(Error("runtime_boot_identity_required"));
        }
        Ok(())
    }

    /// Keep the exclusive data-file lease alive until QEMU has exited.
    pub fn disk_lease(&self) -> Result<File> {
        asset(&self.kernel)?;
        if let Some(path) = &self.initrd {
            asset(path)?;
        }
        let mut image = asset(&self.disks[0].path)?;
        let mut signature = [0; 6];
        image
            .seek(SeekFrom::Start(32768))
            .and_then(|_| image.read_exact(&mut signature))
            .map_err(|_| Error("runtime_iso_required"))?;
        if signature[1..] != *b"CD001" {
            return Err(Error("runtime_iso_required"));
        }
        let mut disk = data_file(&self.disks[1].path, &self.runtime_id)?;
        let size = data_size(&disk)?;
        if !(4 * 1024 * 1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(&size) {
            return Err(Error("invalid_runtime_disk"));
        }
        if unsafe { libc::flock(disk.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error("runtime_disk_in_use"));
        }
        let mut first = [0; 4096];
        disk.read_exact(&mut first)
            .map_err(|_| Error("runtime_disk_unavailable"))?;
        disk_identity(&first, &self.runtime_id)?;
        Ok(disk)
    }
}

fn data_size(file: &File) -> Result<u64> {
    let metadata = file
        .metadata()
        .map_err(|_| Error("runtime_disk_unavailable"))?;
    #[cfg(target_os = "linux")]
    if metadata.file_type().is_block_device() {
        let mut size = 0_u64;
        if unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272_u64, &mut size) } != 0 {
            return Err(Error("runtime_disk_size_unavailable"));
        }
        return Ok(size);
    }
    Ok(metadata.len())
}

fn data_file(path: &Path, runtime_id: &str) -> Result<File> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| Error("runtime_disk_unavailable"))?;
    if metadata.is_file() {
        return private_file(path, true);
    }
    #[cfg(target_os = "linux")]
    if metadata.file_type().is_block_device() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Authorization {
            version: u8,
            path: PathBuf,
            runtime_id: String,
            device_number: String,
            bytes: u64,
        }
        let mut record = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/oblivion-live/storage.json")
            .map_err(|_| Error("live_partition_not_authorized"))?;
        let info = record
            .metadata()
            .map_err(|_| Error("live_partition_not_authorized"))?;
        if !info.is_file()
            || info.uid() != 0
            || info.mode() & 0o022 != 0
            || info.nlink() != 1
            || info.len() > 4096
        {
            return Err(Error("live_partition_not_authorized"));
        }
        let mut bytes = Vec::new();
        record
            .read_to_end(&mut bytes)
            .map_err(|_| Error("live_partition_not_authorized"))?;
        let authorization: Authorization =
            serde_json::from_slice(&bytes).map_err(|_| Error("live_partition_not_authorized"))?;
        let number = format!(
            "{}:{}",
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev())
        );
        if authorization.version != 1
            || authorization.path != path
            || authorization.runtime_id != runtime_id
            || authorization.device_number != number
            || !(4 * 1024_u64.pow(3)..=1024_u64.pow(4)).contains(&authorization.bytes)
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.mode() & 0o077 != 0
            || !Path::new(&format!("/sys/dev/block/{number}/partition")).exists()
        {
            return Err(Error("live_partition_not_authorized"));
        }
        let mounts = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|_| Error("live_partition_observation_failed"))?;
        if mounts
            .lines()
            .any(|line| line.split_whitespace().nth(2) == Some(number.as_str()))
        {
            return Err(Error("live_partition_already_mounted"));
        }
        let swaps = std::fs::read_to_string("/proc/swaps")
            .map_err(|_| Error("live_partition_observation_failed"))?;
        if swaps
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .any(|source| {
                std::fs::metadata(source).is_ok_and(|info| info.rdev() == metadata.rdev())
            })
        {
            return Err(Error("live_partition_is_swap"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error("live_partition_unavailable"))?;
        let opened = file
            .metadata()
            .map_err(|_| Error("live_partition_unavailable"))?;
        let mut size = 0_u64;
        if opened.rdev() != metadata.rdev()
            || !opened.file_type().is_block_device()
            || unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272_u64, &mut size) } != 0
            || size != authorization.bytes
        {
            return Err(Error("live_partition_changed"));
        }
        return Ok(file);
    }
    let _ = runtime_id;
    Err(Error("private_runtime_file_required"))
}

fn disk_identity(first: &[u8; 4096], identity: &str) -> Result<()> {
    let marker = format!("OBLIVION-RUNTIME-1\n{identity}\n");
    if first.starts_with(marker.as_bytes()) && first[marker.len()..].iter().all(|byte| *byte == 0) {
        return Ok(());
    }
    let mut uuid = [0; 16];
    if identity.len() != 32 {
        return Err(Error("runtime_disk_identity_mismatch"));
    }
    for (index, value) in uuid.iter_mut().enumerate() {
        *value = u8::from_str_radix(&identity[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error("runtime_disk_identity_mismatch"))?;
    }
    if first[1080..1082] != [0x53, 0xef]
        || first[1128..1144] != uuid
        || first[1144..1160] != *b"OBLIVION-RUNTIME"
    {
        return Err(Error("runtime_disk_identity_mismatch"));
    }
    Ok(())
}

fn asset(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("runtime_asset_unavailable"))?;
    if !file
        .metadata()
        .map_err(|_| Error("runtime_asset_unavailable"))?
        .is_file()
    {
        return Err(Error("regular_runtime_asset_required"));
    }
    Ok(file)
}

pub fn private_file(path: &Path, writable: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("private_runtime_file_required"))?;
    let info = file
        .metadata()
        .map_err(|_| Error("private_runtime_file_required"))?;
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
    {
        return Err(Error("private_runtime_file_required"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_the_current_install_identity() {
        let id = "00112233445566778899aabbccddeeff";
        let mut first = [0; 4096];
        let marker = format!("OBLIVION-RUNTIME-1\n{id}\n");
        first[..marker.len()].copy_from_slice(marker.as_bytes());
        assert!(disk_identity(&first, id).is_ok());
        first[4095] = 1;
        assert!(disk_identity(&first, id).is_err());
        first.fill(0);
        first[1080..1082].copy_from_slice(&[0x53, 0xef]);
        first[1128..1144].copy_from_slice(&[
            0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
        ]);
        first[1144..1160].copy_from_slice(b"OBLIVION-RUNTIME");
        assert!(disk_identity(&first, id).is_ok());
        assert!(disk_identity(&first, "10112233445566778899aabbccddeeff").is_err());
    }
}
