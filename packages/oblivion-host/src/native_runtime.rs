//! Desktop runtime state contains public boot assets and an encrypted data disk.
use crate::control::{self, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("OBLIVION_RUNTIME_DIRECTORY") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "macos")]
    return Ok(
        PathBuf::from(std::env::var_os("HOME").ok_or("home_unavailable")?)
            .join("Library/Application Support/Oblivion"),
    );
    #[cfg(target_os = "linux")]
    {
        let root = match std::env::var_os("XDG_DATA_HOME") {
            Some(root) => PathBuf::from(root),
            None => PathBuf::from(std::env::var_os("HOME").ok_or("home_unavailable")?)
                .join(".local/share"),
        };
        Ok(root.join("oblivion"))
    }
}
fn socket_directory() -> Result<PathBuf> {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    directory()?.hash(&mut hash);
    let name = format!(
        "oblivion-{}-{:016x}",
        unsafe { libc::getuid() },
        hash.finish()
    );
    #[cfg(target_os = "linux")]
    if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR") {
        let root = PathBuf::from(root);
        let info = fs::symlink_metadata(&root)?;
        if !root.is_absolute()
            || !info.is_dir()
            || info.uid() != unsafe { libc::getuid() }
            || info.mode() & 0o077 != 0
        {
            return Err("unsafe_xdg_runtime_directory".into());
        }
        return Ok(root.join(name));
    }
    Ok(PathBuf::from("/tmp").join(name))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Desktop,
    Direct,
}

pub fn mode() -> Result<Mode> {
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/etc/oblivion/installation.json");
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Mode::Desktop),
            Err(_) => return Err("installation_profile_unavailable".into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err("unsafe_installation_profile".into());
        }
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes)?;
        return installation(&bytes);
    }
    #[cfg(target_os = "macos")]
    Ok(Mode::Desktop)
}

#[cfg(any(target_os = "linux", test))]
fn installation(bytes: &[u8]) -> Result<Mode> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Profile {
        version: u8,
        mode: String,
    }
    if bytes.len() > 1024 {
        return Err("invalid_installation_profile".into());
    }
    let profile: Profile = serde_json::from_slice(bytes)?;
    if profile.version != 1 || profile.mode != "direct-controller" {
        return Err("invalid_installation_profile".into());
    }
    Ok(Mode::Direct)
}

fn backend() -> &'static str {
    #[cfg(target_os = "macos")]
    return "apple-vz";
    #[cfg(target_os = "linux")]
    "qemu-kvm"
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Disk {
    path: PathBuf,
    read_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    version: u8,
    backend: String,
    runtime_id: String,
    kernel: PathBuf,
    initrd: PathBuf,
    command_line: String,
    disks: [Disk; 2],
    cpu_count: u8,
    memory_mi_b: u64,
    control_socket: PathBuf,
    control_port: u32,
    network: bool,
    serial_stdio: bool,
    #[serde(rename = "guestCID", default, skip_serializing_if = "Option::is_none")]
    guest_cid: Option<u32>,
}

impl Settings {
    fn read(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::getuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err("unsafe_runtime_configuration".into());
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("invalid_runtime_configuration".into());
        }
        let value: Self = serde_json::from_slice(&bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        let parameters: Vec<_> = self.command_line.split_whitespace().collect();
        let platform = format!("oblivion.runtime-backend={}", backend());
        let identity = format!("oblivion.runtime-id={}", self.runtime_id);
        if self.version != 1
            || self.backend != backend()
            || self.runtime_id.len() != 32
            || !self
                .runtime_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !self.kernel.is_absolute()
            || !self.initrd.is_absolute()
            || self.disks.iter().any(|disk| !disk.path.is_absolute())
            || !self.disks[0].read_only
            || self.disks[1].read_only
            || !(1..=32).contains(&self.cpu_count)
            || !(1024..=131072).contains(&self.memory_mi_b)
            || self.control_port != 4050
            || !self.control_socket.is_absolute()
            || self.control_socket.as_os_str().len() > 98
            || self.command_line.len() > 4096
            || self.command_line.contains('\0')
            || !parameters.contains(&"oblivion.runtime=1")
            || !parameters.contains(&"console=hvc0")
            || !parameters.contains(&platform.as_str())
            || !parameters.contains(&identity.as_str())
            || parameters
                .iter()
                .filter(|arg| arg.starts_with("oblivion.runtime-backend="))
                .count()
                != 1
            || parameters
                .iter()
                .filter(|arg| arg.starts_with("oblivion.runtime-id="))
                .count()
                != 1
            || (backend() == "qemu-kvm"
                && !self
                    .guest_cid
                    .is_some_and(|cid| (3..u32::MAX).contains(&cid)))
            || (backend() == "apple-vz" && self.guest_cid.is_some())
        {
            return Err("invalid_runtime_configuration".into());
        }
        Ok(())
    }
}

fn preflight() -> Result<()> {
    let capabilities = Command::new(helper()?).arg("capabilities").output()?;
    let value: serde_json::Value = serde_json::from_slice(&capabilities.stdout)?;
    if !capabilities.status.success()
        || value["version"] != 1
        || value["backend"] != backend()
        || value["supported"] != true
    {
        return Err(if backend() == "qemu-kvm" {
            "Linux runtime requires x86_64, usable KVM with nested VMX/SVM, vhost-vsock and QEMU. Run oblivion-vm capabilities."
        } else { "This Mac does not support the nested virtual machines required by Oblivion. Run oblivion-vm capabilities." }.into());
    }
    Ok(())
}

fn extractor() -> Result<&'static Path> {
    #[cfg(target_os = "macos")]
    return Ok(Path::new("/usr/bin/tar"));
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/usr/bin/bsdtar");
        if path.is_file() {
            return Ok(path);
        }
        Err("Install libarchive-tools (bsdtar) before installing the Linux runtime".into())
    }
}

fn extract(image: &Path, assets: &Path) -> Result<()> {
    let program = extractor()?;
    for (source, target) in [("live/vmlinuz", "kernel"), ("live/initrd.img", "initrd")] {
        let path = assets.join(target);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let result = Command::new(program)
            .args(["-xOf"])
            .arg(image)
            .arg(source)
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null())
            .status()?;
        if !result.success() {
            return Err("The ISO is missing its matching runtime boot files".into());
        }
        fs::File::open(path)?.sync_all()?;
    }
    Ok(())
}

fn random_id() -> Result<String> {
    let mut identity = [0; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut identity)?;
    Ok(identity.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn guest_cid() -> Result<Option<u32>> {
    if backend() == "apple-vz" {
        return Ok(None);
    }
    loop {
        let mut bytes = [0; 4];
        fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let cid = u32::from_ne_bytes(bytes);
        if (3..u32::MAX).contains(&cid) {
            return Ok(Some(cid));
        }
    }
}
fn private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err("absolute_runtime_directory_required".into());
    }
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
        return Err("unsafe_runtime_directory".into());
    }
    Ok(())
}
fn helper() -> Result<PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .ok_or("executable_directory_missing")?
        .join("oblivion-vm");
    if !path.is_file() {
        return Err("Install the oblivion-vm helper beside oblivion".into());
    }
    Ok(path)
}

fn require_desktop() -> Result<()> {
    if mode()? == Mode::Direct {
        return Err(
            "This installation uses the local controller; desktop runtime commands are unavailable"
                .into(),
        );
    }
    Ok(())
}

pub fn install(image: &Path) -> Result<()> {
    require_desktop()?;
    // Hardware access and extraction tools are checked before allocating data.
    preflight()?;
    extractor()?;
    let image = image.canonicalize()?;
    let root = directory()?;
    let sockets = socket_directory()?;
    private_directory(&root)?;
    private_directory(&sockets)?;
    let config = root.join("runtime.json");
    let election = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&election)? {
        return Err("runtime_installation_busy".into());
    }
    if fs::symlink_metadata(&config).is_ok() {
        return Err("Runtime is already installed".into());
    }
    let runtime_id = random_id()?;
    let assets = root.join(format!("runtime-{runtime_id}"));
    fs::DirBuilder::new().mode(0o700).create(&assets)?;
    let result = (|| -> Result<()> {
        extract(&image, &assets)?;
        let disk = assets.join("storage.raw");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&disk)?;
        file.set_len(16 * 1024 * 1024 * 1024)?;
        file.write_all(format!("OBLIVION-RUNTIME-1\n{runtime_id}\n").as_bytes())?;
        file.sync_all()?;
        let settings = Settings {
            version: 1,
            backend: backend().into(),
            command_line: format!(
                "boot=live components console=hvc0 quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend={} oblivion.runtime-id={runtime_id}",
                backend()
            ),
            runtime_id,
            kernel: assets.join("kernel"),
            initrd: assets.join("initrd"),
            disks: [
                Disk {
                    path: image,
                    read_only: true,
                },
                Disk {
                    path: disk,
                    read_only: false,
                },
            ],
            cpu_count: 4,
            memory_mi_b: 6144,
            control_socket: sockets.join("runtime.sock"),
            control_port: 4050,
            guest_cid: guest_cid()?,
            network: true,
            serial_stdio: false,
        };
        settings.validate()?;
        write_settings(&root, &settings)?;
        Ok(())
    })();
    if result.is_err() && !config.exists() {
        let _ = fs::remove_dir_all(assets);
    }
    result
}

pub fn update(image: &Path) -> Result<()> {
    require_desktop()?;
    preflight()?;
    extractor()?;
    let image = image.canonicalize()?;
    let root = directory()?;
    private_directory(&root)?;
    let mut settings = Settings::read(&root.join("runtime.json"))?;
    private_directory(
        settings
            .control_socket
            .parent()
            .ok_or("invalid_runtime_socket")?,
    )?;
    let startup = private_lock(&sidecar(&settings.control_socket, ".startup.lock"))?;
    let running = private_lock(&sidecar(&settings.control_socket, ".lock"))?;
    if !try_lock(&startup)? || !try_lock(&running)? {
        return Err("Stop the protected runtime before updating its image".into());
    }
    let assets = root.join(format!("boot-{}", random_id()?));
    fs::DirBuilder::new().mode(0o700).create(&assets)?;
    let result = (|| -> Result<()> {
        extract(&image, &assets)?;
        settings.disks[0].path = image;
        settings.kernel = assets.join("kernel");
        settings.initrd = assets.join("initrd");
        write_settings(&root, &settings)
    })();
    // A directory fsync error after rename must not remove newly committed assets.
    if result.is_err()
        && !Settings::read(&root.join("runtime.json"))
            .is_ok_and(|current| current.kernel == assets.join("kernel"))
    {
        let _ = fs::remove_dir_all(assets);
    }
    result
}

fn write_settings(root: &Path, settings: &Settings) -> Result<()> {
    settings.validate()?;
    let pending = root.join(format!("runtime-{}.pending", random_id()?));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&serde_json::to_vec_pretty(settings)?)?;
        file.sync_all()?;
        fs::rename(&pending, root.join("runtime.json"))?;
        fs::File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

fn prepare_connection() -> Result<Settings> {
    let root = directory()?;
    let path = root.join("runtime.json");
    if !path.is_file() {
        return Err(
            "Install the matching runtime with oblivion runtime install /path/to/oblivion.iso"
                .into(),
        );
    }
    private_directory(&root)?;
    let settings = Settings::read(&path)?;
    private_directory(
        settings
            .control_socket
            .parent()
            .ok_or("invalid_runtime_socket")?,
    )?;
    // At launcher startup there are no worker threads. The selected profile owns
    // transport routing; environment inherited from a shell cannot select another.
    unsafe {
        std::env::set_var("OBLIVION_RUNTIME_MODE", "desktop");
        std::env::set_var("OBLIVION_CONTROL_SOCKET", &settings.control_socket);
    }
    Ok(settings)
}

pub fn start() -> Result<()> {
    require_desktop()?;
    ensure()
}

pub fn ensure() -> Result<()> {
    if mode()? == Mode::Direct {
        unsafe {
            std::env::set_var("OBLIVION_RUNTIME_MODE", "direct");
            std::env::remove_var("OBLIVION_CONTROL_SOCKET");
        }
        return Ok(());
    }
    let settings = prepare_connection()?;
    let config = directory()?.join("runtime.json");
    let socket = &settings.control_socket;
    let deadline = Instant::now() + Duration::from_secs(390);
    if crate::remote_control::probe(socket, Duration::from_secs(2)).is_ok() {
        return Ok(());
    }
    let startup_lock = private_lock(&sidecar(socket, ".startup.lock"))?;
    let helper_lock = private_lock(&sidecar(socket, ".lock"))?;
    let mut owns_startup = false;
    let mut observed_owner = false;
    let mut child: Option<std::process::Child> = None;
    eprintln!("Preparing the protected runtime…");
    loop {
        if let Some(child) = child.as_mut() {
            if child.try_wait()?.is_some() {
                return Err("Runtime startup failed. Inspect oblivion-vm capabilities and the installed image.".into());
            }
        }
        if !owns_startup {
            owns_startup = try_lock(&startup_lock)?;
            observed_owner |= !owns_startup;
        }
        if owns_startup && child.is_none() {
            if try_lock(&helper_lock)? {
                if observed_owner {
                    return Err("The protected runtime stopped before its controller became ready. Retry to start it again.".into());
                }
                preflight()?;
                // Linux never silently adopts an old QMP/control socket. Recovery
                // is an explicit command under both election and lifetime locks.
                if backend() == "qemu-kvm"
                    && [
                        socket.clone(),
                        sidecar(socket, ".qmp"),
                        sidecar(socket, ".auth"),
                    ]
                    .iter()
                    .any(|path| fs::symlink_metadata(path).is_ok())
                {
                    return Err("Run oblivion runtime recover to inspect and remove disconnected runtime sockets".into());
                }
                if unsafe { libc::flock(helper_lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut command = Command::new(helper()?);
                command
                    .args(["run", "--config"])
                    .arg(&config)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                // The startup lease stays held until the helper owns its lifetime
                // lease and its authenticated controller becomes ready.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                child = Some(command.spawn()?);
            } else {
                observed_owner = true;
            }
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("Runtime is still starting. Retry after its controller becomes ready.")?;
        if crate::remote_control::probe(socket, remaining.min(Duration::from_secs(2))).is_ok() {
            return Ok(());
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(
                "Runtime is still starting. Retry after its controller becomes ready.".into(),
            );
        };
        std::thread::sleep(remaining.min(Duration::from_millis(250)));
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Explicitly recover sockets only after all owners and listeners have gone.
pub fn recover() -> Result<()> {
    require_desktop()?;
    let settings = prepare_connection()?;
    let startup = private_lock(&sidecar(&settings.control_socket, ".startup.lock"))?;
    let running = private_lock(&sidecar(&settings.control_socket, ".lock"))?;
    if !try_lock(&startup)? || !try_lock(&running)? {
        return Err("runtime_still_running".into());
    }
    let paths = if backend() == "qemu-kvm" {
        vec![
            settings.control_socket.clone(),
            sidecar(&settings.control_socket, ".qmp"),
            sidecar(&settings.control_socket, ".auth"),
        ]
    } else {
        vec![settings.control_socket.clone()]
    };
    recover_sockets(&paths)
}

fn recover_sockets(paths: &[PathBuf]) -> Result<()> {
    use std::os::unix::net::UnixStream;
    let mut disconnected = Vec::new();
    for path in paths {
        let info = match fs::symlink_metadata(path) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !info.file_type().is_socket()
            || info.uid() != unsafe { libc::getuid() }
            || info.mode() & 0o077 != 0
        {
            return Err("unsafe_runtime_socket".into());
        }
        match UnixStream::connect(path) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                disconnected.push((path, info.ino()))
            }
            _ => return Err("runtime_socket_still_active".into()),
        }
    }
    for (path, inode) in disconnected {
        let info = fs::symlink_metadata(path)?;
        if info.ino() != inode || !info.file_type().is_socket() {
            return Err("runtime_socket_changed".into());
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

fn private_lock(path: &Path) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::getuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err("unsafe_runtime_lock".into());
    }
    Ok(file)
}

fn try_lock(file: &fs::File) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(error.into())
}

pub fn stop() -> Result<()> {
    require_desktop()?;
    prepare_connection()?;
    control::request("lock", None, &[])?;
    control::request("shutdown-runtime", None, &[])?;
    Ok(())
}

pub fn stop_if_idle() -> Result<()> {
    if std::env::var_os("OBLIVION_MANAGER_ACTIVE").is_some()
        || std::env::var_os("OBLIVION_RUNTIME_MODE").as_deref()
            != Some(std::ffi::OsStr::new("desktop"))
    {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match control::request("shutdown-idle", None, &[]) {
            Ok(_) => return Ok(()),
            Err(error) if error.to_string() == "runtime_busy" => return Ok(()),
            // The EOF lease worker can still be removing the completed file
            // channel. Busy is returned before mutation; let it finish before
            // checking whether the runtime is now unowned. Other errors retain
            // their meaning and never trigger a repeated shutdown request.
            Err(error) if error.to_string() == "controller_busy" => {
                if Instant::now() >= deadline { return Ok(()); }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                PathBuf::from("/tmp").join(format!("oblivion-runtime-{}", random_id().unwrap()));
            private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn settings(root: &Path) -> Settings {
        let identity = "00112233445566778899aabbccddeeff";
        Settings {
            version: 1,
            backend: backend().into(),
            runtime_id: identity.into(),
            kernel: root.join("kernel"),
            initrd: root.join("initrd"),
            command_line: format!(
                "boot=live console=hvc0 oblivion.runtime=1 oblivion.runtime-backend={} oblivion.runtime-id={identity}",
                backend()
            ),
            disks: [
                Disk {
                    path: root.join("image.iso"),
                    read_only: true,
                },
                Disk {
                    path: root.join("storage.raw"),
                    read_only: false,
                },
            ],
            cpu_count: 4,
            memory_mi_b: 6144,
            control_socket: root.join("runtime.sock"),
            control_port: 4050,
            network: true,
            serial_stdio: false,
            guest_cid: if backend() == "qemu-kvm" {
                Some(45032)
            } else {
                None
            },
        }
    }
    #[test]
    fn installation_profile_is_explicit_and_exact() {
        assert!(matches!(
            installation(br#"{"version":1,"mode":"direct-controller"}"#),
            Ok(Mode::Direct)
        ));
        for invalid in [
            br#"{"version":0,"mode":"direct-controller"}"#.as_slice(),
            br#"{"version":1,"mode":"desktop"}"#.as_slice(),
            br#"{"version":1,"mode":"direct-controller","fallback":true}"#.as_slice(),
            br#"{"mode":"direct-controller"}"#.as_slice(),
        ] {
            assert!(installation(invalid).is_err());
        }
        assert!(installation(&[b' '; 1025]).is_err());
    }
    #[test]
    fn current_platform_schema_roundtrips_and_rejects_wrong_backend() {
        let fixture = Fixture::new();
        let mut value = settings(&fixture.0);
        write_settings(&fixture.0, &value).unwrap();
        let loaded = Settings::read(&fixture.0.join("runtime.json")).unwrap();
        assert_eq!(loaded.backend, backend());
        assert_eq!(loaded.runtime_id, value.runtime_id);
        assert_eq!(loaded.guest_cid, value.guest_cid);
        value.backend = "other-platform".into();
        assert!(value.validate().is_err());
        value.backend = backend().into();
        value
            .command_line
            .push_str(" oblivion.runtime-backend=other-platform");
        assert!(value.validate().is_err());
        value.command_line = loaded.command_line;
        value.runtime_id.make_ascii_uppercase();
        assert!(value.validate().is_err());
    }
    #[test]
    fn settings_are_private_bounded_regular_and_single_link() {
        let fixture = Fixture::new();
        let path = fixture.0.join("runtime.json");
        let value = settings(&fixture.0);
        write_settings(&fixture.0, &value).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Settings::read(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, fixture.0.join("another-link")).unwrap();
        assert!(Settings::read(&path).is_err());
        fs::remove_file(fixture.0.join("another-link")).unwrap();
        fs::write(&path, vec![b' '; 65537]).unwrap();
        assert!(Settings::read(&path).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(fixture.0.join("missing"), &path).unwrap();
        assert!(Settings::read(&path).is_err());
    }
    #[test]
    fn replacement_preserves_runtime_identity_storage_and_cid() {
        let fixture = Fixture::new();
        let mut value = settings(&fixture.0);
        write_settings(&fixture.0, &value).unwrap();
        let first = Settings::read(&fixture.0.join("runtime.json")).unwrap();
        value.kernel = fixture.0.join("next-kernel");
        value.initrd = fixture.0.join("next-initrd");
        value.disks[0].path = fixture.0.join("next.iso");
        write_settings(&fixture.0, &value).unwrap();
        let next = Settings::read(&fixture.0.join("runtime.json")).unwrap();
        assert_eq!(next.kernel, value.kernel);
        assert_eq!(next.runtime_id, first.runtime_id);
        assert_eq!(next.disks[1].path, first.disks[1].path);
        assert_eq!(next.guest_cid, first.guest_cid);
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
    #[test]
    fn election_lock_rejects_a_second_owner_and_hard_links() {
        let fixture = Fixture::new();
        let path = fixture.0.join("runtime.lock");
        let first = private_lock(&path).unwrap();
        assert!(try_lock(&first).unwrap());
        let next = private_lock(&path).unwrap();
        assert!(!try_lock(&next).unwrap());
        drop(first);
        assert!(try_lock(&next).unwrap());
        fs::hard_link(&path, fixture.0.join("another-lock")).unwrap();
        assert!(private_lock(&path).is_err());
    }
    #[test]
    fn recovery_refuses_any_live_listener_before_removing_stale_sockets() {
        let fixture = Fixture::new();
        let stale = fixture.0.join("stale.sock");
        drop(UnixListener::bind(&stale).unwrap());
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
        let active = fixture.0.join("active.sock");
        let listener = UnixListener::bind(&active).unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(recover_sockets(&[stale.clone(), active.clone()]).is_err());
        assert!(stale.exists());
        drop(listener);
        recover_sockets(&[stale.clone(), active.clone()]).unwrap();
        assert!(!stale.exists() && !active.exists());
        fs::write(&stale, b"not a socket").unwrap();
        assert!(recover_sockets(&[stale.clone()]).is_err());
        assert!(stale.exists());
    }
}
