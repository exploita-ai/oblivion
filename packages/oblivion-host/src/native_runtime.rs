//! Native runtime state contains public boot assets and an encrypted data disk.
#[cfg(target_os = "linux")]
#[path = "live_runtime.rs"]
mod live;
#[path = "native_identity.rs"]
mod identity;
#[path = "native_lifecycle.rs"]
mod lifecycle;
use crate::control::{self, Result};
use crate::desktop_bundle::{self, Binding, Bundle};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn directory() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live { return Ok(PathBuf::from("/run/oblivion-live/user/runtime")); }
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
    Live,
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
    if profile.version != 1 || profile.mode != "live-launcher" {
        return Err("invalid_installation_profile".into());
    }
    Ok(Mode::Live)
}

fn backend() -> &'static str {
    #[cfg(target_os = "macos")]
    return "apple-vz";
    #[cfg(target_os = "linux")]
    "qemu-kvm"
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Disk {
    path: PathBuf,
    read_only: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    version: u8,
    backend: String,
    bundle: Binding,
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
        self.bundle.validate()?;
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
    preflight_with(&helper()?)
}

fn preflight_with(helper: &Path) -> Result<()> {
    let capabilities = Command::new(helper).arg("capabilities").output()?;
    let value: serde_json::Value = serde_json::from_slice(&capabilities.stdout)?;
    #[cfg(target_os = "linux")]
    let value = if capabilities.status.success()
        && value["version"] == 1
        && value["backend"] == backend()
        && value["supported"] != true
        && helper == Path::new(desktop_bundle::PACKAGE_ROOT).join("bin/oblivion-vm")
        && crate::linux_access::prepare(value["reason"].as_str().unwrap_or_default())?
    {
        reprobe_capabilities(helper)?
    } else {
        value
    };
    if !capabilities.status.success()
        || value["version"] != 1
        || value["backend"] != backend()
        || value["supported"] != true
    {
        #[cfg(target_os = "linux")]
        if let Some(message) =
            crate::linux_access::diagnostic(value["reason"].as_str().unwrap_or_default())
        {
            return Err(message.into());
        }
        return Err(if backend() == "qemu-kvm" {
            match value["reason"].as_str() {
                Some("qemu_system_required") => "QEMU for this architecture is missing. Install qemu-system-x86 on amd64 or qemu-system-arm on arm64. The installer changes no system packages.",
                Some("qemu_nested_version_required") => "ARM64 nested virtualization requires QEMU 10.1 or newer. No VM was started; the installer changes no system packages.",
                Some("usable_kvm_required") => "No usable KVM access for this account. Have the administrator check hardware virtualization and /dev/kvm permissions; no VM was started.",
                Some("nested_virtualization_unavailable") => "KVM does not expose usable nested VMX/SVM or ARM EL2. This host is not ready for the desktop runtime; no software-emulation fallback is used.",
                Some("vhost_vsock_unavailable") => "The account lacks usable vhost-vsock access. Have the administrator check /dev/vhost-vsock and AF_VSOCK support; the installer changes no modules or permissions.",
                _ => "Linux runtime requires x86_64/arm64, usable nested KVM, vhost-vsock and QEMU. Run oblivion-vm capabilities.",
            }
        } else { "This Mac does not advertise the nested virtual machines required by Oblivion. Run oblivion-vm capabilities; hardware acceptance remains separate." }.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reprobe_capabilities(helper: &Path) -> Result<serde_json::Value> {
    use std::process::Stdio;

    let mut child = Command::new(helper)
        .arg("capabilities")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = (|| -> Result<_> {
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err("runtime_capability_reprobe_failed".into());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("runtime_capability_reprobe_timeout".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child
            .stdout
            .take()
            .ok_or("runtime_capability_reprobe_failed")?;
        if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err("runtime_capability_reprobe_failed".into());
        }
        let mut bytes = Vec::new();
        output.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err("runtime_capability_reprobe_failed".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn copy_boot(bundle: &Bundle, assets: &Path) -> Result<()> {
    for (source, target) in [
        (&bundle.runtime().image, "controller.iso"),
        (&bundle.runtime().kernel, "kernel"),
        (&bundle.runtime().initrd, "initrd"),
    ] {
        let expected = bundle.file(source)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(bundle.root.join(source))?;
        let target = assets.join(target);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&target)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if output.metadata()?.len() != expected.bytes
            || desktop_bundle::digest(&target)? != expected.sha256
        {
            return Err("desktop_bundle_changed_during_install".into());
        }
    }
    fs::File::open(assets)?.sync_all()?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootRecord {
    version: u8,
    runtime_id: String,
    bundle: Binding,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Uninstalled {
    version: u8,
    runtime_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AtomicIntent {
    version: u8,
    settings: Settings,
    entry: String,
    releases: BTreeSet<String>,
    disk_device: u64,
    disk_inode: u64,
    launcher_sha256: String,
    data_committed: bool,
}

fn atomic_intent(root: &Path) -> Result<Option<AtomicIntent>> {
    let Some(intent) = read_record::<AtomicIntent>(&root.join("atomic.json"))? else { return Ok(None) };
    intent.settings.validate()?;
    if intent.version != 1 || !hex(&intent.entry, 64) || !hex(&intent.launcher_sha256, 64)
        || !intent.releases.contains(&intent.entry) || intent.releases.len() > 256
        || intent.releases.iter().any(|id| !hex(id, 64))
    {
        return Err("invalid_atomic_intent".into());
    }
    Ok(Some(intent))
}

// If the final executable was unlinked before the receipt was cleared, the
// matching installer can finish by removing only verified empty directories.
fn finish_atomic_tail(root: &Path, desktop: &DesktopPaths, bundle: &str) -> Result<()> {
    let Some(intent) = atomic_intent(root)? else { return Ok(()) };
    if !intent.data_committed || bundle != intent.entry {
        return Err("Complete the pending Atomic removal before installing Oblivion".into());
    }
    let installation = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&installation)? { return Err("runtime_installation_busy".into()); }
    for path in [
        intent.settings.disks[1].path.clone(), root.join("runtime.json"), root.join("uninstalled.json"),
        root.join("vm.json"), desktop.prefix.join("installation.json"), desktop.entry.clone(),
    ] {
        if !matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
            return Err("Complete the pending Atomic removal before installing Oblivion".into());
        }
    }
    let releases = desktop.releases();
    private_directory(&releases)?;
    let release = releases.join(intent.entry);
    for entry in fs::read_dir(&releases)? {
        if entry?.path() != release {
            return Err("Complete the pending Atomic removal before installing Oblivion".into());
        }
    }
    if fs::symlink_metadata(&release).is_ok() {
        verify_release_directory(&release)?;
        let bin = release.join("bin");
        let manifest = release.join("bundle.json");
        let manifest = if fs::symlink_metadata(&manifest).is_ok() {
            Bundle::stored_for_removal(&release, bundle, desktop.platform)?;
            Some(Removal::file(manifest)?)
        } else { None };
        for entry in fs::read_dir(&release)? {
            let path = entry?.path();
            if path != bin && !manifest.as_ref().is_some_and(|manifest| manifest.path == path) {
                return Err("Complete the pending Atomic removal before installing Oblivion".into());
            }
        }
        if fs::symlink_metadata(&bin).is_ok() {
            verify_release_directory(&bin)?;
            fs::remove_dir(bin)?;
        }
        if let Some(manifest) = manifest { manifest.remove()?; }
        fs::remove_dir(release)?;
        fs::File::open(releases)?.sync_all()?;
    }
    Removal::file(root.join("atomic.json"))?.remove()?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

fn verify_release_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::getuid() } || metadata.mode() & 0o022 != 0 {
        return Err("unsafe_desktop_release_directory".into());
    }
    Ok(())
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
    {
        return Err("unsafe_runtime_record".into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("runtime_record_limit".into());
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn uninstalled(root: &Path, settings: &Settings) -> Result<bool> {
    let Some(record) = read_record::<Uninstalled>(&root.join("uninstalled.json"))? else {
        return Ok(false);
    };
    if record.version != 1 || record.runtime_id != settings.runtime_id {
        return Err("invalid_runtime_uninstall_record".into());
    }
    Ok(true)
}

fn clear_uninstalled(root: &Path, settings: &Settings) -> Result<()> {
    if uninstalled(root, settings)? {
        fs::remove_file(root.join("uninstalled.json"))?;
        fs::File::open(root)?.sync_all()?;
    }
    Ok(())
}

fn verify_boot(settings: &Settings) -> Result<()> {
    for (path, expected) in [&settings.disks[0].path, &settings.kernel, &settings.initrd]
        .into_iter()
        .zip(&settings.bundle.boot)
    {
        let info = fs::symlink_metadata(path)?;
        let live_asset = cfg!(target_os = "linux") && mode()? == Mode::Live && info.uid() == 0 && info.mode() & 0o022 == 0;
        if !info.is_file()
            || (!live_asset && (info.uid() != unsafe { libc::getuid() } || info.mode() & 0o077 != 0))
            || info.nlink() != 1
            || info.len() != expected.bytes
            || desktop_bundle::digest(path)? != expected.sha256
        {
            return Err("installed_runtime_integrity_failed".into());
        }
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
    let path = desktop_bundle::launcher_path()?
        .parent()
        .ok_or("executable_directory_missing")?
        .join("oblivion-vm");
    if !path.is_file() {
        return Err("Install the oblivion-vm helper beside oblivion".into());
    }
    Ok(path)
}

fn require_desktop() -> Result<()> {
    if mode()? == Mode::Live {
        return Err("The Live image manages its immutable runtime. Desktop installation commands are unavailable.".into());
    }
    #[cfg(target_os = "linux")]
    if desktop_bundle::packaged_entry()?
        && unsafe { libc::geteuid() == 0 || libc::geteuid() != libc::getuid() }
    {
        return Err("Run Oblivion as your regular user".into());
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    previous: Option<String>,
    settings: Settings,
}

fn pending(root: &Path) -> Result<Option<Pending>> {
    let path = root.join("update.pending.json");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
    {
        return Err("unsafe_runtime_update_journal".into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("runtime_update_journal_limit".into());
    }
    let value: Pending = serde_json::from_slice(&bytes)?;
    if value.version != 1 {
        return Err("invalid_runtime_update_journal".into());
    }
    value.settings.validate()?;
    Ok(Some(value))
}

fn commit_pending(root: &Path, bundle: &Bundle) -> Result<bool> {
    let Some(pending) = pending(root)? else {
        return Ok(false);
    };
    if serde_json::to_value(&pending.settings.bundle)? != serde_json::to_value(bundle.binding()?)? {
        return Err(
            "An interrupted update needs its matching desktop bundle; rerun that installer".into(),
        );
    }
    let current = installed_settings(root)?;
    if let Some(current) = &current {
        if current.bundle.bundle_id != pending.settings.bundle.bundle_id
            && Some(&current.bundle.bundle_id) != pending.previous.as_ref()
        {
            return Err("runtime_update_base_changed".into());
        }
        if current.runtime_id != pending.settings.runtime_id
            || current.disks[1].path != pending.settings.disks[1].path
            || current.control_socket != pending.settings.control_socket
            || current.guest_cid != pending.settings.guest_cid
        {
            return Err("runtime_update_identity_changed".into());
        }
    } else if pending.previous.is_some() {
        return Err("runtime_update_base_missing".into());
    }
    verify_boot(&pending.settings)?;
    write_settings(root, &pending.settings)?;
    // Publication of the desktop entry happens after this transaction. The
    // matching binary clears the journal on first launch; an interrupted
    // activation is resumed explicitly by rerunning its installer.
    Ok(true)
}

pub fn install(path: &Path) -> Result<()> {
    install_runtime(path, false, false)
}
pub fn update(path: &Path) -> Result<()> {
    install_runtime(path, true, false)
}
pub fn deploy(path: &Path) -> Result<()> {
    install_runtime(path, true, true)
}

fn install_runtime(path: &Path, updating: bool, deploy: bool) -> Result<()> {
    require_desktop()?;
    let bundle = Bundle::read(path)?;
    preflight_with(&bundle.root.join("bin/oblivion-vm"))?;
    let desktop = DesktopPaths::current()?;
    private_directory(&desktop.prefix)?;
    let installation = private_lock(&desktop.prefix.join("install.lock"))?;
    if !try_lock(&installation)? {
        return Err("desktop_installation_busy".into());
    }
    let root = directory()?;
    finish_atomic_tail(&root, &desktop, bundle.id())?;
    let desktop = if deploy
        && std::env::var_os("OBLIVION_RUNTIME_DIRECTORY").is_some()
        && desktop.can_ignore_entry_for_deploy(&root)?
    {
        DesktopPaths { manage_entry: false, ..desktop }
    } else {
        desktop
    };
    reserve_desktop(&root, &desktop)?;
    change_bundle(&root, &socket_directory()?, &bundle, updating, deploy)?;
    bind_desktop(&root, &desktop)?;
    if collect_locked(&root, &desktop, false).is_err() {
        eprintln!(
            "Installation completed; old software cleanup remains pending. Stop the runtime and run oblivion runtime gc."
        );
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimeBusy;

impl std::fmt::Display for RuntimeBusy {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Stop the protected runtime before updating its bundle")
    }
}

impl std::error::Error for RuntimeBusy {}

fn installed_settings(root: &Path) -> Result<Option<Settings>> {
    let path = root.join("runtime.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => Settings::read(&path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn stopped_locks(socket: &Path) -> Result<Option<(fs::File, fs::File)>> {
    let startup = private_lock(&sidecar(socket, ".startup.lock"))?;
    let running = private_lock(&sidecar(socket, ".lock"))?;
    if !try_lock(&startup)? || !try_lock(&running)? {
        return Ok(None);
    }
    Ok(Some((startup, running)))
}

fn change_bundle(
    root: &Path,
    sockets: &Path,
    bundle: &Bundle,
    updating: bool,
    deploy: bool,
) -> Result<()> {
    private_directory(root)?;
    let election = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&election)? {
        return Err("runtime_installation_busy".into());
    }
    let config = root.join("runtime.json");
    if atomic_intent(root)?.is_some() {
        return Err("Complete the pending Atomic removal before installing Oblivion".into());
    }
    let previous = installed_settings(root)?;
    let transaction = pending(root)?;
    if previous.is_some() && !updating {
        return Err("Runtime is already installed; use runtime update BUNDLE".into());
    }
    if previous.is_none() && updating && !deploy && transaction.is_none() {
        return Err("Runtime is not installed".into());
    }
    if previous.is_none() && fs::symlink_metadata(root.join("uninstalled.json")).is_ok() {
        return Err(
            "Preserved runtime metadata is missing; inspect the retained data before installing"
                .into(),
        );
    }
    let socket = previous
        .as_ref()
        .map(|value| value.control_socket.clone())
        .or_else(|| transaction.map(|value| value.settings.control_socket));
    let socket = match socket {
        Some(socket) => socket,
        None => {
            let default = sockets.join("runtime.sock");
            if sidecar(&default, ".startup.lock").try_exists()? {
                // A retired installation may still have callers holding its old paths.
                sockets.join(format!("runtime-{}.sock", &random_id()?[..12]))
            } else {
                default
            }
        }
    };
    private_directory(socket.parent().ok_or("invalid_runtime_socket")?)?;
    let _stopped = stopped_locks(&socket)?.ok_or(RuntimeBusy)?;
    if commit_pending(root, bundle)? {
        if let Some(current) = previous.as_ref() {
            clear_uninstalled(&root, current)?;
        }
        return Ok(());
    }
    if previous
        .as_ref()
        .is_some_and(|current| current.bundle.bundle_id == bundle.id())
        && !uninstalled(
            &root,
            previous.as_ref().ok_or("runtime_configuration_missing")?,
        )?
    {
        verify_boot(previous.as_ref().ok_or("runtime_configuration_missing")?)?;
        return Ok(());
    }
    let runtime_id = match &previous {
        Some(current) => current.runtime_id.clone(),
        None => random_id()?,
    };
    let assets = root.join(format!("boot-{}", random_id()?));
    fs::DirBuilder::new().mode(0o700).create(&assets)?;
    let result = (|| -> Result<()> {
        copy_boot(bundle, &assets)?;
        write_record(
            &assets,
            "boot.json",
            &BootRecord {
                version: 1,
                runtime_id: runtime_id.clone(),
                bundle: bundle.binding()?,
            },
        )?;
        let mut settings = if let Some(current) = &previous {
            current.clone()
        } else {
            let disk = assets.join("storage.raw");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&disk)?;
            file.set_len(16 * 1024 * 1024 * 1024)?;
            file.write_all(format!("OBLIVION-RUNTIME-1\n{runtime_id}\n").as_bytes())?;
            file.sync_all()?;
            Settings {
                version: 1,
                backend: backend().into(),
                bundle: bundle.binding()?,
                command_line: format!(
                    "boot=live components console=hvc0 quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend={} oblivion.runtime-id={runtime_id}",
                    backend()
                ),
                runtime_id,
                kernel: assets.join("kernel"),
                initrd: assets.join("initrd"),
                disks: [
                    Disk {
                        path: assets.join("controller.iso"),
                        read_only: true,
                    },
                    Disk {
                        path: disk,
                        read_only: false,
                    },
                ],
                cpu_count: 4,
                memory_mi_b: 6144,
                control_socket: socket,
                control_port: 4050,
                guest_cid: guest_cid()?,
                network: true,
                serial_stdio: false,
            }
        };
        settings.kernel = assets.join("kernel");
        settings.initrd = assets.join("initrd");
        settings.disks[0].path = assets.join("controller.iso");
        settings.bundle = bundle.binding()?;
        settings.validate()?;
        let pending = Pending {
            version: 1,
            previous: previous
                .as_ref()
                .map(|current| current.bundle.bundle_id.clone()),
            settings,
        };
        write_record(&root, "update.pending.json", &pending)?;
        commit_pending(root, bundle)?;
        clear_uninstalled(&root, &pending.settings)?;
        Ok(())
    })();
    if result.is_err()
        && pending(&root)?.is_none()
        && !Settings::read(&config).is_ok_and(|current| current.kernel == assets.join("kernel"))
    {
        let _ = fs::remove_dir_all(assets);
    }
    result
}

struct DesktopPaths {
    prefix: PathBuf,
    entry: PathBuf,
    manage_entry: bool,
    platform: &'static str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DesktopOwner {
    version: u8,
    runtime_directory: PathBuf,
    identity: DesktopIdentity,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum DesktopIdentity {
    Preparing,
    Installed { runtime_id: String },
}

fn desktop_owner(
    root: &Path,
    desktop: &DesktopPaths,
    settings: Option<&Settings>,
    preparing: bool,
) -> Result<bool> {
    let Some(owner) = read_record::<DesktopOwner>(&desktop.prefix.join("installation.json"))?
    else {
        return Ok(false);
    };
    if owner.version != 1 || !owner.runtime_directory.is_absolute() {
        return Err("invalid_desktop_installation_record".into());
    }
    let identity_matches = match owner.identity {
        DesktopIdentity::Preparing => preparing,
        DesktopIdentity::Installed { runtime_id } => {
            hex(&runtime_id, 32)
                && settings.is_some_and(|settings| settings.runtime_id == runtime_id)
        }
    };
    if owner.runtime_directory != root.canonicalize()? || !identity_matches {
        return Err("This desktop software belongs to another runtime or its retained metadata is missing; no files were removed. Use a separate desktop installation prefix.".into());
    }
    Ok(true)
}

fn bind_desktop(root: &Path, desktop: &DesktopPaths) -> Result<()> {
    let installation = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&installation)? {
        return Err("runtime_installation_busy".into());
    }
    let settings = Settings::read(&root.join("runtime.json"))?;
    desktop_owner(root, desktop, Some(&settings), true)?;
    write_record(
        &desktop.prefix,
        "installation.json",
        &DesktopOwner {
            version: 1,
            runtime_directory: root.canonicalize()?,
            identity: DesktopIdentity::Installed {
                runtime_id: settings.runtime_id,
            },
        },
    )?;
    Ok(())
}

fn reserve_desktop(root: &Path, desktop: &DesktopPaths) -> Result<()> {
    private_directory(root)?;
    private_directory(&desktop.releases())?;
    let previous = installed_settings(root)?;
    if desktop_owner(root, desktop, previous.as_ref(), true)? {
        return Ok(());
    }
    if fs::read_dir(desktop.releases())?.next().is_some() || desktop.entry_release()?.is_some() {
        return Err("Desktop releases have no current installation ownership record; inspect them before installing".into());
    }
    // Reserve this prefix before copying a release. Failed first installs can
    // resume only against this exact runtime directory.
    write_record(
        &desktop.prefix,
        "installation.json",
        &DesktopOwner {
            version: 1,
            runtime_directory: root.canonicalize()?,
            identity: match previous {
                Some(settings) => DesktopIdentity::Installed {
                    runtime_id: settings.runtime_id,
                },
                None => DesktopIdentity::Preparing,
            },
        },
    )
}

impl DesktopPaths {
    fn current() -> Result<Self> {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or("home_unavailable")?);
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        Ok(Self {
            prefix: data.join("oblivion-desktop"),
            entry: home.join(".local/bin/oblivion"),
            manage_entry: !desktop_bundle::packaged_entry()?,
            platform: desktop_bundle::platform(),
        })
    }

    fn releases(&self) -> PathBuf {
        self.prefix.join("releases")
    }

    fn can_ignore_entry_for_deploy(&self, root: &Path) -> Result<bool> {
        if !self.manage_entry {
            return Ok(false);
        }
        let releases = self.prefix.canonicalize()?.join("releases");
        // A boot-only deploy has no authority over another prefix's command.
        // Keep command protection when its target could resolve into this prefix.
        if !fs::read_link(&self.entry).is_ok_and(|target| {
            target.is_absolute()
                && !target.starts_with(self.releases())
                && target.canonicalize().is_ok_and(|target| !target.starts_with(releases))
        }) {
            return Ok(false);
        }
        let previous = installed_settings(root)?;
        Ok(previous.is_none() || desktop_owner(root, self, previous.as_ref(), true)?)
    }

    fn lock_installation(&self) -> Result<fs::File> {
        private_directory(&self.prefix)?;
        let lock = private_lock(&self.prefix.join("install.lock"))?;
        if !try_lock(&lock)? {
            return Err("desktop_installation_busy".into());
        }
        Ok(lock)
    }

    fn entry_release(&self) -> Result<Option<String>> {
        if !self.manage_entry {
            return Ok(None);
        }
        let info = match fs::symlink_metadata(&self.entry) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !info.file_type().is_symlink() || info.uid() != unsafe { libc::getuid() } {
            return Err("desktop_command_not_owned_by_installer".into());
        }
        let target = fs::read_link(&self.entry)?;
        let relative = target
            .strip_prefix(self.releases())
            .map_err(|_| "desktop_command_not_owned_by_installer")?;
        let parts: Vec<_> = relative.components().collect();
        let Some(identity) = parts.first().and_then(|part| part.as_os_str().to_str()) else {
            return Err("desktop_command_not_owned_by_installer".into());
        };
        if !hex(identity, 64)
            || parts.len() != 3
            || parts[1].as_os_str() != "bin"
            || parts[2].as_os_str() != "oblivion"
        {
            return Err("desktop_command_not_owned_by_installer".into());
        }
        Ok(Some(identity.to_owned()))
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct Removal {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Removal {
    fn file(path: PathBuf) -> Result<Self> {
        let info = fs::symlink_metadata(&path)?;
        if !info.is_file()
            || info.uid() != unsafe { libc::getuid() }
            || info.mode() & 0o022 != 0
            || info.nlink() != 1
        {
            return Err("unsafe_desktop_cleanup_file".into());
        }
        Ok(Self {
            path,
            device: info.dev(),
            inode: info.ino(),
        })
    }

    fn remove(&self) -> Result<()> {
        let info = fs::symlink_metadata(&self.path)?;
        if !info.is_file()
            || info.dev() != self.device
            || info.ino() != self.inode
            || info.nlink() != 1
        {
            return Err("desktop_cleanup_file_changed".into());
        }
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

#[derive(Default)]
struct Cleanup {
    files: Vec<Removal>,
    directories: BTreeSet<PathBuf>,
    releases: usize,
    release_ids: BTreeSet<String>,
    boot_files: usize,
    retained: usize,
}

impl Cleanup {
    fn remove(self) -> Result<()> {
        let mut changed = BTreeSet::new();
        for file in self.files {
            changed.insert(
                file.path
                    .parent()
                    .ok_or("invalid_cleanup_directory")?
                    .to_owned(),
            );
            file.remove()?;
        }
        for directory in changed {
            fs::File::open(directory)?.sync_all()?;
        }
        let mut directories: Vec<_> = self.directories.into_iter().collect();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            // Only individually reviewed files are removed. An unexpected file
            // appearing during collection makes rmdir fail; it is never erased.
            fs::remove_dir(&directory)?;
            fs::File::open(directory.parent().ok_or("invalid_cleanup_directory")?)?.sync_all()?;
        }
        Ok(())
    }
}

fn boot_directory(root: &Path, path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or("invalid_runtime_asset_path")?;
    let name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid_runtime_asset_path")?;
    if parent.parent() != Some(root)
        || !name.strip_prefix("boot-").is_some_and(|name| hex(name, 32))
    {
        return Err("runtime_asset_outside_managed_directory".into());
    }
    Ok(parent.to_owned())
}

fn cleanup_plan(
    root: &Path,
    desktop: &DesktopPaths,
    settings: &Settings,
    uninstall: bool,
    approved: Option<&BTreeSet<String>>,
) -> Result<Cleanup> {
    let active = boot_directory(root, &settings.kernel)?;
    if settings.kernel != active.join("kernel")
        || settings.initrd != active.join("initrd")
        || settings.disks[0].path != active.join("controller.iso")
    {
        return Err("runtime_asset_layout_changed".into());
    }
    let data = boot_directory(root, &settings.disks[1].path)?;
    if settings.disks[1].path != data.join("storage.raw") {
        return Err("runtime_storage_identity_changed".into());
    }
    // This file is retained even when its original boot assets are obsolete.
    if approved.is_none() {
        Removal::file(settings.disks[1].path.clone())?;
    }
    let mut protected_releases = BTreeSet::new();
    let mut protected_boot = BTreeSet::new();
    if !uninstall {
        protected_releases.insert(settings.bundle.bundle_id.clone());
        protected_boot.insert(active);
        if let Some(identity) = desktop.entry_release()? {
            protected_releases.insert(identity);
        }
        if let Ok(executable) = desktop_bundle::launcher_path() {
            if let Some(release) = executable.parent().and_then(Path::parent) {
                if release.parent() == Some(desktop.releases().as_path()) {
                    if let Some(identity) = release.file_name().and_then(|name| name.to_str()) {
                        protected_releases.insert(identity.to_owned());
                    }
                }
            }
        }
        if let Some(transaction) = pending(root)? {
            protected_releases.insert(transaction.settings.bundle.bundle_id);
            if let Some(previous) = transaction.previous {
                protected_releases.insert(previous);
            }
            protected_boot.insert(boot_directory(root, &transaction.settings.kernel)?);
        }
    }
    let mut plan = Cleanup::default();
    if desktop.releases().try_exists()? {
        private_directory(&desktop.releases())?;
        for (index, entry) in fs::read_dir(desktop.releases())?.enumerate() {
            if index >= 256 {
                return Err("desktop_cleanup_inventory_limit".into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(identity) = name.to_str().filter(|name| hex(name, 64)) else {
                continue;
            };
            if protected_releases.contains(identity) {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                plan.retained += 1;
                continue;
            }
            if approved.is_some_and(|approved| !approved.contains(identity)) {
                plan.retained += 1;
                continue;
            }
            if approved.is_some() && fs::read_dir(entry.path())?.next().is_none() {
                verify_release_directory(&entry.path())?;
                plan.directories.insert(entry.path());
                plan.releases += 1;
                plan.release_ids.insert(identity.to_owned());
                continue;
            }
            let bundle = match if approved.is_some() {
                Bundle::stored_for_removal(&entry.path(), identity, desktop.platform)
            } else {
                Bundle::stored(&entry.path(), identity, desktop.platform)
            } {
                Ok(bundle) => bundle,
                _ => {
                    plan.retained += 1;
                    continue;
                }
            };
            for file in bundle.files() {
                let path = bundle.root.join(&file.path);
                let mut parent = path.parent();
                while let Some(directory) = parent.filter(|path| path.starts_with(&bundle.root)) {
                    if directory.try_exists()? {
                        plan.directories.insert(directory.to_owned());
                    }
                    parent = directory.parent();
                }
                if approved.is_none() || path.try_exists()? {
                    plan.files.push(Removal::file(path)?);
                }
            }
            plan.files
                .push(Removal::file(bundle.root.join("bundle.json"))?);
            plan.releases += 1;
            plan.release_ids.insert(identity.to_owned());
        }
    }
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        if index >= 256 {
            return Err("desktop_cleanup_inventory_limit".into());
        }
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if !name
            .to_str()
            .and_then(|name| name.strip_prefix("boot-"))
            .is_some_and(|name| hex(name, 32))
            || protected_boot.contains(&path)
        {
            continue;
        }
        let reviewed = (|| -> Result<Option<(Vec<Removal>, bool)>> {
            private_directory(&path)?;
            let Some(record) = read_record::<BootRecord>(&path.join("boot.json"))? else {
                return Ok(None);
            };
            record.bundle.validate()?;
            if record.version != 1 || record.runtime_id != settings.runtime_id {
                return Err("invalid_boot_cleanup_record".into());
            }
            for (index, child) in fs::read_dir(&path)?.enumerate() {
                if index >= 5 {
                    return Err("boot_cleanup_inventory_limit".into());
                }
                let child = child?;
                let name = child.file_name();
                if !["boot.json", "controller.iso", "kernel", "initrd"]
                    .iter()
                    .any(|expected| name == *expected)
                    && child.path() != settings.disks[1].path
                {
                    return Err("unlisted_boot_cleanup_file".into());
                }
            }
            let mut files = Vec::new();
            for (name, expected) in ["controller.iso", "kernel", "initrd"]
                .iter()
                .zip(record.bundle.boot)
            {
                let file = path.join(name);
                match fs::symlink_metadata(&file) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                    Ok(info) if info.len() == expected.bytes => (),
                    Ok(_) => return Err("installed_runtime_integrity_failed".into()),
                }
                let removal = Removal::file(file.clone())?;
                if desktop_bundle::digest(&file)? != expected.sha256 {
                    return Err("installed_runtime_integrity_failed".into());
                }
                files.push(removal);
            }
            Ok(Some((files, path == data)))
        })();
        match reviewed {
            Ok(Some((files, keeps_data))) => {
                plan.boot_files += files.len();
                plan.files.extend(files);
                if !keeps_data {
                    plan.files.push(Removal::file(path.join("boot.json"))?);
                    plan.directories.insert(path);
                }
            }
            _ => plan.retained += 1,
        }
    }
    Ok(plan)
}

fn collect_locked(root: &Path, desktop: &DesktopPaths, uninstall: bool) -> Result<()> {
    private_directory(root)?;
    let installation = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&installation)? {
        return Err("runtime_installation_busy".into());
    }
    if atomic_intent(root)?.is_some() {
        return Err("Complete the pending Atomic removal first".into());
    }
    let settings = Settings::read(&root.join("runtime.json"))?;
    if !desktop_owner(root, desktop, Some(&settings), false)? {
        return Err("No current desktop installation record; use the matching development bundle installer before removing software".into());
    }
    private_directory(
        settings
            .control_socket
            .parent()
            .ok_or("invalid_runtime_socket")?,
    )?;
    let startup = private_lock(&sidecar(&settings.control_socket, ".startup.lock"))?;
    let running = private_lock(&sidecar(&settings.control_socket, ".lock"))?;
    if !try_lock(&startup)? || !try_lock(&running)? {
        return Err("Stop the protected runtime before removing desktop software".into());
    }
    if uninstall && pending(root)?.is_some() {
        return Err("Complete the matching bundle installation before uninstalling; the update journal was preserved".into());
    }
    let entry = desktop.entry_release()?;
    let plan = cleanup_plan(root, desktop, &settings, uninstall, None)?;
    if uninstall {
        if entry
            .as_ref()
            .is_some_and(|identity| !plan.release_ids.contains(identity))
        {
            return Err(
                "The installed command release could not be verified; no software was removed"
                    .into(),
            );
        }
        write_record(
            root,
            "uninstalled.json",
            &Uninstalled {
                version: 1,
                runtime_id: settings.runtime_id,
            },
        )?;
        if entry.is_some() {
            // Recheck the symlink immediately before unlinking the managed entry.
            if desktop.entry_release()? != entry {
                return Err("desktop_command_changed".into());
            }
            fs::remove_file(&desktop.entry)?;
            fs::File::open(desktop.entry.parent().ok_or("invalid_desktop_command")?)?.sync_all()?;
        }
    }
    let (releases, boot_files, retained) = (plan.releases, plan.boot_files, plan.retained);
    plan.remove()?;
    fs::File::open(root)?.sync_all()?;
    eprintln!(
        "Removed {releases} verified desktop releases and {boot_files} boot files; retained {retained} unverified entries. Encrypted data was preserved."
    );
    Ok(())
}

fn collect(uninstall: bool) -> Result<()> {
    require_desktop()?;
    let desktop = DesktopPaths::current()?;
    let root = directory()?;
    if !desktop.manage_entry && installed_settings(&root)?.is_none() {
        return Err("runtime_not_installed".into());
    }
    let _installation = desktop.lock_installation()?;
    collect_locked(&root, &desktop, uninstall)
}

/// Stop the runtime first. This removes verified software, never Safe data.
pub fn uninstall() -> Result<()> {
    collect(true)
}

/// Destroy only a verified standalone desktop installation, after review on
/// the controlling terminal. Runtime and installation locks span the review.
pub fn atomic() -> Result<()> {
    require_desktop()?;
    let desktop = DesktopPaths::current()?;
    if !desktop.manage_entry || std::env::var_os("OBLIVION_RUNTIME_DIRECTORY").is_some() {
        return Err("Atomic removal requires the standalone desktop installation".into());
    }
    #[cfg(target_os = "linux")]
    if Path::new(desktop_bundle::PACKAGE_ROOT).join("bin/oblivion").try_exists()? {
        return Err("Atomic removal is unavailable on hosts with the Debian package installed".into());
    }
    let root = directory()?.canonicalize()?;
    let _desktop_lock = desktop.lock_installation()?;
    let launcher = desktop_bundle::launcher_path()?;
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")
        .map_err(|_| "Atomic removal requires an interactive terminal")?;
    atomic_locked(&root, &desktop, &socket_directory()?, &launcher, |disk, releases, retained| {
        writeln!(tty, "Permanently remove this Oblivion installation?")?;
        writeln!(tty, "Encrypted Safes and settings: {disk:?}")?;
        writeln!(tty, "Desktop software: {} ({releases} verified releases)", desktop.prefix.display())?;
        writeln!(tty, "Local launcher: {}", desktop.entry.display())?;
        writeln!(tty, "Runtime files: {}", root.display())?;
        if retained != 0 {
            writeln!(tty, "Unverified runtime entries kept: {retained}")?;
        }
        write!(tty, "Type ATOMIC to delete, or press Enter to cancel: ")?;
        tty.flush()?;
        let mut answer = Vec::new();
        BufReader::new(&mut tty).take(64).read_until(b'\n', &mut answer)?;
        Ok(matches!(answer.as_slice(), b"ATOMIC\n" | b"ATOMIC\r\n"))
    })
}

fn atomic_locked(
    root: &Path,
    desktop: &DesktopPaths,
    socket_root: &Path,
    launcher: &Path,
    confirm: impl FnOnce(&Path, usize, usize) -> Result<bool>,
) -> Result<()> {
    let installation = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&installation)? {
        return Err("runtime_installation_busy".into());
    }
    let config = root.join("runtime.json");
    let prior = atomic_intent(root)?;
    let current = installed_settings(root)?;
    let settings = current.as_ref().or_else(|| prior.as_ref().map(|intent| &intent.settings))
        .ok_or("No complete verified desktop installation is available for removal")?;
    let owned = desktop_owner(root, desktop, Some(settings), false)?;
    if (!owned && prior.is_none()) || pending(root)?.is_some() {
        return Err("No complete verified desktop installation is available for removal".into());
    }
    if let Some(intent) = &prior {
        if serde_json::to_value(settings)? != serde_json::to_value(&intent.settings)? {
            return Err("atomic_installation_changed".into());
        }
    }
    if settings.control_socket.parent() != Some(socket_root) {
        return Err("invalid_runtime_socket".into());
    }
    private_directory(socket_root)?;
    let _stopped = stopped_locks(&settings.control_socket)?
        .ok_or("Stop the protected runtime before Atomic removal")?;
    let lifecycle = lifecycle::AtomicCleanup::prepare(settings)?;
    let mut sockets = vec![settings.control_socket.clone()];
    if backend() == "qemu-kvm" {
        sockets.extend([".qmp", ".auth", ".media"].map(|suffix| sidecar(&settings.control_socket, suffix)));
    }
    let endpoints = disconnected_sockets(&sockets)?;

    let entry = desktop.entry_release()?;
    let release = prior.as_ref().map(|intent| &intent.entry).or(entry.as_ref())
        .ok_or("No installed Oblivion command was found")?;
    let release_path = desktop.releases().join(release);
    let installed = release_path.join("bin/oblivion");
    if entry.as_ref().is_some_and(|entry| entry != release) || launcher != installed.canonicalize()? {
        return Err("Run Atomic removal from the installed Oblivion command".into());
    }
    let installed = Removal::file(installed)?;
    let launcher_sha256 = desktop_bundle::digest(&installed.path)?;
    if prior.as_ref().is_some_and(|intent| intent.launcher_sha256 != launcher_sha256) {
        return Err("desktop_command_changed".into());
    }
    let mut plan = cleanup_plan(root, desktop, settings, true, prior.as_ref().map(|intent| &intent.releases))?;
    if !plan.release_ids.contains(release) || fs::read_dir(desktop.releases())?.count() != plan.releases {
        return Err("Unverified desktop release files must be reviewed before Atomic removal".into());
    }
    // Keep release manifests until their files and directories are gone. This
    // lets a resumed removal authenticate every remaining listed file.
    let mut manifests = Vec::new();
    plan.files.retain(|file| file.path != installed.path);
    let mut index = 0;
    while index < plan.files.len() {
        let file = &plan.files[index];
        if file.path.file_name().is_some_and(|name| name == "bundle.json")
            && file.path.parent().is_some_and(|parent| parent.parent() == Some(desktop.releases().as_path()))
        {
            let parent = file.path.parent().expect("verified manifest parent");
            plan.directories.remove(parent);
            manifests.push(plan.files.swap_remove(index));
        } else {
            index += 1;
        }
    }
    plan.directories.remove(&release_path);
    plan.directories.remove(&release_path.join("bin"));

    let disk_path = &settings.disks[1].path;
    let data = boot_directory(root, disk_path)?;
    match fs::symlink_metadata(&data) {
        Ok(_) => private_directory(&data)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && prior.is_some() => {}
        Err(error) => return Err(error.into()),
    }
    let boot = data.join("boot.json");
    let disk = if !matches!(fs::symlink_metadata(disk_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
        if prior.as_ref().is_some_and(|intent| intent.data_committed) {
            return Err("runtime_storage_identity_changed".into());
        }
        let record = read_record::<BootRecord>(&boot)?.ok_or("runtime_storage_identity_changed")?;
        record.bundle.validate()?;
        if record.version != 1 || record.runtime_id != settings.runtime_id {
            return Err("runtime_storage_identity_changed".into());
        }
        let disk = atomic_disk(disk_path, &settings.runtime_id)?;
        if prior.as_ref().is_some_and(|intent| disk.device != intent.disk_device || disk.inode != intent.disk_inode) {
            return Err("runtime_storage_identity_changed".into());
        }
        Some(disk)
    } else if prior.is_some() {
        None
    } else {
        return Err("runtime_storage_identity_changed".into());
    };
    let configuration = current.is_some().then(|| Removal::file(config)).transpose()?;
    let owner = owned.then(|| Removal::file(desktop.prefix.join("installation.json"))).transpose()?;
    let projection = root.join("vm.json");
    let vm = read_record::<serde_json::Value>(&projection)?.map(|value| {
        if value["runtime_id"].as_str() != Some(&settings.runtime_id)
            || value["backend"].as_str() != Some(&settings.backend)
        {
            return Err("runtime_configuration_identity_changed".into());
        }
        Removal::file(projection)
    }).transpose()?;
    // Existing collection keeps the data directory even when its boot assets
    // are obsolete. Remove its record only when all its other entries were reviewed.
    let data_record = if boot.try_exists()? && fs::read_dir(&data)?.count()
        == plan.files.iter().filter(|file| file.path.parent() == Some(&data)).count() + 1 + usize::from(disk.is_some())
    {
        let record = read_record::<BootRecord>(&boot)?.ok_or("runtime_storage_identity_changed")?;
        if record.version != 1 || record.runtime_id != settings.runtime_id { return Err("runtime_storage_identity_changed".into()); }
        record.bundle.validate()?;
        Some(Removal::file(boot)?)
    } else { None };
    uninstalled(root, settings)?;
    if !confirm(disk_path, plan.releases, plan.retained + lifecycle.retained())? {
        eprintln!("Atomic removal cancelled.");
        return Ok(());
    }
    if desktop.entry_release()? != entry {
        return Err("desktop_command_changed".into());
    }
    let mut intent = if let Some(intent) = &prior {
        intent.clone()
    } else {
        let disk = disk.as_ref().ok_or("runtime_storage_identity_changed")?;
        let intent = AtomicIntent {
            version: 1,
            settings: settings.clone(),
            entry: release.clone(),
            releases: plan.release_ids.clone(),
            disk_device: disk.device,
            disk_inode: disk.inode,
            launcher_sha256,
            data_committed: false,
        };
        write_record(root, "atomic.json", &intent)?;
        intent
    };
    let result = (|| -> Result<()> {
        remove_disconnected_sockets(endpoints)?;
        lifecycle.remove()?;
        if let Some(vm) = vm { vm.remove()?; }
        plan.remove()?;
        let mut current_manifest = None;
        for manifest in manifests {
            if manifest.path.parent() == Some(&release_path) {
                current_manifest = Some(manifest);
                continue;
            }
            manifest.remove()?;
            fs::remove_dir(manifest.path.parent().ok_or("invalid_cleanup_directory")?)?;
        }
        // The launcher and intent remain available if any software cleanup
        // fails. Commit irreversible data removal only after it succeeds.
        if let Some(disk) = disk {
            disk.remove()?;
            fs::File::open(&data)?.sync_all()?;
        }
        if !intent.data_committed {
            intent.data_committed = true;
            write_record(root, "atomic.json", &intent)?;
        }
        if let Some(record) = data_record {
            record.remove()?;
            fs::remove_dir(&data)?;
        }
        if let Some(configuration) = configuration { configuration.remove()?; }
        clear_uninstalled(root, settings)?;
        if let Some(owner) = owner { owner.remove()?; }
        fs::File::open(&desktop.prefix)?.sync_all()?;
        fs::File::open(root)?.sync_all()?;
        if entry.is_some() {
            if desktop.entry_release()? != entry { return Err("desktop_command_changed".into()); }
            fs::remove_file(&desktop.entry)?;
            fs::File::open(desktop.entry.parent().ok_or("invalid_cleanup_directory")?)?.sync_all()?;
        }
        installed.remove()?;
        if let Some(manifest) = current_manifest { manifest.remove()?; }
        fs::remove_dir(release_path.join("bin"))?;
        fs::remove_dir(&release_path)?;
        fs::File::open(desktop.releases())?.sync_all()?;
        fs::remove_file(root.join("atomic.json"))?;
        fs::File::open(root)?.sync_all()?;
        Ok(())
    })();
    result.map_err(|error| format!("Atomic removal incomplete ({error}). If the launcher remains, retry {:?} runtime atomic.", installed.path))?;
    eprintln!("Oblivion removed. Private coordination lock files and parent directories were kept.");
    Ok(())
}

fn atomic_disk(path: &Path, runtime_id: &str) -> Result<Removal> {
    let removal = Removal::file(path.to_owned())?;
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let info = file.metadata()?;
    if info.dev() != removal.device || info.ino() != removal.inode || info.mode() & 0o077 != 0 {
        return Err("runtime_storage_identity_changed".into());
    }
    let mut header = [0; 4096];
    file.read_exact(&mut header)?;
    let marker = format!("OBLIVION-RUNTIME-1\n{runtime_id}\n");
    let initial = header.strip_prefix(marker.as_bytes()).is_some_and(|tail| tail.iter().all(|byte| *byte == 0));
    // The controller replaces the initialization marker with an ext4 volume
    // whose label and UUID are bound to the same runtime identity.
    let initialized = header[1080..1082] == [0x53, 0xef]
        && &header[1144..1160] == b"OBLIVION-RUNTIME"
        && header[1128..1144].iter().map(|byte| format!("{byte:02x}")).collect::<String>() == runtime_id;
    if !initial && !initialized {
        return Err("runtime_storage_identity_changed".into());
    }
    Ok(removal)
}

pub fn gc() -> Result<()> {
    collect(false)
}

/// Install a development bundle for this account. App release publication and
/// boot activation are retryable; the encrypted persistence file is never copied
/// into a release, replaced, or removed by this operation.
pub fn install_bundle(path: &Path) -> Result<()> {
    require_desktop()?;
    let bundle = Bundle::read(path)?;
    preflight_with(&bundle.root.join("bin/oblivion-vm"))?;
    let desktop = DesktopPaths::current()?;
    let _installation = desktop.lock_installation()?;
    publish_bundle(&directory()?, &socket_directory()?, &desktop, &bundle)?;
    if desktop.manage_entry {
        eprintln!(
            "Development bundle installed. Run ~/.local/bin/oblivion; add ~/.local/bin to PATH if needed."
        );
    }
    Ok(())
}

fn publish_bundle(
    root: &Path,
    sockets: &Path,
    desktop: &DesktopPaths,
    bundle: &Bundle,
) -> Result<PathBuf> {
    finish_atomic_tail(root, desktop, bundle.id())?;
    reserve_desktop(root, desktop)?;
    let command_directory = if desktop.manage_entry {
        let directory = desktop.entry.parent().ok_or("invalid_desktop_command")?;
        if !directory.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(directory)?;
        }
        let info = fs::symlink_metadata(directory)?;
        if !info.is_dir() || info.uid() != unsafe { libc::getuid() } || info.mode() & 0o022 != 0 {
            return Err("unsafe_desktop_command_directory".into());
        }
        desktop.entry_release()?;
        Some(directory)
    } else {
        None
    };
    let installed = publish_release(desktop, bundle)?;
    activate_bundle(root, sockets, desktop, &installed, command_directory)
}

fn activate_bundle(
    root: &Path,
    sockets: &Path,
    desktop: &DesktopPaths,
    installed: &Bundle,
    command_directory: Option<&Path>,
) -> Result<PathBuf> {
    let launcher = installed.root.join("bin/oblivion");
    change_bundle(root, sockets, installed, true, true)?;
    bind_desktop(root, desktop)?;
    if let Some(directory) = command_directory {
        let temporary = directory.join(format!("oblivion-pending-{}", random_id()?));
        std::os::unix::fs::symlink(&launcher, &temporary)?;
        if let Err(error) = fs::rename(&temporary, &desktop.entry) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        fs::File::open(directory)?.sync_all()?;
    }
    finish_activation(root, installed)?;
    if collect_locked(root, desktop, false).is_err() {
        eprintln!(
            "Installation completed; old software cleanup remains pending. Stop the runtime and run oblivion runtime gc."
        );
    }
    Ok(launcher)
}

#[cfg(any(target_os = "linux", test))]
fn resume_packaged(root: &Path, sockets: &Path, desktop: &DesktopPaths) -> Result<Option<PathBuf>> {
    let Some(transaction) = pending(root)? else {
        return Ok(None);
    };
    let current = installed_settings(root)?;
    if !desktop_owner(root, desktop, current.as_ref(), true)? {
        return Err("The interrupted runtime has no desktop installation owner".into());
    }
    let identity = &transaction.settings.bundle.bundle_id;
    let release = desktop.releases().join(identity);
    let candidate = Bundle::stored(&release, identity, desktop.platform)?;
    // The package may already contain a different release. Complete only the
    // retained candidate recorded by the original activation.
    activate_bundle(root, sockets, desktop, &candidate, None).map(Some)
}

fn publish_release(desktop: &DesktopPaths, bundle: &Bundle) -> Result<Bundle> {
    let releases = desktop.releases();
    let destination = releases.join(bundle.id());
    if fs::symlink_metadata(&destination).is_ok() {
        return Bundle::stored(&destination, bundle.id(), desktop.platform);
    } else {
        let pending = releases.join(format!("pending-{}", random_id()?));
        fs::DirBuilder::new().mode(0o700).create(&pending)?;
        let staged = (|| -> Result<()> {
            for file in bundle.files() {
                let target = pending.join(&file.path);
                fs::create_dir_all(target.parent().ok_or("invalid_desktop_bundle_path")?)?;
                let mut source = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(bundle.root.join(&file.path))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if file.executable { 0o755 } else { 0o644 })
                    .open(&target)?;
                std::io::copy(&mut source, &mut output)?;
                output.sync_all()?;
                if output.metadata()?.len() != file.bytes
                    || desktop_bundle::digest(&target)? != file.sha256
                {
                    return Err("desktop_bundle_changed_during_install".into());
                }
            }
            let manifest = bundle.manifest_bytes()?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(pending.join("bundle.json"))?;
            output.write_all(&manifest)?;
            output.sync_all()?;
            Bundle::stored(&pending, bundle.id(), desktop.platform)?;
            let mut directories = vec![pending.clone()];
            let mut index = 0;
            while index < directories.len() {
                for entry in fs::read_dir(&directories[index])? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        directories.push(entry.path());
                    }
                }
                index += 1;
            }
            for directory in directories.into_iter().rev() {
                fs::File::open(directory)?.sync_all()?;
            }
            fs::rename(&pending, &destination)?;
            fs::File::open(&releases)?.sync_all()?;
            Ok(())
        })();
        if staged.is_err() {
            let _ = fs::remove_dir_all(&pending);
        }
        staged?;
    }
    Bundle::stored(&destination, bundle.id(), desktop.platform)
}

#[cfg(any(target_os = "linux", test))]
fn packaged_current(
    root: &Path,
    desktop: &DesktopPaths,
    incoming: &str,
    enroll: bool,
) -> Result<Option<PathBuf>> {
    if pending(root)?.is_some() {
        if enroll {
            return Ok(None);
        }
        return Err(
            "Complete the matching desktop package activation before starting the runtime".into(),
        );
    }
    let Some(settings) = installed_settings(root)? else {
        if enroll {
            return Ok(None);
        }
        return Err("Open Oblivion once to prepare its runtime".into());
    };
    if !desktop_owner(root, desktop, Some(&settings), false)? {
        return Err("The existing runtime has no desktop installation owner".into());
    }
    if uninstalled(root, &settings)? {
        if enroll {
            return Ok(None);
        }
        return Err("Open Oblivion again to reinstall its runtime software".into());
    }
    if enroll && settings.bundle.bundle_id != incoming {
        private_directory(
            settings
                .control_socket
                .parent()
                .ok_or("invalid_runtime_socket")?,
        )?;
        if stopped_locks(&settings.control_socket)?.is_some() {
            return Ok(None);
        }
        eprintln!("The desktop update will apply after the protected runtime stops.");
    }
    let release = desktop.releases().join(&settings.bundle.bundle_id);
    let bundle = Bundle::deployed(&release, &settings.bundle, desktop.platform)?;
    Ok(Some(bundle.root.join("bin/oblivion")))
}

#[cfg(target_os = "linux")]
pub fn packaged_launcher(enroll: bool) -> Result<PathBuf> {
    require_desktop()?;
    if !desktop_bundle::packaged_entry()? {
        return Err("desktop_package_entry_required".into());
    }
    let desktop = DesktopPaths::current()?;
    let root = directory()?;
    if !enroll && installed_settings(&root)?.is_none() {
        return Err("Open Oblivion once to prepare its runtime".into());
    }
    let _installation = desktop.lock_installation()?;
    let sockets = socket_directory()?;
    if enroll {
        if let Some(launcher) = resume_packaged(&root, &sockets, &desktop)? {
            return Ok(launcher);
        }
    }
    let bundle = Bundle::current()?;
    if let Some(launcher) = packaged_current(&root, &desktop, bundle.id(), enroll)? {
        return Ok(launcher);
    }
    // The fixed, package-owned helper is verified before it can offer setup.
    // Its probe passes before publication can allocate any private backing.
    bundle.verify_native()?;
    preflight_with(&bundle.root.join("bin/oblivion-vm"))?;
    match publish_bundle(&root, &sockets, &desktop, &bundle) {
        Err(error) if error.is::<RuntimeBusy>() => {
            eprintln!("The desktop update will apply after the protected runtime stops.");
            packaged_current(&root, &desktop, bundle.id(), false)?.ok_or_else(|| RuntimeBusy.into())
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
pub fn observe_packaged() -> Result<()> {
    require_desktop()?;
    let root = directory()?;
    let settings = installed_settings(&root)?.ok_or("runtime_not_installed")?;
    if uninstalled(&root, &settings)? {
        return Err("runtime_not_installed".into());
    }
    control_environment(&settings);
    Ok(())
}

fn finish_activation(root: &Path, bundle: &Bundle) -> Result<()> {
    let installation = private_lock(&root.join("installation.lock"))?;
    if !try_lock(&installation)? {
        return Err("runtime_installation_busy".into());
    }
    let Some(transaction) = pending(root)? else {
        return Ok(());
    };
    let current = Settings::read(&root.join("runtime.json"))?;
    if transaction.settings.bundle.bundle_id != bundle.id()
        || serde_json::to_value(&transaction.settings)? != serde_json::to_value(&current)?
    {
        return Err("runtime_update_requires_matching_bundle_installer".into());
    }
    fs::remove_file(root.join("update.pending.json"))?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

fn write_settings(root: &Path, settings: &Settings) -> Result<()> {
    settings.validate()?;
    write_record(root, "runtime.json", settings)
}

fn write_record(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let pending = root.join(format!("runtime-{}.pending", random_id()?));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        fs::rename(&pending, root.join(name))?;
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
    if mode()? == Mode::Desktop && atomic_intent(&root)?.is_some() {
        return Err("Complete the pending Atomic removal before starting Oblivion".into());
    }
    let path = root.join("runtime.json");
    if !path.is_file() {
        return Err(if mode()? == Mode::Live { "The Live runtime has not been prepared. Run oblivion to choose its storage mode." } else { "Install the matching development desktop bundle before starting Oblivion" }.into());
    }
    private_directory(&root)?;
    let settings = Settings::read(&path)?;
    if uninstalled(&root, &settings)? {
        return Err("Desktop software was uninstalled; install a matching development bundle to reuse the preserved encrypted data".into());
    }
    private_directory(
        settings
            .control_socket
            .parent()
            .ok_or("invalid_runtime_socket")?,
    )?;
    control_environment(&settings);
    Ok(settings)
}

fn control_environment(settings: &Settings) {
    // At launcher startup there are no worker threads. The selected profile owns
    // transport routing; environment inherited from a shell cannot select another.
    unsafe {
        std::env::set_var("OBLIVION_RUNTIME_MODE", "desktop");
        std::env::set_var("OBLIVION_CONTROL_SOCKET", &settings.control_socket);
    }
}

pub fn request_live_storage(ephemeral: Option<bool>) -> Result<()> {
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live {
        unsafe {
            match ephemeral {
                Some(true) => std::env::set_var("OBLIVION_LIVE_STORAGE_REQUEST", "ephemeral"),
                Some(false) => std::env::set_var("OBLIVION_LIVE_STORAGE_REQUEST", "persistent"),
                None => std::env::remove_var("OBLIVION_LIVE_STORAGE_REQUEST"),
            }
        }
    }
    let _ = ephemeral;
    Ok(())
}

pub fn choose_live_storage() -> Result<()> {
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live { return live::reset(); }
    Err("Storage-mode selection is available only on Debian Live".into())
}

pub fn live_media() -> Result<()> {
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live {
        return live::media();
    }
    Err("USB media listing is available only on Oblivion Live".into())
}

pub fn start() -> Result<()> {
    ensure_as(lifecycle::Kind::Resident, true)
}

/// Keep physical storage review on the trusted terminal, before the Live TUI.
/// The manager's initial status request starts the VM while its logo renders.
pub fn prepare_manager() -> Result<()> {
    unsafe {
        std::env::remove_var("OBLIVION_SHOW_INTRO");
    }
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live {
        let root = directory()?;
        live::prepare(&root, &root.join("runtime.json"))?;
        let settings = prepare_connection()?;
        lifecycle::register(&settings, lifecycle::Kind::Manager)?;
        live::intro()?;
        return Ok(());
    }
    ensure_as(lifecycle::Kind::Manager, true)
}

pub fn ensure() -> Result<()> {
    ensure_as(lifecycle::Kind::Command, true)
}

pub fn ensure_quiet() -> Result<()> {
    ensure_as(lifecycle::Kind::Command, false)
}

pub fn ensure_status() -> Result<()> {
    ensure_as(lifecycle::Kind::Observation, true)
}

fn ensure_as(kind: lifecycle::Kind, show_progress: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live {
        let root = directory()?;
        live::prepare(&root, &root.join("runtime.json"))?;
    }
    let settings = prepare_connection()?;
    lifecycle::register(&settings, kind)?;
    let bundle = Bundle::current()?;
    if bundle.id() != settings.bundle.bundle_id || bundle.source() != settings.bundle.source_sha256
    {
        return Err(
            "Desktop binary and runtime image differ; rerun the matching bundle installer".into(),
        );
    }
    let root = directory()?;
    if pending(&root)?.is_some() {
        let installation = private_lock(&root.join("installation.lock"))?;
        if !try_lock(&installation)? {
            return Err("runtime_installation_busy".into());
        }
        let transaction = pending(&root)?.ok_or("runtime_update_journal_changed")?;
        if transaction.settings.bundle.bundle_id != bundle.id()
            || serde_json::to_value(&transaction.settings)? != serde_json::to_value(&settings)?
        {
            return Err("runtime_update_requires_matching_bundle_installer".into());
        }
        verify_boot(&settings)?;
        bundle.verify_native()?;
        fs::remove_file(root.join("update.pending.json"))?;
        fs::File::open(&root)?.sync_all()?;
    }
    let socket = &settings.control_socket;
    let deadline = Instant::now() + Duration::from_secs(390);
    if crate::remote_control::probe(socket, Duration::from_secs(2)).is_ok() {
        return ready(&settings);
    }
    let startup_lock = private_lock(&sidecar(socket, ".startup.lock"))?;
    let mut owns_startup = false;
    let mut child: Option<std::process::Child> = None;
    if show_progress { eprintln!("Preparing the protected runtime…"); }
    loop {
        if !lifecycle::owner_alive(&settings)? { return Err("runtime_owner_lost".into()); }
        if let Some(child) = child.as_mut() {
            if child.try_wait()?.is_some() {
                return Err("Runtime startup failed. Inspect oblivion-vm capabilities and the installed image.".into());
            }
        }
        if !owns_startup {
            owns_startup = try_lock(&startup_lock)?;
        }
        if owns_startup && child.is_none() {
            child = lifecycle::launch(&settings, || {
                preflight()?;
                bundle.verify_native()?;
                verify_boot(&settings)?;
                // Linux never silently adopts an old QMP/control socket. Recovery
                // is an explicit command under both election and lifetime locks.
                if backend() == "qemu-kvm"
                    && [
                        socket.clone(),
                        sidecar(socket, ".qmp"),
                        sidecar(socket, ".auth"),
                        sidecar(socket, ".media"),
                    ]
                    .iter()
                    .any(|path| fs::symlink_metadata(path).is_ok())
                {
                    return Err("Run oblivion runtime recover to inspect and remove disconnected runtime sockets".into());
                }
                // Backend configuration is a distinct current protocol. The
                // launcher-owned bundle binding remains in runtime.json and is
                // verified before generating this private, fixed VM projection.
                let mut wire = serde_json::to_value(&settings)?;
                wire.as_object_mut()
                    .ok_or("invalid_runtime_configuration")?
                    .remove("bundle");
                write_record(&root, "vm.json", &wire)?;
                Ok(())
            })?;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("Runtime is still starting. Retry after its controller becomes ready.")?;
        if crate::remote_control::probe(socket, remaining.min(Duration::from_secs(2))).is_ok() {
            return ready(&settings);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(
                "Runtime is still starting. Retry after its controller becomes ready.".into(),
            );
        };
        std::thread::sleep(remaining.min(Duration::from_millis(250)));
    }
}

fn ready(settings: &Settings) -> Result<()> {
    lifecycle::admit(settings)?;
    #[cfg(target_os = "linux")]
    if mode()? == Mode::Live { live::activate_ram()?; }
    Ok(())
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Explicitly recover sockets only after all owners and listeners have gone.
pub fn recover() -> Result<()> {
    let settings = prepare_connection()?;
    lifecycle::recovering(&settings)?;
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
            sidecar(&settings.control_socket, ".media"),
        ]
    } else {
        vec![settings.control_socket.clone()]
    };
    recover_sockets(&paths)?;
    lifecycle::recovered(&settings)
}

fn recover_sockets(paths: &[PathBuf]) -> Result<()> {
    remove_disconnected_sockets(disconnected_sockets(paths)?)
}

fn disconnected_sockets(paths: &[PathBuf]) -> Result<Vec<(PathBuf, u64, u64)>> {
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
                disconnected.push((path.to_owned(), info.dev(), info.ino()))
            }
            _ => return Err("runtime_socket_still_active".into()),
        }
    }
    Ok(disconnected)
}

fn remove_disconnected_sockets(disconnected: Vec<(PathBuf, u64, u64)>) -> Result<()> {
    for (path, device, inode) in disconnected {
        let info = fs::symlink_metadata(&path)?;
        if info.dev() != device || info.ino() != inode || !info.file_type().is_socket() {
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
    let settings = prepare_connection()?;
    // A replacement backend must not acquire this socket between the lock and shutdown RPCs.
    let startup = private_lock(&sidecar(&settings.control_socket, ".startup.lock"))?;
    if !try_lock(&startup)? {
        return Err("Runtime startup or shutdown is in progress. Retry after it completes.".into());
    }
    let generation = lifecycle::begin_stop(&settings)?;
    if lifecycle::stop_disconnected(&settings, &generation)? {
        return Ok(());
    }
    let (error, locked) = match control::request("lock", None, &[]) {
        Ok(_) => match control::request("shutdown-runtime", None, &[]) {
            Ok(_) => return lifecycle::stopped(&settings, &generation),
            Err(error) => (error, true),
        },
        Err(error) => (error, false),
    };
    let disconnected = error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
            || locked && error.kind() == std::io::ErrorKind::UnexpectedEof
    });
    if disconnected {
        // systemd may close the relay before the shutdown acknowledgement is sent.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if lifecycle::stop_disconnected(&settings, &generation)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Err(format!("Runtime stop could not be verified ({error}). Admission remains blocked; retry oblivion runtime stop, then oblivion runtime recover.").into())
}

pub fn supervise(generation: &str) -> Result<()> {
    let settings = prepare_connection()?;
    lifecycle::supervise(&settings, generation)
}

pub fn release_owner() -> Result<()> {
    lifecycle::release()
}

pub struct ManagerHandoff(lifecycle::Handoff);

impl ManagerHandoff {
    pub fn prepare(command: &mut Command) -> Result<Self> {
        let settings = prepare_connection()?;
        Ok(Self(lifecycle::Handoff::new(&settings, command)?))
    }

    pub fn bind(&mut self, child: &std::process::Child) -> Result<()> {
        self.0.bind(child)
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
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    pub(super) fn settings(root: &Path) -> Settings {
        let identity = "00112233445566778899aabbccddeeff";
        Settings {
            version: 1,
            backend: backend().into(),
            bundle: Binding {
                bundle_id: "aa".repeat(32),
                source_sha256: "bb".repeat(32),
                boot: ["runtime/controller.iso", "runtime/kernel", "runtime/initrd"].map(|path| {
                    desktop_bundle::File {
                        path: path.into(),
                        sha256: "cc".repeat(32),
                        bytes: 1,
                        executable: false,
                    }
                }),
            },
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

    fn installed_fixture() -> (Fixture, DesktopPaths, Settings, String) {
        let fixture = Fixture::new();
        let desktop = DesktopPaths {
            prefix: fixture.0.join("desktop"),
            entry: fixture.0.join("bin/oblivion"),
            manage_entry: true,
            platform: if desktop_bundle::platform() == "unsupported" {
                "linux-x86_64"
            } else {
                desktop_bundle::platform()
            },
        };
        private_directory(&desktop.releases()).unwrap();
        private_directory(desktop.entry.parent().unwrap()).unwrap();
        let mut old = desktop_bundle::tests::Fixture::new();
        old.change_source(&"cd".repeat(32));
        let old_bundle = old.bundle();
        let new = desktop_bundle::tests::Fixture::new();
        let new_bundle = new.bundle();
        let mut current = settings(&fixture.0);
        let original = fixture.0.join(format!("boot-{}", "11".repeat(16)));
        let active = fixture.0.join(format!("boot-{}", "22".repeat(16)));
        for (directory, bundle) in [(&original, &old_bundle), (&active, &new_bundle)] {
            private_directory(directory).unwrap();
            copy_boot(bundle, directory).unwrap();
            write_record(
                directory,
                "boot.json",
                &BootRecord {
                    version: 1,
                    runtime_id: current.runtime_id.clone(),
                    bundle: bundle.binding().unwrap(),
                },
            )
            .unwrap();
        }
        current.bundle = new_bundle.binding().unwrap();
        current.kernel = active.join("kernel");
        current.initrd = active.join("initrd");
        current.disks[0].path = active.join("controller.iso");
        current.disks[1].path = original.join("storage.raw");
        let mut data = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&current.disks[1].path)
            .unwrap();
        data.write_all(b"synthetic encrypted data sentinel")
            .unwrap();
        data.sync_all().unwrap();
        let old_id = old_bundle.id().to_owned();
        let new_id = new_bundle.id().to_owned();
        fs::rename(&old.root, desktop.releases().join(&old_id)).unwrap();
        fs::rename(&new.root, desktop.releases().join(&new_id)).unwrap();
        std::os::unix::fs::symlink(
            desktop.releases().join(new_id).join("bin/oblivion"),
            &desktop.entry,
        )
        .unwrap();
        write_settings(&fixture.0, &current).unwrap();
        bind_desktop(&fixture.0, &desktop).unwrap();
        (fixture, desktop, current, old_id)
    }

    fn mark_atomic_disk(settings: &Settings) {
        let mut disk = OpenOptions::new().write(true).truncate(true).open(&settings.disks[1].path).unwrap();
        writeln!(disk, "OBLIVION-RUNTIME-1\n{}", settings.runtime_id).unwrap();
        disk.set_len(4096).unwrap();
    }

    #[test]
    fn atomic_resumes_partial_release_cleanup_before_data_deletion() {
        let (fixture, desktop, settings, old) = installed_fixture();
        mark_atomic_disk(&settings);
        let launcher = desktop.entry.canonicalize().unwrap();
        atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| Ok(false)).unwrap();
        assert!(settings.disks[1].path.exists() && launcher.exists());
        assert!(!fixture.0.join("atomic.json").exists());

        let other = desktop.releases().join(old).join("bin/user-file");
        let result = atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| {
            fs::write(&other, b"unreviewed")?;
            Ok(true)
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&other).unwrap(), b"unreviewed");
        assert!(settings.disks[1].path.exists() && launcher.exists());
        assert!(atomic_intent(&fixture.0).unwrap().is_some());
        assert!(atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| Ok(true)).is_err());
        assert!(settings.disks[1].path.exists());
        fs::remove_file(other).unwrap();
        atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| Ok(true)).unwrap();
        assert!(!settings.disks[1].path.exists() && !launcher.exists());
        assert!(!fixture.0.join("atomic.json").exists());
    }

    #[test]
    fn atomic_resumes_after_data_deletion_and_removes_owned_metadata() {
        let (fixture, desktop, settings, _) = installed_fixture();
        mark_atomic_disk(&settings);
        let launcher = desktop.entry.canonicalize().unwrap();
        let result = atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| {
            let owner = read_record::<DesktopOwner>(&desktop.prefix.join("installation.json"))?.unwrap();
            write_record(&desktop.prefix, "installation.json", &owner)?;
            Ok(true)
        });
        assert!(result.is_err());
        assert!(!settings.disks[1].path.exists());
        assert!(launcher.exists() && atomic_intent(&fixture.0).unwrap().is_some());
        atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| Ok(true)).unwrap();
        assert!(!launcher.exists() && !desktop.prefix.join("installation.json").exists());
        assert!(!fixture.0.join("atomic.json").exists());
    }

    #[test]
    fn atomic_final_receipt_can_be_finished_only_by_matching_installer() {
        let (fixture, desktop, settings, _) = installed_fixture();
        mark_atomic_disk(&settings);
        let launcher = desktop.entry.canonicalize().unwrap();
        let entry = desktop.entry_release().unwrap().unwrap();
        let result = atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| {
            let owner = read_record::<DesktopOwner>(&desktop.prefix.join("installation.json"))?.unwrap();
            write_record(&desktop.prefix, "installation.json", &owner)?;
            Ok(true)
        });
        assert!(result.is_err());
        assert!(atomic_intent(&fixture.0).unwrap().unwrap().data_committed);
        assert!(finish_atomic_tail(&fixture.0, &desktop, &entry).is_err());

        // Simulate a process exiting immediately after its final executable
        // unlink, before it removes the manifest, empty directories and receipt.
        fs::remove_file(desktop.prefix.join("installation.json")).unwrap();
        fs::remove_file(&desktop.entry).unwrap();
        fs::remove_file(&launcher).unwrap();
        assert!(finish_atomic_tail(&fixture.0, &desktop, &"f".repeat(64)).is_err());
        finish_atomic_tail(&fixture.0, &desktop, &entry).unwrap();
        assert!(!fixture.0.join("atomic.json").exists());
        assert!(fs::read_dir(desktop.releases()).unwrap().next().is_none());
    }

    #[test]
    fn atomic_rejects_data_directory_symlink_before_confirmation() {
        let (fixture, desktop, settings, _) = installed_fixture();
        mark_atomic_disk(&settings);
        let launcher = desktop.entry.canonicalize().unwrap();
        let data = settings.disks[1].path.parent().unwrap();
        let outside = Fixture::new();
        let moved = outside.0.join("data");
        fs::rename(data, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, data).unwrap();
        let result = atomic_locked(&fixture.0, &desktop, &fixture.0, &launcher, |_, _, _| {
            panic!("unverified directory must be refused before prompting");
        });
        assert!(result.is_err());
        assert!(moved.join("storage.raw").exists());
        assert!(!fixture.0.join("atomic.json").exists());
    }

    #[test]
    fn packaged_enrollment_publishes_private_release_without_claiming_user_command() {
        let fixture = Fixture::new();
        let source = desktop_bundle::tests::Fixture::new();
        let bundle = source.bundle();
        let root = fixture.0.join("runtime");
        let desktop = DesktopPaths {
            prefix: fixture.0.join("desktop"),
            entry: fixture.0.join("user-bin/oblivion"),
            manage_entry: false,
            platform: desktop_bundle::platform(),
        };
        assert!(packaged_current(&root, &desktop, bundle.id(), false).is_err());
        assert!(!root.exists() && !desktop.prefix.exists());
        assert!(
            packaged_current(&root, &desktop, bundle.id(), true)
                .unwrap()
                .is_none()
        );
        let _installation = desktop.lock_installation().unwrap();
        let launcher =
            publish_bundle(&root, &fixture.0.join("sockets"), &desktop, &bundle).unwrap();
        assert_eq!(
            launcher,
            desktop.releases().join(bundle.id()).join("bin/oblivion")
        );
        assert!(!desktop.entry.parent().unwrap().exists());
        assert!(!root.join("update.pending.json").exists());
        let settings = installed_settings(&root).unwrap().unwrap();
        assert!(settings.disks[1].path.is_file());
        assert_eq!(
            packaged_current(&root, &desktop, bundle.id(), true).unwrap(),
            Some(launcher)
        );
    }

    #[test]
    fn packaged_update_keeps_busy_release_and_adopts_new_bundle_only_when_stopped() {
        use std::os::unix::fs::FileExt;

        let (fixture, mut desktop, current, _) = installed_fixture();
        desktop.manage_entry = false;
        fs::remove_file(&desktop.entry).unwrap();
        fs::write(&desktop.entry, b"unrelated user command").unwrap();
        let _installation = desktop.lock_installation().unwrap();
        let mut incoming = desktop_bundle::tests::Fixture::new();
        incoming.change_source(&"ee".repeat(32));
        let incoming = incoming.bundle();
        let active = desktop.releases().join(&current.bundle.bundle_id);
        let runtime_image = active.join("runtime/controller.iso");
        let original = fs::read(&runtime_image).unwrap();
        fs::write(&runtime_image, vec![b'x'; original.len()]).unwrap();
        let before = fs::read(fixture.0.join("runtime.json")).unwrap();
        for suffix in [".startup.lock", ".lock"] {
            let busy = private_lock(&sidecar(&current.control_socket, suffix)).unwrap();
            assert!(try_lock(&busy).unwrap());
            assert_eq!(
                packaged_current(&fixture.0, &desktop, incoming.id(), true).unwrap(),
                Some(active.join("bin/oblivion")),
            );
            assert_eq!(fs::read(fixture.0.join("runtime.json")).unwrap(), before);
            assert!(!desktop.releases().join(incoming.id()).exists());
        }
        fs::write(&runtime_image, original).unwrap();
        let launcher = active.join("bin/oblivion");
        let original = fs::read(&launcher).unwrap();
        fs::write(&launcher, vec![b'x'; original.len()]).unwrap();
        assert!(packaged_current(&fixture.0, &desktop, incoming.id(), false).is_err());
        fs::write(launcher, original).unwrap();

        let backing = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&current.disks[1].path)
            .unwrap();
        backing.write_all_at(b"preserve", 4096).unwrap();
        let inode = backing.metadata().unwrap().ino();
        assert!(
            packaged_current(&fixture.0, &desktop, incoming.id(), true)
                .unwrap()
                .is_none()
        );
        let launcher = publish_bundle(&fixture.0, &fixture.0, &desktop, &incoming).unwrap();
        let next = installed_settings(&fixture.0).unwrap().unwrap();
        assert_eq!(
            launcher,
            desktop.releases().join(incoming.id()).join("bin/oblivion")
        );
        assert_eq!(next.runtime_id, current.runtime_id);
        assert_eq!(next.disks[1].path, current.disks[1].path);
        let retained = fs::File::open(&next.disks[1].path).unwrap();
        assert_eq!(retained.metadata().unwrap().ino(), inode);
        let mut bytes = [0; 8];
        retained.read_exact_at(&mut bytes, 4096).unwrap();
        assert_eq!(&bytes, b"preserve");
        assert_eq!(fs::read(&desktop.entry).unwrap(), b"unrelated user command");
    }

    #[test]
    fn packaged_activation_resumes_retained_candidate_after_apt_replaces_bundle() {
        for committed in [false, true] {
            let (fixture, mut desktop, previous, _) = installed_fixture();
            desktop.manage_entry = false;
            let _installation = desktop.lock_installation().unwrap();
            let mut source = desktop_bundle::tests::Fixture::new();
            source.change_source(&"ee".repeat(32));
            let candidate = publish_release(&desktop, &source.bundle()).unwrap();
            let backing = fs::File::open(&previous.disks[1].path).unwrap();
            let inode = backing.metadata().unwrap().ino();
            let bytes = fs::read(&previous.disks[1].path).unwrap();
            change_bundle(&fixture.0, &fixture.0, &candidate, true, true).unwrap();
            if !committed {
                write_settings(&fixture.0, &previous).unwrap();
            }

            // APT now supplies a different bundle, and the original package
            // tree is gone. Only the verified private release can resume.
            drop(source);
            let mut replacement = desktop_bundle::tests::Fixture::new();
            replacement.change_source(&"ff".repeat(32));
            let replacement = replacement.bundle();
            let journal_path = fixture.0.join("update.pending.json");
            let journal = fs::read(&journal_path).unwrap();
            let config = fs::read(fixture.0.join("runtime.json")).unwrap();
            let launcher = candidate.root.join("bin/oblivion");
            let original = fs::read(&launcher).unwrap();
            fs::write(&launcher, vec![b'x'; original.len()]).unwrap();
            assert!(resume_packaged(&fixture.0, &fixture.0, &desktop).is_err());
            assert_eq!(fs::read(&journal_path).unwrap(), journal);
            assert_eq!(fs::read(fixture.0.join("runtime.json")).unwrap(), config);
            fs::write(&launcher, original).unwrap();

            assert_eq!(
                resume_packaged(&fixture.0, &fixture.0, &desktop).unwrap(),
                Some(launcher),
            );
            assert!(!journal_path.exists());
            let current = installed_settings(&fixture.0).unwrap().unwrap();
            assert_eq!(current.bundle.bundle_id, candidate.id());
            assert_eq!(current.runtime_id, previous.runtime_id);
            assert_eq!(current.disks[1].path, previous.disks[1].path);
            assert_eq!(fs::metadata(&current.disks[1].path).unwrap().ino(), inode);
            assert_eq!(fs::read(&current.disks[1].path).unwrap(), bytes);
            assert!(!desktop.releases().join(replacement.id()).exists());
            assert!(
                packaged_current(&fixture.0, &desktop, replacement.id(), true)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn collection_removes_only_verified_old_assets_and_preserves_data_current_and_unknown_files() {
        let (fixture, desktop, current, old_id) = installed_fixture();
        let original = current.disks[1].path.parent().unwrap();
        let unknown = fixture.0.join(format!("boot-{}", "33".repeat(16)));
        private_directory(&unknown).unwrap();
        fs::write(unknown.join("personal-document"), b"keep").unwrap();
        let changed = desktop.releases().join("99".repeat(32));
        private_directory(&changed).unwrap();
        fs::write(changed.join("personal-document"), b"keep").unwrap();
        let config = fs::read(fixture.0.join("runtime.json")).unwrap();
        let plan = cleanup_plan(&fixture.0, &desktop, &current, false, None).unwrap();
        assert_eq!((plan.releases, plan.boot_files, plan.retained), (1, 3, 2));
        plan.remove().unwrap();
        assert!(!desktop.releases().join(old_id).exists());
        assert!(
            desktop
                .releases()
                .join(&current.bundle.bundle_id)
                .join("bundle.json")
                .exists()
        );
        assert!(
            current.kernel.is_file() && current.initrd.is_file() && current.disks[0].path.is_file()
        );
        assert!(!original.join("kernel").exists() && original.join("boot.json").is_file());
        assert_eq!(
            fs::read(&current.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
        assert_eq!(fs::read(fixture.0.join("runtime.json")).unwrap(), config);
        assert!(
            unknown.join("personal-document").is_file()
                && changed.join("personal-document").is_file()
        );
    }

    #[test]
    fn collection_preserves_staged_journal_and_its_previous_release() {
        let (fixture, desktop, current, old_id) = installed_fixture();
        write_record(
            &fixture.0,
            "update.pending.json",
            &Pending {
                version: 1,
                previous: Some(old_id.clone()),
                settings: current.clone(),
            },
        )
        .unwrap();
        let journal = fs::read(fixture.0.join("update.pending.json")).unwrap();
        let plan = cleanup_plan(&fixture.0, &desktop, &current, false, None).unwrap();
        assert_eq!(plan.releases, 0);
        plan.remove().unwrap();
        assert_eq!(
            fs::read(fixture.0.join("update.pending.json")).unwrap(),
            journal
        );
        assert!(
            desktop
                .releases()
                .join(old_id)
                .join("bundle.json")
                .is_file()
        );
    }

    #[test]
    fn uninstall_is_stopped_only_and_never_touches_identity_or_encrypted_data() {
        let (fixture, desktop, current, _) = installed_fixture();
        let lock = private_lock(&sidecar(&current.control_socket, ".lock")).unwrap();
        assert!(try_lock(&lock).unwrap());
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(desktop.entry.exists() && current.kernel.exists());
        assert!(!fixture.0.join("uninstalled.json").exists());
        drop(lock);
        let config = fs::read(fixture.0.join("runtime.json")).unwrap();
        collect_locked(&fixture.0, &desktop, true).unwrap();
        assert!(fs::symlink_metadata(&desktop.entry).is_err());
        assert!(!current.kernel.exists());
        assert_eq!(fs::read_dir(desktop.releases()).unwrap().count(), 0);
        assert_eq!(
            fs::read(&current.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
        assert_eq!(fs::read(fixture.0.join("runtime.json")).unwrap(), config);
        assert!(uninstalled(&fixture.0, &current).unwrap());
        collect_locked(&fixture.0, &desktop, true).unwrap();
        assert_eq!(
            fs::read(&current.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
    }

    #[test]
    fn uninstall_refuses_foreign_command_modified_release_and_unfinished_update() {
        let (fixture, desktop, current, _) = installed_fixture();
        write_record(
            &fixture.0,
            "update.pending.json",
            &Pending {
                version: 1,
                previous: None,
                settings: current.clone(),
            },
        )
        .unwrap();
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(desktop.entry.exists() && !fixture.0.join("uninstalled.json").exists());
        fs::remove_file(fixture.0.join("update.pending.json")).unwrap();
        fs::remove_file(&desktop.entry).unwrap();
        std::os::unix::fs::symlink(fixture.0.join("unrelated"), &desktop.entry).unwrap();
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(!fixture.0.join("uninstalled.json").exists());
        fs::remove_file(&desktop.entry).unwrap();
        let release = desktop.releases().join(&current.bundle.bundle_id);
        std::os::unix::fs::symlink(release.join("bin/oblivion"), &desktop.entry).unwrap();
        fs::write(release.join("bin/oblivion-vm"), b"modified helper").unwrap();
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(desktop.entry.exists() && current.kernel.exists());
        assert!(!fixture.0.join("uninstalled.json").exists());
    }

    #[test]
    fn uninstall_receipt_reinstall_preserves_disk_and_rejects_another_identity() {
        let (fixture, desktop, previous, _) = installed_fixture();
        collect_locked(&fixture.0, &desktop, true).unwrap();
        let source = desktop_bundle::tests::Fixture::new();
        let bundle = source.bundle();
        let assets = fixture.0.join(format!("boot-{}", "44".repeat(16)));
        private_directory(&assets).unwrap();
        copy_boot(&bundle, &assets).unwrap();
        let mut next = previous.clone();
        next.bundle = bundle.binding().unwrap();
        next.kernel = assets.join("kernel");
        next.initrd = assets.join("initrd");
        next.disks[0].path = assets.join("controller.iso");
        write_record(
            &fixture.0,
            "update.pending.json",
            &Pending {
                version: 1,
                previous: Some(previous.bundle.bundle_id.clone()),
                settings: next.clone(),
            },
        )
        .unwrap();
        assert!(commit_pending(&fixture.0, &bundle).unwrap());
        let mut wrong = next.clone();
        wrong.runtime_id = "ee".repeat(16);
        assert!(clear_uninstalled(&fixture.0, &wrong).is_err());
        assert!(uninstalled(&fixture.0, &next).unwrap());
        clear_uninstalled(&fixture.0, &next).unwrap();
        assert!(!uninstalled(&fixture.0, &next).unwrap());
        assert_eq!(next.disks[1].path, previous.disks[1].path);
        assert_eq!(next.runtime_id, previous.runtime_id);
        assert_eq!(next.guest_cid, previous.guest_cid);
        assert_eq!(
            fs::read(&next.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
        finish_activation(&fixture.0, &bundle).unwrap();
        assert!(pending(&fixture.0).unwrap().is_none());
    }

    #[test]
    fn shared_desktop_prefix_cannot_collect_another_runtime_or_changed_identity() {
        let (fixture, desktop, current, _) = installed_fixture();
        let other = Fixture::new();
        let mut impostor = current.clone();
        impostor.runtime_id = "dd".repeat(16);
        impostor.command_line = impostor
            .command_line
            .replace(&current.runtime_id, &impostor.runtime_id);
        write_settings(&other.0, &impostor).unwrap();
        assert!(collect_locked(&other.0, &desktop, true).is_err());
        assert!(collect_locked(&other.0, &desktop, false).is_err());
        assert!(bind_desktop(&other.0, &desktop).is_err());
        assert!(desktop.entry.exists() && current.kernel.is_file());
        assert!(!other.0.join("uninstalled.json").exists());
        write_settings(&fixture.0, &impostor).unwrap();
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(desktop.entry.exists() && current.disks[1].path.is_file());
    }

    #[test]
    fn preparing_install_is_bound_to_directory_but_cannot_authorize_collection() {
        let (fixture, desktop, current, _) = installed_fixture();
        write_record(
            &desktop.prefix,
            "installation.json",
            &DesktopOwner {
                version: 1,
                runtime_directory: fixture.0.clone(),
                identity: DesktopIdentity::Preparing,
            },
        )
        .unwrap();
        assert!(desktop_owner(&fixture.0, &desktop, Some(&current), true).unwrap());
        assert!(collect_locked(&fixture.0, &desktop, true).is_err());
        assert!(desktop.entry.exists() && current.kernel.is_file());
        let other = Fixture::new();
        assert!(desktop_owner(&other.0, &desktop, None, true).is_err());
        bind_desktop(&fixture.0, &desktop).unwrap();
        assert!(desktop_owner(&fixture.0, &desktop, Some(&current), false).unwrap());
    }

    #[test]
    fn first_install_reservation_is_retryable_and_cannot_adopt_another_prefix() {
        let fixture = Fixture::new();
        let desktop = DesktopPaths {
            prefix: fixture.0.join("desktop"),
            entry: fixture.0.join("bin/oblivion"),
            manage_entry: true,
            platform: "linux-x86_64",
        };
        private_directory(&desktop.prefix).unwrap();
        reserve_desktop(&fixture.0, &desktop).unwrap();
        private_directory(&desktop.releases().join("aa".repeat(32))).unwrap();
        reserve_desktop(&fixture.0, &desktop).unwrap();
        let other = Fixture::new();
        assert!(reserve_desktop(&other.0, &desktop).is_err());
        assert!(fs::read_dir(desktop.releases()).unwrap().next().is_some());
        let current = settings(&fixture.0);
        write_settings(&fixture.0, &current).unwrap();
        bind_desktop(&fixture.0, &desktop).unwrap();
        assert!(desktop_owner(&fixture.0, &desktop, Some(&current), false).unwrap());
        fs::remove_file(desktop.prefix.join("installation.json")).unwrap();
        assert!(reserve_desktop(&fixture.0, &desktop).is_err());
    }

    #[test]
    fn runtime_deploy_allows_a_separate_prefix_without_losing_local_entry_protection() {
        let (fixture, desktop, current, old_id) = installed_fixture();
        let old_entry = desktop.releases().join(&old_id).join("bin/oblivion");
        fs::remove_file(&desktop.entry).unwrap();
        std::os::unix::fs::symlink(&old_entry, &desktop.entry).unwrap();

        let separate = Fixture::new();
        let separate_desktop = DesktopPaths {
            prefix: separate.0.join("desktop"),
            entry: desktop.entry.clone(),
            manage_entry: true,
            platform: desktop.platform,
        };
        private_directory(&separate_desktop.prefix).unwrap();
        assert!(reserve_desktop(&separate.0, &separate_desktop).is_err());
        assert!(!separate_desktop.prefix.join("installation.json").exists());

        assert!(!separate_desktop.can_ignore_entry_for_deploy(&fixture.0).unwrap());
        assert!(separate_desktop.can_ignore_entry_for_deploy(&separate.0).unwrap());
        let separate_desktop = DesktopPaths {
            manage_entry: false,
            ..separate_desktop
        };
        reserve_desktop(&separate.0, &separate_desktop).unwrap();
        assert_eq!(fs::read_link(&desktop.entry).unwrap(), old_entry);

        assert!(!desktop.can_ignore_entry_for_deploy(&fixture.0).unwrap());
        assert_eq!(desktop.entry_release().unwrap(), Some(old_id.clone()));
        let plan = cleanup_plan(&fixture.0, &desktop, &current, false, None).unwrap();
        assert!(!plan.release_ids.contains(&old_id));
    }

    #[test]
    fn collection_retains_tampered_boot_and_refuses_aliased_data_or_changed_current_layout() {
        let (fixture, desktop, current, _) = installed_fixture();
        let old = current.disks[1].path.parent().unwrap().join("kernel");
        fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&old, b"changed old kernel").unwrap();
        let plan = cleanup_plan(&fixture.0, &desktop, &current, false, None).unwrap();
        assert_eq!(plan.retained, 1);
        assert_eq!(plan.boot_files, 0);
        let mut changed = current.clone();
        changed.initrd = old;
        assert!(cleanup_plan(&fixture.0, &desktop, &changed, false, None).is_err());
        fs::hard_link(&current.disks[1].path, fixture.0.join("raw-alias")).unwrap();
        assert!(cleanup_plan(&fixture.0, &desktop, &current, false, None).is_err());
        assert!(desktop.entry.exists() && current.kernel.is_file());
    }
    #[test]
    fn installation_profile_is_explicit_and_exact() {
        assert!(matches!(
            installation(br#"{"version":1,"mode":"live-launcher"}"#),
            Ok(Mode::Live)
        ));
        for invalid in [
            br#"{"version":0,"mode":"live-launcher"}"#.as_slice(),
            br#"{"version":1,"mode":"controller-runtime"}"#.as_slice(),
            br#"{"version":1,"mode":"desktop"}"#.as_slice(),
            br#"{"version":1,"mode":"live-launcher","fallback":true}"#.as_slice(),
            br#"{"mode":"live-launcher"}"#.as_slice(),
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

    #[test]
    fn interrupted_bundle_activation_preserves_storage_identity_and_rejects_changed_boot() {
        let fixture = Fixture::new();
        let source = desktop_bundle::tests::Fixture::new();
        let bundle = source.bundle();
        let assets = fixture.0.join("next");
        fs::create_dir(&assets).unwrap();
        fs::set_permissions(&assets, fs::Permissions::from_mode(0o700)).unwrap();
        copy_boot(&bundle, &assets).unwrap();
        let previous = settings(&fixture.0);
        fs::write(
            &previous.disks[1].path,
            b"synthetic encrypted data sentinel",
        )
        .unwrap();
        write_settings(&fixture.0, &previous).unwrap();
        let mut next = previous.clone();
        next.bundle = bundle.binding().unwrap();
        next.kernel = assets.join("kernel");
        next.initrd = assets.join("initrd");
        next.disks[0].path = assets.join("controller.iso");
        let transaction = Pending {
            version: 1,
            previous: Some(previous.bundle.bundle_id.clone()),
            settings: next,
        };
        write_record(&fixture.0, "update.pending.json", &transaction).unwrap();
        assert!(commit_pending(&fixture.0, &bundle).unwrap());
        let current = Settings::read(&fixture.0.join("runtime.json")).unwrap();
        assert_eq!(current.runtime_id, previous.runtime_id);
        assert_eq!(current.disks[1].path, previous.disks[1].path);
        assert_eq!(current.guest_cid, previous.guest_cid);
        assert_eq!(
            fs::read(&current.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
        assert!(commit_pending(&fixture.0, &bundle).unwrap());
        fs::set_permissions(&current.kernel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&current.kernel, b"modified fixture").unwrap();
        assert!(commit_pending(&fixture.0, &bundle).is_err());
        assert_eq!(
            fs::read(&current.disks[1].path).unwrap(),
            b"synthetic encrypted data sentinel"
        );
    }

    #[test]
    fn update_journal_never_rebinds_an_existing_persistence_disk() {
        let fixture = Fixture::new();
        let source = desktop_bundle::tests::Fixture::new();
        let bundle = source.bundle();
        let previous = settings(&fixture.0);
        write_settings(&fixture.0, &previous).unwrap();
        let mut next = previous.clone();
        next.bundle = bundle.binding().unwrap();
        next.disks[1].path = fixture.0.join("replacement.raw");
        write_record(
            &fixture.0,
            "update.pending.json",
            &Pending {
                version: 1,
                previous: Some(previous.bundle.bundle_id.clone()),
                settings: next,
            },
        )
        .unwrap();
        assert!(commit_pending(&fixture.0, &bundle).is_err());
        assert_eq!(
            Settings::read(&fixture.0.join("runtime.json"))
                .unwrap()
                .disks[1]
                .path,
            previous.disks[1].path
        );
        let mut prior = serde_json::to_value(&previous).unwrap();
        prior.as_object_mut().unwrap().remove("bundle");
        assert!(serde_json::from_value::<Settings>(prior).is_err());
    }
}
