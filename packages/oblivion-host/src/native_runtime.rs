//! Desktop runtime state contains public boot assets and an encrypted data disk.
use crate::control::{self, Result};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("OBLIVION_RUNTIME_DIRECTORY") {
        return Ok(PathBuf::from(path));
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").ok_or("home_unavailable")?)
            .join("Library/Application Support/Oblivion"),
    )
}
fn socket_directory() -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    std::env::var_os("OBLIVION_RUNTIME_DIRECTORY").hash(&mut hash);
    PathBuf::from(format!(
        "/tmp/oblivion-{}-{:016x}",
        unsafe { libc::getuid() },
        hash.finish()
    ))
}
fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
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

pub fn install(image: &Path) -> Result<()> {
    let root = directory()?;
    private_directory(&root)?;
    private_directory(&socket_directory())?;
    let config = root.join("runtime.json");
    if config.exists() {
        return Err("Runtime is already installed".into());
    }
    let capabilities = Command::new(helper()?).arg("capabilities").output()?;
    let capabilities: serde_json::Value = serde_json::from_slice(&capabilities.stdout)?;
    if capabilities["supported"] != true {
        return Err(
            "This Mac does not support the nested virtual machines required by Oblivion".into(),
        );
    }
    let image = image.canonicalize()?;
    let assets = root.join(format!("runtime-{}", std::process::id()));
    fs::create_dir(&assets)?;
    fs::set_permissions(&assets, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        for (source, target) in [("live/vmlinuz", "kernel"), ("live/initrd.img", "initrd")] {
            let path = assets.join(target);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            let status = Command::new("/usr/bin/tar")
                .args(["-xOf"])
                .arg(&image)
                .arg(source)
                .stdin(Stdio::null())
                .stdout(Stdio::from(file))
                .stderr(Stdio::null())
                .status()?;
            if !status.success() {
                let _ = fs::remove_file(path);
                return Err("The image is missing its ARM64 runtime boot files".into());
            }
        }
        let disk = assets.join("storage.raw");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&disk)?;
        file.set_len(16 * 1024 * 1024 * 1024)?;
        file.sync_all()?;
        let value = json!({
            "version":1, "kernel":assets.join("kernel"), "initrd":assets.join("initrd"),
            "commandLine":"boot=live components console=hvc0 quiet loglevel=0 oblivion.runtime=1",
            "disks":[{"path":image,"readOnly":true},{"path":disk,"readOnly":false}],
            "cpuCount":4,"memoryMiB":6144,"controlSocket":socket_directory().join("runtime.sock"),
            "controlPort":4050,"network":true,"serialStdio":false
        });
        use std::io::Write;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)?;
        file.write_all(&serde_json::to_vec_pretty(&value)?)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() && !config.exists() {
        let _ = fs::remove_dir_all(assets);
    }
    result
}

pub fn ensure() -> Result<()> {
    let root = directory()?;
    let config = root.join("runtime.json");
    if !config.is_file() {
        return Err(
            "Install the ARM64 runtime with oblivion runtime install /path/to/oblivion-arm64.iso"
                .into(),
        );
    }
    private_directory(&root)?;
    let settings: serde_json::Value = serde_json::from_slice(&fs::read(&config)?)?;
    let socket = PathBuf::from(
        settings["controlSocket"]
            .as_str()
            .ok_or("invalid_runtime_configuration")?,
    );
    private_directory(socket.parent().ok_or("invalid_runtime_socket")?)?;
    // Set once at launcher startup, before any worker threads are created.
    unsafe {
        std::env::set_var("OBLIVION_CONTROL_SOCKET", &socket);
    }
    let deadline = Instant::now() + Duration::from_secs(390);
    if crate::remote_control::probe(&socket, Duration::from_secs(2)).is_ok() {
        return Ok(());
    }
    let mut startup_path = socket.as_os_str().to_os_string();
    startup_path.push(".startup.lock");
    let startup_lock = private_lock(Path::new(&startup_path))?;
    let mut helper_path = socket.as_os_str().to_os_string();
    helper_path.push(".lock");
    let helper_lock = private_lock(Path::new(&helper_path))?;
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
                if unsafe { libc::flock(helper_lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if observed_owner {
                    return Err("The protected runtime stopped before its controller became ready. Retry to start it again.".into());
                }
                let mut command = Command::new(helper()?);
                command
                    .args(["run", "--config"])
                    .arg(&config)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                // One launcher owns startup while the helper takes its lifetime
                // lock and safely removes its own stale socket under that lock.
                // Other launchers poll the same boot without creating a helper.
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
        if crate::remote_control::probe(&socket, remaining.min(Duration::from_secs(2))).is_ok() {
            return Ok(());
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            // The live helper still owns its runtime lock and boot. A timeout
            // must not create a second runtime or discard its persistent disk.
            return Err(
                "Runtime is still starting. Retry after its controller becomes ready.".into(),
            );
        };
        std::thread::sleep(remaining.min(Duration::from_millis(250)));
    }
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
    if !meta.is_file() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
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
    ensure()?;
    control::request("lock", None, &[])?;
    control::request("shutdown-runtime", None, &[])?;
    Ok(())
}

pub fn stop_if_idle() -> Result<()> {
    if std::env::var_os("OBLIVION_MANAGER_ACTIVE").is_some() {
        return Ok(());
    }
    match control::request("shutdown-idle", None, &[]) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string() == "runtime_busy" => Ok(()),
        Err(error) => Err(error),
    }
}
