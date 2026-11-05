//! Live-specific data presentation; the controller image and protocol stay shared.
use super::{
    Disk, Settings, backend, directory, guest_cid, hex, preflight, private_directory, private_lock,
    random_id, recover_sockets, sidecar, socket_directory, try_lock, write_settings,
};
use crate::control::{self, Result};
use crate::desktop_bundle::Bundle;
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Deserialize)]
struct Data {
    path: PathBuf,
    runtime_id: String,
    bytes: u64,
}

#[derive(Deserialize)]
struct Review {
    version: u8,
    boot_device: PathBuf,
    plan_sha256: String,
    existing: Option<Data>,
    bytes: Option<u64>,
    #[serde(default)]
    relocate_gpt_backup: bool,
}

fn selection(message: &str) -> Result<String> {
    let mut terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    terminal.write_all(message.as_bytes())?;
    terminal.flush()?;
    let mut answer = String::new();
    BufReader::new(&mut terminal)
        .take(1024)
        .read_line(&mut answer)?;
    Ok(answer.trim().to_owned())
}

fn storage(operation: &str, plan: Option<&str>) -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/bin/sudo");
    command.args(["-n", "/usr/lib/oblivion/live-storage.py", operation]);
    if let Some(plan) = plan {
        command.arg(plan);
    }
    let output = command.stdin(Stdio::null()).output()?;
    if !output.status.success() || output.stdout.len() > 16384 {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Live storage is unavailable: {}",
            detail
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || " _-".contains(*c))
                .take(160)
                .collect::<String>()
        )
        .into());
    }
    Ok(output.stdout)
}

pub(super) fn media() -> Result<()> {
    let output = Command::new("/usr/lib/oblivion/live-media.py")
        .arg("list")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 16 * 1024 {
        return Err("USB media could not be inspected".into());
    }
    std::io::stdout().write_all(&output.stdout)?;
    Ok(())
}

pub(super) fn prepare(root: &Path, path: &Path) -> Result<()> {
    if fs::read_to_string("/proc/swaps")?
        .lines()
        .skip(1)
        .any(|line| !line.trim().is_empty())
    {
        return Err("Oblivion Live refuses to start with active host swap".into());
    }
    private_directory(root)?;
    if path.exists() {
        let settings = Settings::read(path)?;
        let selected = if settings
            .command_line
            .split_whitespace()
            .any(|arg| arg == "oblivion.ephemeral=1")
        {
            "ephemeral"
        } else {
            "persistent"
        };
        if std::env::var("OBLIVION_LIVE_STORAGE_REQUEST")
            .is_ok_and(|requested| requested != selected)
        {
            return Err("This Live runtime uses a different storage mode. Close all work, run oblivion runtime stop, then oblivion runtime choose-storage before retrying.".into());
        }
        unsafe {
            std::env::set_var("OBLIVION_LIVE_STORAGE", selected);
        }
        return Ok(());
    }
    preflight()?;
    let bundle = Bundle::current()?;
    bundle.verify_native()?;
    let memory = fs::read_to_string("/proc/meminfo")?;
    let available = memory
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .ok_or("live_memory_observation_unavailable")?;
    if available < (6144 + 512) * 1024 {
        return Err("Oblivion Live needs at least 6656 MiB currently available for this controller profile. No data disk was initialized.".into());
    }
    let choice = match std::env::var("OBLIVION_LIVE_STORAGE_REQUEST")
        .ok()
        .as_deref()
    {
        Some("ephemeral") => "2".to_owned(),
        Some("persistent") => "1".to_owned(),
        _ => selection(
            "\nOblivion Live\n\n  1  Encrypted storage on this boot USB\n     Keep Safes, chats and settings between boots.\n\n  2  Ephemeral mode\n     Use RAM only; the USB data partition is never attached.\n\nChoose 1 or 2: ",
        )?,
    };
    let ephemeral = match choice.as_str() {
        "1" => false,
        "2" => true,
        _ => return Err("Choose 1 or 2 to start the protected runtime".into()),
    };
    let data = if ephemeral {
        let id = random_id()?;
        let path = root.join("ephemeral.raw");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.set_len(4 * 1024 * 1024 * 1024)?;
        file.write_all(format!("OBLIVION-RUNTIME-1\n{id}\n").as_bytes())?;
        file.sync_all()?;
        Data {
            path,
            runtime_id: id,
            bytes: 4 * 1024 * 1024 * 1024,
        }
    } else {
        let review: Review = serde_json::from_slice(&storage("review", None)?)?;
        if review.version != 1 || !review.boot_device.is_absolute() || !hex(&review.plan_sha256, 64)
        {
            return Err("invalid_live_storage_review".into());
        }
        let bytes = review
            .existing
            .as_ref()
            .map(|data| data.bytes)
            .or(review.bytes)
            .ok_or("invalid_live_storage_review")?;
        let question = format!(
            "\nBoot USB: {}\nDedicated data capacity: {} MiB\n{}\nThe host will not mount the protected filesystem.\nContinue? [y/N]: ",
            review.boot_device.display(),
            bytes / (1024 * 1024),
            if review.existing.is_some() {
                "Use the existing Oblivion data partition."
            } else {
                if review.relocate_gpt_backup {
                    "Move the GPT backup metadata to the USB end, then add one partition in free space. Existing partition starts and sizes stay unchanged."
                } else {
                    "Create one partition in unused trailing space; existing partitions stay unchanged."
                }
            }
        );
        if !selection(&question)?.eq_ignore_ascii_case("y") {
            return Err("Live storage preparation cancelled".into());
        }
        serde_json::from_slice::<Data>(&storage("prepare", Some(&review.plan_sha256))?)?
    };
    if !data.path.is_absolute()
        || !hex(&data.runtime_id, 32)
        || !(4 * 1024_u64.pow(3)..=1024_u64.pow(4)).contains(&data.bytes)
    {
        return Err("invalid_live_storage_authorization".into());
    }
    let settings = Settings {
        version: 1,
        backend: backend().into(),
        bundle: bundle.binding()?,
        runtime_id: data.runtime_id.clone(),
        kernel: bundle.root.join(&bundle.runtime().kernel),
        initrd: bundle.root.join(&bundle.runtime().initrd),
        command_line: format!(
            "boot=live components console=hvc0 quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend={} oblivion.runtime-id={}{}",
            backend(),
            data.runtime_id,
            if ephemeral {
                " oblivion.ephemeral=1"
            } else {
                ""
            }
        ),
        disks: [
            Disk {
                path: bundle.root.join(&bundle.runtime().image),
                read_only: true,
            },
            Disk {
                path: data.path,
                read_only: false,
            },
        ],
        cpu_count: 4,
        memory_mi_b: 6144,
        control_socket: socket_directory()?.join("runtime.sock"),
        control_port: 4050,
        network: true,
        serial_stdio: false,
        guest_cid: guest_cid()?,
    };
    private_directory(
        settings
            .control_socket
            .parent()
            .ok_or("invalid_runtime_socket")?,
    )?;
    settings.validate()?;
    write_settings(root, &settings)?;
    unsafe {
        std::env::set_var(
            "OBLIVION_LIVE_STORAGE",
            if ephemeral { "ephemeral" } else { "persistent" },
        );
    }
    Ok(())
}

pub(super) fn intro() -> Result<()> {
    unsafe {
        std::env::remove_var("OBLIVION_SHOW_INTRO");
    }
    if claim_intro(Path::new("/run/oblivion-live/user/intro.shown"))? {
        unsafe {
            std::env::set_var("OBLIVION_SHOW_INTRO", "1");
        }
    }
    Ok(())
}

fn claim_intro(path: &Path) -> Result<bool> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn activate_ram() -> Result<()> {
    if std::env::var("OBLIVION_LIVE_STORAGE").as_deref() != Ok("ephemeral") {
        return Ok(());
    }
    let path = directory()?.join("ram-entered");
    if path.exists() {
        return Ok(());
    }
    let status: serde_json::Value = serde_json::from_str(&control::request("status", None, &[])?)?;
    if status["app_open"] == false {
        control::request("enter-ram", None, &[])?;
    } else if status["app_mode"] != "ram-only" {
        return Err("unexpected_live_storage_mode".into());
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .sync_all()?;
    Ok(())
}

pub(super) fn reset() -> Result<()> {
    let root = directory()?;
    let path = root.join("runtime.json");
    let socket = if path.exists() {
        Settings::read(&path)?.control_socket
    } else {
        socket_directory()?.join("runtime.sock")
    };
    private_directory(socket.parent().ok_or("invalid_runtime_socket")?)?;
    let startup = private_lock(&sidecar(&socket, ".startup.lock"))?;
    let running = private_lock(&sidecar(&socket, ".lock"))?;
    if !try_lock(&startup)? || !try_lock(&running)? {
        return Err(
            "Close all work and stop the Live runtime before changing its storage mode".into(),
        );
    }
    recover_sockets(&[
        socket.clone(),
        sidecar(&socket, ".qmp"),
        sidecar(&socket, ".auth"),
    ])?;
    for name in ["runtime.json", "vm.json", "ram-entered", "ephemeral.raw"] {
        let target = root.join(name);
        match fs::symlink_metadata(&target) {
            Ok(info)
                if info.is_file()
                    && info.uid() == unsafe { libc::getuid() }
                    && info.nlink() == 1
                    && info.mode() & 0o077 == 0 =>
            {
                fs::remove_file(target)?
            }
            Ok(_) => return Err("unsafe_live_runtime_state".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_intro_is_claimed_once_outside_resettable_runtime_state() {
        let root = std::env::temp_dir().join(format!("oblivion-intro-{}", random_id().unwrap()));
        fs::create_dir(&root).unwrap();
        let marker = root.join("intro.shown");
        assert!(claim_intro(&marker).unwrap());
        assert!(!claim_intro(&marker).unwrap());
        let runtime = root.join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::write(runtime.join("runtime.json"), b"synthetic runtime state").unwrap();
        fs::remove_dir_all(runtime).unwrap();
        assert!(!claim_intro(&marker).unwrap());
        assert_eq!(fs::metadata(&marker).unwrap().mode() & 0o777, 0o600);
        fs::remove_file(&marker).unwrap();
        assert!(claim_intro(&marker).unwrap());
        fs::remove_dir_all(root).unwrap();
    }
}
