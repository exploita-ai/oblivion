use crate::storage::{Error, Result, require, trusted_file};
use oblivion_host::settings::{Catalog, Preferences, Status};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};

const CURRENT: &str = "/run/oblivion/system-settings.json";
const SAVED: &str = "/run/oblivion/general/profile/system-settings.json";

pub fn catalog() -> Result<Catalog> {
    // The installed catalog is public data, unlike the private saved profile.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/share/oblivion/settings-catalog.json")
        .map_err(|_| Error("settings_catalog_unavailable"))?;
    let metadata = file.metadata().map_err(|_| Error("metadata_failed"))?;
    require(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "unsafe_settings_catalog",
    )?;
    serde_json::from_reader(file.take(1024 * 1024))
        .map_err(|_| Error("settings_catalog_unavailable"))
}

pub fn status(open: bool) -> Result<Status> {
    Ok(Status {
        current: read(CURRENT)?.unwrap_or_default(),
        saved: if open { read(SAVED)? } else { None },
    })
}

pub fn restore() -> Result<()> {
    if let Some(preferences) = read(SAVED)? {
        apply(&preferences)?;
    }
    Ok(())
}

pub fn save(preferences: &Preferences) -> Result<()> {
    apply(preferences)?;
    write(SAVED, preferences)
}

pub fn apply(preferences: &Preferences) -> Result<()> {
    catalog()?.validate(preferences).map_err(Error)?;
    let zone = Path::new("/usr/share/zoneinfo")
        .join(&preferences.timezone)
        .canonicalize()
        .map_err(|_| Error("invalid_timezone"))?;
    require(
        zone.starts_with("/usr/share/zoneinfo") && zone.is_file(),
        "invalid_timezone",
    )?;
    let mut magic = [0; 4];
    File::open(&zone)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|_| Error("invalid_timezone"))?;
    require(&magic == b"TZif", "invalid_timezone")?;
    let keymap = Command::new("/usr/bin/ckbcomp")
        .args([
            "-model",
            "pc105",
            "-layout",
            &preferences.keyboard,
            "-variant",
            &preferences.variant,
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error("keyboard_tools_unavailable"))?;
    require(
        keymap.status.success() && keymap.stdout.len() < 1024 * 1024,
        "keyboard_apply_failed",
    )?;
    let mut child = Command::new("/usr/bin/loadkeys")
        .args(["--unicode", "-C", "/dev/tty1"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("keyboard_apply_failed"))?;
    child
        .stdin
        .take()
        .ok_or(Error("keyboard_apply_failed"))?
        .write_all(&keymap.stdout)
        .map_err(|_| Error("keyboard_apply_failed"))?;
    require(
        child
            .wait()
            .map_err(|_| Error("keyboard_apply_failed"))?
            .success(),
        "keyboard_apply_failed",
    )?;
    apply_display_keymap(preferences)?;
    let pending = Path::new("/etc/localtime.oblivion-pending");
    if pending.symlink_metadata().is_ok() {
        fs::remove_file(pending).map_err(|_| Error("timezone_apply_failed"))?;
    }
    symlink(&zone, pending)
        .and_then(|_| fs::rename(pending, "/etc/localtime"))
        .map_err(|_| Error("timezone_apply_failed"))?;
    write(CURRENT, preferences)
}

fn apply_display_keymap(preferences: &Preferences) -> Result<()> {
    // Console-only integration labs retain their existing dependency set.
    if !Path::new("/etc/oblivion/foot.ini").exists() {
        return Ok(());
    }
    let keymap = Command::new("/usr/bin/xkbcli")
        .args([
            "compile-keymap",
            "--rules",
            "evdev",
            "--model",
            "pc105",
            "--layout",
            &preferences.keyboard,
            "--variant",
            &preferences.variant,
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error("keyboard_tools_unavailable"))?;
    require(
        keymap.status.success() && !keymap.stdout.is_empty() && keymap.stdout.len() < 1024 * 1024,
        "keyboard_apply_failed",
    )?;
    let pending = "/run/oblivion-keymap.pending";
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(pending)
        .map_err(|_| Error("keyboard_apply_failed"))?;
    file.write_all(&keymap.stdout)
        .and_then(|_| file.sync_all())
        .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o644)))
        .map_err(|_| Error("keyboard_apply_failed"))?;
    let generation = file
        .metadata()
        .map_err(|_| Error("keyboard_apply_failed"))?
        .ino();
    fs::rename(pending, "/run/oblivion-keymap.xkb").map_err(|_| Error("keyboard_apply_failed"))?;
    let active = Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", "oblivion-display.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error("keyboard_apply_failed"))?;
    if !active.success() {
        return Ok(());
    }
    let reload = Command::new("/usr/bin/systemctl")
        .args([
            "kill",
            "--kill-whom=main",
            "--signal=HUP",
            "oblivion-display.service",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error("keyboard_apply_failed"))?;
    require(reload.success(), "keyboard_apply_failed")?;
    // The next password form must not open until Cage applied this exact map.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if fs::read_to_string("/run/oblivion-display/keymap-applied")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            == Some(generation)
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(Error("keyboard_apply_failed"))
}

fn read(path: &str) -> Result<Option<Preferences>> {
    if !Path::new(path)
        .try_exists()
        .map_err(|_| Error("settings_unavailable"))?
    {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    trusted_file(Path::new(path))?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("settings_unavailable"))?;
    require(bytes.len() <= 4096, "invalid_settings")?;
    let preferences: Preferences =
        serde_json::from_slice(&bytes).map_err(|_| Error("invalid_settings"))?;
    preferences.validate().map_err(Error)?;
    Ok(Some(preferences))
}

fn write(path: &str, preferences: &Preferences) -> Result<()> {
    let path = Path::new(path);
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("settings_save_failed"))?;
    let bytes = serde_json::to_vec(preferences).map_err(|_| Error("invalid_settings"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error("settings_save_failed"))?;
    fs::rename(&pending, path).map_err(|_| Error("settings_save_failed"))?;
    File::open(path.parent().unwrap())
        .and_then(|file| file.sync_all())
        .map_err(|_| Error("settings_save_failed"))
}
