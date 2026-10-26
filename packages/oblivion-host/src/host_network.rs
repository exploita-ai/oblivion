use crate::storage::{Error, Result, require, trusted_file};
use oblivion_host::connections;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const RUNTIME: &str = "/run/NetworkManager/system-connections";
const ARCHIVE: &str = "/run/oblivion/general/profile/network-connections.json";
const LIMIT: u64 = 1024 * 1024;

pub fn snapshot() -> Result<connections::Snapshot> {
    let general = nmcli(&["-t", "-f", "STATE,CONNECTIVITY,WIFI", "general"])?;
    let general = connections::fields(general.trim()).map_err(Error)?;
    require(general.len() == 3, "invalid_network_metadata")?;
    let devices = nmcli(&["-t", "-f", "DEVICE,TYPE,STATE", "device", "status"])?;
    let devices = devices
        .lines()
        .filter_map(|line| {
            let fields = connections::fields(line).ok()?;
            if fields.len() != 3
                || !connections::device_name(&fields[0])
                || !matches!(fields[1].as_str(), "wifi" | "ethernet")
            {
                return None;
            }
            Some(connections::Device {
                name: fields[0].clone(),
                kind: fields[1].clone(),
                state: fields[2].clone(),
            })
        })
        .collect::<Vec<_>>();
    let mut access_points = Vec::new();
    if devices.iter().any(|device| device.kind == "wifi") {
        let wifi = nmcli(&[
            "-t",
            "-f",
            "DEVICE,BSSID,SSID,SIGNAL,SECURITY,IN-USE",
            "device",
            "wifi",
            "list",
            "--rescan",
            "no",
        ])?;
        for fields in wifi
            .lines()
            .filter_map(|line| connections::fields(line).ok())
        {
            if fields.len() != 6
                || fields[2].is_empty()
                || fields[2].len() > 32
                || !devices
                    .iter()
                    .any(|device| device.kind == "wifi" && device.name == fields[0])
            {
                continue;
            }
            let bssid = fields[1].split(':').collect::<Vec<_>>();
            if bssid.len() != 6
                || bssid
                    .iter()
                    .any(|part| part.len() != 2 || !part.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                continue;
            }
            let Ok(signal) = fields[3].parse::<u8>() else {
                continue;
            };
            access_points.push(connections::AccessPoint {
                device: fields[0].clone(),
                bssid: fields[1].clone(),
                ssid: fields[2].clone(),
                signal: signal.min(100),
                security: fields[4].clone(),
                active: fields[5] == "*",
            });
            if access_points.len() == 256 {
                break;
            }
        }
        access_points.sort_by(|a, b| {
            b.active
                .cmp(&a.active)
                .then(b.signal.cmp(&a.signal))
                .then(a.ssid.cmp(&b.ssid))
        });
    }
    // NM reports "full" even when its external connectivity checks are disabled.
    // Read the cached property only; never ask NM to contact a probe service.
    let checks = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--timeout=2",
            "get-property",
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            "ConnectivityCheckEnabled",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && output.stdout == b"b true\n");
    let internet = if general[0] == "disconnected" || general[0] == "asleep" {
        "offline"
    } else if general[1] == "full" && checks {
        "available"
    } else if general[0].starts_with("connected") {
        "local"
    } else {
        "unknown"
    };
    Ok(connections::Snapshot {
        internet: internet.into(),
        wifi_enabled: general[2] == "enabled",
        devices,
        access_points,
    })
}

pub fn change(command: connections::Command, persist: bool) -> Result<()> {
    let snapshot = snapshot()?;
    let connecting = matches!(&command, connections::Command::Connect { .. });
    match command {
        connections::Command::Scan => {
            require(
                snapshot.devices.iter().any(|device| device.kind == "wifi"),
                "wifi_unavailable",
            )?;
            nmcli(&["device", "wifi", "rescan"])?;
        }
        connections::Command::Radio { enabled } => {
            require(
                snapshot.devices.iter().any(|device| device.kind == "wifi"),
                "wifi_unavailable",
            )?;
            nmcli(&["radio", "wifi", if enabled { "on" } else { "off" }])?;
            if persist {
                write(
                    Path::new("/run/oblivion/general/profile/wifi-radio.json"),
                    if enabled { b"true" } else { b"false" },
                )?;
            }
        }
        connections::Command::Disconnect { device } => {
            require(
                snapshot.devices.iter().any(|item| item.name == device),
                "network_device_unavailable",
            )?;
            nmcli(&["device", "disconnect", &device])?;
        }
        connections::Command::Connect {
            device,
            bssid,
            password,
        } => {
            let device = snapshot
                .devices
                .iter()
                .find(|item| item.name == device)
                .ok_or(Error("network_device_unavailable"))?;
            if device.kind == "ethernet" {
                require(
                    bssid.is_none() && password.is_none(),
                    "invalid_network_request",
                )?;
                nmcli(&["device", "connect", &device.name])?;
                if persist {
                    save()?;
                }
                return Ok(());
            }
            let ap = snapshot
                .access_points
                .iter()
                .find(|ap| ap.device == device.name && Some(&ap.bssid) == bssid.as_ref())
                .ok_or(Error("wifi_network_unavailable"))?;
            let id = crate::storage::random_id()?;
            let profile = connections::wifi_profile(
                &id,
                &device.name,
                ap,
                password.as_ref().map(|value| value.as_str()).unwrap_or(""),
            )
            .map_err(Error)?;
            directory()?;
            let path = Path::new(RUNTIME).join(format!("oblivion-{id}.nmconnection"));
            write(&path, profile.as_bytes())?;
            let uuid = format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            );
            let connected = nmcli(&["connection", "load", path.to_str().unwrap()]).and_then(|_| {
                nmcli(&[
                    "connection",
                    "up",
                    "uuid",
                    &uuid,
                    "ifname",
                    &device.name,
                    "ap",
                    &ap.bssid,
                ])
            });
            if connected.is_err() {
                let _ = nmcli(&["connection", "delete", "uuid", &uuid]);
                if path.exists() {
                    fs::remove_file(path).map_err(|_| Error("network_cleanup_failed"))?;
                }
                return Err(Error("network_connection_failed"));
            }
        }
    }
    if persist && connecting {
        save()?;
    }
    Ok(())
}

fn nmcli(args: &[&str]) -> Result<String> {
    let mut child = Command::new("/usr/bin/timeout")
        .args([
            "--signal=KILL",
            "40",
            "/usr/bin/nmcli",
            "--wait",
            "30",
            "--colors",
            "no",
        ])
        .args(args)
        .env_clear()
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("network_manager_unavailable"))?;
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .unwrap()
        .take(LIMIT + 1)
        .read_to_end(&mut output);
    if read.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error("invalid_network_metadata"));
    }
    if output.len() > LIMIT as usize {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error("network_metadata_too_large"));
    }
    require(
        child
            .wait()
            .map_err(|_| Error("network_manager_unavailable"))?
            .success(),
        "network_operation_failed",
    )?;
    String::from_utf8(output).map_err(|_| Error("invalid_network_metadata"))
}

pub fn saved() -> Result<bool> {
    Path::new(ARCHIVE)
        .try_exists()
        .map_err(|_| Error("network_profile_unavailable"))
}

pub fn save() -> Result<()> {
    directory()?;
    let mut profiles = BTreeMap::new();
    let mut size = 0;
    for entry in fs::read_dir(RUNTIME).map_err(|_| Error("network_profile_unavailable"))? {
        let entry = entry.map_err(|_| Error("network_profile_unavailable"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error("network_profile_invalid"))?;
        validate_name(&name)?;
        let mut contents = Zeroizing::new(String::new());
        trusted_file(&entry.path())?
            .take(65537)
            .read_to_string(&mut contents)
            .map_err(|_| Error("network_profile_invalid"))?;
        size += contents.len();
        require(
            contents.len() <= 65536 && size <= LIMIT as usize / 2 && profiles.len() < 64,
            "network_profile_too_large",
        )?;
        profiles.insert(name, contents);
    }
    require(!profiles.is_empty(), "network_profile_empty")?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&profiles).map_err(|_| Error("network_profile_invalid"))?,
    );
    require(bytes.len() <= LIMIT as usize, "network_profile_too_large")?;
    let pending = Path::new(ARCHIVE).with_extension("pending");
    write(&pending, &bytes)?;
    fs::rename(pending, ARCHIVE).map_err(|_| Error("network_profile_save_failed"))?;
    File::open(Path::new(ARCHIVE).parent().unwrap())
        .and_then(|file| file.sync_all())
        .map_err(|_| Error("network_profile_save_failed"))
}

pub fn restore() -> Result<()> {
    let radio = Path::new("/run/oblivion/general/profile/wifi-radio.json");
    if radio
        .try_exists()
        .map_err(|_| Error("network_profile_unavailable"))?
    {
        let mut value = String::new();
        trusted_file(radio)?
            .take(16)
            .read_to_string(&mut value)
            .map_err(|_| Error("network_profile_invalid"))?;
        let enabled: bool =
            serde_json::from_str(&value).map_err(|_| Error("network_profile_invalid"))?;
        nmcli(&["radio", "wifi", if enabled { "on" } else { "off" }])?;
    }
    if !saved()? {
        return Ok(());
    }
    directory()?;
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(Path::new(ARCHIVE))?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("network_profile_unavailable"))?;
    require(bytes.len() <= LIMIT as usize, "network_profile_too_large")?;
    let profiles: BTreeMap<String, Zeroizing<String>> =
        serde_json::from_slice(&bytes).map_err(|_| Error("network_profile_invalid"))?;
    require(profiles.len() <= 64, "network_profile_too_large")?;
    // Validate the complete archive before changing NetworkManager's RAM files.
    for (name, contents) in &profiles {
        validate_name(name)?;
        require(contents.len() <= 65536, "network_profile_too_large")?;
    }
    for (name, contents) in &profiles {
        write(&Path::new(RUNTIME).join(name), contents.as_bytes())?;
    }
    let status = Command::new("/usr/bin/nmcli")
        .args(["--wait", "10", "connection", "reload"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error("network_profile_reload_failed"))?;
    require(status.success(), "network_profile_reload_failed")
}

fn directory() -> Result<()> {
    fs::create_dir_all(RUNTIME).map_err(|_| Error("network_profile_unavailable"))?;
    let metadata =
        fs::symlink_metadata(RUNTIME).map_err(|_| Error("network_profile_unavailable"))?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "network_profile_invalid",
    )?;
    fs::set_permissions(RUNTIME, fs::Permissions::from_mode(0o700))
        .map_err(|_| Error("network_profile_unavailable"))
}

fn validate_name(name: &str) -> Result<()> {
    require(
        name.len() <= 255
            && name.ends_with(".nmconnection")
            && !name.starts_with('.')
            && !name
                .bytes()
                .any(|b| b == b'/' || b == b'\\' || b.is_ascii_control()),
        "network_profile_invalid",
    )
}

fn write(path: &Path, contents: &[u8]) -> Result<()> {
    if path
        .try_exists()
        .map_err(|_| Error("network_profile_save_failed"))?
    {
        trusted_file(path)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("network_profile_save_failed"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error("network_profile_save_failed"))?;
    require(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0,
        "network_profile_invalid",
    )?;
    file.set_len(0)
        .and_then(|_| file.write_all(contents))
        .and_then(|_| file.sync_all())
        .map_err(|_| Error("network_profile_save_failed"))
}
