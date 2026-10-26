//! NetworkManager metadata and requests. Secrets never appear in command arguments.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Scan,
    Radio {
        enabled: bool,
    },
    Connect {
        device: String,
        bssid: Option<String>,
        password: Option<Zeroizing<String>>,
    },
    Disconnect {
        device: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub internet: String,
    pub wifi_enabled: bool,
    pub devices: Vec<Device>,
    pub access_points: Vec<AccessPoint>,
}

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub kind: String,
    pub state: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccessPoint {
    pub device: String,
    pub bssid: String,
    pub ssid: String,
    pub signal: u8,
    pub security: String,
    pub active: bool,
}

pub fn fields(line: &str) -> Result<Vec<String>, &'static str> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in line.chars() {
        if character.is_control() {
            return Err("invalid_network_metadata");
        }
        if escaped {
            if !matches!(character, ':' | '\\') {
                return Err("invalid_network_metadata");
            }
            fields.last_mut().unwrap().push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            ':' => fields.push(String::new()),
            _ => fields.last_mut().unwrap().push(character),
        }
    }
    if escaped {
        return Err("invalid_network_metadata");
    }
    Ok(fields)
}

pub fn device_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

pub fn security(value: &str) -> Option<&'static str> {
    if value.contains("802.1X") || value.contains("EAP") {
        return None;
    }
    if value.contains("WPA2") {
        return Some("wpa-psk");
    }
    if value.contains("WPA3") {
        return Some("sae");
    }
    if value == "--" || value.is_empty() {
        return Some("open");
    }
    None
}

pub fn wifi_profile(
    id: &str,
    device: &str,
    ap: &AccessPoint,
    password: &str,
) -> Result<Zeroizing<String>, &'static str> {
    if id.len() != 32
        || !id.bytes().all(|c| c.is_ascii_hexdigit())
        || !device_name(device)
        || ap.ssid.is_empty()
        || ap.ssid.len() > 32
        || ap.ssid.chars().any(char::is_control)
    {
        return Err("invalid_network_request");
    }
    let mode = security(&ap.security).ok_or("wifi_security_unsupported")?;
    let valid = match mode {
        "open" => password.is_empty(),
        "sae" => (1..=63).contains(&password.len()),
        _ => {
            (8..=63).contains(&password.len())
                || password.len() == 64 && password.bytes().all(|c| c.is_ascii_hexdigit())
        }
    };
    if !valid || password.chars().any(char::is_control) {
        return Err("invalid_wifi_password");
    }
    let mut profile = Zeroizing::new(format!(
        "[connection]\nid=Oblivion Wi-Fi {}\nuuid={}-{}-{}-{}-{}\ntype=wifi\ninterface-name={device}\nautoconnect=true\n\n[wifi]\nmode=infrastructure\nssid={}\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=disabled\n",
        &id[..8],
        &id[..8],
        &id[8..12],
        &id[12..16],
        &id[16..20],
        &id[20..],
        ap.ssid
            .bytes()
            .map(|byte| format!("{byte};"))
            .collect::<String>(),
    ));
    if mode != "open" {
        profile.push_str(&format!("\n[wifi-security]\nkey-mgmt={mode}\npsk="));
        // GLib keyfile escaping, including leading spaces. No raw newlines are accepted.
        for character in password.chars() {
            match character {
                '\\' => profile.push_str("\\\\"),
                ' ' => profile.push_str("\\s"),
                _ => profile.push(character),
            }
        }
        profile.push('\n');
    }
    Ok(profile)
}
