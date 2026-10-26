use crate::storage::{Error, Result, require, trusted_file};
use serde::Deserialize;
use std::path::Path;
use std::process::{Command, Stdio};

const HELPER: &str = "/usr/lib/oblivion/hardware/debug.py";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    Status,
    EnableSsh,
    DisableSsh,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: Action,
}

pub fn available() -> bool {
    trusted_file(Path::new(HELPER)).is_ok()
}

pub fn run(payload: &[u8]) -> Result<()> {
    require(available(), "debug_image_required")?;
    let request: Request =
        serde_json::from_slice(payload).map_err(|_| Error("invalid_debug_request"))?;
    let action = match request.action {
        Action::Status => "status",
        Action::EnableSsh => "enable-ssh",
        Action::DisableSsh => "disable-ssh",
    };
    let output = Command::new("/usr/bin/python3")
        .args([HELPER, action])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error("debug_unavailable"))?;
    require(
        output.status.success() && output.stdout.len() <= 16384,
        "debug_operation_failed",
    )?;
    let text = std::str::from_utf8(&output.stdout).map_err(|_| Error("invalid_debug_response"))?;
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_fixed_diagnostic_actions_are_accepted() {
        assert!(serde_json::from_str::<Request>(r#"{"action":"enable-ssh"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"action":"shell"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"action":"status","command":"id"}"#).is_err());
    }
    #[test]
    fn a_normal_image_cannot_enable_debug_access() {
        assert!(!available());
        assert_eq!(
            run(br#"{"action":"enable-ssh"}"#).err().unwrap().0,
            "debug_image_required"
        );
    }
}
