use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use zeroize::Zeroizing;

// Low-level trusted-manager client. Password entry is supplied by the future
// trusted TUI, or a private pipe in the synthetic lab; never by command arguments.
fn main() {
    if execute().is_err() {
        eprintln!("control_request_failed");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
        {
            return Err("dump_protection_failed".into());
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let operation = args.first().ok_or("missing_operation")?;
    if args.len()
        != if matches!(
            operation.as_str(),
            "open" | "open-documents" | "discard-session-pending"
        ) {
            2
        } else {
            1
        }
    {
        return Err("invalid_arguments".into());
    }
    let needs_secret = matches!(
        operation.as_str(),
        "init-general"
            | "prepare-usb"
            | "unlock"
            | "unlock-ephemeral"
            | "create"
            | "rename-session"
            | "debug"
            | "open"
            | "open-documents"
            | "set-api-key"
            | "api-keys"
            | "egress"
            | "network-policy"
            | "transfers"
            | "settings"
            | "browse"
    );
    let limit = if matches!(
        operation.as_str(),
        "api-keys"
            | "egress"
            | "network-policy"
            | "transfers"
            | "settings"
            | "browse"
            | "prepare-usb"
    ) {
        4096
    } else {
        1024
    };
    let mut secret = Zeroizing::new(Vec::with_capacity(limit + 1));
    if needs_secret {
        std::io::stdin()
            .take(limit as u64 + 1)
            .read_to_end(&mut secret)?;
    }
    if secret.len() > limit {
        return Err("secret_too_large".into());
    }
    let header = serde_json::to_vec(&json!({
        "operation": operation, "session": args.get(1), "secret_len": secret.len(),
    }))?;
    let mut stream = UnixStream::connect("/run/oblivion-control.sock")?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&(header.len() as u32).to_be_bytes())?;
    stream.write_all(&header)?;
    stream.write_all(&secret)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.take(1024 * 1024).read_to_end(&mut response)?;
    let response: serde_json::Value = serde_json::from_slice(&response)?;
    if response.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        return Err("operation_rejected".into());
    }
    print!(
        "{}",
        response
            .get("output")
            .and_then(|value| value.as_str())
            .ok_or("invalid_output")?
    );
    Ok(())
}
