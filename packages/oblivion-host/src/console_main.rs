use oblivion_host::terminal::Terminal;
use oblivion_host::{control, terminal};
use std::io::{Read, Write};
use std::process::Command;
use std::time::Duration;

fn main() {
    let result = run();
    match result {
        Ok(terminal::Action::New) => std::process::exit(10),
        Ok(_) => {}
        Err(_) => {
            eprintln!("console_operation_failed");
            std::process::exit(1);
        }
    }
}

fn run() -> control::Result<terminal::Action> {
    control::protect()?;
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 1000 {
        return Err("linux_nonroot_manager_required".into());
    }
    if std::env::args().nth(1).as_deref() == Some("--screen") {
        oblivion_host::chat_screen::bridge(control::console()?)?;
        // Detaching a view never closes a session. The trusted manager owns lock.
        return Ok(terminal::Action::Sessions);
    }
    if std::env::args().nth(1).as_deref() == Some("--terminal-screen") {
        oblivion_host::chat_screen::bridge_terminal(control::terminal()?)?;
        return Ok(terminal::Action::Sessions);
    }
    let mut terminal = Terminal::open()?;
    if std::env::args().nth(1).as_deref() == Some("--documents") {
        documents()?.wait()?;
        return Ok(terminal::Action::Sessions);
    }
    let (observed, observations) = std::sync::mpsc::sync_channel(1);
    let (stop, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        loop {
            let header = (|| -> control::Result<terminal::SessionHeader> {
                #[derive(serde::Deserialize)]
                struct Status {
                    active_session: Option<String>,
                    general_readonly: bool,
                    network_status: oblivion_host::network::Observation,
                }
                let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
                let id = status.active_session.ok_or("session_not_open")?;
                if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("invalid_session_id".into());
                }
                if !matches!(
                    status.network_status.label.as_str(),
                    "NOT STARTED"
                        | "CONNECTING"
                        | "TOR READY"
                        | "SOCKS5 READY"
                        | "OFFLINE"
                        | "STATUS UNKNOWN"
                ) || !matches!(
                    status.network_status.host_link.as_str(),
                    "CONNECTED" | "OFFLINE" | "STATUS UNKNOWN"
                ) {
                    return Err("invalid_network_status".into());
                }
                Ok(terminal::SessionHeader {
                    session: id[..8].into(),
                    ephemeral: status.general_readonly,
                    network: status.network_status,
                    observed: std::time::Instant::now(),
                })
            })();
            if let Ok(header) = header {
                let _ = observed.try_send(header);
            }
            if !matches!(
                stopped.recv_timeout(Duration::from_secs(3)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                break;
            }
        }
    });
    let result = terminal::bridge_observed(
        &mut terminal,
        control::console()?,
        |terminal, stream, parser| {
            let mut child = documents()?;
            let mut bytes = [0; 8192];
            // Keep consuming the bounded terminal screen while OpenTUI owns input.
            // Otherwise a long response could fill the serial socket and stall chat.
            while child.try_wait()?.is_none() {
                match stream.read(&mut bytes) {
                    Ok(0) => {
                        child.kill()?;
                        child.wait()?;
                        return Err("console_closed".into());
                    }
                    Ok(size) => {
                        parser.process(&bytes[..size]);
                        if parser.callbacks_mut().take_ready() {
                            let (rows, cols) = terminal.size();
                            stream.write_all(format!("\x1b[8;{};{cols}t", rows - 3).as_bytes())?;
                        }
                        parser.callbacks_mut().write_replies(stream)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(error) => {
                        child.kill()?;
                        child.wait()?;
                        return Err(error.into());
                    }
                }
            }
            let state: serde_json::Value =
                serde_json::from_str(&control::request("status", None, &[])?)?;
            Ok(state["session_open"] == true)
        },
        Some(&observations),
    );
    let _ = stop.send(());
    control::request("close", None, &[])?;
    result
}

fn documents() -> control::Result<std::process::Child> {
    Ok(Command::new("/usr/bin/oblivion-manager")
        .arg("--documents")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/run/oblivion-manager")
        .env("TMPDIR", "/run/oblivion-manager")
        .env("BUN_TMPDIR", "/run/oblivion-manager")
        .env("OTUI_ASSET_ROOT", "/usr/lib/oblivion/manager")
        .env(
            "TERM",
            std::env::var("TERM").unwrap_or_else(|_| "linux".into()),
        )
        .env("LANG", "C.UTF-8")
        .spawn()?)
}
