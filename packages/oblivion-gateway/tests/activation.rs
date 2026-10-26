#![cfg(feature = "lab-emulation")]

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const KEY: &str = "synthetic-provider-key-from-private-channel";
const TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Process(Child);

impl Process {
    fn finish(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "broker did not terminate");
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(!String::from_utf8_lossy(&stdout).contains(KEY));
        assert!(!String::from_utf8_lossy(&stderr).contains(KEY));
        assert!(!String::from_utf8_lossy(&stderr).contains(TOKEN));
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch() -> (Process, UnixStream, SocketAddr) {
    launch_binary(env!("CARGO_BIN_EXE_oblivion-api"))
}

fn launch_binary(binary: &str) -> (Process, UnixStream, SocketAddr) {
    let (control, inherited) = UnixStream::pair().unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    // Duplicate above the destination range, avoiding 3/4 aliasing in pre_exec.
    let duplicate = |fd| {
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
        assert!(copy >= 10);
        unsafe { OwnedFd::from_raw_fd(copy) }
    };
    let inherited = duplicate(inherited.as_raw_fd());
    let listener = duplicate(listener.as_raw_fd());
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("HTTPS_PROXY", "http://192.0.2.1:9")
        .env("ALL_PROXY", "http://192.0.2.1:9")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(inherited.as_raw_fd(), 3) != 3 || libc::dup2(listener.as_raw_fd(), 4) != 4
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    (Process(command.spawn().unwrap()), control, address)
}

fn ready(control: &mut UnixStream, process: &mut Process) {
    let config = json!({"api_key":KEY,"session_token":TOKEN,"socks":"127.0.0.1:1"});
    writeln!(control, "{config}").unwrap();
    let mut line = String::new();
    BufReader::new(control).read_line(&mut line).unwrap();
    if line.is_empty() {
        let output = process.finish();
        panic!(
            "startup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(line, "{\"ready\":true}\n");
}

fn request(address: SocketAddr, token: &str) -> String {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let body = r#"{"model":"abliterated-model","messages":[{"role":"user","content":"test"}],"stream":true}"#;
    write!(socket, "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(!response.contains(KEY));
    response
}

#[test]
fn inherited_control_grants_once_and_eof_revokes_without_logs() {
    let (mut process, mut control, address) = launch();
    ready(&mut control, &mut process);
    assert!(request(address, "invalid").starts_with("HTTP/1.1 401"));
    // NO_PROXY=* and a competing HTTPS_PROXY must not bypass the closed SOCKS
    // endpoint supplied by the controller. There is no DNS/direct fallback.
    assert!(request(address, TOKEN).starts_with("HTTP/1.1 502"));
    drop(control);
    let output = process.finish();
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn control_byte_and_sigterm_both_revoke_the_process() {
    for signal in [false, true] {
        let (mut process, mut control, address) = launch();
        ready(&mut control, &mut process);
        if signal {
            assert_eq!(
                unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
                0
            );
        } else {
            control.write_all(b"revoke").unwrap();
        }
        let output = process.finish();
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(TcpStream::connect(address).is_err());
    }
}

#[test]
fn invalid_startup_has_no_credential_or_payload_diagnostics() {
    for (field, value) in [
        ("origin", json!("https://example.com")),
        ("session_token", json!("short")),
        ("socks", json!("192.0.2.1:9050")),
        ("api_key", json!("secret\r\nInjected: header")),
    ] {
        let (mut process, mut control, _) = launch();
        let mut config = json!({"api_key":KEY,"session_token":TOKEN,"socks":"127.0.0.1:1"});
        config[field] = value;
        writeln!(control, "{config}").unwrap();
        let output = process.finish();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"oblivion-api: service_failed\n");
    }
}

#[test]
fn missing_inherited_sockets_fail_before_runtime_allocates_descriptors() {
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-api"))
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-api: service_failed\n");
}

#[test]
fn egress_private_configuration_and_revocation_do_not_log_secrets() {
    for revoke in [0, 1, 2] {
        let (mut process, mut control, address) =
            launch_binary(env!("CARGO_BIN_EXE_oblivion-egress"));
        let config = json!({"transport":{"mode":"socks5","endpoint":"192.0.2.1:1080","authentication":{"username":"fixture-user","password":"fixture-proxy-secret"}},"session_token":TOKEN});
        writeln!(control, "{config}").unwrap();
        let mut line = String::new();
        BufReader::new(&mut control).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"ready\":true}\n");
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 255]);
        if revoke == 1 {
            control.write_all(b"revoke").unwrap();
        }
        if revoke == 2 {
            assert_eq!(
                unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
                0
            );
        }
        if revoke == 0 {
            drop(control);
        }
        let output = process.finish();
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(TcpStream::connect(address).is_err());
    }
}

#[test]
fn egress_invalid_configuration_and_missing_descriptors_fail_without_secrets() {
    let (mut process, mut control, _) = launch_binary(env!("CARGO_BIN_EXE_oblivion-egress"));
    let config = json!({"transport":{"mode":"socks5","endpoint":"127.0.0.1:9050","authentication":{"username":"fixture-user","password":"fixture-proxy-secret"}},"session_token":TOKEN});
    writeln!(control, "{config}").unwrap();
    let output = process.finish();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-egress: service_failed\n");
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-egress"))
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-egress: service_failed\n");
}

#[test]
fn egress_reads_a_full_private_policy_and_denies_unknown_tools_without_logs() {
    let (mut process, mut control, address) = launch_binary(env!("CARGO_BIN_EXE_oblivion-egress"));
    control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let rules = (0..128)
        .map(|index| {
            json!({
                "destination": format!("site-{index}.example.com"), "port": 443, "action": "deny"
            })
        })
        .collect::<Vec<_>>();
    let config = json!({
        "transport": {"mode": "tor"}, "session_token": TOKEN,
        "tools": {"session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy": {"version": 1, "rules": rules}},
    }).to_string();
    assert!(config.len() > 4096 && config.len() < 128 * 1024);
    writeln!(control, "{config}").unwrap();
    let mut line = String::new();
    BufReader::new(&mut control).read_line(&mut line).unwrap();
    assert_eq!(line, "{\"ready\":true}\n");
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(&[5, 1, 2]).unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 2]);
    let mut auth = b"\x01\x0eoblivion-tools\x40".to_vec();
    auth.extend_from_slice(TOKEN.as_bytes());
    client.write_all(&auth).unwrap();
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [1, 0]);
    client
        .write_all(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 2);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    drop(control);
    let output = process.finish();
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[test]
fn egress_rejects_an_oversized_private_frame_without_logs() {
    let (mut process, mut control, _) = launch_binary(env!("CARGO_BIN_EXE_oblivion-egress"));
    control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let result = control.write_all(&vec![b' '; 128 * 1024 + 1]);
    assert!(
        result.is_ok()
            || result.is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ))
    );
    let output = process.finish();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-egress: service_failed\n");
}

#[test]
fn tools_private_configuration_authenticates_and_every_control_exit_revokes() {
    for revoke in [0, 1, 2] {
        let (mut process, mut control, address) =
            launch_binary(env!("CARGO_BIN_EXE_oblivion-tools"));
        let config = json!({"session_token": TOKEN, "socks": "127.0.0.1:1"});
        writeln!(control, "{config}").unwrap();
        let mut line = String::new();
        BufReader::new(&mut control).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"ready\":true}\n");
        for (token, expected) in [("invalid", "HTTP/1.1 407"), (TOKEN, "HTTP/1.1 502")] {
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let auth = STANDARD.encode(format!("oblivion-tools:{token}"));
            write!(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n").unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.starts_with(expected), "{response}");
            assert!(!response.contains(TOKEN));
        }
        // Leave an incomplete request open: revocation must also close an
        // accepted connection whose HTTP headers have not finished arriving.
        let mut pending = TcpStream::connect(address).unwrap();
        pending
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        pending
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
            .unwrap();
        if revoke == 1 {
            control.write_all(b"revoke").unwrap();
        }
        if revoke == 2 {
            assert_eq!(
                unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
                0
            );
        }
        if revoke == 0 {
            drop(control);
        }
        let output = process.finish();
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(TcpStream::connect(address).is_err());
        let closed = pending.read(&mut [0]);
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        );
    }
}

#[test]
fn tools_reject_invalid_credentials_frames_and_missing_descriptors_without_logs() {
    for (field, value) in [
        ("api_key", json!(KEY)),
        ("session_token", json!("short")),
        ("socks", json!("192.0.2.1:9051")),
        ("socks", json!("127.0.0.1:0")),
    ] {
        let (mut process, mut control, _) = launch_binary(env!("CARGO_BIN_EXE_oblivion-tools"));
        let mut config = json!({"session_token": TOKEN, "socks": "127.0.0.1:1"});
        config[field] = value;
        writeln!(control, "{config}").unwrap();
        let output = process.finish();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"oblivion-tools: service_failed\n");
    }
    let (mut process, mut control, _) = launch_binary(env!("CARGO_BIN_EXE_oblivion-tools"));
    control.write_all(&vec![b' '; 4097]).unwrap();
    let output = process.finish();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-tools: service_failed\n");
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-tools"))
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"oblivion-tools: service_failed\n");
}
