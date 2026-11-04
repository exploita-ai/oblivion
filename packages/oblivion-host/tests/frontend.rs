use oblivion_cli::controller::{self, Command};
use oblivion_host::{control, scope};
use oblivion_wire::control::{HEADER_LIMIT, Operation, RESPONSE_LIMIT, Request, Response};
use oblivion_wire::frame;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> (Self, UnixListener) {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        let directory =
            PathBuf::from("/tmp").join(format!("ob-frontend-{:016x}", u64::from_be_bytes(bytes)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (Self { directory, path }, listener)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn read(stream: &mut UnixStream) -> Request<scope::Slot> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header: serde_json::Value =
        serde_json::from_slice(&frame::read(stream, 1..=HEADER_LIMIT).unwrap()).unwrap();
    assert_eq!(
        header.as_object_mut().unwrap().remove("version"),
        Some(serde_json::json!(1))
    );
    let request: Request<scope::Slot> = serde_json::from_value(header).unwrap();
    assert_eq!(request.secret_len, 0);
    request
}
fn reply(stream: &mut UnixStream, output: &str, error: Option<&str>) {
    frame::write(
        stream,
        &serde_json::to_vec(&Response {
            ok: error.is_none(),
            output,
            error,
        })
        .unwrap(),
        1..=RESPONSE_LIMIT,
    )
    .unwrap();
}
fn state() -> serde_json::Value {
    serde_json::json!({
        "app_open":true,"app_mode":"persistent","general_present":true,
        "general_incomplete":false,"general_bytes":8589934592_u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},
        "open_sessions":[{"slot":4,"id":SAFE,"mode":"documents"}],
        "agent_safes":[],"platform_details":{"preserve_this_field":true}
    })
}

#[test]
fn common_status_executor_preserves_full_json_through_the_real_authenticated_unix_adapter() {
    let (fixture, listener) = Fixture::new();
    let source = state().to_string();
    let expected = source.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::Status);
        assert_eq!(request.slot.index(), 0);
        assert!(request.session.is_none() && request.expected_session.is_none());
        reply(&mut stream, &source, None);
    });
    let command = Command::parse(&["status".into(), "--json".into()])
        .unwrap()
        .unwrap();
    let mut output = Vec::new();
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            command,
            &mut output
        )
        .unwrap(),
        0
    );
    assert_eq!(String::from_utf8(output).unwrap(), format!("{expected}\n"));
    server.join().unwrap();
}

#[test]
fn common_safe_listing_uses_the_portable_model_and_keeps_native_child_states() {
    let (fixture, listener) = Fixture::new();
    let mut source = state();
    source["sessions"] = serde_json::json!([SAFE, SAFE]);
    source["agent_safes"] = serde_json::json!([
        {"id":"b".repeat(32),"ephemeral":true,"state":"awaiting-start"},
        {"id":"c".repeat(32),"ephemeral":true,"state":"failed"},
        {"id":"d".repeat(32),"ephemeral":false,"state":"awaiting-start"}
    ]);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &source.to_string(), None);
    });
    let mut output = Vec::new();
    controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::Safes,
        &mut output,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!(
            "GB\t{SAFE}\tdocuments\n{b}\t{b}\tawaiting-start\n{c}\t{c}\tcreation-failed\n",
            b = "b".repeat(32),
            c = "c".repeat(32)
        )
    );
    server.join().unwrap();
}

#[test]
fn common_close_uses_fresh_safe_resolution_explicit_slot_and_expected_identity() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &state().to_string(), None);
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::Close);
        assert_eq!(request.slot.index(), 4);
        assert_eq!(request.expected_session.as_deref(), Some(SAFE));
        assert!(request.session.is_none());
        reply(&mut stream, "", None);
    });
    let mut output = Vec::new();
    controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::Close { name: "GB".into() },
        &mut output,
    )
    .unwrap();
    assert!(output.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn common_close_refuses_ambiguous_names_and_closed_safes_before_any_mutation() {
    for ambiguous in [true, false] {
        let (fixture, listener) = Fixture::new();
        let mut source = state();
        if ambiguous {
            source["sessions"] = serde_json::json!([SAFE, "b".repeat(32)]);
            source["session_titles"]["b".repeat(32)] = serde_json::json!("GB");
        } else {
            source["open_sessions"] = serde_json::json!([]);
        }
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read(&mut stream).operation, Operation::Status);
            reply(&mut stream, &source.to_string(), None);
        });
        let error = controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::Close { name: "GB".into() },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            if ambiguous {
                "Ambiguous Safe name. Use its full identifier."
            } else {
                "Safe is already locked"
            }
        );
        server.join().unwrap();
    }
}

#[test]
fn the_common_frontend_keeps_unix_socket_authentication_and_sanitized_rejections() {
    let (fixture, _listener) = Fixture::new();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::StatusJson,
            &mut Vec::new()
        )
        .unwrap_err()
        .to_string(),
        "untrusted_runtime_socket"
    );
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(
            &mut stream,
            "must not be shown",
            Some("private /vault/path or arbitrary guest text"),
        );
    });
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::StatusJson,
            &mut Vec::new()
        )
        .unwrap_err()
        .to_string(),
        "operation_rejected"
    );
    server.join().unwrap();
}

#[test]
fn common_read_model_rejects_peer_values_with_a_static_error() {
    for invalid_slot in [false, true] {
        let (fixture, listener) = Fixture::new();
        let mut source = state();
        if invalid_slot {
            source["open_sessions"][0]["slot"] = serde_json::json!(33);
        } else {
            source["app_mode"] = serde_json::json!("SYNTHETIC_PRIVATE_STATE_CANARY");
        }
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read(&mut stream).operation, Operation::Status);
            reply(&mut stream, &source.to_string(), None);
        });
        let error = controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::Safes,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_controller_state");
        assert!(!format!("{error:?}").contains("CANARY"));
        server.join().unwrap();
    }
}

#[test]
fn the_compiled_launcher_uses_shared_metadata_grammar_before_runtime_start() {
    for args in [vec!["status"], vec!["safes", "extra"], vec!["close"]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "Oblivion: Use oblivion status --json, safes, or close NAME\n"
        );
    }
}

#[test]
fn malformed_response_envelopes_do_not_expose_peer_json_in_frontend_errors() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        let body = serde_json::to_vec(&serde_json::json!({"ok":true,"output":"", "error":null,"SYNTHETIC_PRIVATE_ENVELOPE_CANARY":true})).unwrap();
        frame::write(&mut stream, &body, 1..=RESPONSE_LIMIT).unwrap();
    });
    let error = controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::StatusJson,
        &mut Vec::new(),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(
        !message.is_empty()
            && message.len() <= 80
            && message
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    );
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(error.source().is_none());
    server.join().unwrap();
}
