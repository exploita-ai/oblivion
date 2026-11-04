mod frontend_support;
use frontend_support::{Fixture, SAFE, accept, read, receive, reply};
use oblivion_cli::settings;
use oblivion_host::control;
use oblivion_wire::control::Operation;

fn observation() -> serde_json::Value {
    serde_json::json!({"idle_lock":{
        "preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
        "host":{"nonce":"e".repeat(32),"remaining_seconds":120,"closing":false},
        "safes":[{"opening":{"slot":4,"safe_id":SAFE,"nonce":"f".repeat(32)},"remaining_seconds":60,"closing":false}],
        "last_error":null,"storage":"saved-encrypted","writable":true
    }})
}

#[test]
fn partial_idle_update_preserves_the_host_timer_and_emits_the_complete_new_observation() {
    let (fixture, listener) = Fixture::new();
    let mut final_state = observation();
    final_state["idle_lock"]["preferences"]["safe_minutes"] = serde_json::json!(0);
    final_state["idle_lock"]["safes"][0]["remaining_seconds"] = serde_json::Value::Null;
    let expected = final_state["idle_lock"].clone();
    let server = std::thread::spawn(move || {
        let mut changed = false;
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            assert!(request.session.is_none() && request.expected_session.is_none());
            match request.operation {
                Operation::Status => {
                    reply(
                        &mut stream,
                        &if changed {
                            final_state.to_string()
                        } else {
                            observation().to_string()
                        },
                        None,
                    );
                    if changed {
                        break;
                    }
                }
                Operation::IdleSettings => {
                    assert!(!changed);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                        serde_json::json!({"version":1,"safe_minutes":0,"host_minutes":30})
                    );
                    changed = true;
                    reply(&mut stream, "", None);
                }
                operation => panic!("Unexpected settings operation: {operation:?}"),
            }
        }
    });
    let command =
        settings::parse(&["idle", "--safe-minutes", "0", "--json"].map(String::from)).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        settings::execute(
            &mut control::Client::remote(&fixture.path),
            command,
            &mut output
        )
        .unwrap(),
        0
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
        expected
    );
    server.join().unwrap();
}

#[test]
fn malformed_idle_observations_fail_without_echoing_peer_values_or_writing_preferences() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        assert_eq!(read(&mut stream).operation, Operation::Status);
        let mut source = observation();
        source["idle_lock"]["storage"] = serde_json::json!("SETTINGS_PRIVATE_CANARY");
        reply(&mut stream, &source.to_string(), None);
    });
    let command = settings::parse(&["idle", "--safe-minutes", "0"].map(String::from)).unwrap();
    let mut output = Vec::new();
    let error = settings::execute(
        &mut control::Client::remote(&fixture.path),
        command,
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "invalid_idle_status");
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(error.source().is_none() && output.is_empty());
    server.join().unwrap();
}

#[test]
fn timer_bounds_and_duplicate_options_are_checked_before_the_launcher_starts_a_vm() {
    for args in [
        vec!["settings", "idle", "--safe-minutes", "1441"],
        vec!["settings", "idle", "--host-minutes", "65536"],
        vec![
            "settings",
            "idle",
            "--safe-minutes",
            "15",
            "--safe-minutes",
            "0",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("invalid_idle_preferences")
                || error.contains("Unknown or duplicate automatic-lock option")
        );
    }
}

#[test]
fn compiled_activity_uses_the_opening_body_slot_without_runtime_startup_or_expected_safe() {
    use std::io::Write;
    use std::process::Stdio;

    let (fixture, listener) = Fixture::new();
    let body = serde_json::to_vec(&oblivion_wire::idle::Activity {
        host: "e".repeat(32),
        safe: Some(oblivion_wire::idle::Opening {
            slot: oblivion_host::scope::Slot::try_from(4).unwrap(),
            safe_id: SAFE.into(),
            nonce: "f".repeat(32),
        }),
    })
    .unwrap();
    let expected = body.clone();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let (request, body) = receive(&mut stream);
        assert_eq!(request.operation, Operation::Activity);
        assert_eq!(request.slot.index(), 4);
        assert!(request.session.is_none() && request.expected_session.is_none());
        assert_eq!(*body, expected);
        reply(&mut stream, "", None);
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
        .arg("activity")
        .env_clear()
        .env("OBLIVION_CONTROL_SOCKET", &fixture.path)
        .env("OBLIVION_SAFE_SLOT", "7")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&body).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    server.join().unwrap();
}
