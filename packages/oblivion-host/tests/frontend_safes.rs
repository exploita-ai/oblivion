mod frontend_support;
use frontend_support::{Fixture, RunTerminal, SAFE, accept, receive, reply, state};
use oblivion_cli::safe;
use oblivion_host::scope;
use oblivion_wire::control::Operation;

#[test]
fn offline_open_uses_a_free_slot_and_pins_the_safe_without_starting_an_agent() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => {
                    let mut source = state();
                    source["open_sessions"] =
                        serde_json::json!([{"slot":0,"id":"b".repeat(32),"mode":"agent"}]);
                    reply(&mut stream, &source.to_string(), None);
                }
                Operation::OpenDocuments => {
                    assert_eq!(request.slot.index(), 1);
                    assert_eq!(request.session.as_deref(), Some(SAFE));
                    assert!(request.expected_session.is_none());
                    assert_eq!(secret.as_slice(), b"SYNTHETIC_PASSWORD_CANARY");
                    reply(&mut stream, "", None);
                }
                Operation::PinSafe => {
                    assert_eq!(request.slot.index(), 1);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none() && secret.is_empty());
                    reply(&mut stream, "", None);
                    break;
                }
                operation => panic!("Unexpected offline-open operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = safe::parse(&["open", "GB"].map(String::from)).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        safe::execute(&mut terminal, command, &mut output).unwrap(),
        0
    );
    assert_eq!(terminal.prompts, ["Safe password"]);
    assert!(terminal.attached.is_empty());
    assert_eq!(scope::current().index(), 0);
    assert!(!String::from_utf8(output).unwrap().contains("CANARY"));
    server.join().unwrap();
}

#[test]
fn rename_uses_the_catalog_when_slots_are_full_and_the_active_slot_for_ram_titles() {
    for temporary in [false, true] {
        let (fixture, listener) = Fixture::new();
        let server = std::thread::spawn(move || {
            loop {
                let mut stream = accept(&listener);
                let (request, secret) = receive(&mut stream);
                match request.operation {
                    Operation::Status => {
                        let mut source = state();
                        if temporary {
                            source["app_mode"] = serde_json::json!("ram-only");
                            source["sessions"] = serde_json::json!([]);
                        } else {
                            source["open_sessions"] = serde_json::json!((0..scope::LIMIT).map(|index| serde_json::json!({"slot":index,"id":format!("{index:032x}"),"mode":"agent"})).collect::<Vec<_>>());
                        }
                        reply(&mut stream, &source.to_string(), None);
                    }
                    Operation::RenameSession => {
                        assert_eq!(request.slot.index(), if temporary { 4 } else { 0 });
                        assert_eq!(
                            request.expected_session.as_deref(),
                            temporary.then_some(SAFE)
                        );
                        assert!(request.session.is_none());
                        assert_eq!(
                            serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                            serde_json::json!({"id":SAFE,"title":"Research"})
                        );
                        reply(&mut stream, "", None);
                        break;
                    }
                    operation => panic!("Unexpected rename operation: {operation:?}"),
                }
            }
        });
        let mut terminal = RunTerminal::new(&fixture.path);
        let command = safe::parse(&["rename", "GB", "Research"].map(String::from)).unwrap();
        assert_eq!(
            safe::execute(&mut terminal, command, &mut Vec::new()).unwrap(),
            0
        );
        assert!(terminal.prompts.is_empty() && terminal.attached.is_empty());
        assert_eq!(scope::current().index(), 0);
        server.join().unwrap();
    }
}

#[test]
fn storage_growth_uses_a_free_maintenance_slot_and_sends_the_password_privately() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => {
                    let mut source = state();
                    source["open_sessions"] =
                        serde_json::json!([{"slot":0,"id":"b".repeat(32),"mode":"agent"}]);
                    reply(&mut stream, &source.to_string(), None);
                }
                Operation::SessionStorage => {
                    assert_eq!(request.slot.index(), 1);
                    assert!(request.session.is_none() && request.expected_session.is_none());
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                        serde_json::json!({"action":"grow","id":SAFE,"mib":4096,"password":"SYNTHETIC_PASSWORD_CANARY"})
                    );
                    reply(&mut stream, "", None);
                    break;
                }
                operation => panic!("Unexpected growth operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = safe::parse(&["grow", "GB", "4096"].map(String::from)).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        safe::execute(&mut terminal, command, &mut output).unwrap(),
        0
    );
    assert_eq!(terminal.prompts, ["Safe password"]);
    assert!(terminal.attached.is_empty());
    assert_eq!(scope::current().index(), 0);
    assert!(!String::from_utf8(output).unwrap().contains("CANARY"));
    server.join().unwrap();
}

#[test]
fn safe_syntax_and_capacity_are_checked_by_the_compiled_launcher_before_startup() {
    for args in [
        vec!["safe", "open"],
        vec!["safe", "rename", "GB", " invalid "],
        vec!["safe", "grow", "GB", "127"],
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
            error.contains("Use safe open NAME")
                || error.contains("invalid_session_title")
                || error.contains("invalid_session_size")
        );
    }
}
