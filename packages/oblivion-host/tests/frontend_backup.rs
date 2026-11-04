mod frontend_support;
use frontend_support::{Fixture, RunTerminal, SAFE, accept, read, receive, reply, state};
use oblivion_cli::backup;
use oblivion_host::scope;
use oblivion_wire::control::Operation;
use serde_json::{Value, json};

const TRANSACTION: &str = "cccccccccccccccccccccccccccccccc";
fn status(outcome: &str) -> Value {
    json!({"transactions":[{"transaction":TRANSACTION,"slot":3,"kind":"import",
        "safe_id":if outcome=="committed" {Some(SAFE)} else {None},"bytes":33554432,"outcome":outcome,"active":false}]})
}
fn command(values: &[&str]) -> backup::Control {
    match backup::parse(
        &values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )
    .unwrap()
    {
        backup::Command::Control(command) => command,
        _ => panic!("not management"),
    }
}

#[test]
fn restore_reconciles_a_lost_reply_through_the_real_unix_codec_without_repeating_it() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        for (index, operation) in [
            Operation::Status,
            Operation::BackupStatus,
            Operation::BackupImportFinish,
            Operation::BackupStatus,
        ]
        .into_iter()
        .enumerate()
        {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            assert_eq!(request.operation, operation);
            assert!(request.session.is_none() && request.expected_session.is_none());
            assert_eq!(
                request.slot.index(),
                if operation == Operation::BackupImportFinish {
                    3
                } else {
                    0
                }
            );
            match operation {
                Operation::Status => {
                    assert!(secret.is_empty());
                    reply(&mut stream, &state().to_string(), None);
                }
                Operation::BackupStatus => {
                    assert!(secret.is_empty());
                    reply(
                        &mut stream,
                        &status(if index == 3 { "committed" } else { "copied" }).to_string(),
                        None,
                    );
                }
                Operation::BackupImportFinish => {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&secret).unwrap(),
                        json!({"transaction":TRANSACTION,"password":"SYNTHETIC_PASSWORD_CANARY"})
                    );
                    reply(&mut stream, "", Some("backup_reply_lost"));
                }
                _ => unreachable!(),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let mut output = vec![];
    let mut diagnostics = vec![];
    let code = scope::within(scope::Slot::try_from(4).unwrap(), || {
        backup::execute(
            &mut terminal,
            command(&["finish", TRANSACTION]),
            &mut output,
            &mut diagnostics,
        )
    })
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"transaction":TRANSACTION,"safe_id":SAFE})
    );
    assert_eq!(terminal.prompts, ["Original Safe password"]);
    assert!(terminal.confirmations.is_empty() && terminal.attached.is_empty());
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(diagnostics.contains("it was not repeated") && !diagnostics.contains("CANARY"));
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn discard_confirmation_targets_only_the_recorded_slot_and_never_closes_other_safes() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &state().to_string(), None);
        let mut stream = accept(&listener);
        assert_eq!(read(&mut stream).operation, Operation::BackupStatus);
        reply(&mut stream, &status("cancelled").to_string(), None);
        let mut stream = accept(&listener);
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::BackupDiscard);
        assert_eq!(request.slot.index(), 3);
        assert_eq!(request.session.as_deref(), Some(TRANSACTION));
        assert!(request.expected_session.is_none());
        reply(&mut stream, "", None);
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    terminal.confirmed = true;
    assert_eq!(
        backup::execute(
            &mut terminal,
            command(&["discard", TRANSACTION]),
            &mut vec![],
            &mut vec![]
        )
        .unwrap(),
        0
    );
    assert_eq!(terminal.confirmations, ["DISCARD"]);
    assert!(terminal.prompts.is_empty() && terminal.attached.is_empty());
    server.join().unwrap();
}

#[test]
fn all_backup_syntax_is_checked_by_the_compiled_launcher_before_runtime_startup() {
    for args in [
        vec!["backup"],
        vec!["backup", "export", "--safe", "GB"],
        vec!["backup", "import", "file", "--password", "PRIVATE_CANARY"],
        vec!["backup", "finish", "../outside"],
        vec!["backup", "discard", "bad-id"],
        vec!["backup", "status", "--json", "file"],
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
            error.contains("Use backup export --safe SAFE FILE"),
            "{error}"
        );
        assert!(!error.contains("PRIVATE_CANARY"));
    }
}
