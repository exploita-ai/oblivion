mod frontend_support;
use frontend_support::{Fixture, RunTerminal, SAFE, accept, read, reply, state};
use oblivion_cli::family_password;
use oblivion_host::scope;
use oblivion_wire::control::Operation;
use serde_json::json;

const HOST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FAMILY: &str = "cccccccccccccccccccccccccccccccc";
const SHA: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn preview_uses_the_real_private_unix_protocol_and_binds_the_safe_and_host_opening() {
    let (fixture, listener) = Fixture::new();
    let expected = json!({"host_opening":HOST,"family_id":FAMILY,"sha256":SHA,
        "members":[{"safe_id":SAFE,"title":"GB"}]});
    let plan = expected.clone();
    let server = std::thread::spawn(move || {
        for operation in [
            Operation::Status,
            Operation::FamilyPasswordPreview,
            Operation::Status,
        ] {
            let mut stream = accept(&listener);
            let request = read(&mut stream);
            assert_eq!(request.operation, operation);
            assert_eq!(request.slot.index(), 0);
            match operation {
                Operation::FamilyPasswordPreview => {
                    assert_eq!(request.session.as_deref(), Some(SAFE));
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    reply(&mut stream, &plan.to_string(), None);
                }
                _ => {
                    assert!(request.session.is_none() && request.expected_session.is_none());
                    let mut source = state();
                    source["idle_lock"] = json!({
                        "preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
                        "host":{"nonce":HOST,"closing":false,"remaining_seconds":60},
                        "safes":[],"last_error":null});
                    reply(&mut stream, &source.to_string(), None);
                }
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = family_password::parse(&["preview", "GB", "--json"].map(String::from)).unwrap();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    assert_eq!(
        family_password::execute(&mut terminal, command, &mut output, &mut diagnostics).unwrap(),
        0
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
        expected
    );
    assert!(
        terminal.prompts.is_empty()
            && terminal.confirmations.is_empty()
            && terminal.attached.is_empty()
    );
    assert!(diagnostics.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn malformed_family_syntax_is_rejected_by_the_compiled_launcher_before_runtime_startup() {
    for args in [
        vec!["safe", "password", "preview", "GB"],
        vec!["safe", "password", "GB", "--yes"],
        vec!["safe", "password", "recover", "bad-id", "--complete"],
        vec![
            "safe",
            "password",
            "GB",
            "--confirmed-plan",
            "PRIVATE_CANARY",
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
        assert!(error.contains("Use safe password SAFE"), "{error}");
        assert!(!error.contains("PRIVATE_CANARY"));
    }
}
