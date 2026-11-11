use oblivion_cli::controller::{Call, Controller, Result};
use oblivion_cli::{family_password, run};
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;
use zeroize::Zeroizing;

const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FAMILY: &str = "cccccccccccccccccccccccccccccccc";
const TRANSACTION: &str = "dddddddddddddddddddddddddddddddd";
const SHA: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
struct Sent {
    operation: Operation,
    session: Option<String>,
    expected: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
struct Runtime {
    responses: VecDeque<std::result::Result<String, &'static str>>,
    sent: Vec<Sent>,
    passwords: VecDeque<Zeroizing<Vec<u8>>>,
    prompts: Vec<&'static str>,
    confirmations: Vec<&'static str>,
    confirmed: bool,
}
impl Runtime {
    fn new(responses: Vec<Value>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|value| Ok(value.to_string()))
                .collect(),
            sent: vec![],
            passwords: VecDeque::new(),
            prompts: vec![],
            confirmations: vec![],
            confirmed: true,
        }
    }
}
impl Controller for Runtime {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        assert!(call.slot.is_none());
        self.sent.push(Sent {
            operation: call.operation,
            session: call.session.map(str::to_owned),
            expected: call.expected_session.map(str::to_owned),
            body: Zeroizing::new(call.secret.to_vec()),
        });
        self.responses
            .pop_front()
            .expect("unexpected controller call")
            .map_err(Into::into)
    }
}
impl run::Runtime for Runtime {
    type Mark = ();
    fn slots(&self) -> Vec<u8> {
        panic!("password wrappers never allocate a Safe")
    }
    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.prompts.push(label);
        Ok(self
            .passwords
            .pop_front()
            .expect("unexpected secret prompt"))
    }
    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.password(label)
    }
    fn confirm(&mut self, word: &'static str) -> Result<bool> {
        self.confirmations.push(word);
        Ok(self.confirmed)
    }
    fn now(&self) {}
    fn elapsed(&self, _: &()) -> Duration {
        panic!("no gateway")
    }
    fn wait(&mut self, _: Duration) -> Result<()> {
        panic!("no gateway")
    }
    fn notice(&mut self, _: run::Notice<'_>) -> Result<()> {
        panic!("diagnostics use supplied writer")
    }
    fn attach(&mut self, _: u8, _: &str, _: &str, _: &[String]) -> Result<i32> {
        panic!("no agent")
    }
    fn attach_workspace(&mut self, _: u8, _: &str) -> Result<i32> {
        panic!("no workspace")
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn state(mode: &str) -> Value {
    json!({"app_open":mode!="locked","app_mode":mode,"general_present":true,
        "general_incomplete":false,"backing_recovery_required":false,"general_bytes":8589934592u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},"open_sessions":[],"agent_safes":[]})
}
fn current(host: &str) -> Value {
    json!({"idle_lock":{"preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
        "host":{"nonce":host,"closing":false,"remaining_seconds":60},"safes":[],"last_error":null}})
}
fn members() -> Value {
    json!([{"safe_id":SAFE,"title":"GB"}])
}
fn plan() -> Value {
    json!({"host_opening":HOST,"family_id":FAMILY,"sha256":SHA,"members":members()})
}
fn entry(outcome: &str) -> Value {
    json!({"transaction":TRANSACTION,"family_id":FAMILY,"members":members(),"outcome":outcome})
}
fn status(outcome: &str) -> Value {
    json!({"host_opening":HOST,"transactions":[entry(outcome)]})
}
fn invoke(runtime: &mut Runtime, values: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut output = vec![];
    let mut diagnostics = vec![];
    let code = family_password::execute(
        runtime,
        family_password::parse(&args(values))?,
        &mut output,
        &mut diagnostics,
    )?;
    Ok((code, output, diagnostics))
}

#[test]
fn syntax_has_no_noninteractive_confirmation_or_password_bypass() {
    for values in [
        vec![],
        vec!["preview", "GB"],
        vec!["GB", "--yes"],
        vec!["GB", "--confirmed-plan", "invalid"],
        vec!["preview", "GB", "--json", "--yes"],
        vec!["recover", "bad-id", "--complete"],
        vec!["recover", TRANSACTION, "--auto"],
        vec!["status", "--json", "--json"],
        vec!["GB\u{1b}[2J"],
    ] {
        assert!(family_password::parse(&args(&values)).is_err());
    }
    assert!(family_password::parse(&args(&["GB", "--confirmed-plan", SHA])).is_ok());
    for mode in ["locked", "read-only", "ram-only"] {
        let mut runtime = Runtime::new(vec![state(mode)]);
        assert!(invoke(&mut runtime, &["status"]).is_err());
        assert_eq!(runtime.sent.len(), 1);
        assert!(runtime.prompts.is_empty() && runtime.confirmations.is_empty());
    }
}

#[test]
fn preview_is_read_only_and_binds_safe_membership_and_current_host_opening() {
    let mut runtime = Runtime::new(vec![state("persistent"), plan(), current(HOST)]);
    let (code, output, diagnostics) = invoke(&mut runtime, &["preview", "GB", "--json"]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), plan());
    assert!(
        diagnostics.is_empty() && runtime.prompts.is_empty() && runtime.confirmations.is_empty()
    );
    assert_eq!(runtime.sent[1].operation, Operation::FamilyPasswordPreview);
    assert_eq!(runtime.sent[1].session.as_deref(), Some(SAFE));
    assert_eq!(runtime.sent[1].expected.as_deref(), Some(SAFE));
    assert!(runtime.sent.iter().all(|call| call.body.is_empty()));
    for changed in [current(&"f".repeat(32)), json!({"idle_lock":{"host":null}})] {
        let mut runtime = Runtime::new(vec![state("persistent"), plan(), changed]);
        assert!(invoke(&mut runtime, &["preview", "GB", "--json"]).is_err());
        assert_eq!(runtime.sent.len(), 3);
        assert!(runtime.prompts.is_empty());
    }
    let mut foreign = plan();
    foreign["members"][0]["safe_id"] = json!("f".repeat(32));
    let mut runtime = Runtime::new(vec![state("persistent"), foreign, current(HOST)]);
    assert!(invoke(&mut runtime, &["GB"]).is_err());
    assert!(runtime.confirmations.is_empty());
}

#[test]
fn stale_review_or_cancel_never_requests_passwords_or_mutates() {
    let mut runtime = Runtime::new(vec![state("persistent"), plan(), current(HOST)]);
    assert!(invoke(&mut runtime, &["GB", "--confirmed-plan", &"f".repeat(64)]).is_err());
    assert!(runtime.confirmations.is_empty() && runtime.prompts.is_empty());
    let mut runtime = Runtime::new(vec![state("persistent"), plan(), current(HOST)]);
    runtime.confirmed = false;
    let (code, output, diagnostics) =
        invoke(&mut runtime, &["GB", "--confirmed-plan", SHA]).unwrap();
    assert_eq!(code, 130);
    assert!(output.is_empty());
    assert!(!diagnostics.is_empty());
    assert_eq!(runtime.confirmations, ["CHANGE"]);
    assert!(runtime.prompts.is_empty());
    assert_eq!(runtime.sent.len(), 3);
}

#[test]
fn change_sends_only_a_zeroizing_private_body_bound_to_the_reviewed_plan() {
    let mut runtime = Runtime::new(vec![
        state("persistent"),
        plan(),
        current(HOST),
        entry("complete"),
    ]);
    runtime.passwords.extend([
        Zeroizing::new(b"CURRENT_SECRET_CANARY".to_vec()),
        Zeroizing::new(b"NEW_SECRET_CANARY".to_vec()),
    ]);
    let (code, output, diagnostics) =
        invoke(&mut runtime, &["GB", "--confirmed-plan", SHA]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(runtime.confirmations, ["CHANGE"]);
    assert_eq!(
        runtime.prompts,
        ["Current family password", "New family password"]
    );
    let sent = &runtime.sent[3];
    assert_eq!(sent.operation, Operation::FamilyPasswordChange);
    assert!(sent.session.is_none() && sent.expected.is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&sent.body).unwrap(),
        json!({"safe_id":SAFE,"host_opening":HOST,
        "plan_sha256":SHA,"current_password":"CURRENT_SECRET_CANARY","new_password":"NEW_SECRET_CANARY"})
    );
    assert!(!String::from_utf8(output).unwrap().contains("CANARY"));
    assert!(!String::from_utf8(diagnostics).unwrap().contains("CANARY"));
}

#[test]
fn invalid_secret_encoding_has_no_echo_debug_source_or_mutation() {
    for invalid_new in [false, true] {
        let mut runtime = Runtime::new(vec![state("persistent"), plan(), current(HOST)]);
        if invalid_new {
            runtime
                .passwords
                .push_back(Zeroizing::new(b"CURRENT_SECRET_CANARY".to_vec()));
        }
        runtime.passwords.push_back(Zeroizing::new(
            [b"PRIVATE_SECRET_CANARY".as_slice(), &[0xff]].concat(),
        ));
        let error = invoke(&mut runtime, &["GB"]).unwrap_err();
        assert_eq!(error.to_string(), "invalid_secret_encoding");
        assert!(error.source().is_none());
        assert!(!format!("{error:?}").contains("CANARY"));
        assert_eq!(runtime.sent.len(), 3);
    }
}

#[test]
fn recovery_uses_recorded_transaction_and_opening_with_explicit_direction_confirmation() {
    for (option, word, outcome, direction) in [
        ("--complete", "COMPLETE", "complete", "complete"),
        ("--rollback", "ROLLBACK", "rolled-back", "rollback"),
    ] {
        let mut runtime = Runtime::new(vec![
            state("persistent"),
            status("pending"),
            current(HOST),
            entry(outcome),
        ]);
        let (code, _, _) = invoke(&mut runtime, &["recover", TRANSACTION, option]).unwrap();
        assert_eq!(code, 0);
        assert_eq!(runtime.confirmations, [word]);
        assert!(runtime.prompts.is_empty());
        assert_eq!(runtime.sent[3].operation, Operation::FamilyPasswordRecover);
        assert_eq!(
            serde_json::from_slice::<Value>(&runtime.sent[3].body).unwrap(),
            json!({"transaction":TRANSACTION,"host_opening":HOST,"direction":direction})
        );
    }
    let mut runtime = Runtime::new(vec![state("persistent"), status("complete"), current(HOST)]);
    assert!(invoke(&mut runtime, &["recover", TRANSACTION, "--rollback"]).is_err());
    assert!(runtime.confirmations.is_empty() && runtime.prompts.is_empty());
}

#[test]
fn status_is_bound_to_host_and_malformed_peer_values_have_static_errors() {
    let mut runtime = Runtime::new(vec![state("persistent"), status("pending"), current(HOST)]);
    let (_, output, _) = invoke(&mut runtime, &["status", "--json"]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        status("pending")
    );
    let mut malformed = status("pending");
    malformed["transactions"][0]["outcome"] = json!("PRIVATE_PEER_CANARY");
    let mut runtime = Runtime::new(vec![state("persistent"), malformed]);
    let error = invoke(&mut runtime, &["status"]).unwrap_err();
    assert_eq!(error.to_string(), "invalid_family_password_response");
    assert!(error.source().is_none());
    assert!(!format!("{error:?}").contains("CANARY"));
}

#[test]
fn failed_change_reports_recovery_instead_of_claiming_success_or_retrying() {
    let mut runtime = Runtime::new(vec![state("persistent"), plan(), current(HOST)]);
    runtime
        .responses
        .push_back(Err("family_password_update_incomplete"));
    runtime.passwords.extend([
        Zeroizing::new(b"CURRENT".to_vec()),
        Zeroizing::new(b"NEW".to_vec()),
    ]);
    let mut output = vec![];
    let mut diagnostics = vec![];
    let error = family_password::execute(
        &mut runtime,
        family_password::parse(&args(&["GB"])).unwrap(),
        &mut output,
        &mut diagnostics,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "family_password_update_incomplete");
    assert!(output.is_empty());
    assert!(
        String::from_utf8(diagnostics)
            .unwrap()
            .contains("safe password status")
    );
    assert_eq!(runtime.sent.len(), 4);
}
