use oblivion_cli::controller::{Call, Controller, Result};
use oblivion_cli::{backup, run};
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;
use zeroize::Zeroizing;

const TRANSACTION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SAFE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
struct Sent {
    operation: Operation,
    slot: Option<u8>,
    session: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
struct Runtime {
    responses: VecDeque<std::result::Result<String, &'static str>>,
    sent: Vec<Sent>,
    password: Zeroizing<Vec<u8>>,
    prompts: Vec<&'static str>,
    confirmations: Vec<&'static str>,
    confirmed: bool,
    elapsed: Duration,
}
impl Runtime {
    fn new(responses: Vec<Value>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|value| Ok(value.to_string()))
                .collect(),
            sent: vec![],
            password: Zeroizing::new(b"BACKUP_PASSWORD_CANARY".to_vec()),
            prompts: vec![],
            confirmations: vec![],
            confirmed: true,
            elapsed: Duration::ZERO,
        }
    }
}
impl Controller for Runtime {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        assert!(call.expected_session.is_none());
        self.sent.push(Sent {
            operation: call.operation,
            slot: call.slot,
            session: call.session.map(str::to_owned),
            body: Zeroizing::new(call.secret.to_vec()),
        });
        self.responses
            .pop_front()
            .expect("unexpected RPC")
            .map_err(Into::into)
    }
}
impl run::Runtime for Runtime {
    type Mark = Duration;
    fn slots(&self) -> Vec<u8> {
        panic!("management cannot allocate copy slots")
    }
    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.prompts.push(label);
        Ok(Zeroizing::new(self.password.to_vec()))
    }
    fn new_password(&mut self, _: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        panic!("no new password")
    }
    fn confirm(&mut self, word: &'static str) -> Result<bool> {
        self.confirmations.push(word);
        Ok(self.confirmed)
    }
    fn now(&self) -> Duration {
        self.elapsed
    }
    fn elapsed(&self, start: &Duration) -> Duration {
        self.elapsed - *start
    }
    fn wait(&mut self, duration: Duration) -> Result<()> {
        self.elapsed += duration;
        Ok(())
    }
    fn notice(&mut self, _: run::Notice<'_>) -> Result<()> {
        panic!("use diagnostic writer")
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
        "general_incomplete":false,"general_bytes":8589934592u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},"open_sessions":[],"agent_safes":[]})
}
fn entry(outcome: &str, active: bool) -> Value {
    json!({"transaction":TRANSACTION,"slot":3,"kind":"import","safe_id":if outcome=="committed" {Some(SAFE)} else {None},
        "bytes":33554432,"outcome":outcome,"active":active})
}
fn status(outcome: &str, active: bool) -> Value {
    json!({"transactions":[entry(outcome,active)]})
}
fn command(values: &[&str]) -> backup::Control {
    match backup::parse(&args(values)).unwrap() {
        backup::Command::Control(command) => command,
        _ => panic!("not management"),
    }
}
fn invoke(runtime: &mut Runtime, values: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut output = vec![];
    let mut diagnostics = vec![];
    let code = backup::execute(runtime, command(values), &mut output, &mut diagnostics)?;
    Ok((code, output, diagnostics))
}

#[test]
fn one_parser_owns_copy_and_management_syntax_without_password_arguments() {
    for values in [
        vec!["export", "--safe", "GB", "dir/backup.luks"],
        vec!["export", "dir/backup.luks", "--safe", "GB"],
    ] {
        assert!(
            matches!(backup::parse(&args(&values)).unwrap(),backup::Command::Export {safe,path} if safe=="GB"&&path=="dir/backup.luks")
        );
    }
    assert!(
        matches!(backup::parse(&args(&["import","../literal.luks"])).unwrap(),backup::Command::Import {path} if path=="../literal.luks")
    );
    for values in [
        vec![],
        vec!["import", "file", "--password", "SECRET_CANARY"],
        vec!["export", "--safe", "GB", "--safe", "file"],
        vec!["discard", "../outside"],
        vec!["finish", "bad-id"],
        vec!["status", "--json", "file"],
        vec!["import", ""],
        vec!["import", "--password=SECRET_CANARY"],
        vec!["export", "--safe", "GB\u{1b}[2J", "file"],
    ] {
        let error = backup::parse(&args(&values)).err().unwrap();
        assert!(!format!("{error:?}").contains("CANARY"));
    }
}

#[test]
fn status_uses_the_global_slot_and_requires_writable_storage_without_prompting() {
    let mut runtime = Runtime::new(vec![state("persistent"), status("copied", false)]);
    let (_, output, diagnostics) = invoke(&mut runtime, &["status", "--json"]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        status("copied", false)
    );
    assert!(
        diagnostics.is_empty() && runtime.prompts.is_empty() && runtime.confirmations.is_empty()
    );
    assert!(
        runtime
            .sent
            .iter()
            .all(|call| call.slot == Some(0) && call.session.is_none() && call.body.is_empty())
    );
    for mode in ["locked", "read-only", "ram-only"] {
        let mut runtime = Runtime::new(vec![state(mode)]);
        assert!(invoke(&mut runtime, &["status"]).is_err());
        assert_eq!(runtime.sent.len(), 1);
        assert!(runtime.prompts.is_empty());
    }
}

#[test]
fn discard_requires_confirmation_and_only_mutates_the_recorded_transaction_slot() {
    let mut runtime = Runtime::new(vec![
        state("persistent"),
        status("cancelled", false),
        json!(null),
    ]);
    let (code, output, _) = invoke(&mut runtime, &["discard", TRANSACTION]).unwrap();
    assert_eq!(code, 0);
    assert!(output.is_empty());
    assert_eq!(runtime.confirmations, ["DISCARD"]);
    assert_eq!(runtime.sent[2].operation, Operation::BackupDiscard);
    assert_eq!(runtime.sent[2].slot, Some(3));
    assert_eq!(runtime.sent[2].session.as_deref(), Some(TRANSACTION));
    let mut runtime = Runtime::new(vec![state("persistent"), status("copied", false)]);
    runtime.confirmed = false;
    assert_eq!(
        invoke(&mut runtime, &["discard", TRANSACTION]).unwrap().0,
        130
    );
    assert_eq!(runtime.sent.len(), 2);
    for (outcome, active) in [("committed", false), ("copying", true)] {
        let mut runtime = Runtime::new(vec![state("persistent"), status(outcome, active)]);
        assert!(invoke(&mut runtime, &["discard", TRANSACTION]).is_err());
        assert!(runtime.confirmations.is_empty());
    }
}

#[test]
fn finish_sends_the_original_password_privately_on_the_transaction_slot() {
    let finished = json!({"transaction":TRANSACTION,"safe_id":SAFE});
    let mut runtime = Runtime::new(vec![
        state("persistent"),
        status("copied", false),
        finished.clone(),
    ]);
    let (code, output, diagnostics) = invoke(&mut runtime, &["finish", TRANSACTION]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), finished);
    assert_eq!(runtime.prompts, ["Original Safe password"]);
    assert!(runtime.confirmations.is_empty());
    let sent = &runtime.sent[2];
    assert_eq!(sent.operation, Operation::BackupImportFinish);
    assert_eq!(sent.slot, Some(3));
    assert!(sent.session.is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&sent.body).unwrap(),
        json!({"transaction":TRANSACTION,"password":"BACKUP_PASSWORD_CANARY"})
    );
    assert!(!String::from_utf8(output).unwrap().contains("CANARY"));
    assert!(!String::from_utf8(diagnostics).unwrap().contains("CANARY"));
    for (outcome, active) in [("prepared", false), ("copied", true), ("committed", false)] {
        let mut runtime = Runtime::new(vec![state("persistent"), status(outcome, active)]);
        assert!(invoke(&mut runtime, &["finish", TRANSACTION]).is_err());
        assert!(runtime.prompts.is_empty());
    }
}

#[test]
fn lost_finish_reply_reconciles_a_commit_without_repeating_restore_or_cancelling() {
    let mut runtime = Runtime::new(vec![state("persistent"), status("copied", false)]);
    runtime.responses.extend([
        Err("response_lost"),
        Ok(status("committed", false).to_string()),
    ]);
    let (code, _, diagnostics) = invoke(&mut runtime, &["finish", TRANSACTION]).unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8(diagnostics)
            .unwrap()
            .contains("it was not repeated")
    );
    assert_eq!(
        runtime
            .sent
            .iter()
            .filter(|call| call.operation == Operation::BackupImportFinish)
            .count(),
        1
    );
    assert_eq!(runtime.sent[3].operation, Operation::BackupStatus);
    assert_eq!(runtime.sent[3].slot, Some(0));
    assert!(
        !runtime
            .sent
            .iter()
            .any(|call| call.operation == Operation::BackupCancel)
    );
}

#[test]
fn uncertain_restore_or_wrong_slot_remains_an_error_and_cancels_only_its_original_slot() {
    for wrong_slot in [false, true] {
        let mut runtime = Runtime::new(vec![state("persistent"), status("copied", false)]);
        let mut observed = status(if wrong_slot { "committed" } else { "copied" }, false);
        if wrong_slot {
            observed["transactions"][0]["slot"] = json!(4);
        }
        runtime.responses.extend([
            Err("response_lost"),
            Ok(observed.to_string()),
            Ok(String::new()),
        ]);
        let mut output = vec![];
        let mut diagnostics = vec![];
        assert!(
            backup::execute(
                &mut runtime,
                command(&["finish", TRANSACTION]),
                &mut output,
                &mut diagnostics
            )
            .is_err()
        );
        assert!(output.is_empty());
        assert!(
            String::from_utf8(diagnostics)
                .unwrap()
                .contains("do not repeat")
        );
        assert_eq!(
            runtime.sent.last().unwrap().operation,
            Operation::BackupCancel
        );
        assert_eq!(runtime.sent.last().unwrap().slot, Some(3));
        assert_eq!(
            runtime.sent.last().unwrap().session.as_deref(),
            Some(TRANSACTION)
        );
        assert_eq!(
            runtime
                .sent
                .iter()
                .filter(|call| call.operation == Operation::BackupImportFinish)
                .count(),
            1
        );
    }
}

#[test]
fn malformed_password_and_peer_completion_do_not_expose_secret_bytes_or_claim_success() {
    let mut runtime = Runtime::new(vec![
        state("persistent"),
        status("copied", false),
        json!(null),
    ]);
    runtime.password = Zeroizing::new([b"PRIVATE_SECRET_CANARY".as_slice(), &[0xff]].concat());
    let error = invoke(&mut runtime, &["finish", TRANSACTION]).unwrap_err();
    assert_eq!(error.to_string(), "invalid_secret_encoding");
    assert!(error.source().is_none());
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(
        !runtime
            .sent
            .iter()
            .any(|call| call.operation == Operation::BackupImportFinish)
    );
    let mut runtime = Runtime::new(vec![
        state("persistent"),
        status("copied", false),
        json!({"transaction":TRANSACTION,"safe_id":"PRIVATE_PEER_CANARY"}),
        json!(null),
    ]);
    let error = invoke(&mut runtime, &["finish", TRANSACTION]).unwrap_err();
    assert_eq!(error.to_string(), "invalid_backup_completion");
    assert!(!format!("{error:?}").contains("CANARY"));
}

#[test]
fn copy_completion_polling_is_shared_bounded_and_bound_to_the_original_slot() {
    let mut runtime = Runtime::new(vec![status("copying", true), status("copied", false)]);
    backup::copied(&mut runtime, TRANSACTION, 3).unwrap();
    assert_eq!(runtime.elapsed, Duration::from_millis(100));
    assert!(
        runtime
            .sent
            .iter()
            .all(|call| call.operation == Operation::BackupStatus && call.slot == Some(0))
    );
    let mut runtime = Runtime::new(vec![status("copied", false)]);
    assert_eq!(
        backup::copied(&mut runtime, TRANSACTION, 4)
            .unwrap_err()
            .to_string(),
        "invalid_backup_status"
    );
    let mut runtime = Runtime::new(vec![status("recovery-required", false)]);
    assert_eq!(
        backup::copied(&mut runtime, TRANSACTION, 3)
            .unwrap_err()
            .to_string(),
        "backup_copy_requires_recovery"
    );
}

#[test]
fn status_rejects_malformed_native_metadata_with_static_errors() {
    let mut malformed = status("copied", false);
    malformed["transactions"][0]["outcome"] = json!("PRIVATE_PEER_CANARY");
    let mut runtime = Runtime::new(vec![state("persistent"), malformed]);
    let error = invoke(&mut runtime, &["status"]).unwrap_err();
    assert_eq!(error.to_string(), "invalid_backup_status");
    assert!(error.source().is_none());
    assert!(!format!("{error:?}").contains("CANARY"));
    let mut duplicate = status("copied", false);
    duplicate["transactions"]
        .as_array_mut()
        .unwrap()
        .push(entry("copied", false));
    let mut runtime = Runtime::new(vec![state("persistent"), duplicate]);
    assert!(invoke(&mut runtime, &["status"]).is_err());
}
