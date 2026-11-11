mod support;
use oblivion_cli::child_task;
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use support::{ID, Runtime, active, rejected, response, status};

const REQUEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ATTEMPT: &str = "cccccccccccccccccccccccccccccccc";

fn command(values: &[&str]) -> child_task::Command {
    child_task::parse(
        &values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn saved() -> Value {
    json!({"version":1,"safe_id":ID,"agent":"codex","request_id":REQUEST,
        "attempt_request_id":null,"attempts":0,"attempt_limit":16,"phase":"not-started",
        "job":null,"can_start":true,"can_retry":false,"can_cancel":false,"blocked":null})
}

fn submitted(state: &str) -> Value {
    let mut value = saved();
    value["attempt_request_id"] = json!(ATTEMPT);
    value["attempts"] = json!(1);
    value["phase"] = json!("submitted");
    value["can_start"] = json!(false);
    value["can_retry"] = json!(state == "failed" || state == "cancelled");
    value["can_cancel"] = json!(state == "running");
    value["job"] = json!({"job_id":"dddddddddddddddddddddddddddddddd","request_id":ATTEMPT,
        "agent":"codex","state":state,"native_chat_id":null,
        "reason":if state=="failed"{Some("needs-auth")}else{None}});
    value
}

#[test]
fn grammar_rejects_unknown_duplicate_and_inapplicable_options_before_runtime() {
    for values in [
        vec![],
        vec!["status"],
        vec!["unknown", "GB"],
        vec!["status", "GB", "--request", REQUEST],
        vec!["review", "GB", "--request", REQUEST],
        vec!["start", "GB", "--request"],
        vec!["start", "GB", "--request", "not-an-id"],
        vec!["start", "GB", "--request", REQUEST, "--request", REQUEST],
        vec!["cancel", "GB", "--json", "--json"],
        vec!["review", "bad\u{1b}name"],
    ] {
        assert!(
            child_task::parse(
                &values
                    .iter()
                    .map(|value| (*value).into())
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    for action in ["start", "retry", "cancel"] {
        let _ = command(&[action, "GB", "--json", "--request", REQUEST]);
    }
}

#[test]
fn status_is_scoped_and_never_fetches_saved_plaintext() {
    let mut runtime = Runtime::new(vec![
        status(&active()),
        response(Operation::ChildTaskStatus, saved().to_string()),
    ]);
    let mut output = vec![];
    child_task::execute(
        &mut runtime,
        command(&["status", "GB", "--json"]),
        &mut output,
    )
    .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), saved());
    assert_eq!(runtime.sent[1].slot, Some(1));
    assert_eq!(runtime.sent[1].expected.as_deref(), Some(ID));
    assert!(runtime.sent[1].session.is_none());
    assert!(runtime.sent[1].body.is_empty());
    assert!(runtime.events.is_empty());
    runtime.finished();
}

#[test]
fn review_escapes_terminal_controls_but_explicit_json_preserves_the_task() {
    let task = "saved\n\u{1b}[31m\u{061c}\u{2028}\u{202e}\t日本語";
    let review = json!({"status":saved(),"task":task});
    for json in [false, true] {
        let mut runtime = Runtime::new(vec![
            status(&active()),
            response(Operation::ChildTaskReview, review.to_string()),
        ]);
        let mut output = vec![];
        let args = if json {
            vec!["review", "GB", "--json"]
        } else {
            vec!["review", "GB"]
        };
        child_task::execute(&mut runtime, command(&args), &mut output).unwrap();
        if json {
            assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), review);
        } else {
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("saved\n\\u{1b}[31m\\u{61c}\\u{2028}\\u{202e}\\u{9}日本語"));
            assert!(!output.contains('\u{1b}'));
        }
        assert_eq!(runtime.sent[1].expected.as_deref(), Some(ID));
        runtime.finished();
    }
}

#[test]
fn malformed_peer_review_never_exposes_plaintext_in_errors() {
    let review = json!({"status":saved(),"task":"PRIVATE_TASK_CANARY","PRIVATE_FIELD_CANARY":true});
    let mut runtime = Runtime::new(vec![
        status(&active()),
        response(Operation::ChildTaskReview, review.to_string()),
    ]);
    let mut output = vec![];
    let error =
        child_task::execute(&mut runtime, command(&["review", "GB"]), &mut output).unwrap_err();
    assert_eq!(error.to_string(), "Invalid task review response");
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(output.is_empty());
    runtime.finished();
}

#[test]
fn retry_keeps_the_reviewed_creation_request_and_waits_through_gateway_startup() {
    let mut runtime = Runtime::new(vec![
        status(&active()),
        response(Operation::ChildTaskStatus, submitted("failed").to_string()),
        response(Operation::PinSafe, ""),
        rejected(Operation::StartAgent, "gateway_not_ready"),
        response(Operation::StartAgent, ""),
        response(Operation::ChildTaskRetry, submitted("running").to_string()),
    ]);
    let mut output = vec![];
    child_task::execute(
        &mut runtime,
        command(&["retry", "GB", "--request", REQUEST, "--json"]),
        &mut output,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        submitted("running")
    );
    assert_eq!(runtime.events, ["waiting", "wait:500"]);
    for sent in runtime.sent.iter().skip(1) {
        assert_eq!(sent.slot, Some(1));
        assert_eq!(sent.expected.as_deref(), Some(ID));
        assert!(sent.session.is_none());
    }
    assert_eq!(
        serde_json::from_slice::<Value>(&runtime.sent.last().unwrap().body).unwrap(),
        json!({"request_id":REQUEST})
    );
    assert!(runtime.attached.is_none());
    runtime.finished();
}

#[test]
fn changed_request_and_unconfirmed_outcomes_do_not_admit_an_attempt() {
    for (args, before, message) in [
        (
            vec!["retry", "GB", "--request", ATTEMPT],
            submitted("failed"),
            "The saved task changed. Review it again.",
        ),
        (
            vec!["retry", "GB"],
            saved(),
            "Retry requires a confirmed failed or cancelled attempt; inspect task status first.",
        ),
        (
            vec!["cancel", "GB"],
            saved(),
            "No running attempt could be confirmed. Inspect task status before cancelling.",
        ),
    ] {
        let mut runtime = Runtime::new(vec![
            status(&active()),
            response(Operation::ChildTaskStatus, before.to_string()),
        ]);
        let mut output = vec![];
        assert_eq!(
            child_task::execute(&mut runtime, command(&args), &mut output)
                .unwrap_err()
                .to_string(),
            message
        );
        assert!(output.is_empty());
        assert!(runtime.events.is_empty());
        runtime.finished();
    }
}

#[test]
fn repeated_start_or_cancel_returns_existing_terminal_attempt_without_new_work() {
    for action in ["start", "cancel"] {
        let terminal = submitted("completed");
        let mut runtime = Runtime::new(vec![
            status(&active()),
            response(Operation::ChildTaskStatus, terminal.to_string()),
        ]);
        let mut output = vec![];
        child_task::execute(
            &mut runtime,
            command(&[action, "GB", "--json"]),
            &mut output,
        )
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), terminal);
        assert!(runtime.events.is_empty());
        runtime.finished();
    }
}

#[test]
fn cancel_is_scoped_but_does_not_start_network_or_agent() {
    let mut runtime = Runtime::new(vec![
        status(&active()),
        response(Operation::ChildTaskStatus, submitted("running").to_string()),
        response(
            Operation::ChildTaskCancel,
            submitted("cancelled").to_string(),
        ),
    ]);
    let mut output = vec![];
    child_task::execute(
        &mut runtime,
        command(&["cancel", "GB", "--request", REQUEST]),
        &mut output,
    )
    .unwrap();
    let sent = runtime.sent.last().unwrap();
    assert_eq!(sent.slot, Some(1));
    assert_eq!(sent.expected.as_deref(), Some(ID));
    assert_eq!(
        serde_json::from_slice::<Value>(&sent.body).unwrap(),
        json!({"request_id":REQUEST})
    );
    assert!(runtime.events.is_empty());
    runtime.finished();
}

#[test]
fn provider_failure_does_not_send_saved_task_or_assume_login() {
    let mut runtime = Runtime::new(vec![
        status(&active()),
        response(Operation::ChildTaskStatus, saved().to_string()),
        response(Operation::PinSafe, ""),
        rejected(Operation::StartAgent, "provider_needs_auth"),
    ]);
    let mut output = vec![];
    assert_eq!(
        child_task::execute(&mut runtime, command(&["start", "GB"]), &mut output)
            .unwrap_err()
            .to_string(),
        "provider_needs_auth"
    );
    assert!(output.is_empty());
    assert!(runtime.events.is_empty());
    runtime.finished();
}

#[test]
fn locked_closed_recovery_and_invalid_safe_ids_stop_before_task_access() {
    for mutation in ["locked", "closed", "recovery", "invalid-id"] {
        let mut state = active();
        match mutation {
            "locked" => state["app_open"] = json!(false),
            "closed" => state["open_sessions"] = json!([]),
            "recovery" => state["recovery_required"] = json!(true),
            _ => {
                state["sessions"] = json!(["BAD"]);
                state["session_titles"] = json!({"BAD":"GB"});
                state["open_sessions"] = json!([{"slot":1,"id":"BAD","mode":"agent","recovery_required":false}]);
            }
        }
        let mut runtime = Runtime::new(vec![status(&state)]);
        let mut output = vec![];
        assert!(
            child_task::execute(&mut runtime, command(&["status", "GB"]), &mut output).is_err()
        );
        assert!(output.is_empty());
        runtime.finished();
    }
}

#[test]
fn operation_response_must_preserve_safe_and_creation_request_identity() {
    for field in ["request_id", "safe_id"] {
        let mut next = submitted("cancelled");
        next[field] = json!(ATTEMPT);
        let mut runtime = Runtime::new(vec![
            status(&active()),
            response(Operation::ChildTaskStatus, submitted("running").to_string()),
            response(Operation::ChildTaskCancel, next.to_string()),
        ]);
        let mut output = vec![];
        assert!(
            child_task::execute(&mut runtime, command(&["cancel", "GB"]), &mut output)
                .unwrap_err()
                .to_string()
                .starts_with("Invalid task operation response")
        );
        assert!(output.is_empty());
        runtime.finished();
    }
}
