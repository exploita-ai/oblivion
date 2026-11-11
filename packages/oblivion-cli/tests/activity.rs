mod support;

use oblivion_cli::activity;
use oblivion_wire::control::Operation;
use oblivion_wire::idle::{Activity, Opening};
use serde_json::{Value, json};
use support::{ID, Runtime, response, status};

const HOST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OPENING: &str = "cccccccccccccccccccccccccccccccc";

fn current() -> Value {
    json!({"idle_lock": {
        "preferences": {"version":1,"safe_minutes":15,"host_minutes":30},
        "host": {"nonce":HOST,"remaining_seconds":120,"closing":false},
        "safes": [{"opening":{"slot":2,"safe_id":ID,"nonce":OPENING},
            "remaining_seconds":90,"closing":false}],
        "last_error":null,"storage":"saved-encrypted","writable":true
    }})
}

#[test]
fn safe_activity_binds_the_status_call_and_report_to_the_exact_opening() {
    let mut runtime = Runtime::new(vec![status(&current())]);
    let activity = activity::current_safe(&mut runtime, 2, ID).unwrap();
    assert_eq!(activity.host, HOST);
    let opening = activity.safe.unwrap();
    assert_eq!(opening.slot, 2);
    assert_eq!(opening.safe_id, ID);
    assert_eq!(opening.nonce, OPENING);
    assert_eq!(runtime.sent[0].slot, Some(2));
    assert_eq!(runtime.sent[0].expected.as_deref(), Some(ID));
    assert!(runtime.sent[0].session.is_none());
    assert!(runtime.sent[0].body.is_empty());
    runtime.finished();
}

#[test]
fn safe_activity_rejects_closing_or_replaced_openings() {
    for (field, value, expected) in [
        (
            "host.closing",
            json!(true),
            "Oblivion is closing and locking its Safes",
        ),
        (
            "safe.closing",
            json!(true),
            "Automatic lock state is unavailable. Reopen this Safe.",
        ),
        (
            "slot",
            json!(3),
            "Automatic lock state is unavailable. Reopen this Safe.",
        ),
        (
            "safe_id",
            json!(HOST),
            "Automatic lock state is unavailable. Reopen this Safe.",
        ),
    ] {
        let mut state = current();
        match field {
            "host.closing" => state["idle_lock"]["host"]["closing"] = value,
            "safe.closing" => state["idle_lock"]["safes"][0]["closing"] = value,
            _ => state["idle_lock"]["safes"][0]["opening"][field] = value,
        }
        let mut runtime = Runtime::new(vec![status(&state)]);
        assert_eq!(
            activity::current_safe(&mut runtime, 2, ID)
                .unwrap_err()
                .to_string(),
            expected
        );
        runtime.finished();
    }
}

#[test]
fn malformed_idle_schema_and_nonces_never_become_activity_or_diagnostics() {
    for field in ["host", "safe", "schema"] {
        let mut state = current();
        match field {
            "host" => state["idle_lock"]["host"]["nonce"] = json!("PRIVATE_CANARY"),
            "safe" => state["idle_lock"]["safes"][0]["opening"]["nonce"] = json!("PRIVATE_CANARY"),
            _ => state["idle_lock"]["storage"] = json!("PRIVATE_CANARY"),
        }
        let mut runtime = Runtime::new(vec![status(&state)]);
        let error = activity::current_safe(&mut runtime, 2, ID).unwrap_err();
        assert_eq!(error.to_string(), "invalid_idle_status");
        assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
        runtime.finished();
    }
}

#[test]
fn host_activity_uses_a_global_status_and_never_keeps_a_closing_host_open() {
    let mut runtime = Runtime::new(vec![status(&current())]);
    let activity = activity::current_host(&mut runtime).unwrap().unwrap();
    assert_eq!(activity.host, HOST);
    assert!(activity.safe.is_none());
    assert!(runtime.sent[0].slot.is_none());
    assert!(runtime.sent[0].expected.is_none());
    runtime.finished();

    for host in [
        Value::Null,
        json!({"nonce":HOST,"remaining_seconds":0,"closing":true}),
    ] {
        let mut state = current();
        state["idle_lock"]["host"] = host;
        let mut runtime = Runtime::new(vec![status(&state)]);
        assert!(activity::current_host(&mut runtime).unwrap().is_none());
        runtime.finished();
    }

    let mut state = current();
    state["idle_lock"]["host"]["nonce"] = json!("PRIVATE_CANARY");
    let mut runtime = Runtime::new(vec![status(&state)]);
    assert_eq!(
        activity::current_host(&mut runtime)
            .unwrap_err()
            .to_string(),
        "invalid_idle_status"
    );
}

#[test]
fn invalid_safe_ids_are_rejected_before_controller_access() {
    let mut runtime = Runtime::new(vec![]);
    assert_eq!(
        activity::current_safe(&mut runtime, 2, "PRIVATE_CANARY")
            .unwrap_err()
            .to_string(),
        "invalid_session_id"
    );
    assert!(runtime.sent.is_empty());
    runtime.finished();
}

#[test]
fn activity_reports_keep_authority_in_the_body_and_never_set_expected_session() {
    for safe in [
        Some(Opening {
            slot: 2,
            safe_id: ID.into(),
            nonce: OPENING.into(),
        }),
        None,
    ] {
        let activity = Activity {
            host: HOST.into(),
            safe,
        };
        let mut runtime = Runtime::new(vec![response(Operation::Activity, "")]);
        activity::report(&mut runtime, &activity).unwrap();
        assert_eq!(
            runtime.sent[0].slot,
            activity.safe.as_ref().map(|safe| safe.slot)
        );
        assert!(runtime.sent[0].expected.is_none());
        assert!(runtime.sent[0].session.is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&runtime.sent[0].body).unwrap(),
            serde_json::to_value(&activity).unwrap()
        );
        runtime.finished();
    }
}
