mod support;
use oblivion_cli::safe;
use oblivion_wire::control::Operation;
use serde_json::{json, Value};
use support::{active, rejected, response, state, status, Runtime, ID};
use zeroize::Zeroizing;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn command(values: &[&str]) -> safe::Command {
    safe::parse(&args(values)).unwrap()
}
fn closed() -> Value {
    let mut value = active();
    value["open_sessions"] = json!([]);
    value
}

#[test]
fn grammar_validates_complete_names_and_capacity_before_runtime() {
    for values in [
        vec!["open", "GB"],
        vec!["open", "GB", "--already-open"],
        vec!["rename", "GB", "Research 文档"],
        vec!["grow", "GB", "128"],
        vec!["grow", "GB", "1048576"],
    ] {
        safe::parse(&args(&values)).unwrap();
    }
    for values in [
        vec![],
        vec!["open"],
        vec!["open", "GB", "extra"],
        vec!["rename", "GB"],
        vec!["rename", "GB", ""],
        vec!["rename", "GB", "bad\nname"],
        vec!["grow", "GB", "127"],
        vec!["grow", "GB", "1048577"],
        vec!["grow", "GB", "18446744073709551616"],
        vec!["grow", "GB", "-1"],
        vec!["grow", "GB", "2048", "extra"],
        vec!["task", "GB"],
        vec!["password", "GB"],
    ] {
        assert!(safe::parse(&args(&values)).is_err());
    }
}

#[test]
fn open_uses_offline_documents_then_pins_exact_opening_without_starting_agent() {
    let value = closed();
    let mut runtime = Runtime::new(vec![
        status(&value),
        status(&value),
        response(Operation::OpenDocuments, ""),
        response(Operation::PinSafe, ""),
    ]);
    let mut output = Vec::new();
    assert_eq!(
        safe::execute(&mut runtime, command(&["open", "GB"]), &mut output).unwrap(),
        0
    );
    runtime.finished();
    assert_eq!(runtime.events, ["password:Safe password"]);
    assert_eq!(runtime.sent[2].slot, Some(0));
    assert_eq!(runtime.sent[2].session.as_deref(), Some(ID));
    assert!(runtime.sent[2].expected.is_none());
    assert_eq!(runtime.sent[3].slot, Some(0));
    assert_eq!(runtime.sent[3].expected.as_deref(), Some(ID));
    assert!(runtime.attached.is_none());
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Safe aaaaaaaa opened for files and offline work\n"
    );
}

#[test]
fn already_open_pins_an_active_safe_without_attaching_or_prompting() {
    let mut runtime = Runtime::new(vec![status(&active()), response(Operation::PinSafe, "")]);
    assert_eq!(
        safe::execute(
            &mut runtime,
            command(&["open", "GB", "--already-open"]),
            &mut Vec::new()
        )
        .unwrap(),
        0
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
    assert!(runtime.attached.is_none());
    assert_eq!(runtime.sent[1].slot, Some(1));
    assert_eq!(runtime.sent[1].expected.as_deref(), Some(ID));
}

#[test]
fn already_open_never_prompts_to_reopen_locked_storage_or_a_closed_safe() {
    let mut locked = closed();
    locked["app_open"] = json!(false);
    locked["app_mode"] = json!("locked");
    for (state, error) in [
        (locked, "Oblivion is locked. Run oblivion unlock."),
        (closed(), "This Safe is no longer open"),
    ] {
        let mut runtime = Runtime::new(vec![status(&state)]);
        assert_eq!(
            safe::execute(
                &mut runtime,
                command(&["open", "GB", "--already-open"]),
                &mut Vec::new()
            )
            .unwrap_err()
            .to_string(),
            error
        );
        runtime.finished();
        assert!(runtime.events.is_empty());
    }
}

#[test]
fn only_failed_new_openings_are_eligible_for_fenced_idle_cleanup() {
    for cleanup_changed in [false, true] {
        let value = closed();
        let cleanup = if cleanup_changed {
            rejected(Operation::CloseIdle, "session_changed")
        } else {
            response(Operation::CloseIdle, "")
        };
        let mut runtime = Runtime::new(vec![
            status(&value),
            status(&value),
            response(Operation::OpenDocuments, ""),
            rejected(Operation::PinSafe, "pin_failed"),
            cleanup,
        ]);
        let mut output = Vec::new();
        assert_eq!(
            safe::execute(&mut runtime, command(&["open", "GB"]), &mut output)
                .unwrap_err()
                .to_string(),
            "pin_failed"
        );
        runtime.finished();
        assert_eq!(runtime.sent[4].slot, Some(0));
        assert_eq!(runtime.sent[4].expected.as_deref(), Some(ID));
        assert!(output.is_empty());
    }
    let value = active();
    let mut runtime = Runtime::new(vec![
        status(&value),
        status(&value),
        rejected(Operation::PinSafe, "pin_failed"),
    ]);
    assert_eq!(
        safe::execute(&mut runtime, command(&["open", "GB"]), &mut Vec::new())
            .unwrap_err()
            .to_string(),
        "pin_failed"
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
    assert_eq!(runtime.sent[2].slot, Some(1));
    assert_eq!(runtime.sent[2].expected.as_deref(), Some(ID));
}

#[test]
fn persistent_catalog_rename_needs_no_free_slot_or_password() {
    let mut value = closed();
    value["open_sessions"] = json!([
        {"slot":0,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode":"agent"},
        {"slot":1,"id":"cccccccccccccccccccccccccccccccc","mode":"documents"}
    ]);
    let mut runtime = Runtime::new(vec![
        status(&value),
        status(&value),
        response(Operation::RenameSession, ""),
    ]);
    safe::execute(
        &mut runtime,
        command(&["rename", "GB", "Research"]),
        &mut Vec::new(),
    )
    .unwrap();
    runtime.finished();
    assert!(runtime.events.is_empty());
    let request = &runtime.sent[2];
    assert!(request.slot.is_none() && request.expected.is_none() && request.session.is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        json!({"id":ID,"title":"Research"})
    );
}

#[test]
fn temporary_titles_require_and_fence_an_active_safe_and_collisions_are_rejected() {
    for mode in ["ram-only", "read-only"] {
        let mut value = active();
        value["app_mode"] = json!(mode);
        let mut runtime = Runtime::new(vec![
            status(&value),
            status(&value),
            response(Operation::RenameSession, ""),
        ]);
        safe::execute(
            &mut runtime,
            command(&["rename", "GB", "Temporary"]),
            &mut Vec::new(),
        )
        .unwrap();
        runtime.finished();
        assert_eq!(runtime.sent[2].slot, Some(1));
        assert_eq!(runtime.sent[2].expected.as_deref(), Some(ID));
        value["open_sessions"] = json!([]);
        let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
        assert_eq!(
            safe::execute(
                &mut runtime,
                command(&["rename", "GB", "Temporary"]),
                &mut Vec::new()
            )
            .unwrap_err()
            .to_string(),
            "Open the Safe before renaming it in this storage mode"
        );
        runtime.finished();
    }
    let mut value = closed();
    value["sessions"] = json!([ID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]);
    value["session_titles"]["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = json!("Research");
    let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
    assert_eq!(
        safe::execute(
            &mut runtime,
            command(&["rename", "GB", "Research"]),
            &mut Vec::new()
        )
        .unwrap_err()
        .to_string(),
        "A Safe with this name already exists"
    );
    runtime.finished();
}

#[test]
fn grow_reserves_a_free_maintenance_slot_and_sends_the_shared_closed_target_request() {
    let mut value = closed();
    value["open_sessions"] =
        json!([{"slot":0,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode":"agent"}]);
    let mut runtime = Runtime::new(vec![
        status(&value),
        status(&value),
        response(Operation::SessionStorage, ""),
    ]);
    let mut output = Vec::new();
    safe::execute(&mut runtime, command(&["grow", "GB", "2048"]), &mut output).unwrap();
    runtime.finished();
    assert_eq!(runtime.events, ["password:Safe password"]);
    let request = &runtime.sent[2];
    assert_eq!(request.slot, Some(1));
    assert!(request.session.is_none() && request.expected.is_none());
    let request = serde_json::from_slice::<oblivion_wire::volume::Request>(&request.body).unwrap();
    request.validate().unwrap();
    let oblivion_wire::volume::Request::Grow { id, mib, password } = request else {
        panic!("expected grow")
    };
    assert_eq!(id, ID);
    assert_eq!(mib, 2048);
    assert_eq!(&*password, "synthetic unlock password");
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Safe storage increased to 2048 MiB\n"
    );
}

#[test]
fn grow_rejects_ineligible_storage_and_exhausted_slots_before_password_entry() {
    let mut readonly = closed();
    readonly["app_mode"] = json!("read-only");
    let mut ram_child = state("ram-only");
    ram_child["agent_safes"] = json!([{"id":ID,"ephemeral":true,"state":"awaiting-start"}]);
    ram_child["session_titles"] = json!({ID:"GB"});
    let mut full = closed();
    full["open_sessions"] = json!([
        {"slot":0,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode":"agent"},
        {"slot":1,"id":"cccccccccccccccccccccccccccccccc","mode":"agent"}
    ]);
    for (value, message) in [
        (active(), "Close the Safe before increasing its storage"),
        (
            readonly,
            "Safe storage growth requires writable persistent storage",
        ),
        (
            ram_child,
            "RAM-only Safe storage cannot be grown. Create a Safe with sufficient capacity.",
        ),
        (full, "No Safe slots available"),
    ] {
        let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
        assert_eq!(
            safe::execute(
                &mut runtime,
                command(&["grow", "GB", "2048"]),
                &mut Vec::new()
            )
            .unwrap_err()
            .to_string(),
            message
        );
        runtime.finished();
        assert!(runtime.events.is_empty());
    }
}

#[test]
fn invalid_password_bytes_never_reach_controller_or_escape_in_diagnostics() {
    for (bytes, message) in [
        (b"secret-canary\xff".to_vec(), "invalid_secret_encoding"),
        (Vec::new(), "invalid_secret_length"),
        (vec![b'x'; 1025], "invalid_secret_length"),
    ] {
        let value = closed();
        let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
        runtime.password_bytes = Some(Zeroizing::new(bytes));
        let mut output = Vec::new();
        let error =
            safe::execute(&mut runtime, command(&["grow", "GB", "2048"]), &mut output).unwrap_err();
        assert_eq!(error.to_string(), message);
        assert!(!format!("{error:?}").contains("canary"));
        assert!(error.source().is_none());
        runtime.finished();
        assert!(output.is_empty());
    }
}

#[test]
fn locked_open_uses_shared_unlock_and_never_replaces_storage() {
    let locked = state("locked");
    let value = closed();
    let mut runtime = Runtime::new(vec![
        status(&locked),
        status(&locked),
        response(Operation::Unlock, ""),
        status(&value),
        response(Operation::OpenDocuments, ""),
        response(Operation::PinSafe, ""),
    ]);
    safe::execute(&mut runtime, command(&["open", "GB"]), &mut Vec::new()).unwrap();
    runtime.finished();
    assert_eq!(
        runtime.events,
        ["password:Oblivion password", "password:Safe password"]
    );
}

#[test]
fn rejected_grow_does_not_report_success_and_invalid_peer_id_is_static() {
    let value = closed();
    let mut runtime = Runtime::new(vec![
        status(&value),
        status(&value),
        rejected(Operation::SessionStorage, "storage_unavailable"),
    ]);
    let mut output = Vec::new();
    assert_eq!(
        safe::execute(&mut runtime, command(&["grow", "GB", "2048"]), &mut output)
            .unwrap_err()
            .to_string(),
        "storage_unavailable"
    );
    runtime.finished();
    assert!(output.is_empty());
    let mut value = closed();
    value["sessions"] = json!(["unsafe-peer-canary"]);
    value["session_titles"] = json!({"unsafe-peer-canary":"GB"});
    let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
    let error = safe::execute(&mut runtime, command(&["open", "GB"]), &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "invalid_safe_id");
    assert!(!format!("{error:?}").contains("canary"));
    runtime.finished();
    assert!(runtime.events.is_empty());
}
