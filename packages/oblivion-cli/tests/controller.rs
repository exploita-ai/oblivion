use oblivion_cli::controller::{AgentSafeState, Command, State};
use serde_json::json;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn state() -> serde_json::Value {
    json!({
        "app_open":true,"app_mode":"persistent","general_present":true,
        "general_incomplete":false,"backing_recovery_required":false,"general_bytes":8589934592_u64,"recovery_required":false,
        "sessions":["a".repeat(32)],"session_titles":{"a".repeat(32):"GB"},
        "open_sessions":[{"slot":2,"id":"a".repeat(32),"mode":"documents","recovery_required":false}],
        "agent_safes":[{"id":"b".repeat(32),"ephemeral":true,"state":"awaiting-start"},
            {"id":"c".repeat(32),"ephemeral":false,"state":"awaiting-start"}],
        "additional_controller_state":{"retained_by_raw_status":true}
    })
}

#[test]
fn recovery_observations_cannot_be_omitted_from_controller_state() {
    let mut missing = state();
    missing.as_object_mut().unwrap().remove("backing_recovery_required");
    assert!(serde_json::from_value::<State<u8>>(missing).is_err());
    let mut missing = state();
    missing["open_sessions"][0].as_object_mut().unwrap().remove("recovery_required");
    assert!(serde_json::from_value::<State<u8>>(missing).is_err());
}

#[test]
fn shared_command_parser_owns_exact_status_safes_and_close_syntax() {
    assert_eq!(
        Command::parse(&args(&["status", "--json"])).unwrap(),
        Some(Command::StatusJson)
    );
    assert_eq!(
        Command::parse(&args(&["safes"])).unwrap(),
        Some(Command::Safes)
    );
    assert_eq!(
        Command::parse(&args(&["close", "GB"])).unwrap(),
        Some(Command::Close { name: "GB".into() })
    );
    for values in [
        vec!["status"],
        vec!["status", "--json", "extra"],
        vec!["safes", "extra"],
        vec!["close"],
        vec!["close", "GB", "extra"],
    ] {
        assert!(Command::parse(&args(&values)).is_err());
    }
    for values in [
        vec![],
        vec!["run", "codex", "--resume", "native-id"],
        vec!["files", "transfers"],
    ] {
        assert!(Command::parse(&args(&values)).unwrap().is_none());
    }
}

#[test]
fn one_safe_read_model_deduplicates_existing_and_open_safes_and_includes_ram_children() {
    let state = serde_json::from_value::<State<u8>>(state()).unwrap();
    assert_eq!(
        state.safe_ids().into_iter().cloned().collect::<Vec<_>>(),
        ["a".repeat(32), "b".repeat(32)]
    );
    assert_eq!(state.find_safe("GB").unwrap(), Some("a".repeat(32)));
    assert_eq!(
        state.find_safe(&"b".repeat(32)).unwrap(),
        Some("b".repeat(32))
    );
    assert!(state.find_safe(&"c".repeat(32)).unwrap().is_none());
    assert!(state.find_safe("missing").unwrap().is_none());
    assert!(state.find_safe("a").unwrap().is_none());
    assert_eq!(state.general_bytes, 8589934592_u64);
}

#[test]
fn duplicate_titles_are_ambiguous_and_failed_child_state_remains_explicit() {
    let mut state = serde_json::from_value::<State<u8>>(state()).unwrap();
    state.session_titles.insert("b".repeat(32), "GB".into());
    assert_eq!(
        state.find_safe("GB").unwrap_err().to_string(),
        "Ambiguous Safe name. Use its full identifier."
    );
    assert_eq!(
        state.find_safe(&"a".repeat(32)).unwrap(),
        Some("a".repeat(32))
    );
    state.agent_safes[0].state = AgentSafeState::Failed;
    assert_eq!(state.agent_safes[0].state, AgentSafeState::Failed);
}
