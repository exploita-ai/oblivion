mod support;
use oblivion_cli::settings;
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use support::{Runtime, response};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn view(storage: &str, writable: bool, safe: u16, host: u16) -> Value {
    json!({"preferences":{"version":1,"safe_minutes":safe,"host_minutes":host},
        "host":{"nonce":"host-generation","remaining_seconds":123,"closing":false},
        "safes":[{"opening":{"slot":1,"safe_id":"a".repeat(32),"nonce":"safe-generation"},
            "remaining_seconds":42,"closing":true}],"last_error":"close_failed",
        "storage":storage,"writable":writable})
}
fn status(value: Value) -> support::Step {
    response(Operation::Status, json!({"idle_lock":value}).to_string())
}

#[test]
fn settings_parser_rejects_invalid_timers_before_controller_access() {
    for values in [
        vec![],
        vec!["network"],
        vec!["idle", "--safe-minutes"],
        vec!["idle", "--safe-minutes", "1441"],
        vec!["idle", "--host-minutes", "65536"],
        vec!["idle", "--safe-minutes", "-1"],
        vec!["idle", "--safe-minutes", "PRIVATE_CANARY"],
        vec!["idle", "--safe-minutes", "0", "--safe-minutes", "1"],
        vec!["idle", "--json", "--json"],
        vec!["idle", "--host-minutes", "1", "--unknown"],
    ] {
        let error = settings::parse(&args(&values)).err().unwrap();
        assert!(!error.contains("PRIVATE_CANARY"));
    }
    assert!(
        settings::parse(&args(&[
            "idle",
            "--safe-minutes",
            "0",
            "--host-minutes",
            "1440",
            "--json"
        ]))
        .is_ok()
    );
}

#[test]
fn partial_settings_preserve_the_other_timer_and_json_keeps_full_public_status() {
    for (flags, safe, host) in [
        (vec!["--safe-minutes", "0"], 0, 47),
        (vec!["--host-minutes", "1440"], 22, 1440),
    ] {
        let expected = view("saved-encrypted", true, safe, host);
        let mut runtime = Runtime::new(vec![
            status(view("saved-encrypted", true, 22, 47)),
            response(Operation::IdleSettings, ""),
            status(expected.clone()),
        ]);
        let mut values = vec!["idle", "--json"];
        values.extend(flags);
        let mut output = vec![];
        settings::execute(
            &mut runtime,
            settings::parse(&args(&values)).unwrap(),
            &mut output,
        )
        .unwrap();
        runtime.finished();
        assert_eq!(runtime.sent.len(), 3);
        assert_eq!(
            serde_json::from_slice::<Value>(&runtime.sent[1].body).unwrap(),
            json!({"version":1,"safe_minutes":safe,"host_minutes":host})
        );
        for call in &runtime.sent {
            assert_eq!(call.slot, None);
            assert_eq!(call.expected, None);
            assert_eq!(call.session, None);
        }
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), expected);
        assert!(runtime.events.is_empty());
    }
}

#[test]
fn settings_read_only_defaults_and_ram_views_use_one_status_without_prompts() {
    for (storage, writable, label) in [
        ("defaults", false, "Defaults"),
        ("ram-only", false, "RAM only"),
        ("saved-encrypted", false, "Saved encrypted"),
    ] {
        let mut runtime = Runtime::new(vec![status(view(storage, writable, 0, 30))]);
        let mut output = vec![];
        settings::execute(
            &mut runtime,
            settings::parse(&args(&["idle"])).unwrap(),
            &mut output,
        )
        .unwrap();
        runtime.finished();
        assert_eq!(runtime.sent.len(), 1);
        assert!(runtime.events.is_empty());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Safe idle lock: Disabled"));
        assert!(output.contains("Oblivion idle lock: 30 minutes"));
        assert!(output.contains(&format!("Preferences: {label}")));
    }
}

#[test]
fn malformed_status_never_exposes_peer_parse_data_or_submits_an_update() {
    for value in [
        json!({"idle_lock":"PRIVATE_CANARY"}),
        json!({"idle_lock":{"storage":"PRIVATE_CANARY"}}),
        json!({"idle_lock":view("ram-only",false,1441,30)}),
    ] {
        let mut runtime = Runtime::new(vec![response(Operation::Status, value.to_string())]);
        let mut output = vec![];
        let error = settings::execute(
            &mut runtime,
            settings::parse(&args(&["idle", "--safe-minutes", "0", "--json"])).unwrap(),
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_idle_status");
        assert_eq!(runtime.sent.len(), 1);
        assert!(output.is_empty());
    }
}
