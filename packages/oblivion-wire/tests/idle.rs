use oblivion_wire::idle::{Opening, Preferences, View};
use serde_json::{Value, json};

fn view() -> Value {
    json!({"preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
        "host":{"nonce":"host-opening","remaining_seconds":1700,"closing":false},
        "safes":[{"opening":{"slot":2,"safe_id":"a".repeat(32),"nonce":"safe-opening"},
            "remaining_seconds":800,"closing":true}],"last_error":"lock_failed",
        "storage":"ram-only","writable":false})
}

#[test]
fn idle_wire_owns_defaults_limits_and_slot_generic_openings() {
    assert_eq!(
        Preferences::default(),
        Preferences {
            version: 1,
            safe_minutes: 15,
            host_minutes: 30
        }
    );
    for minutes in [0, 1, 1440] {
        Preferences {
            version: 1,
            safe_minutes: minutes,
            host_minutes: minutes,
        }
        .validate()
        .unwrap();
    }
    for preferences in [
        Preferences {
            version: 2,
            ..Preferences::default()
        },
        Preferences {
            safe_minutes: 1441,
            ..Preferences::default()
        },
        Preferences {
            host_minutes: u16::MAX,
            ..Preferences::default()
        },
    ] {
        assert_eq!(preferences.validate(), Err("invalid_idle_preferences"));
    }
    let opening = Opening {
        slot: 2u8,
        safe_id: "a".repeat(32),
        nonce: "generation".into(),
    };
    let json = serde_json::to_value(&opening).unwrap();
    assert_eq!(
        serde_json::from_value::<Opening<u8>>(json.clone()).unwrap(),
        opening
    );
    let mut extra = json;
    extra["old_nonce"] = json!("generation");
    assert!(serde_json::from_value::<Opening<u8>>(extra).is_err());
}

#[test]
fn idle_public_view_preserves_every_current_status_field_and_sanitizes_decode_errors() {
    let expected = view();
    let source =
        serde_json::to_vec(&json!({"idle_lock":expected,"other_controller_state":true})).unwrap();
    let decoded = View::<u8>::decode_status(&source).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), expected);
    for (field, value) in [
        ("storage", json!("PRIVATE_CANARY")),
        ("safes", json!("PRIVATE_CANARY")),
        (
            "preferences",
            json!({"version":1,"safe_minutes":1441,"host_minutes":30}),
        ),
        (
            "preferences",
            json!({"version":2,"safe_minutes":15,"host_minutes":30}),
        ),
    ] {
        let mut invalid = view();
        invalid[field] = value;
        assert_eq!(
            View::<u8>::decode_status(&serde_json::to_vec(&json!({"idle_lock":invalid})).unwrap())
                .err(),
            Some("invalid_idle_status")
        );
    }
}
