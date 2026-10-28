use oblivion_host::onion::{Access, ClientAuth, Command, OwnerRequest, Phase, Status};

#[test]
fn preparation_cannot_choose_targets_paths_credentials_or_transport_fallbacks() {
    for value in [
        r#"{"action":"prepare","ttl_seconds":30,"api_key":"synthetic"}"#,
        r#"{"action":"prepare","ttl_seconds":30,"endpoint":"192.168.1.1:22"}"#,
        r#"{"action":"prepare","ttl_seconds":30,"transport":"direct"}"#,
        r#"{"action":"prepare","ttl_seconds":30,"session":"other"}"#,
        r#"{"action":"prepare","ttl_seconds":30,"path":"/vault"}"#,
        r#"{"action":"status","command":"GETINFO anything"}"#,
        r#"{"action":"cancel","force":true}"#,
    ] {
        assert!(serde_json::from_str::<Command>(value).is_err(), "{value}");
    }
    for seconds in [0, 3601, 65535] {
        assert!(
            Command::Prepare {
                ttl_seconds: seconds
            }
            .validate()
            .is_err()
        );
    }
    for seconds in [1, 30, 3600] {
        Command::Prepare {
            ttl_seconds: seconds,
        }
        .validate()
        .unwrap();
    }
    for value in [r#"{"action":"status"}"#, r#"{"action":"cancel"}"#] {
        serde_json::from_str::<Command>(value)
            .unwrap()
            .validate()
            .unwrap();
    }
}

#[test]
fn backup_authority_is_explicit_and_cannot_name_a_host_file() {
    let valid = serde_json::json!({"action":"prepare-backup","id":"a".repeat(32),"password":"synthetic-session-password","ttl_seconds":300});
    serde_json::from_value::<Command>(valid.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (key, value) in [
        ("id", serde_json::json!("../general")),
        ("password", serde_json::json!("")),
        ("ttl_seconds", serde_json::json!(3601)),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        assert!(
            serde_json::from_value::<Command>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut invalid = valid;
    invalid["path"] = serde_json::json!("/run/oblivion/general/profile");
    assert!(serde_json::from_value::<Command>(invalid).is_err());
}

#[test]
fn stale_or_unverified_observations_never_report_a_ready_tor_connection() {
    let id = "a".repeat(32);
    let ready = Status::observed(id.clone(), Some(100), true, 10_000);
    assert!(ready.active && ready.tor_ready);
    let stale = Status::observed(id.clone(), Some(100), true, 10_001);
    assert!(stale.active && !stale.tor_ready && stale.tor_progress.is_none());
    for (progress, verified) in [
        (Some(100), false),
        (Some(99), true),
        (None, true),
        (Some(101), true),
    ] {
        assert!(!Status::observed(id.clone(), progress, verified, 0).tor_ready);
    }
    let fields = serde_json::to_value(ready).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 9);
    assert_eq!(fields["phase"], "ready");
    assert!(
        fields.get("api_key").is_none()
            && fields.get("address").is_none()
            && fields.get("private_key").is_none()
    );
    let closed = Status::closed(true);
    assert!(closed.configured && !closed.active && closed.id.is_none() && !closed.tor_ready);
    assert!(closed.phase == Phase::Closed && closed.progress.is_none());
}

#[test]
fn publication_accepts_only_a_canonical_public_key_and_no_private_credentials() {
    for key in ["A".repeat(52), format!("{}Q", "7".repeat(51))] {
        ClientAuth::try_from(key.clone()).unwrap();
        serde_json::from_value::<Command>(
            serde_json::json!({"action":"receive","client_auth":key}),
        )
        .unwrap();
    }
    for key in [
        "A".repeat(51),
        "A".repeat(53),
        "a".repeat(52),
        "0".repeat(52),
        format!("{}B", "A".repeat(51)),
        format!("{}\r\n", "A".repeat(50)),
    ] {
        assert!(ClientAuth::try_from(key).is_err());
    }
    for value in [
        serde_json::json!({"action":"receive","client_auth":"A".repeat(52),"private_key":"synthetic"}),
        serde_json::json!({"action":"receive","client_auth":"A".repeat(52),"ttl_seconds":3600}),
        serde_json::json!({"action":"receive","client_auth":"A".repeat(52),"target":"127.0.0.1:22"}),
        serde_json::json!({"action":"freeze","paths":["../workspace"]}),
        serde_json::json!({"action":"import","path":"/vault"}),
        serde_json::json!({"action":"access","include_secrets":true}),
        serde_json::json!({"action":"stage","paths":["/vault"]}),
        serde_json::json!({"action":"share","client_auth":"A".repeat(52),"paths":["unapproved.txt"]}),
    ] {
        assert!(serde_json::from_value::<Command>(value).is_err());
    }
    for request in [
        r#"{"action":"freeze"}"#,
        r#"{"action":"access"}"#,
        r#"{"action":"import"}"#,
    ] {
        serde_json::from_str::<Command>(request)
            .unwrap()
            .validate()
            .unwrap();
    }
    for request in [r#"{"operation":"freeze"}"#, r#"{"operation":"access"}"#] {
        serde_json::from_str::<OwnerRequest>(request).unwrap();
    }
}

#[test]
fn an_explicit_address_response_cannot_inject_a_path_port_or_terminal_control() {
    let address = Access::published("a".repeat(56)).unwrap();
    assert_eq!(
        address.url.as_str(),
        format!("http://{}.onion/", "a".repeat(56))
    );
    let encoded = serde_json::to_value(address).unwrap();
    assert_eq!(encoded.as_object().unwrap().len(), 1);
    for id in [
        "a".repeat(55),
        "a".repeat(57),
        "A".repeat(56),
        "0".repeat(56),
        format!("{}\x1b", "a".repeat(55)),
        "host:22/path".into(),
    ] {
        assert!(Access::published(id).is_err());
    }
}

#[test]
fn private_owner_control_rejects_raw_commands_and_stop_overrides() {
    for request in [
        r#"{"operation":"observe","command":"GETINFO anything"}"#,
        r#"{"operation":"observe","api_key":"synthetic"}"#,
        r#"{"operation":"stop","force":true}"#,
        r#"{"operation":"publish","target":"127.0.0.1:22"}"#,
    ] {
        assert!(serde_json::from_str::<OwnerRequest>(request).is_err());
    }
    for request in [r#"{"operation":"observe"}"#, r#"{"operation":"stop"}"#] {
        assert!(serde_json::from_str::<OwnerRequest>(request).is_ok());
    }
}
