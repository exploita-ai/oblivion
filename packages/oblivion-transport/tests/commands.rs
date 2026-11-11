use oblivion_transport::{egress, policy, proxy_profiles};

#[test]
fn tool_policy_requires_an_explicit_current_access_mode() {
    let input = serde_json::json!({
        "session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": {"version": 1, "rules": []},
    });
    assert!(serde_json::from_value::<policy::Tools>(input.clone()).is_err());
    for access in ["open", "strict", "offline"] {
        let mut current = input.clone();
        current["access"] = serde_json::json!(access);
        let tools: policy::Tools = serde_json::from_value(current.clone()).unwrap();
        assert_eq!(serde_json::to_value(tools).unwrap(), current);
    }
}

#[test]
fn transport_and_access_commands_keep_the_existing_strict_wire_shapes() {
    for json in [
        r#"{"action":"save","transport":{"mode":"tor"}}"#,
        r#"{"action":"select","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authentication":null}}"#,
        r#"{"action":"saved"}"#,
    ] {
        let command: egress::Command = serde_json::from_str(json).unwrap();
        assert_eq!(
            serde_json::to_value(command).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }
    assert!(
        serde_json::from_str::<egress::Command>(r#"{"action":"saved","path":"/tmp"}"#).is_err()
    );
    for mode in ["open", "strict", "offline"] {
        let command: policy::Command =
            serde_json::from_value(serde_json::json!({"mode":mode,"save":true})).unwrap();
        assert_eq!(
            serde_json::to_value(command).unwrap(),
            serde_json::json!({"mode":mode,"save":true})
        );
    }
    for request in [
        r#"{"action":"access","mode":"open","save":true}"#,
        r#"{"mode":"open","save":true,"keyboard":"us"}"#,
        r#"{"mode":"direct","save":false}"#,
    ] {
        assert!(serde_json::from_str::<policy::Command>(request).is_err());
    }
}

#[test]
fn profile_decoder_preserves_credential_payload_and_rejects_invalid_boundary_data() {
    let source = br#"{"action":"add","name":"Office","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authentication":{"username":"PRIVATE_USER","password":"PRIVATE_PASSWORD"}}}"#;
    let command = proxy_profiles::Command::decode(source).unwrap();
    assert_eq!(
        serde_json::to_value(command).unwrap(),
        serde_json::from_slice::<serde_json::Value>(source).unwrap()
    );
    for source in [
        br#"{"action":"list","PRIVATE_CANARY":true}"#.as_slice(),
        br#"{"action":"select","name":"../profile"}"#.as_slice(),
        br#"{"action":"add","name":"Tor","transport":{"mode":"tor"}}"#.as_slice(),
        br#"{"action":"add","name":"Bad","transport":{"mode":"socks5","endpoint":"127.0.0.1:1080","authentication":null}}"#.as_slice(),
    ] {
        assert!(proxy_profiles::Command::decode(source).is_err());
    }
    assert_eq!(
        proxy_profiles::Command::decode(&vec![b' '; 4097]).err(),
        Some("invalid_proxy_profile_command")
    );
    assert_eq!(
        proxy_profiles::Command::decode(br#"{"action":"list","PRIVATE_CANARY":true}"#).err(),
        Some("invalid_proxy_profile_command")
    );
    for name in ["", "../profile", "line\nname", " trailing "] {
        assert!(proxy_profiles::valid_name(name).is_err());
    }
}

#[test]
fn profile_status_accepts_only_bounded_unique_public_socks_metadata() {
    let source = br#"{"entries":[{"name":"Office","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authenticated":true},"temporary":false}]}"#;
    let status = proxy_profiles::Status::decode(source).unwrap();
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        serde_json::from_slice::<serde_json::Value>(source).unwrap()
    );
    let entry = serde_json::from_slice::<serde_json::Value>(source).unwrap()["entries"][0].clone();
    for value in [
        serde_json::json!({"entries":[entry.clone(),entry.clone()]}),
        serde_json::json!({"entries":vec![entry;65]}),
        serde_json::json!({"entries":[{"name":"Tor","transport":{"mode":"tor"},"temporary":true}]}),
        serde_json::json!({"entries":[{"name":"Office","transport":{"mode":"socks5","endpoint":"127.0.0.1:1080","authenticated":true},"temporary":false}]}),
        serde_json::json!({"entries":[{"name":"Office","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authenticated":true,"PRIVATE_CANARY":true},"temporary":false}]}),
    ] {
        assert_eq!(
            proxy_profiles::Status::decode(&serde_json::to_vec(&value).unwrap()).err(),
            Some("invalid_proxy_profile_status")
        );
    }
    assert_eq!(
        proxy_profiles::Status::decode(&vec![b' '; 65537]).err(),
        Some("invalid_proxy_profile_status")
    );
}
