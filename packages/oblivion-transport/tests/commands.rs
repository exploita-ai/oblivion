use oblivion_transport::{egress, policy, proxy_profiles};

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
