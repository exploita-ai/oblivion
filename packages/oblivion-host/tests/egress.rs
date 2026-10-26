use oblivion_host::egress::{Command, LIMIT, Profile, Status};
use oblivion_transport::{Authentication, Metadata, Transport};
use serde_json::json;
use zeroize::Zeroizing;

#[test]
fn missing_profile_defaults_to_tor_and_roundtrips() {
    let profile = Profile::decode(&Profile::default().encode().unwrap()).unwrap();
    assert!(matches!(profile.into_transport(), Transport::Tor {}));
}

#[test]
fn proxy_credentials_roundtrip_but_never_appear_in_status() {
    let saved = Profile::new(Transport::Socks5 {
        endpoint: "192.168.1.20:1080".parse().unwrap(),
        authentication: Some(Authentication {
            username: Zeroizing::new("synthetic-proxy-user".into()),
            password: Zeroizing::new("synthetic-proxy-password".into()),
        }),
    })
    .unwrap();
    let selected = Profile::decode(&saved.encode().unwrap()).unwrap();
    let status = serde_json::to_string(&Status {
        saved: saved.metadata(),
        selected: selected.metadata(),
        temporary: true,
    })
    .unwrap();
    assert!(status.contains("192.168.1.20:1080"));
    assert!(
        !status.contains("synthetic-proxy-user") && !status.contains("synthetic-proxy-password")
    );
    let Transport::Socks5 {
        authentication: Some(authentication),
        ..
    } = selected.into_transport()
    else {
        panic!("missing proxy authentication")
    };
    assert_eq!(authentication.username.as_str(), "synthetic-proxy-user");
    assert_eq!(authentication.password.as_str(), "synthetic-proxy-password");
}

#[test]
fn invalid_or_unknown_profiles_never_become_default_tor() {
    for value in [
        json!({}),
        json!({"version": 2, "transport": {"mode": "tor"}}),
        json!({"version": 1, "transport": {"mode": "direct"}}),
        json!({"version": 1, "transport": {"mode": "tor", "endpoint": "192.168.1.20:1080"}}),
        json!({"version": 1, "transport": {"mode": "tor"}, "extra": true}),
        json!({"version": 1, "transport": {"mode": "socks5", "endpoint": "127.0.0.1:9050"}}),
        json!({"version": 1, "transport": {"mode": "socks5", "endpoint": "proxy.example:1080"}}),
        json!({"version": 1, "transport": {"mode": "socks5", "endpoint": "192.168.1.20:1080", "authentication": {"username": "user", "password": ""}}}),
    ] {
        assert!(Profile::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(Profile::decode(b"not json").is_err());
    assert!(Profile::decode(br#"{"version":1,"version":1,"transport":{"mode":"tor"}}"#).is_err());
}

#[test]
fn profile_length_is_bounded_even_with_valid_json_padding() {
    let mut bytes = Profile::default().encode().unwrap();
    bytes.resize(LIMIT, b' ');
    assert!(Profile::decode(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(
        Profile::decode(&bytes).err(),
        Some("transport_profile_too_large")
    );
}

#[test]
fn profile_constructor_rejects_invalid_proxy_and_keeps_no_auth_explicit() {
    assert!(
        Profile::new(Transport::Socks5 {
            endpoint: "10.88.0.1:8111".parse().unwrap(),
            authentication: None,
        })
        .is_err()
    );
    let profile = Profile::new(Transport::Socks5 {
        endpoint: "192.168.1.20:1080".parse().unwrap(),
        authentication: None,
    })
    .unwrap();
    assert!(matches!(
        profile.metadata(),
        Metadata::Socks5 {
            authenticated: false,
            ..
        }
    ));
}

#[test]
fn saved_action_cannot_smuggle_new_transport_configuration() {
    assert!(matches!(
        serde_json::from_str::<Command>(r#"{"action":"saved"}"#).unwrap(),
        Command::Saved {}
    ));
    for body in [
        r#"{"action":"saved","transport":{"mode":"socks5","endpoint":"192.168.1.20:1080"}}"#,
        r#"{"action":"select","transport":{"mode":"tor","extra":true}}"#,
        r#"{"action":"save","transport":{"mode":"tor"},"extra":true}"#,
        r#"{"action":"delete"}"#,
    ] {
        assert!(serde_json::from_str::<Command>(body).is_err());
    }
    let command: Command =
        serde_json::from_str(r#"{"action":"select","transport":{"mode":"tor"}}"#).unwrap();
    assert!(matches!(
        command,
        Command::Select {
            transport: Transport::Tor {}
        }
    ));
}
