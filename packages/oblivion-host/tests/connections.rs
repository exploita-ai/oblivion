use oblivion_host::connections::{self, AccessPoint, Command};

fn ap(security: &str) -> AccessPoint {
    AccessPoint {
        device: "wlan0".into(),
        bssid: "00:11:22:33:44:55".into(),
        ssid: "  casa:è\\rete;".into(),
        signal: 75,
        security: security.into(),
        active: false,
    }
}

#[test]
fn nmcli_fields_preserve_delimiters_and_reject_terminal_controls() {
    assert_eq!(
        connections::fields(r"wlan0:00\:11\:22\:33\:44\:55:casa\:è\\rete:75:WPA2:*").unwrap(),
        [
            "wlan0",
            "00:11:22:33:44:55",
            "casa:è\\rete",
            "75",
            "WPA2",
            "*"
        ]
    );
    for line in ["wifi:\x1b[31m", "wifi:\nnew", "wifi:\\", r"wifi:\q"] {
        assert!(connections::fields(line).is_err());
    }
}

#[test]
fn profile_serializes_names_and_password_without_keyfile_injection() {
    let profile =
        connections::wifi_profile(&"a".repeat(32), "wlan0", &ap("WPA2 WPA3"), "  pass\\word;#")
            .unwrap();
    assert!(profile.contains("ssid=32;32;99;97;115;97;58;195;168;92;114;101;116;101;59;"));
    assert!(profile.contains("psk=\\s\\spass\\\\word;#\n"));
    assert!(profile.contains("key-mgmt=wpa-psk"));
    assert!(profile.contains("uuid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    for password in ["short", "password\n[evil]", "password\r", "password\0"] {
        assert!(
            connections::wifi_profile(&"a".repeat(32), "wlan0", &ap("WPA2"), password).is_err()
        );
    }
    assert!(
        connections::wifi_profile(&"a".repeat(32), "wlan0", &ap("WPA3"), "sae-pass")
            .unwrap()
            .contains("key-mgmt=sae")
    );
    assert!(
        !connections::wifi_profile(&"a".repeat(32), "wlan0", &ap("--"), "")
            .unwrap()
            .contains("psk=")
    );
    assert!(
        connections::wifi_profile(&"a".repeat(32), "wlan0", &ap("WPA2 802.1X"), "password")
            .is_err()
    );
}

#[test]
fn requests_and_devices_are_restricted() {
    for name in ["--help", "../eth0", "eth0\n", "eth0/", ""] {
        assert!(!connections::device_name(name));
    }
    assert!(connections::device_name("enp0s1"));
    assert!(serde_json::from_str::<Command>(r#"{"action":"connect","device":"wlan0","bssid":"00:11:22:33:44:55","password":"synthetic"}"#).is_ok());
    for request in [
        r#"{"action":"shell","device":"wlan0"}"#,
        r#"{"action":"radio","enabled":true,"extra":"no"}"#,
    ] {
        assert!(serde_json::from_str::<Command>(request).is_err());
    }
}
