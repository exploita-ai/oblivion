use oblivion_host::network;
use oblivion_transport::policy::{Action, Destination, Policy, RULE_LIMIT, Rule, Session, Tools};
use serde_json::{Value, json};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn policy(rules: Value) -> Policy {
    serde_json::from_value(json!({"version": 1, "rules": rules})).unwrap()
}

fn decide(policy: &Policy, id: &str, host: &str, port: u16) -> Action {
    policy.decision(
        &Session::new(id).unwrap(),
        &Destination::new(host, port).unwrap(),
    )
}

#[test]
fn unknown_destinations_wait_for_approval() {
    for host in ["example.com", "8.8.8.8", "2001:4860:4860::8888"] {
        assert_eq!(decide(&Policy::default(), A, host, 443), Action::Ask);
    }
}

#[test]
fn wildcard_is_label_delimited_and_excludes_the_apex() {
    let policy = policy(json!([
        {"destination": "*.Example.COM.", "port": 443, "action": "allow"}
    ]));
    for host in ["www.example.com", "a.b.example.com", "WWW.EXAMPLE.COM."] {
        assert_eq!(decide(&policy, A, host, 443), Action::Allow);
    }
    for host in ["example.com", "notexample.com", "example.com.attacker.org"] {
        assert_eq!(decide(&policy, A, host, 443), Action::Ask);
    }
    assert_eq!(decide(&policy, A, "www.example.com", 80), Action::Ask);
}

#[test]
fn deny_then_ask_precedence_is_independent_of_rule_order() {
    let rules = [
        json!({"destination": "*.example.com", "port": 443, "action": "allow"}),
        json!({"destination": "www.example.com", "port": 443, "action": "ask", "session": A}),
        json!({"destination": "*.example.com", "port": 443, "action": "deny"}),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let policy = policy(Value::Array(order.map(|index| rules[index].clone()).into()));
        assert_eq!(decide(&policy, A, "www.example.com", 443), Action::Deny);
        assert_eq!(decide(&policy, B, "www.example.com", 443), Action::Deny);
    }
    for order in [[0, 1], [1, 0]] {
        let policy = policy(Value::Array(order.map(|index| rules[index].clone()).into()));
        assert_eq!(decide(&policy, A, "www.example.com", 443), Action::Ask);
        assert_eq!(decide(&policy, B, "www.example.com", 443), Action::Allow);
    }
}

#[test]
fn exact_rules_do_not_extend_to_subdomains_or_other_sessions() {
    let policy = policy(json!([
        {"destination": "example.com", "port": 8443, "action": "allow", "session": A}
    ]));
    assert_eq!(decide(&policy, A, "example.com", 8443), Action::Allow);
    assert_eq!(decide(&policy, B, "example.com", 8443), Action::Ask);
    assert_eq!(decide(&policy, A, "www.example.com", 8443), Action::Ask);
    assert_eq!(decide(&policy, A, "example.com", 443), Action::Ask);
}

#[test]
fn profile_roundtrip_preserves_canonical_names_and_ip_rules() {
    let policy = policy(json!([
        {"destination": "Example.COM.", "port": 443, "action": "allow"},
        {"destination": "2001:4860:4860:0:0:0:0:8888", "port": 443, "action": "deny"},
        {"destination": "8.8.8.8", "port": 8443, "action": "allow", "session": A}
    ]));
    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(serialized["rules"][0]["destination"], "example.com");
    assert_eq!(
        serialized["rules"][1]["destination"],
        "2001:4860:4860::8888"
    );
    let decoded: Policy = serde_json::from_value(serialized).unwrap();
    assert_eq!(decide(&decoded, A, "EXAMPLE.com", 443), Action::Allow);
    assert_eq!(
        decide(&decoded, A, "2001:4860:4860::8888", 443),
        Action::Deny
    );
    assert_eq!(decide(&decoded, A, "8.8.8.8", 8443), Action::Allow);
}

#[test]
fn ambiguous_addresses_and_authority_syntax_are_rejected_before_resolution() {
    for host in [
        "",
        "localhost",
        "example..com",
        "example.com..",
        " example.com",
        "example.com\n",
        "https://example.com",
        "example.com:443",
        "user@example.com",
        "example.com/path",
        "example.com?x=1",
        "example%2ecom",
        "example\\com",
        "-example.com",
        "example-.com",
        "ex_ample.com",
        "éxample.com",
        "127.1",
        "0177.0.0.1",
        "0x7f000001",
        "2130706433",
        "127.0.0.1.",
        "8.8.8.8.",
        "[2001:4860::8888]",
        "2001:4860::8888%lo",
        "fe80::1%25eth0",
    ] {
        assert!(Destination::new(host, 443).is_err(), "accepted {host:?}");
    }
    assert!(Destination::new(&format!("{}.com", "a".repeat(64)), 443).is_err());
    assert!(Destination::new("example.com", 0).is_err());
    assert_eq!(
        Destination::new("xn--bcher-kva.de", 65535).unwrap().port(),
        65535
    );
}

#[test]
fn local_and_special_purpose_targets_cannot_be_authorized() {
    for host in [
        "0.0.0.0",
        "10.88.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.168.1.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:1::1",
        "2001:db8::1",
        "2002:808:808::1",
        "2620:4f:8000::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "router.local",
        "a.localhost",
        "a.internal",
        "a.home.arpa",
        "a.lan",
        "a.invalid",
        "a.test",
        "a.example",
    ] {
        assert_eq!(
            Destination::new(host, 443).err(),
            Some("reserved_destination"),
            "{host}"
        );
        assert!(
            serde_json::from_value::<Policy>(json!({"version": 1, "rules": [
                {"destination": host, "port": 443, "action": "allow"}
            ]}))
            .is_err()
        );
    }
    for host in [
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.1",
        "192.0.1.1",
        "198.17.255.255",
        "198.20.0.1",
        "2001:200::1",
        "3fff:1000::1",
    ] {
        assert!(
            Destination::new(host, 443).is_ok(),
            "overbroad exclusion: {host}"
        );
    }
}

#[test]
fn malformed_policy_never_becomes_an_empty_or_permissive_profile() {
    for value in [
        json!({}),
        json!({"version": 2, "rules": []}),
        json!({"version": 1, "rules": [], "extra": true}),
    ] {
        assert!(serde_json::from_value::<Policy>(value).is_err());
    }
    for rule in [
        json!({"destination": "*", "port": 443, "action": "allow"}),
        json!({"destination": "*.com", "port": 443, "action": "allow"}),
        json!({"destination": "*example.com", "port": 443, "action": "allow"}),
        json!({"destination": "a.*.example.com", "port": 443, "action": "allow"}),
        json!({"destination": "*.8.8.8.8", "port": 443, "action": "allow"}),
        json!({"destination": "example.com", "port": 0, "action": "allow"}),
        json!({"destination": "example.com", "port": 65536, "action": "allow"}),
        json!({"destination": "example.com", "port": 443, "action": "direct"}),
        json!({"destination": "example.com", "port": 443, "action": "allow", "session": "../vault"}),
        json!({"destination": "example.com", "port": 443, "action": "allow", "extra": true}),
    ] {
        assert!(serde_json::from_value::<Policy>(json!({"version": 1, "rules": [rule]})).is_err());
    }
    assert!(serde_json::from_str::<Policy>(r#"{"version":1,"version":1,"rules":[]}"#).is_err());
    assert!(Session::new(&A.to_uppercase()).is_err());
    assert!(Session::new("").is_err());
}

#[test]
fn rule_count_is_bounded_at_the_policy_boundary() {
    let rule = json!({"destination": "example.com", "port": 443, "action": "deny"});
    assert!(
        serde_json::from_value::<Policy>(
            json!({"version": 1, "rules": vec![rule.clone(); RULE_LIMIT]})
        )
        .is_ok()
    );
    assert!(
        serde_json::from_value::<Policy>(
            json!({"version": 1, "rules": vec![rule; RULE_LIMIT + 1]})
        )
        .is_err()
    );
}

#[test]
fn trusted_edits_replace_only_the_same_destination_port_and_scope() {
    let mut policy = policy(json!([
        {"destination":"example.com","port":443,"action":"allow"},
        {"destination":"example.com","port":443,"action":"deny"},
        {"destination":"example.com","port":80,"action":"deny"},
        {"destination":"example.com","port":443,"action":"ask","session":B}
    ]));
    let rule = Rule::new("EXAMPLE.COM.".into(), 443, Action::Allow, None).unwrap();
    policy.put(rule.clone()).unwrap();
    assert_eq!(policy.rules().len(), 3);
    assert_eq!(decide(&policy, A, "example.com", 443), Action::Allow);
    assert_eq!(decide(&policy, B, "example.com", 443), Action::Ask);
    assert_eq!(decide(&policy, A, "example.com", 80), Action::Deny);
    let stale = Rule::new("example.com".into(), 443, Action::Deny, None).unwrap();
    assert_eq!(policy.remove(&stale).err(), Some("network_rule_missing"));
    policy.remove(&rule).unwrap();
    assert_eq!(decide(&policy, A, "example.com", 443), Action::Ask);
    assert_eq!(policy.remove(&rule).err(), Some("network_rule_missing"));
}

#[test]
fn a_full_policy_allows_replacement_but_never_a_new_rule() {
    let mut policy = Policy::default();
    for index in 0..RULE_LIMIT {
        policy
            .put(
                Rule::new(
                    format!("site-{index}.example.com"),
                    443,
                    Action::Allow,
                    None,
                )
                .unwrap(),
            )
            .unwrap();
    }
    let before = serde_json::to_vec(&policy).unwrap();
    assert_eq!(
        policy
            .put(Rule::new("extra.example.com".into(), 443, Action::Allow, None).unwrap())
            .err(),
        Some("too_many_network_rules")
    );
    assert_eq!(serde_json::to_vec(&policy).unwrap(), before);
    policy
        .put(Rule::new("site-0.example.com".into(), 443, Action::Deny, None).unwrap())
        .unwrap();
    assert_eq!(policy.rules().len(), RULE_LIMIT);
    assert_eq!(decide(&policy, A, "site-0.example.com", 443), Action::Deny);
}

#[test]
fn private_edit_commands_validate_each_rule_before_mutation() {
    for rule in [
        json!({"destination":"127.0.0.1","port":443,"action":"allow"}),
        json!({"destination":"example.com","port":0,"action":"allow"}),
        json!({"destination":"example.com","port":443,"action":"allow","session":"../vault"}),
        json!({"destination":"example.com","port":443,"action":"allow","extra":true}),
    ] {
        assert!(
            serde_json::from_value::<network::Command>(
                json!({"action":"put","rule":rule,"save":true})
            )
            .is_err()
        );
    }
    assert!(Rule::new("*.8.8.8.8".into(), 443, Action::Allow, None).is_err());
    assert!(
        serde_json::from_value::<network::Command>(json!({"action":"saved","extra":true})).is_err()
    );
    let command: network::Command = serde_json::from_value(json!({"action":"put","rule":{"destination":"EXAMPLE.COM.","port":443,"action":"allow"},"save":false})).unwrap();
    assert_eq!(
        serde_json::to_value(command).unwrap()["rule"]["destination"],
        "example.com"
    );
}

#[test]
fn selected_policy_and_private_grant_preserve_scope_without_a_default_allow() {
    let saved =
        policy(json!([{"destination":"example.com","port":443,"action":"allow","session":A}]));
    let status = network::Status::new(Some(saved), Some(Policy::default()));
    assert!(status.enabled && status.temporary);
    assert_eq!(decide(&status.policy, A, "example.com", 443), Action::Ask);
    let status = network::Status::new(None, None);
    assert!(!status.enabled && !status.temporary && status.policy.rules().is_empty());
    let tools = Tools {
        session: Session::new(A).unwrap(),
        policy: policy(json!([
            {"destination":"EXAMPLE.COM.","port":443,"action":"allow","session":A}
        ])),
    };
    let bytes = serde_json::to_vec(&tools).unwrap();
    let decoded: Tools = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded.policy.decision(
            &decoded.session,
            &Destination::new("example.com", 443).unwrap()
        ),
        Action::Allow
    );
    assert_eq!(decide(&decoded.policy, B, "example.com", 443), Action::Ask);
}
