use oblivion_host::{
    delegation::{Credential, SealedCredential},
    family::{Capability, TaskContext},
};
use zeroize::Zeroizing;

fn context() -> TaskContext<'static> {
    TaskContext {
        safe_id: "11111111111111111111111111111111",
        parent_id: "22222222222222222222222222222222",
        request_id: "33333333333333333333333333333333",
        agent: "codex",
    }
}

#[test]
fn sealed_identity_is_bound_to_the_exact_child_source_task_agent_and_family() {
    let capability =
        Capability::from_root_secret(&"4".repeat(32), Zeroizing::new([41; 32])).unwrap();
    let credential = Credential::decode(
        br#"{"kind":"codex-api-key","key":"synthetic-private-identity-canary"}"#,
        "codex",
    )
    .unwrap();
    let first = SealedCredential::seal(&capability, &context(), &credential).unwrap();
    let second = SealedCredential::seal(&capability, &context(), &credential).unwrap();
    let encoded = serde_json::to_vec(&first).unwrap();
    assert!(
        !encoded
            .windows(16)
            .any(|bytes| bytes == b"synthetic-privat")
    );
    assert!(encoded != serde_json::to_vec(&second).unwrap());
    let decoded: SealedCredential = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        decoded
            .open(&capability, &context())
            .unwrap()
            .encode()
            .unwrap()
            .as_slice(),
        credential.encode().unwrap().as_slice()
    );
    for changed in [
        TaskContext {
            safe_id: "55555555555555555555555555555555",
            ..context()
        },
        TaskContext {
            parent_id: "55555555555555555555555555555555",
            ..context()
        },
        TaskContext {
            request_id: "55555555555555555555555555555555",
            ..context()
        },
        TaskContext {
            agent: "claude",
            ..context()
        },
    ] {
        assert!(decoded.open(&capability, &changed).is_err());
    }
    let other = Capability::from_root_secret(&"4".repeat(32), Zeroizing::new([42; 32])).unwrap();
    assert!(decoded.open(&other, &context()).is_err());
    let other = Capability::from_root_secret(&"5".repeat(32), Zeroizing::new([41; 32])).unwrap();
    assert!(decoded.open(&other, &context()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["nonce"][0] = (value["nonce"][0].as_u64().unwrap() ^ 1).into();
    assert!(
        serde_json::from_value::<SealedCredential>(value)
            .unwrap()
            .open(&capability, &context())
            .is_err()
    );
}

#[test]
fn only_explicit_supported_identity_types_cross_the_private_boundary() {
    for (agent, fixture) in [
        (
            "codex",
            r#"{"kind":"codex-access-token","token":"at-synthetic-fixture"}"#,
        ),
        (
            "claude",
            r#"{"kind":"claude-api-key","key":"synthetic-fixture"}"#,
        ),
        (
            "claude",
            r#"{"kind":"claude-setup-token","token":"synthetic-fixture"}"#,
        ),
        (
            "opencode2",
            r#"{"kind":"opencode-key","integration_id":"openai","key":"synthetic-fixture","model":"openai/gpt-model"}"#,
        ),
    ] {
        assert!(Credential::decode(fixture.as_bytes(), agent).is_ok());
    }
    for fixture in [
        r#"{"kind":"codex-oauth","refresh_token":"fixture"}"#,
        r#"{"kind":"codex-access-token","token":"eyJ-this-is-not-a-native-access-token"}"#,
        r#"{"kind":"codex-api-key","key":"fixture","home":{"hooks":"not transferred"}}"#,
        r#"{"kind":"codex-api-key","key":"bad\nvalue"}"#,
        r#"{"kind":"claude-api-key","key":"fixture"}"#,
    ] {
        assert!(Credential::decode(fixture.as_bytes(), "codex").is_err());
    }
    for fixture in [
        r#"{"kind":"opencode-key","integration_id":"arbitrary","key":"fixture","model":"arbitrary/model"}"#,
        r#"{"kind":"opencode-key","integration_id":"openai","key":"fixture","model":"anthropic/model"}"#,
        r#"{"kind":"opencode-key","integration_id":"openai","key":"fixture","model":"openai/model","base_url":"https://other.invalid"}"#,
    ] {
        assert!(Credential::decode(fixture.as_bytes(), "opencode2").is_err());
    }
    assert!(
        Credential::decode(&vec![b' '; oblivion_host::delegation::LIMIT + 1], "codex").is_err()
    );
}
