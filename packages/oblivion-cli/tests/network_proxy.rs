use oblivion_cli::{
    controller::{Call, Controller, Result},
    network, proxy_profiles, run,
};
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;
use zeroize::Zeroizing;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Sent {
    operation: Operation,
    slot: Option<u8>,
    expected: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
struct Runtime {
    responses: VecDeque<String>,
    sent: Vec<Sent>,
    passwords: VecDeque<Vec<u8>>,
    prompts: Vec<&'static str>,
}
impl Runtime {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: responses.into(),
            sent: vec![],
            passwords: VecDeque::new(),
            prompts: vec![],
        }
    }
}
impl Controller for Runtime {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        assert!(call.session.is_none());
        self.sent.push(Sent {
            operation: call.operation,
            slot: call.slot,
            expected: call.expected_session.map(str::to_owned),
            body: Zeroizing::new(call.secret.to_vec()),
        });
        Ok(self.responses.pop_front().expect("unexpected RPC"))
    }
}
impl run::Runtime for Runtime {
    type Mark = ();
    fn slots(&self) -> Vec<u8> {
        panic!("network cannot allocate Safe slots")
    }
    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.prompts.push(label);
        Ok(Zeroizing::new(
            self.passwords
                .pop_front()
                .expect("unexpected password prompt"),
        ))
    }
    fn new_password(&mut self, _: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        panic!("cannot create storage")
    }
    fn confirm(&mut self, _: &'static str) -> Result<bool> {
        panic!("cannot reset storage")
    }
    fn now(&self) {}
    fn elapsed(&self, _: &()) -> Duration {
        panic!("cannot start a gateway")
    }
    fn wait(&mut self, _: Duration) -> Result<()> {
        panic!("cannot start a gateway")
    }
    fn notice(&mut self, _: run::Notice<'_>) -> Result<()> {
        panic!("diagnostics use supplied writer")
    }
    fn attach(&mut self, _: u8, _: &str, _: &str, _: &[String]) -> Result<i32> {
        panic!("cannot attach")
    }
    fn attach_workspace(&mut self, _: u8, _: &str) -> Result<i32> {
        panic!("cannot attach")
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn state(mode: &str, open: bool) -> String {
    json!({"app_open":mode!="locked","app_mode":mode,"general_present":true,
        "general_incomplete":false,"general_bytes":8589934592u64,"recovery_required":false,
        "sessions":[ID],"session_titles":{ID:"GB"},
        "open_sessions":if open { json!([{"slot":2,"id":ID,"mode":"documents"}]) } else {json!([])},
        "agent_safes":[]})
    .to_string()
}
fn observation() -> String {
    r#"{ "network_status":{"label":"TOR READY"},"safe_access":{"current":"open"},"extra":true }"#
        .into()
}

#[test]
fn full_pure_parsing_rejects_invalid_changes_and_private_proxy_options() {
    for values in [
        vec!["status"],
        vec!["set", "--safe", "GB"],
        vec!["status", "--safe", "GB", "--tor"],
        vec![
            "status",
            "--safe",
            "GB",
            "-x",
            "socks5h://user@192.0.2.5:1080",
        ],
        vec![
            "set",
            "--safe",
            "GB",
            "-x",
            "socks5h://user@192.0.2.5:1080",
            "--policy",
            "strict",
        ],
        vec!["set", "--safe", "GB", "--tor", "--proxy-profile", "Office"],
        vec!["set", "--safe", "GB", "--proxy-profile", "../invalid"],
        vec!["set", "--safe", "GB", "--policy", "direct"],
        vec!["set", "--safe", "GB", "--tor", "--safe", "other"],
        vec!["status", "--safe", "GB", "--json", "--json"],
    ] {
        assert!(network::parse(&args(&values)).is_err());
    }
    for values in [
        vec![],
        vec!["add", "../invalid"],
        vec!["list", "--secret"],
        vec!["remove", "Office", "--json"],
        vec!["add", "Office", "-x", "PRIVATE_CANARY"],
        vec!["add", "Office", "-x", "socks5h://user@127.0.0.1:1080"],
    ] {
        let error = proxy_profiles::parse(&args(&values)).err().unwrap();
        assert!(!error.contains("PRIVATE_CANARY"));
    }
    assert!(network::parse(&args(&["set", "--safe", "GB", "--proxy-profile", "Office"])).is_ok());
    assert!(proxy_profiles::parse(&args(&["add", "Office"])).is_ok());
}

#[test]
fn network_scopes_transport_and_raw_status_and_chooses_persistence_from_app_mode() {
    for mode in ["persistent", "read-only", "ram-only"] {
        let mut runtime = Runtime::new(vec![state(mode, true), String::new(), observation()]);
        runtime.passwords.push_back(b"PRIVATE_PASSWORD".to_vec());
        let mut output = vec![];
        let mut diagnostics = vec![];
        network::execute(
            &mut runtime,
            network::parse(&args(&[
                "set",
                "--safe",
                "GB",
                "-x",
                "socks5h://PRIVATE_USER@192.0.2.5:1080",
                "--json",
            ]))
            .unwrap(),
            &mut output,
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{}\n", observation())
        );
        assert_eq!(runtime.prompts, ["Proxy password"]);
        assert_eq!(runtime.sent.len(), 3);
        for call in &runtime.sent[1..] {
            assert_eq!(call.slot, Some(2));
            assert_eq!(call.expected.as_deref(), Some(ID));
        }
        assert_eq!(runtime.sent[1].operation, Operation::Egress);
        let body: Value = serde_json::from_slice(&runtime.sent[1].body).unwrap();
        assert_eq!(
            body["action"],
            if mode == "persistent" {
                "save"
            } else {
                "select"
            }
        );
        assert_eq!(
            body["transport"]["authentication"],
            json!({"username":"PRIVATE_USER","password":"PRIVATE_PASSWORD"})
        );
        let diagnostics = String::from_utf8(diagnostics).unwrap();
        assert!(diagnostics.contains("requests will be interrupted"));
        assert!(!diagnostics.contains("PRIVATE_"));
    }
}

#[test]
fn network_policy_is_typed_and_locked_or_closed_safes_never_prompt_or_mutate() {
    for mode in ["persistent", "read-only", "ram-only"] {
        let mut runtime = Runtime::new(vec![state(mode, true), String::new(), observation()]);
        let mut output = vec![];
        let mut diagnostics = vec![];
        network::execute(
            &mut runtime,
            network::parse(&args(&["set", "--safe", "GB", "--policy", "open-internet"])).unwrap(),
            &mut output,
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(runtime.sent[1].operation, Operation::SafeAccess);
        assert_eq!(
            serde_json::from_slice::<Value>(&runtime.sent[1].body).unwrap(),
            json!({"mode":"open","save":mode=="persistent"})
        );
        assert_eq!(output, b"TOR READY \xc2\xb7 open-internet\n");
        assert!(diagnostics.is_empty());
        assert!(runtime.prompts.is_empty());
    }
    for (mode, open) in [("locked", true), ("persistent", false)] {
        let mut runtime = Runtime::new(vec![state(mode, open)]);
        let error = network::execute(
            &mut runtime,
            network::parse(&args(&[
                "set",
                "--safe",
                "GB",
                "-x",
                "socks5h://PRIVATE_USER@192.0.2.5:1080",
            ]))
            .unwrap(),
            &mut vec![],
            &mut vec![],
        )
        .unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(runtime.sent.len(), 1);
        assert!(runtime.prompts.is_empty());
    }
}

#[test]
fn proxy_hidden_url_and_user_password_stay_in_controller_payload_only() {
    let mut runtime = Runtime::new(vec![String::new()]);
    runtime
        .passwords
        .push_back(b"socks5h://PRIVATE_USER@192.0.2.5:1080".to_vec());
    runtime.passwords.push_back(b"PRIVATE_PASSWORD".to_vec());
    let mut output = vec![];
    let mut diagnostics = vec![];
    proxy_profiles::execute(
        &mut runtime,
        proxy_profiles::parse(&args(&["add", "Office"])).unwrap(),
        &mut output,
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(runtime.prompts, ["SOCKS5 URL (hidden)", "Proxy password"]);
    let call = &runtime.sent[0];
    assert_eq!(call.operation, Operation::ProxyProfiles);
    assert_eq!(call.slot, None);
    assert_eq!(call.expected, None);
    assert_eq!(
        serde_json::from_slice::<Value>(&call.body).unwrap(),
        json!({"action":"add","name":"Office",
        "transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authentication":{"username":"PRIVATE_USER","password":"PRIVATE_PASSWORD"}}})
    );
    assert!(output.is_empty());
    assert!(!String::from_utf8(diagnostics).unwrap().contains("PRIVATE_"));
}

#[test]
fn proxy_listing_only_formats_positive_metadata_and_never_peer_parse_errors() {
    for response in [
        r#"{"entries":[{"name":"Office","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authenticated":true,"authentication":{"password":"PRIVATE_CANARY"}},"temporary":false}]}"#,
        r#"{"entries":[],"PRIVATE_CANARY":true}"#,
        r#"{"entries":"PRIVATE_CANARY"}"#,
    ] {
        let mut runtime = Runtime::new(vec![response.into()]);
        let mut output = vec![];
        let mut diagnostics = vec![];
        let error = proxy_profiles::execute(
            &mut runtime,
            proxy_profiles::parse(&args(&["list", "--json"])).unwrap(),
            &mut output,
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_proxy_profile_status");
        assert!(output.is_empty());
        assert!(diagnostics.is_empty());
    }
    let response=json!({"entries":[{"name":"Office","transport":{"mode":"socks5","endpoint":"192.0.2.5:1080","authenticated":true},"temporary":false}]}).to_string();
    let mut runtime = Runtime::new(vec![response.clone()]);
    let mut output = vec![];
    proxy_profiles::execute(
        &mut runtime,
        proxy_profiles::parse(&args(&["list", "--json"])).unwrap(),
        &mut output,
        &mut vec![],
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        serde_json::from_str::<Value>(&response).unwrap()
    );
    assert!(runtime.prompts.is_empty());
}
