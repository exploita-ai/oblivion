use oblivion_cli::{
    controller::{Call, Controller, Result},
    proxy, run,
};
use oblivion_transport::Transport;
use oblivion_wire::control::Operation;
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::VecDeque;
use std::time::Duration;
use zeroize::Zeroizing;
const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CREATED: &str = "cccccccccccccccccccccccccccccccc";
struct Step {
    operation: Operation,
    output: std::result::Result<String, &'static str>,
}
struct Sent {
    operation: Operation,
    slot: Option<u8>,
    session: Option<String>,
    expected: Option<String>,
    body: Zeroizing<Vec<u8>>,
}
struct Runtime {
    steps: VecDeque<Step>,
    sent: Vec<Sent>,
    events: Vec<String>,
    clock: Cell<Duration>,
    advance: Option<Duration>,
    attached: Option<(u8, String, String, Vec<String>)>,
    slots: Vec<u8>,
}
impl Runtime {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            sent: Vec::new(),
            events: Vec::new(),
            clock: Cell::new(Duration::ZERO),
            advance: None,
            attached: None,
            slots: vec![0, 1],
        }
    }
    fn finished(&self) {
        assert!(self.steps.is_empty());
    }
}
impl Controller for Runtime {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        let step = self.steps.pop_front().expect("unexpected controller call");
        assert_eq!(call.operation, step.operation);
        self.sent.push(Sent {
            operation: call.operation,
            slot: call.slot,
            session: call.session.map(str::to_owned),
            expected: call.expected_session.map(str::to_owned),
            body: Zeroizing::new(call.secret.to_vec()),
        });
        step.output.map_err(Into::into)
    }
}
impl run::Runtime for Runtime {
    type Mark = Duration;
    fn slots(&self) -> Vec<u8> {
        self.slots.clone()
    }
    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.events.push(format!("password:{label}"));
        Ok(Zeroizing::new(b"synthetic unlock password".to_vec()))
    }
    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.events.push(format!("new-password:{label}"));
        Ok(Zeroizing::new(b"synthetic new password".to_vec()))
    }
    fn initialize_archive(&mut self) -> Result<()> {
        self.events.push("initialize".into());
        Ok(())
    }
    fn now(&self) -> Duration {
        self.clock.get()
    }
    fn elapsed(&self, start: &Duration) -> Duration {
        self.clock.get().saturating_sub(*start)
    }
    fn wait(&mut self, duration: Duration) -> Result<()> {
        self.events.push(format!("wait:{}", duration.as_millis()));
        self.clock
            .set(self.clock.get() + self.advance.unwrap_or(duration));
        Ok(())
    }
    fn notice(&mut self, notice: run::Notice<'_>) -> Result<()> {
        self.events.push(match notice {
            run::Notice::WaitingForConnection => "waiting".into(),
            run::Notice::SafeOpened(id) => format!("opened:{id}"),
        });
        Ok(())
    }
    fn attach(&mut self, slot: u8, id: &str, agent: &str, argv: &[String]) -> Result<i32> {
        self.attached = Some((slot, id.into(), agent.into(), argv.to_vec()));
        Ok(7)
    }
    fn attach_workspace(&mut self, _: u8, _: &str) -> Result<i32> {
        panic!("agent launch cannot attach a Workspace")
    }
}
fn state(mode: &str) -> Value {
    json!({"app_open":mode!="locked","app_mode":mode,"general_present":true,"general_incomplete":false,
        "general_bytes":8589934592_u64,"recovery_required":false,"sessions":[],"session_titles":{},"open_sessions":[],"agent_safes":[]})
}
fn active() -> Value {
    let mut value = state("persistent");
    value["sessions"] = json!([ID]);
    value["session_titles"] = json!({ID:"GB"});
    value["open_sessions"] = json!([{"slot":1,"id":ID,"mode":"agent"}]);
    value
}
fn response(operation: Operation, value: impl Into<String>) -> Step {
    Step {
        operation,
        output: Ok(value.into()),
    }
}
fn status(value: &Value) -> Step {
    response(Operation::Status, value.to_string())
}
fn rejected(operation: Operation, error: &'static str) -> Step {
    Step {
        operation,
        output: Err(error),
    }
}
fn options(values: &[&str]) -> run::Options<Transport> {
    run::parse(
        &values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .resolve_transport(|request| -> std::result::Result<_, &'static str> {
        match request {
            proxy::Request::Ready(transport) => Ok(transport),
            proxy::Request::NeedsPassword(_) => Err("no proxy prompt in this fixture"),
        }
    })
    .unwrap()
}

#[test]
fn first_new_launch_guides_setup_unlock_and_creation_and_keeps_native_arguments() {
    let mut missing = state("locked");
    missing["general_present"] = json!(false);
    let locked = state("locked");
    let opened = state("persistent");
    let mut runtime = Runtime::new(vec![
        status(&missing),
        status(&locked),
        response(Operation::Unlock, ""),
        status(&opened),
        response(Operation::Create, format!("{CREATED}\n")),
        response(Operation::RenameSession, ""),
        response(Operation::OpenDocuments, ""),
        response(Operation::StartAgent, ""),
    ]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&[
                "codex",
                "--resume",
                "native-id",
                "--safe",
                "opaque",
                "",
                "$(not a shell)",
                "città"
            ]),
            run::Context::default()
        )
        .unwrap(),
        7
    );
    runtime.finished();
    assert_eq!(
        runtime.events,
        [
            "initialize",
            "password:Oblivion password",
            "new-password:New Safe password",
            &format!("opened:{CREATED}")
        ]
    );
    let renamed = runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::RenameSession)
        .unwrap();
    let rename: oblivion_wire::session_title::Rename =
        serde_json::from_slice(&renamed.body).unwrap();
    assert_eq!(rename.id, CREATED);
    assert_eq!(rename.title, "Safe cccccccc");
    let created = runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::Create)
        .unwrap();
    let opened = runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::OpenDocuments)
        .unwrap();
    assert_eq!(&*created.body, &*opened.body);
    assert_eq!(opened.slot, Some(0));
    assert_eq!(opened.session.as_deref(), Some(CREATED));
    assert!(opened.expected.is_none());
    let attached = runtime.attached.unwrap();
    assert_eq!(
        (attached.0, attached.1.as_str(), attached.2.as_str()),
        (0, CREATED, "codex")
    );
    assert_eq!(
        attached.3,
        [
            "--resume",
            "native-id",
            "--safe",
            "opaque",
            "",
            "$(not a shell)",
            "città"
        ]
    );
}

#[test]
fn read_only_unnamed_launch_creates_ram_safe_and_applies_temporary_network() {
    let readonly = state("read-only");
    let mut after = readonly.clone();
    after["open_sessions"] = json!([{"slot":0,"id":CREATED,"mode":"documents"}]);
    let mut runtime = Runtime::new(vec![
        status(&readonly),
        status(&readonly),
        response(Operation::OpenDocumentsEphemeral, ""),
        status(&after),
        response(Operation::Egress, ""),
        response(Operation::SafeAccess, ""),
        response(Operation::StartAgent, ""),
    ]);
    run::execute(
        &mut runtime,
        options(&["--tor", "--policy", "strict", "claude"]),
        run::Context::default(),
    )
    .unwrap();
    runtime.finished();
    assert!(runtime.events.is_empty());
    for sent in runtime.sent.iter().filter(|sent| {
        matches!(
            sent.operation,
            Operation::Egress | Operation::SafeAccess | Operation::StartAgent
        )
    }) {
        assert_eq!(sent.slot, Some(0));
        assert_eq!(sent.expected.as_deref(), Some(CREATED));
    }
    let egress = &runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::Egress)
        .unwrap()
        .body;
    assert!(matches!(
        serde_json::from_slice::<oblivion_transport::egress::Command>(egress).unwrap(),
        oblivion_transport::egress::Command::Select { .. }
    ));
    let policy: oblivion_transport::policy::Command = serde_json::from_slice(
        &runtime
            .sent
            .iter()
            .find(|sent| sent.operation == Operation::SafeAccess)
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(!policy.save);
    assert_eq!(policy.mode, oblivion_transport::policy::Access::Strict);
}

#[test]
fn an_existing_safe_request_never_initializes_missing_encrypted_storage() {
    let mut missing = state("locked");
    missing["general_present"] = json!(false);
    let mut runtime = Runtime::new(vec![status(&missing), status(&missing)]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "Encrypted storage is missing. Run oblivion init."
    );
    runtime.finished();
    assert!(runtime.events.is_empty() && runtime.attached.is_none());
}

#[test]
fn storage_mode_guards_and_active_network_override_refuse_before_mutation() {
    for (value, args, message) in [
        (
            state("persistent"),
            vec!["--ephemeral", "codex"],
            "Lock Oblivion, then enter Ephemeral mode before creating a RAM-only Safe.",
        ),
        (
            state("read-only"),
            vec!["--name", "New", "codex"],
            "Named persistent Safes require persistent mode. Lock and unlock encrypted storage first.",
        ),
        (
            active(),
            vec!["--safe", "GB", "--tor", "codex"],
            "Safe is active. Change its network through the trusted network controls.",
        ),
    ] {
        let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
        assert_eq!(
            run::execute(&mut runtime, options(&args), run::Context::default())
                .unwrap_err()
                .to_string(),
            message
        );
        runtime.finished();
        assert!(runtime.events.is_empty() && runtime.attached.is_none());
    }
}

#[test]
fn protected_start_uses_the_monotonic_retry_window_without_waiting_in_the_test() {
    let active = active();
    let mut runtime = Runtime::new(vec![
        status(&active),
        status(&active),
        rejected(Operation::StartAgent, "gateway_not_ready"),
        rejected(Operation::StartAgent, "gateway_not_ready"),
    ]);
    runtime.advance = Some(Duration::from_secs(240));
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "gateway_not_ready"
    );
    runtime.finished();
    assert_eq!(runtime.events, ["waiting", "wait:500"]);
    assert!(runtime.attached.is_none());
    assert!(
        runtime
            .sent
            .iter()
            .filter(|sent| sent.operation == Operation::StartAgent)
            .all(|sent| sent.slot == Some(1) && sent.expected.as_deref() == Some(ID))
    );
    let mut runtime = Runtime::new(vec![
        status(&active),
        status(&active),
        rejected(Operation::StartAgent, "transport_failed"),
    ]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "transport_failed"
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
}

#[test]
fn occupied_slots_and_failed_ram_children_never_create_an_unrelated_safe() {
    let mut full = state("ram-only");
    full["open_sessions"] =
        json!([{"slot":0,"id":null,"mode":"starting"},{"slot":1,"id":null,"mode":"recovery"}]);
    let mut runtime = Runtime::new(vec![status(&full), status(&full)]);
    assert_eq!(
        run::execute(&mut runtime, options(&["codex"]), run::Context::default())
            .unwrap_err()
            .to_string(),
        "No Safe slots available"
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
    let mut failed = state("ram-only");
    failed["agent_safes"] = json!([{"id":ID,"ephemeral":true,"state":"failed"}]);
    let mut runtime = Runtime::new(vec![status(&failed), status(&failed)]);
    assert!(
        run::execute(
            &mut runtime,
            options(&["--safe", ID, "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string()
        .contains("not created successfully")
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
}
