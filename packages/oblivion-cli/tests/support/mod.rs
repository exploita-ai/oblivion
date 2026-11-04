// Shared fixtures are compiled independently by each integration target.
#![allow(dead_code)]
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
pub const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const CREATED: &str = "cccccccccccccccccccccccccccccccc";
pub struct Step {
    pub operation: Operation,
    pub output: std::result::Result<String, &'static str>,
}
pub struct Sent {
    pub operation: Operation,
    pub slot: Option<u8>,
    pub session: Option<String>,
    pub expected: Option<String>,
    pub body: Zeroizing<Vec<u8>>,
}
pub struct Runtime {
    pub steps: VecDeque<Step>,
    pub sent: Vec<Sent>,
    pub events: Vec<String>,
    pub clock: Cell<Duration>,
    pub advance: Option<Duration>,
    pub attached: Option<(u8, String, String, Vec<String>)>,
    pub slots: Vec<u8>,
    pub confirmation: bool,
    pub prompt_error: Option<&'static str>,
    pub reject_notice: Option<&'static str>,
}
impl Runtime {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            sent: Vec::new(),
            events: Vec::new(),
            clock: Cell::new(Duration::ZERO),
            advance: None,
            attached: None,
            slots: vec![0, 1],
            confirmation: false,
            prompt_error: None,
            reject_notice: None,
        }
    }
    pub fn finished(&self) {
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
        if let Some(error) = self.prompt_error {
            return Err(error.into());
        }
        Ok(Zeroizing::new(b"synthetic unlock password".to_vec()))
    }
    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.events.push(format!("new-password:{label}"));
        if let Some(error) = self.prompt_error {
            return Err(error.into());
        }
        Ok(Zeroizing::new(b"synthetic new password".to_vec()))
    }
    fn confirm(&mut self, word: &'static str) -> Result<bool> {
        self.events.push(format!("confirm:{word}"));
        Ok(self.confirmation)
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
            run::Notice::StorageCapacity(bytes) => format!("capacity:{bytes}"),
            run::Notice::StorageCreated => "storage-created".into(),
            run::Notice::IncompleteStorageReview => "storage-review".into(),
            run::Notice::IncompleteStorageDiscarded => "storage-discarded".into(),
        });
        if self
            .reject_notice
            .is_some_and(|expected| self.events.last().is_some_and(|notice| notice == expected))
        {
            return Err("notice_unavailable".into());
        }
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
pub fn state(mode: &str) -> Value {
    json!({"app_open":mode!="locked","app_mode":mode,"general_present":true,"general_incomplete":false,
        "general_bytes":8589934592_u64,"recovery_required":false,"sessions":[],"session_titles":{},"open_sessions":[],"agent_safes":[]})
}
pub fn active() -> Value {
    let mut value = state("persistent");
    value["sessions"] = json!([ID]);
    value["session_titles"] = json!({ID:"GB"});
    value["open_sessions"] = json!([{"slot":1,"id":ID,"mode":"agent"}]);
    value
}
pub fn response(operation: Operation, value: impl Into<String>) -> Step {
    Step {
        operation,
        output: Ok(value.into()),
    }
}
pub fn status(value: &Value) -> Step {
    response(Operation::Status, value.to_string())
}
pub fn rejected(operation: Operation, error: &'static str) -> Step {
    Step {
        operation,
        output: Err(error),
    }
}
pub fn options(values: &[&str]) -> run::Options<Transport> {
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
