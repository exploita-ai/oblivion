//! Shared controller frontend. Platform adapters own authenticated connections,
//! runtime startup, slot scoping, deadlines, terminal state and attachment leases.
use oblivion_wire::control::Operation;
use serde::{Deserialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Secrets stay borrowed from their zeroizing owner and are never formatted.
pub struct Call<'a, S> {
    pub operation: Operation,
    pub slot: Option<S>,
    pub session: Option<&'a str>,
    pub expected_session: Option<&'a str>,
    pub secret: &'a [u8],
}

pub trait Controller {
    type Slot: Copy + Eq + DeserializeOwned;
    fn request(&mut self, call: Call<'_, Self::Slot>) -> Result<String>;
}

/// The common frontend projection of current controller state. The controller
/// emits additional platform/domain status fields; status --json preserves them.
/// Slot validation belongs to the adapter's concrete slot type.
#[derive(Deserialize)]
pub struct State<S> {
    pub app_open: bool,
    pub app_mode: AppMode,
    pub general_present: bool,
    pub general_incomplete: bool,
    pub general_bytes: u64,
    pub recovery_required: bool,
    pub backing_recovery_required: bool,
    pub sessions: Vec<String>,
    pub session_titles: BTreeMap<String, String>,
    pub open_sessions: Vec<Opened<S>>,
    pub agent_safes: Vec<AgentSafe>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AppMode {
    Locked,
    Persistent,
    ReadOnly,
    RamOnly,
}

#[derive(Deserialize)]
pub struct Opened<S> {
    pub slot: S,
    pub id: Option<String>,
    pub mode: Option<String>,
    pub recovery_required: bool,
}

#[derive(Deserialize)]
pub struct AgentSafe {
    pub id: String,
    pub ephemeral: bool,
    pub state: AgentSafeState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentSafeState {
    AwaitingStart,
    Failed,
    RecoveryRequired,
}

impl<S> State<S> {
    pub fn safe_ids(&self) -> BTreeSet<&String> {
        self.sessions
            .iter()
            .chain(
                self.open_sessions
                    .iter()
                    .filter_map(|safe| safe.id.as_ref()),
            )
            .chain(
                self.agent_safes
                    .iter()
                    .filter(|safe| safe.ephemeral)
                    .map(|safe| &safe.id),
            )
            .collect()
    }

    pub fn find_safe(&self, name: &str) -> Result<Option<String>> {
        let ids = self
            .safe_ids()
            .into_iter()
            .filter(|id| {
                id.as_str() == name
                    || self
                        .session_titles
                        .get(*id)
                        .is_some_and(|title| title == name)
            })
            .collect::<BTreeSet<_>>();
        match ids.len() {
            0 => Ok(None),
            1 => Ok(ids.first().map(|id| (*id).clone())),
            _ => Err("Ambiguous Safe name. Use its full identifier.".into()),
        }
    }
}

pub fn status<C: Controller>(controller: &mut C) -> Result<State<C::Slot>> {
    status_at(controller, None)
}

pub fn status_at<C: Controller>(
    controller: &mut C,
    slot: Option<C::Slot>,
) -> Result<State<C::Slot>> {
    let output = controller.request(Call {
        operation: Operation::Status,
        slot,
        session: None,
        expected_session: None,
        secret: &[],
    })?;
    serde_json::from_str(&output).map_err(|_| "invalid_controller_state".into())
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    StatusJson,
    Safes,
    Close { name: String },
}

impl Command {
    /// Parse controller commands for the shared top-level dispatcher. Other
    /// command families have their own parser in this crate.
    pub fn parse(args: &[String]) -> Result<Option<Self>> {
        match args.first().map(String::as_str) {
            Some("status") if args.len() == 2 && args[1] == "--json" => Ok(Some(Self::StatusJson)),
            Some("safes") if args.len() == 1 => Ok(Some(Self::Safes)),
            Some("close") if args.len() == 2 => Ok(Some(Self::Close {
                name: args[1].clone(),
            })),
            Some("status" | "safes" | "close") => {
                Err("Use oblivion status --json, safes, or close NAME".into())
            }
            _ => Ok(None),
        }
    }
}

pub fn execute<C: Controller>(
    controller: &mut C,
    command: Command,
    output: &mut impl Write,
) -> Result<i32> {
    match command {
        Command::StatusJson => {
            writeln!(
                output,
                "{}",
                controller.request(Call {
                    operation: Operation::Status,
                    slot: None,
                    session: None,
                    expected_session: None,
                    secret: &[]
                })?
            )?;
        }
        Command::Safes => {
            let state = status(controller)?;
            if !state.app_open {
                return Err("Oblivion is locked. Run oblivion unlock.".into());
            }
            for id in state.safe_ids() {
                let name = state
                    .session_titles
                    .get(id)
                    .map(String::as_str)
                    .unwrap_or(id);
                let mode = state
                    .open_sessions
                    .iter()
                    .find(|opened| opened.id.as_ref() == Some(id))
                    .and_then(|opened| opened.mode.as_deref())
                    .unwrap_or_else(|| {
                        match state
                            .agent_safes
                            .iter()
                            .find(|safe| safe.id == *id)
                            .map(|safe| safe.state)
                        {
                            Some(AgentSafeState::AwaitingStart) => "awaiting-start",
                            Some(AgentSafeState::Failed) => "creation-failed",
                            Some(AgentSafeState::RecoveryRequired) => "recovery-required",
                            None => "locked",
                        }
                    });
                writeln!(output, "{name}\t{id}\t{mode}")?;
            }
        }
        Command::Close { name } => {
            let state = status(controller)?;
            let id = state.find_safe(&name)?.ok_or("Safe not found")?;
            let opened = state
                .open_sessions
                .iter()
                .find(|opened| opened.id.as_deref() == Some(&id))
                .ok_or("Safe is already locked")?;
            controller.request(Call {
                operation: Operation::Close,
                slot: Some(opened.slot),
                session: None,
                expected_session: Some(&id),
                secret: &[],
            })?;
        }
    }
    Ok(0)
}
