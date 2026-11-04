//! One launch workflow shared by native frontends. Runtime adapters own human
//! interaction, validated platform slots, monotonic clocks and terminal leases.
use crate::controller::{self, AgentSafeState, AppMode, Call, Controller, Result, State};
use crate::run::Options;
use oblivion_transport::Transport;
use oblivion_wire::control::Operation;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default)]
pub struct Context {
    pub prefer_ephemeral: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notice<'a> {
    WaitingForConnection,
    SafeOpened(&'a str),
    StorageCapacity(u64),
    StorageCreated,
    IncompleteStorageReview,
    IncompleteStorageDiscarded,
}

impl Notice<'_> {
    pub fn write(self, output: &mut impl std::io::Write) -> Result<()> {
        match self {
            Self::WaitingForConnection => {
                writeln!(output, "Waiting for the protected connection…")?
            }
            Self::SafeOpened(id) => writeln!(
                output,
                "Safe {} opened",
                id.get(..8).ok_or("invalid_safe_id")?
            )?,
            Self::StorageCapacity(bytes) => writeln!(
                output,
                "Create the managed encrypted archive: {} MiB.",
                bytes / 1024 / 1024
            )?,
            Self::StorageCreated => {
                writeln!(output, "Encrypted storage created. Run oblivion unlock.")?
            }
            Self::IncompleteStorageReview => writeln!(
                output,
                "Only the unfinished app archive is removed. Published encrypted storage is preserved."
            )?,
            Self::IncompleteStorageDiscarded => writeln!(
                output,
                "Incomplete setup removed. Run oblivion init to create encrypted storage."
            )?,
        }
        Ok(())
    }
}

pub trait Runtime: Controller {
    type Mark;
    fn slots(&self) -> Vec<Self::Slot>;
    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>>;
    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>>;
    fn confirm(&mut self, word: &'static str) -> Result<bool>;
    fn now(&self) -> Self::Mark;
    fn elapsed(&self, start: &Self::Mark) -> Duration;
    fn wait(&mut self, duration: Duration) -> Result<()>;
    fn notice(&mut self, notice: Notice<'_>) -> Result<()>;
    fn attach(&mut self, slot: Self::Slot, id: &str, agent: &str, argv: &[String]) -> Result<i32>;
    fn attach_workspace(&mut self, slot: Self::Slot, id: &str) -> Result<i32>;
}

pub fn free_slot<R: Runtime>(runtime: &R, state: &State<R::Slot>) -> Result<R::Slot> {
    runtime
        .slots()
        .into_iter()
        .find(|slot| {
            !state
                .open_sessions
                .iter()
                .any(|opened| opened.slot == *slot)
        })
        .ok_or_else(|| "No Safe slots available".into())
}

pub fn open_existing<R: Runtime>(
    runtime: &mut R,
    state: &State<R::Slot>,
    slot: R::Slot,
    id: &str,
) -> Result<()> {
    require_id(id)?;
    let child = state.agent_safes.iter().find(|safe| safe.id == id);
    if child.is_some_and(|safe| safe.state != AgentSafeState::AwaitingStart) {
        return Err("The child Safe was not created successfully. Review its recovery state before opening.".into());
    }
    if child.is_some_and(|safe| safe.ephemeral) {
        runtime.request(Call {
            operation: Operation::OpenChildDocuments,
            slot: Some(slot),
            session: Some(id),
            expected_session: Some(id),
            secret: &[],
        })?;
        return Ok(());
    }
    let secret = runtime.password("Safe password")?;
    runtime.request(Call {
        operation: Operation::OpenDocuments,
        slot: Some(slot),
        session: Some(id),
        expected_session: None,
        secret: &secret,
    })?;
    Ok(())
}

/// The window limits retrying gateway_not_ready, as in the current launcher.
/// Each controller RPC keeps the platform adapter's own bounded deadline.
pub fn start_agent<R: Runtime>(runtime: &mut R, slot: R::Slot, id: &str) -> Result<()> {
    require_id(id)?;
    let started = runtime.now();
    let mut waiting = false;
    loop {
        match safe_call(runtime, slot, id, Operation::StartAgent, &[]) {
            Ok(_) => return Ok(()),
            Err(error)
                if error.to_string() == "gateway_not_ready"
                    && runtime.elapsed(&started) < Duration::from_secs(240) =>
            {
                if !waiting {
                    runtime.notice(Notice::WaitingForConnection)?;
                    waiting = true;
                }
                runtime.wait(Duration::from_millis(500))?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub fn execute<R: Runtime>(
    runtime: &mut R,
    mut options: Options<Transport>,
    context: Context,
) -> Result<i32> {
    let initial = controller::status(runtime)?;
    if !initial.app_open {
        if options.ephemeral || context.prefer_ephemeral {
            runtime.request(Call {
                operation: Operation::EnterRam,
                slot: None,
                session: None,
                expected_session: None,
                secret: &[],
            })?;
        } else {
            // Selecting an existing Safe must never replace missing storage.
            if options.safe.is_none() && !initial.general_present {
                crate::storage::execute(
                    runtime,
                    crate::storage::Command::Init {
                        reset_incomplete: false,
                        confirmed_reset: false,
                    },
                )?;
            }
            crate::storage::execute(
                runtime,
                crate::storage::Command::Unlock { read_only: false },
            )?;
        }
    }
    let state = controller::status(runtime)?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    if options.ephemeral && state.app_mode == AppMode::Persistent {
        return Err(
            "Lock Oblivion, then enter Ephemeral mode before creating a RAM-only Safe.".into(),
        );
    }
    if options.name.is_some() && state.app_mode != AppMode::Persistent {
        return Err("Named persistent Safes require persistent mode. Lock and unlock encrypted storage first.".into());
    }
    let existing = options
        .safe
        .as_deref()
        .map(|name| state.find_safe(name))
        .transpose()?
        .flatten();
    if options.safe.is_some() && existing.is_none() {
        return Err("Safe not found. Create it explicitly with --name NAME.".into());
    }
    if options
        .name
        .as_deref()
        .map(|name| state.find_safe(name))
        .transpose()?
        .flatten()
        .is_some()
    {
        return Err("A Safe with this name already exists".into());
    }
    if let Some(opened) = state
        .open_sessions
        .iter()
        .find(|opened| opened.id == existing && existing.is_some())
    {
        if options.transport.is_some()
            || options.proxy_profile.is_some()
            || options.policy.is_some()
        {
            return Err(
                "Safe is active. Change its network through the trusted network controls.".into(),
            );
        }
        let id = existing.as_deref().ok_or("Safe failed to open")?;
        start_agent(runtime, opened.slot, id)?;
        return runtime.attach(opened.slot, id, &options.agent, &options.argv);
    }
    let slot = free_slot(runtime, &state)?;
    let created = existing.is_none() && !options.ephemeral && state.app_mode == AppMode::Persistent;
    let id = if let Some(id) = existing {
        open_existing(runtime, &state, slot, &id)?;
        id
    } else if options.ephemeral || state.app_mode != AppMode::Persistent {
        runtime.request(Call {
            operation: Operation::OpenDocumentsEphemeral,
            slot: Some(slot),
            session: None,
            expected_session: None,
            secret: &[],
        })?;
        let id = controller::status_at(runtime, Some(slot))?
            .open_sessions
            .into_iter()
            .find(|opened| opened.slot == slot)
            .and_then(|opened| opened.id)
            .ok_or("Safe failed to open")?;
        require_id(&id)?;
        id
    } else {
        let secret = runtime.new_password("New Safe password")?;
        let response = runtime.request(Call {
            operation: Operation::Create,
            slot: Some(slot),
            session: None,
            expected_session: None,
            secret: &secret,
        })?;
        let id = response.trim();
        require_id(id)?;
        let title = options
            .name
            .clone()
            .unwrap_or_else(|| format!("Safe {}", &id[..8]));
        let rename = oblivion_wire::session_title::Rename {
            id: id.into(),
            title,
        };
        runtime.request(Call {
            operation: Operation::RenameSession,
            slot: Some(slot),
            session: None,
            expected_session: None,
            secret: &serde_json::to_vec(&rename)?,
        })?;
        runtime.request(Call {
            operation: Operation::OpenDocuments,
            slot: Some(slot),
            session: Some(id),
            expected_session: None,
            secret: &secret,
        })?;
        id.to_owned()
    };
    let result = (|| {
        if created {
            runtime.notice(Notice::SafeOpened(&id))?;
        }
        if let Some(transport) = options.transport.take() {
            let command = if state.app_mode == AppMode::Persistent {
                oblivion_transport::egress::Command::Save { transport }
            } else {
                oblivion_transport::egress::Command::Select { transport }
            };
            safe_call(
                runtime,
                slot,
                &id,
                Operation::Egress,
                &Zeroizing::new(serde_json::to_vec(&command)?),
            )?;
        }
        if let Some(name) = options.proxy_profile.take() {
            let command = oblivion_transport::proxy_profiles::Command::Select { name };
            safe_call(
                runtime,
                slot,
                &id,
                Operation::ProxyProfiles,
                &serde_json::to_vec(&command)?,
            )?;
        }
        if let Some(policy) = options.policy {
            let command = oblivion_transport::policy::Command {
                mode: oblivion_transport::policy::Access::parse(policy)?,
                save: state.app_mode == AppMode::Persistent,
            };
            safe_call(
                runtime,
                slot,
                &id,
                Operation::SafeAccess,
                &serde_json::to_vec(&command)?,
            )?;
        }
        start_agent(runtime, slot, &id)?;
        runtime.attach(slot, &id, &options.agent, &options.argv)
    })();
    // Only an opening performed by this launch is eligible for idle cleanup;
    // already-active Safes retain the other clients/work which own them.
    cleanup(runtime, slot, &id, result)
}

pub fn cleanup<R: Runtime, T>(
    runtime: &mut R,
    slot: R::Slot,
    id: &str,
    result: Result<T>,
) -> Result<T> {
    if result.is_err() {
        require_id(id)?;
        if let Err(error) = safe_call(runtime, slot, id, Operation::CloseIdle, &[]) {
            if error.to_string() != "session_changed" {
                return Err(error);
            }
        }
    }
    result
}

fn safe_call<R: Runtime>(
    runtime: &mut R,
    slot: R::Slot,
    id: &str,
    operation: Operation,
    secret: &[u8],
) -> Result<String> {
    runtime.request(Call {
        operation,
        slot: Some(slot),
        session: None,
        expected_session: Some(id),
        secret,
    })
}

fn require_id(id: &str) -> Result<()> {
    if !oblivion_wire::control::valid_id(id) {
        return Err("invalid_safe_id".into());
    }
    Ok(())
}
