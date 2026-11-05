//! Safe catalog and offline-storage commands. Only the platform Runtime owns
//! password entry and native slot primitives; no Safe agent is launched here.
use crate::controller::{self, AppMode, Call, Result};
use crate::run;
use oblivion_wire::control::{valid_id, Operation};
use oblivion_wire::{session_title, volume};
use std::io::Write;
use zeroize::Zeroizing;

const HELP: &str =
    "Use safe open NAME [--already-open], safe rename NAME NEW_NAME or safe grow NAME MIB";

#[derive(Debug, Eq, PartialEq)]
pub struct Command {
    action: Action,
}

#[derive(Debug, Eq, PartialEq)]
enum Action {
    Open { name: String, already_open: bool },
    Rename { name: String, title: String },
    Grow { name: String, mib: u64 },
}

impl Action {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Open { name, .. } => session_title::validate(name)?,
            Self::Rename { name, title } => {
                session_title::validate(name)?;
                session_title::validate(title)?;
            }
            Self::Grow { name, mib } => {
                session_title::validate(name)?;
                volume::size(*mib)?;
            }
        }
        Ok(())
    }
}

pub fn parse(args: &[String]) -> Result<Command> {
    let command = match args {
        [action, name, options @ ..]
            if action == "open" && (options.is_empty() || options == ["--already-open"]) =>
        {
            Action::Open {
                name: name.clone(),
                already_open: !options.is_empty(),
            }
        }
        [action, name, title] if action == "rename" => Action::Rename {
            name: name.clone(),
            title: title.clone(),
        },
        [action, name, mib] if action == "grow" => Action::Grow {
            name: name.clone(),
            mib: mib
                .parse()
                .map_err(|_| "Storage size must be a number in MiB")?,
        },
        _ => return Err(HELP.into()),
    };
    command.validate()?;
    Ok(Command { action: command })
}

pub fn execute<R: run::Runtime>(
    runtime: &mut R,
    command: Command,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    let already_open = matches!(
        command.action,
        Action::Open {
            already_open: true,
            ..
        }
    );
    let state = controller::status(runtime)?;
    if !state.app_open {
        if already_open {
            return Err("Oblivion is locked. Run oblivion unlock.".into());
        }
        crate::storage::execute(
            runtime,
            crate::storage::Command::Unlock { read_only: false },
        )?;
    }
    let state = if already_open {
        state
    } else {
        controller::status(runtime)?
    };
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    let name = match &command.action {
        Action::Open { name, .. } | Action::Rename { name, .. } | Action::Grow { name, .. } => name,
    };
    let id = state.find_safe(name)?.ok_or("Safe not found")?;
    if !valid_id(&id) {
        return Err("invalid_safe_id".into());
    }
    let active = state
        .open_sessions
        .iter()
        .find(|safe| safe.id.as_deref() == Some(&id));
    match command.action {
        Action::Open { .. } => {
            let slot = match active {
                Some(safe) => safe.slot,
                None if already_open => return Err("This Safe is no longer open".into()),
                None => run::free_slot(runtime, &state)?,
            };
            if active.is_none() {
                run::open_existing(runtime, &state, slot, &id)?;
            }
            let result = (|| {
                runtime.request(Call {
                    operation: Operation::PinSafe,
                    slot: Some(slot),
                    session: None,
                    expected_session: Some(&id),
                    secret: &[],
                })?;
                writeln!(
                    diagnostics,
                    "Safe {} opened for files and offline work",
                    &id[..8]
                )?;
                Ok(0)
            })();
            if active.is_none() {
                return run::cleanup(runtime, slot, &id, result);
            }
            result
        }
        Action::Rename { title, .. } => {
            if state.find_safe(&title)?.is_some_and(|other| other != id) {
                return Err("A Safe with this name already exists".into());
            }
            let slot = if state.app_mode == AppMode::Persistent {
                None
            } else {
                Some(
                    active
                        .ok_or("Open the Safe before renaming it in this storage mode")?
                        .slot,
                )
            };
            let rename = session_title::Rename {
                id: id.clone(),
                title,
            };
            runtime.request(Call {
                operation: Operation::RenameSession,
                slot,
                session: None,
                expected_session: slot.map(|_| id.as_str()),
                secret: &serde_json::to_vec(&rename)?,
            })?;
            Ok(0)
        }
        Action::Grow { mib, .. } => {
            if state
                .agent_safes
                .iter()
                .any(|safe| safe.id == id && safe.ephemeral)
            {
                return Err("RAM-only Safe storage cannot be grown. Create a Safe with sufficient capacity.".into());
            }
            if state.app_mode != AppMode::Persistent || !state.sessions.contains(&id) {
                return Err("Safe storage growth requires writable persistent storage".into());
            }
            if active.is_some() {
                return Err("Close the Safe before increasing its storage".into());
            }
            // The Linux worker temporarily owns this slot's mapper and resize
            // VM. A closed target must not reuse another Safe's active slot.
            let slot = run::free_slot(runtime, &state)?;
            let secret = runtime.password("Safe password")?;
            let password = std::str::from_utf8(&secret).map_err(|_| "invalid_secret_encoding")?;
            let request = volume::Request::Grow {
                id,
                mib,
                password: Zeroizing::new(password.to_owned()),
            };
            request.validate()?;
            let payload = Zeroizing::new(
                serde_json::to_vec(&request).map_err(|_| "invalid_storage_request")?,
            );
            runtime.request(Call {
                operation: Operation::SessionStorage,
                slot: Some(slot),
                session: None,
                expected_session: None,
                secret: &payload,
            })?;
            writeln!(diagnostics, "Safe storage increased to {mib} MiB")?;
            Ok(0)
        }
    }
}
