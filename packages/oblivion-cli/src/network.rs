//! Network controls address an already-open Safe, including their final status
//! read. Parsing has no effects and completes before runtime startup.
use crate::controller::{self, AppMode, Call, Result};
use crate::{proxy, run};
use oblivion_transport::policy::Access;
use oblivion_wire::control::Operation;
use serde::Deserialize;
use std::io::Write;
use zeroize::Zeroizing;

// A transport may contain credentials; neither command type implements Debug.
pub struct Command {
    safe: String,
    change: Option<Change>,
    json: bool,
}

enum Change {
    Transport(proxy::Request),
    Profile(String),
    Policy(Access),
}

pub fn parse(args: &[String]) -> std::result::Result<Command, &'static str> {
    let action = args.first().map(String::as_str);
    if !matches!(action, Some("status" | "set")) {
        return Err("Choose network status or network set");
    }
    let mut safe = None;
    let mut change = None;
    let mut json = false;
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe");
                }
                safe = Some(values.next().ok_or("Missing Safe name")?.clone());
            }
            "--json" if !json => json = true,
            "--tor" | "--proxy" | "-x" | "--proxy-profile" | "--policy" => {
                if action == Some("status") {
                    return Err("Use network set to change the selected transport or policy");
                }
                if change.is_some() {
                    return Err("Choose either a transport or a policy for this change");
                }
                change = Some(match value.as_str() {
                    "--tor" => Change::Transport(proxy::Request::Ready(
                        oblivion_transport::Transport::Tor {},
                    )),
                    "--proxy" | "-x" => {
                        Change::Transport(proxy::parse(values.next().ok_or("Missing proxy URL")?)?)
                    }
                    "--proxy-profile" => {
                        let name = values.next().ok_or("Missing proxy profile name")?;
                        oblivion_transport::proxy_profiles::valid_name(name)?;
                        Change::Profile(name.clone())
                    }
                    _ => Change::Policy(match values.next().map(String::as_str) {
                        Some("open-internet") => Access::Open,
                        Some("strict") => Access::Strict,
                        Some("offline") => Access::Offline,
                        _ => return Err("Policy must be open-internet, strict or offline"),
                    }),
                });
            }
            _ => return Err("Unknown network option"),
        }
    }
    if action == Some("set") && change.is_none() {
        return Err("Choose either a transport or a policy for this change");
    }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    oblivion_wire::session_title::validate(&safe)?;
    Ok(Command { safe, change, json })
}

pub fn execute<R: run::Runtime>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    let state = controller::status(runtime)?;
    if !state.app_open {
        return Err("Unlock Oblivion before selecting a Safe".into());
    }
    let id = state.find_safe(&command.safe)?.ok_or("Safe not found")?;
    let opened = state
        .open_sessions
        .iter()
        .find(|opened| opened.id.as_deref() == Some(&id))
        .ok_or("Open the Safe offline before changing its network")?;
    if !oblivion_wire::control::valid_id(&id) {
        return Err("invalid_safe_id".into());
    }
    if let Some(change) = command.change {
        let (operation, body) = match change {
            Change::Transport(request) => {
                let transport = proxy::complete(request, runtime)?;
                writeln!(
                    diagnostics,
                    "Changing transport for Safe {}. Its active network requests will be interrupted.",
                    &id[..8]
                )?;
                let change = if state.app_mode == AppMode::Persistent {
                    oblivion_transport::egress::Command::Save { transport }
                } else {
                    oblivion_transport::egress::Command::Select { transport }
                };
                (
                    Operation::Egress,
                    Zeroizing::new(serde_json::to_vec(&change)?),
                )
            }
            Change::Profile(name) => {
                writeln!(
                    diagnostics,
                    "Changing transport for Safe {}. Its active network requests will be interrupted.",
                    &id[..8]
                )?;
                (
                    Operation::ProxyProfiles,
                    Zeroizing::new(serde_json::to_vec(
                        &oblivion_transport::proxy_profiles::Command::Select { name },
                    )?),
                )
            }
            Change::Policy(mode) => (
                Operation::SafeAccess,
                Zeroizing::new(serde_json::to_vec(&oblivion_transport::policy::Command {
                    mode,
                    save: state.app_mode == AppMode::Persistent,
                })?),
            ),
        };
        runtime.request(Call {
            operation,
            slot: Some(opened.slot),
            session: None,
            expected_session: Some(&id),
            secret: &body,
        })?;
    }
    let status = runtime.request(Call {
        operation: Operation::Status,
        slot: Some(opened.slot),
        session: None,
        expected_session: Some(&id),
        secret: &[],
    })?;
    if command.json {
        writeln!(output, "{status}")?;
        return Ok(0);
    }
    let status: NetworkStatus =
        serde_json::from_str(&status).map_err(|_| "invalid_network_status")?;
    writeln!(
        output,
        "{} · {}",
        status.network_status.label,
        match status.safe_access.current {
            Access::Open => "open-internet",
            Access::Strict => "strict",
            Access::Offline => "offline",
        }
    )?;
    Ok(0)
}

#[derive(Deserialize)]
struct NetworkStatus {
    network_status: Observation,
    safe_access: Policy,
}
#[derive(Deserialize)]
struct Observation {
    label: String,
}
#[derive(Deserialize)]
struct Policy {
    current: Access,
}
