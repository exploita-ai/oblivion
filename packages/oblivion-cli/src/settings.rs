//! Shared automatic-lock controls. Parsing completes before controller access;
//! a partial change preserves the other timer from the current typed status.
use crate::controller::{Call, Controller, Result};
use oblivion_wire::control::Operation;
use oblivion_wire::idle::{Preferences, Storage, View};
use serde::Serialize;
use std::io::Write;

pub struct Command {
    safe: Option<u16>,
    host: Option<u16>,
    json: bool,
}

pub fn parse(args: &[String]) -> std::result::Result<Command, &'static str> {
    if args.first().map(String::as_str) != Some("idle") {
        return Err("Use oblivion settings idle [--safe-minutes N] [--host-minutes N] [--json]");
    }
    let mut safe = None;
    let mut host = None;
    let mut json = false;
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe-minutes" if safe.is_none() => {
                safe = Some(minutes(values.next(), "Missing Safe idle minutes")?);
            }
            "--host-minutes" if host.is_none() => {
                host = Some(minutes(values.next(), "Missing host idle minutes")?);
            }
            "--json" if !json => json = true,
            _ => return Err("Unknown or duplicate automatic-lock option"),
        }
    }
    Ok(Command { safe, host, json })
}

pub fn execute<C: Controller>(
    controller: &mut C,
    command: Command,
    output: &mut impl Write,
) -> Result<i32>
where
    C::Slot: Serialize,
{
    let current = read(controller)?;
    let current = if command.safe.is_some() || command.host.is_some() {
        let preferences = Preferences {
            version: 1,
            safe_minutes: command
                .safe
                .unwrap_or(current.state.preferences.safe_minutes),
            host_minutes: command
                .host
                .unwrap_or(current.state.preferences.host_minutes),
        };
        controller.request(Call {
            operation: Operation::IdleSettings,
            slot: None,
            session: None,
            expected_session: None,
            secret: &serde_json::to_vec(&preferences)?,
        })?;
        read(controller)?
    } else {
        current
    };
    if command.json {
        writeln!(output, "{}", serde_json::to_string(&current)?)?;
        return Ok(0);
    }
    let minutes = |value| {
        if value == 0 {
            "Disabled".to_owned()
        } else {
            format!("{value} minutes")
        }
    };
    writeln!(
        output,
        "Safe idle lock: {}",
        minutes(current.state.preferences.safe_minutes)
    )?;
    writeln!(
        output,
        "Oblivion idle lock: {}",
        minutes(current.state.preferences.host_minutes)
    )?;
    writeln!(
        output,
        "Preferences: {}",
        match current.storage {
            Storage::Defaults => "Defaults",
            Storage::SavedEncrypted => "Saved encrypted",
            Storage::RamOnly => "RAM only",
        }
    )?;
    writeln!(
        output,
        "Only human input keeps work open. Automatic locks stop agents and lock encrypted volumes."
    )?;
    Ok(0)
}

fn minutes(
    value: Option<&String>,
    missing: &'static str,
) -> std::result::Result<u16, &'static str> {
    let minutes = value
        .ok_or(missing)?
        .parse::<u16>()
        .map_err(|_| "invalid_idle_preferences")?;
    if minutes > oblivion_wire::idle::MAX_MINUTES {
        return Err("invalid_idle_preferences");
    }
    Ok(minutes)
}

fn read<C: Controller>(controller: &mut C) -> Result<View<C::Slot>> {
    let response = controller.request(Call {
        operation: Operation::Status,
        slot: None,
        session: None,
        expected_session: None,
        secret: &[],
    })?;
    Ok(View::decode_status(response.as_bytes())?)
}
