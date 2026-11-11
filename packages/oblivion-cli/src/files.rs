//! Files inspection and receiver-authoritative recovery shared by frontends.
//! Local filesystem access and private file-channel leases belong to the adapter.
use crate::controller::{self, Call, Controller, Result};
use oblivion_transfer::browser;
use oblivion_transfer::native_files::{
    Action, Direction, Status, TRANSFERS_PAGE_LIMIT, TransfersPage, TransfersQuery,
};
use oblivion_wire::control::{Operation, valid_id};
use oblivion_wire::idle::{Opening, View};
use serde_json::json;
use std::io::Write;

const HELP: &str = "Choose files import, export, list, transfers, status, recover or discard";

pub struct Command {
    safe: String,
    action: CommandAction,
    expected_opening: Option<String>,
    json: bool,
}

impl Command {
    /// Native frontends without a local publication endpoint reject these
    /// commands before runtime discovery. Guest metadata uses only its lease.
    pub fn needs_local_filesystem(&self) -> bool {
        matches!(
            &self.action,
            CommandAction::Transfers {
                destination: Some(_),
                ..
            } | CommandAction::Manage {
                destination: Some(_),
                ..
            }
        )
    }

    pub fn needs_live_media(&self) -> bool {
        matches!(&self.action, CommandAction::Usb { .. })
    }

    pub fn into_usb(self) -> std::result::Result<UsbCommand, Self> {
        let CommandAction::Usb { device, action } = self.action else {
            return Err(self);
        };
        Ok(UsbCommand {
            safe: self.safe,
            device,
            expected_opening: self.expected_opening,
            json: self.json,
            action,
        })
    }
}

pub struct UsbCommand {
    pub safe: String,
    pub device: String,
    pub expected_opening: Option<String>,
    pub json: bool,
    pub action: UsbAction,
}

pub enum UsbAction {
    Inventory {
        after: Option<String>,
        limit: usize,
    },
    Manage {
        operation: String,
        action: Action,
        confirmed_state: Option<String>,
    },
}

enum CommandAction {
    List(browser::Request),
    Usb {
        device: String,
        action: UsbAction,
    },
    Transfers {
        destination: Option<String>,
        after: Option<String>,
        limit: usize,
    },
    Manage {
        destination: Option<String>,
        operation: String,
        action: Action,
    },
}

/// Copy preparation, trusted local selection and approval remain explicitly
/// adapter-owned. Every other Files command is parsed and executed here.
pub fn parse(args: &[String]) -> Result<Option<Command>> {
    let operation = args.first().map(String::as_str).ok_or(HELP)?;
    if matches!(operation, "import" | "export") {
        return Ok(None);
    }
    if !matches!(
        operation,
        "list" | "transfers" | "status" | "recover" | "discard"
    ) {
        return Err(HELP.into());
    }
    let mut safe = None;
    let mut cursor = None;
    let mut limit = None;
    let mut operation_id = None;
    let mut expected_opening = None;
    let mut destination = None;
    let mut usb = None;
    let mut confirmed_state = None;
    let mut path = None;
    let mut json = false;
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe" if safe.is_none() => {
                safe = Some(values.next().ok_or("Missing Safe name")?.clone());
            }
            "--cursor" if cursor.is_none() => {
                cursor = Some(values.next().ok_or("Missing cursor")?.clone());
            }
            "--limit" if limit.is_none() => {
                if operation != "transfers" {
                    return Err("--limit applies only to files transfers".into());
                }
                limit = Some(
                    values
                        .next()
                        .ok_or("Missing page limit")?
                        .parse::<usize>()
                        .ok()
                        .filter(|value| (1..=TRANSFERS_PAGE_LIMIT).contains(value))
                        .ok_or("Choose a page limit from 1 to 8")?,
                );
            }
            "--operation" if operation_id.is_none() => {
                operation_id = Some(values.next().ok_or("Missing operation ID")?.clone());
            }
            "--opening" if expected_opening.is_none() => {
                expected_opening = Some(values.next().ok_or("Missing opening nonce")?.clone());
            }
            "--destination" if destination.is_none() => {
                destination = Some(
                    values
                        .next()
                        .ok_or("Missing destination directory")?
                        .clone(),
                );
            }
            "--usb" if usb.is_none() => {
                let device = values.next().ok_or("Missing USB device ID")?;
                if !oblivion_wire::live_media::valid_device_id(device) {
                    return Err("Invalid USB device ID".into());
                }
                usb = Some(device.clone());
            }
            "--confirmed-state" if confirmed_state.is_none() => {
                let digest = values.next().ok_or("Missing reviewed USB state")?;
                if !oblivion_wire::live_media::valid_device_id(digest) {
                    return Err("Invalid reviewed USB state".into());
                }
                confirmed_state = Some(digest.clone());
            }
            "--json" if !json => json = true,
            "--events" | "--yes" => {
                return Err("--events and --yes apply only to file import or export".into());
            }
            value if !value.starts_with('-') && path.is_none() => path = Some(value.to_owned()),
            _ => return Err("Unknown or duplicate file option".into()),
        }
    }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    oblivion_wire::session_title::validate(&safe)?;
    for value in operation_id.iter().chain(expected_opening.iter()) {
        if !valid_id(value) {
            return Err("Invalid operation or opening ID".into());
        }
    }
    if confirmed_state.is_some() && (usb.is_none() || !matches!(operation, "recover" | "discard")) {
        return Err("A reviewed state applies only to USB recover or discard".into());
    }
    if usb.is_some() && (destination.is_some() || path.is_some() || operation == "list") {
        return Err(
            "Use --usb with files transfers, status, recover or discard without a local path"
                .into(),
        );
    }
    let action = match operation {
        "list" => {
            if destination.is_some() || operation_id.is_some() || expected_opening.is_some() {
                return Err("Use files list [PATH] --safe SAFE [--cursor NAME] [--json]".into());
            }
            let request = browser::Request {
                path: path.unwrap_or_default(),
                after: cursor,
                limit: 100,
            };
            request.validate()?;
            CommandAction::List(request)
        }
        "transfers" => {
            if path.is_some() || operation_id.is_some() {
                return Err("Use files transfers --safe SAFE [--destination DIRECTORY] [--cursor ID] [--limit 8] --json".into());
            }
            if cursor.as_deref().is_some_and(|cursor| !valid_id(cursor)) {
                return Err("Invalid transfer cursor".into());
            }
            let limit = limit.unwrap_or(TRANSFERS_PAGE_LIMIT);
            match usb {
                Some(device) => CommandAction::Usb {
                    device,
                    action: UsbAction::Inventory {
                        after: cursor,
                        limit,
                    },
                },
                None => CommandAction::Transfers {
                    destination,
                    after: cursor,
                    limit,
                },
            }
        }
        _ => {
            if path.is_some() || cursor.is_some() {
                return Err("Use files status, recover or discard --safe SAFE --operation ID [--destination DIRECTORY]".into());
            }
            let action = match operation {
                "recover" => Action::Recover,
                "discard" => Action::Discard,
                _ => Action::Status,
            };
            let operation = operation_id.ok_or("Choose an operation ID")?;
            match usb {
                Some(device) => CommandAction::Usb {
                    device,
                    action: UsbAction::Manage {
                        operation,
                        action,
                        confirmed_state,
                    },
                },
                None => CommandAction::Manage {
                    destination,
                    operation,
                    action,
                },
            }
        }
    };
    Ok(Some(Command {
        safe,
        action,
        expected_opening,
        json,
    }))
}

pub trait Backend: Controller {
    fn transfers(
        &mut self,
        opening: &Opening<Self::Slot>,
        query: &TransfersQuery,
        destination: Option<&str>,
    ) -> Result<TransfersPage>;
    fn manage(
        &mut self,
        opening: &Opening<Self::Slot>,
        operation: &str,
        action: Action,
        destination: Option<&str>,
    ) -> Result<Status>;
}

/// An open Safe selected from authenticated controller state. Copy adapters
/// reuse this lookup and the fresh-opening check instead of duplicating them.
pub struct Target<S> {
    safe_id: String,
    slot: S,
}
impl<S: Copy> Target<S> {
    pub fn safe_id(&self) -> &str {
        &self.safe_id
    }
    pub fn slot(&self) -> S {
        self.slot
    }
}

pub fn target<C: Controller>(controller: &mut C, name: &str) -> Result<Target<C::Slot>> {
    let state = controller::status(controller)?;
    let id = state.find_safe(name)?.ok_or("Safe not found")?;
    if !valid_id(&id) {
        return Err("invalid_safe_id".into());
    }
    let opened = state
        .open_sessions
        .iter()
        .find(|opened| opened.id.as_deref() == Some(&id))
        .ok_or("Open the Safe before inspecting or copying files")?;
    Ok(Target {
        safe_id: id,
        slot: opened.slot,
    })
}

pub fn opening<C: Controller>(
    controller: &mut C,
    target: &Target<C::Slot>,
    expected: Option<&str>,
) -> Result<Opening<C::Slot>> {
    let response = controller.request(Call {
        operation: Operation::Status,
        slot: Some(target.slot),
        session: None,
        expected_session: Some(&target.safe_id),
        secret: &[],
    })?;
    let current = View::<C::Slot>::decode_status(response.as_bytes())?.state;
    if current.host.as_ref().is_some_and(|host| host.closing) {
        return Err("Safe opening changed; reopen Files before continuing".into());
    }
    let opening = current
        .safes
        .into_iter()
        .find(|entry| {
            entry.opening.slot == target.slot
                && entry.opening.safe_id == target.safe_id
                && !entry.closing
        })
        .ok_or("Safe opening changed; reopen Files before continuing")?
        .opening;
    if !valid_id(&opening.nonce) {
        return Err("invalid_safe_opening".into());
    }
    if expected.is_some_and(|expected| expected != opening.nonce) {
        return Err("Safe opening changed; inspect the operation again".into());
    }
    Ok(opening)
}

pub fn execute<B: Backend>(
    backend: &mut B,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    if command.needs_live_media() {
        return Err("USB transfer records require the Live launcher".into());
    }
    let target = target(backend, &command.safe)?;
    if let CommandAction::List(request) = command.action {
        let response = backend.request(Call {
            operation: Operation::Browse,
            slot: Some(target.slot),
            session: None,
            expected_session: Some(&target.safe_id),
            secret: &serde_json::to_vec(&request)?,
        })?;
        let response: browser::Response =
            serde_json::from_str(&response).map_err(|_| "invalid_directory_response")?;
        let browser::Response::Page(page) = response else {
            return Err("Directory unavailable".into());
        };
        page.validate(&request)?;
        if command.json {
            write_directory_page(output, &page)?;
        } else {
            for entry in page.entries {
                writeln!(
                    output,
                    "{}{}\t{}",
                    entry.name,
                    if entry.directory { "/" } else { "" },
                    entry.bytes
                )?;
            }
        }
        return Ok(0);
    }
    let opening = opening(backend, &target, command.expected_opening.as_deref())?;
    match command.action {
        CommandAction::Transfers {
            destination,
            after,
            limit,
        } => {
            let query = TransfersQuery {
                safe_id: target.safe_id,
                opening: opening.nonce.clone(),
                direction: if destination.is_some() {
                    Direction::Export
                } else {
                    Direction::Import
                },
                after,
                limit,
            };
            let page = backend.transfers(&opening, &query, destination.as_deref())?;
            page.validate(&query)?;
            if command.json {
                writeln!(output, "{}", serde_json::to_string(&page)?)?;
                return Ok(0);
            }
            for entry in page.entries {
                writeln!(output, "{}\t{:?}", entry.operation_id, entry.name)?;
            }
            if let Some(cursor) = page.next_cursor {
                writeln!(
                    diagnostics,
                    "More recorded operations: repeat with --cursor {cursor}"
                )?;
            }
            if page.skipped != 0 {
                writeln!(
                    diagnostics,
                    "{} unavailable records skipped. Listing does not authorize recovery or discard.",
                    page.skipped
                )?;
            }
        }
        CommandAction::Manage {
            destination,
            operation,
            action,
        } => {
            let result = backend.manage(&opening, &operation, action, destination.as_deref())?;
            result.validate(&operation, &target.safe_id, &opening.nonce)?;
            writeln!(output, "{}", serde_json::to_string(&result)?)?;
        }
        CommandAction::List(_) => unreachable!("listing handled before opening admission"),
        CommandAction::Usb { .. } => unreachable!("USB operation handled by the Live launcher"),
    }
    Ok(0)
}

pub fn write_directory_page(output: &mut impl Write, page: &browser::Page) -> std::io::Result<()> {
    let entries = page.entries.iter().map(|entry| json!({
        "name": entry.name,
        "path": if page.path.is_empty() { entry.name.clone() } else { format!("{}/{}", page.path, entry.name) },
        "kind": if entry.directory { "directory" } else { "file" },
        "bytes": entry.bytes,
    })).collect::<Vec<_>>();
    writeln!(output, "{}", json!({
        "path": page.path,
        "entries": entries,
        "next_cursor": page.next,
        "skipped": page.skipped,
    }))
}
