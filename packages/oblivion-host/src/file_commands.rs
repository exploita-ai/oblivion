use oblivion_host::{control, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::{Limits, MAX_DOCUMENT_BYTES, MAX_ENTRIES, stream};
use oblivion_transfer::native_files::{Action, Context, Direction, Request, Status};
use oblivion_host::autolock::Opening;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

pub fn run(args: &[String]) -> control::Result<i32> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("Choose files import, export, list, status, recover or discard")?;
    if !matches!(operation, "import" | "export" | "list" | "status" | "recover" | "discard") {
        return Err("Choose files import, export, list, status, recover or discard".into());
    }
    let mut safe = None;
    let mut name = None;
    let mut paths = vec![];
    let mut cursor = None;
    let mut json_output = false;
    let mut operation_id = None;
    let mut expected_opening = None;
    let mut recovery_destination = None;
    let mut options = args.iter().skip(1);
    while let Some(value) = options.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                safe = Some(options.next().ok_or("Missing Safe name")?);
            }
            "--cursor" => {
                cursor = Some(options.next().ok_or("Missing directory cursor")?.clone());
            }
            "--json" => json_output = true,
            "--operation" => { if operation_id.is_some() { return Err("Duplicate --operation".into()); } operation_id = Some(options.next().ok_or("Missing operation ID")?.clone()); },
            "--opening" => { if expected_opening.is_some() { return Err("Duplicate --opening".into()); } expected_opening = Some(options.next().ok_or("Missing opening nonce")?.clone()); },
            "--destination" => { if recovery_destination.is_some() { return Err("Duplicate --destination".into()); } recovery_destination = Some(options.next().ok_or("Missing destination directory")?.clone()); },
            "--name" => {
                if name.is_some() {
                    return Err("Duplicate --name".into());
                }
                name = Some(options.next().ok_or("Missing destination name")?);
            }
            value if value.starts_with('-') => return Err("Unknown file option".into()),
            _ => paths.push(value),
        }
    }
    let managing = matches!(operation, "status" | "recover" | "discard");
    if operation == "list" && (paths.len() > 1 || operation_id.is_some() || recovery_destination.is_some() || expected_opening.is_some())
        || managing && (!paths.is_empty() || operation_id.is_none() || name.is_some() || cursor.is_some())
        || !managing && operation != "list" && (paths.len() != if operation == "import" { 1 } else { 2 } || recovery_destination.is_some()) {
        return Err("Use files import/export --safe SAFE SOURCE [DESTINATION], or files status/recover/discard --safe SAFE --operation ID [--destination DIRECTORY]".into());
    }
    for value in operation_id.iter().chain(expected_opening.iter()) { if !oblivion_host::managed::id(value) { return Err("Invalid operation or opening ID".into()); } }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    let state = super::status()?;
    let id = super::find_safe(&state, safe)?.ok_or("Safe not found")?;
    let opened = state
        .open_sessions
        .iter()
        .find(|opened| opened.id.as_deref() == Some(&id))
        .ok_or("Open the Safe before inspecting or copying files")?;
    if operation == "list" {
        if name.is_some() {
            return Err("--name applies to copying files".into());
        }
        let request = oblivion_transfer::browser::Request {
            path: paths
                .first()
                .map(|value| (*value).clone())
                .unwrap_or_default(),
            after: cursor,
            limit: 100,
        };
        request.validate()?;
        let output = scope::within(opened.slot, || {
            control::request_for(&id, "browse", None, &serde_json::to_vec(&request)?)
        })?;
        let reply: oblivion_transfer::browser::Response = serde_json::from_str(&output)?;
        let oblivion_transfer::browser::Response::Page(page) = reply else {
            return Err("Directory unavailable".into());
        };
        page.validate(&request)?;
        if json_output {
            let entries = page.entries.iter().map(|entry| json!({
                "name":entry.name,"path":if page.path.is_empty() { entry.name.clone() } else { format!("{}/{}",page.path,entry.name) },
                "kind":if entry.directory { "directory" } else { "file" },"bytes":entry.bytes
            })).collect::<Vec<_>>();
            println!(
                "{}",
                json!({"path":page.path,"entries":entries,"next_cursor":page.next,"skipped":page.skipped})
            );
        } else {
            for entry in page.entries {
                println!(
                    "{}{}\t{}",
                    entry.name,
                    if entry.directory { "/" } else { "" },
                    entry.bytes
                );
            }
        }
        return Ok(0);
    }
    if cursor.is_some() { return Err("--cursor applies to directory listing".into()); }
    #[derive(Deserialize)]
    struct Current { idle_lock: oblivion_host::autolock::Status }
    let current: Current = serde_json::from_str(&control::request("status", None, &[])?)?;
    let opening = current.idle_lock.safes.into_iter().find(|entry| entry.opening.slot == opened.slot && entry.opening.safe_id == id && !entry.closing)
        .ok_or("Safe opening changed; reopen Files before continuing")?.opening;
    if expected_opening.as_deref().is_some_and(|expected| expected != opening.nonce) { return Err("Safe opening changed; inspect the operation again".into()); }
    if managing {
        let operation_id = operation_id.ok_or("Choose an operation ID")?;
        let action = match operation { "recover" => Action::Recover, "discard" => Action::Discard, _ => Action::Status };
        let result = if let Some(destination) = recovery_destination {
            let destination = Path::new(&destination).canonicalize()?;
            stream::operations::manage(&destination.join(".oblivion-transfers"), &destination, &operation_id, &id, &opening.nonce, Direction::Export, action)?
        } else {
            scope::within(opened.slot, || manage_import(&opening, &operation_id, action))?
        };
        result.validate(&operation_id, &id, &opening.nonce)?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(0);
    }
    let destination_name = name.map(String::as_str).or_else(|| Path::new(paths[0]).file_name().and_then(|name| name.to_str()))
        .ok_or("Choose a destination name with --name")?;
    let source = (operation == "import").then(|| std::path::absolute(paths[0])).transpose()?;
    let destination = (operation == "export").then(|| Path::new(paths[1]).canonicalize()).transpose()?;
    let export = if operation == "export" {
        let (root, selected) = paths[0].split_once('/').ok_or("Export a path under workspace/ or imports/")?;
        if !matches!(root, "workspace" | "imports") || selected.is_empty() { return Err("Export a path under workspace/ or imports/".into()); }
        Some((root, selected))
    } else { None };
    let operation_id = match operation_id { Some(id) => id, None => { let mut random = [0; 16]; File::open("/dev/urandom")?.read_exact(&mut random)?; random.iter().map(|byte| format!("{byte:02x}")).collect() } };
    let context = Context { id: operation_id, safe_id: id.clone(), opening: opening.nonce.clone(), direction: if export.is_some() { Direction::Export } else { Direction::Import }, name: destination_name.into() };
    context.validate()?;
    // Stable identity is available before allocating any receiver state. Keep
    // stdout parseable as the final receipt, even if the copy is interrupted.
    eprintln!("File operation {}. Inspect with oblivion files status --safe {} --operation {}{}", context.id, id, context.id, if export.is_some() { " --destination DIRECTORY" } else { "" });
    if let Some(destination) = &destination {
        let inbox = destination.join(".oblivion-transfers");
        match std::fs::DirBuilder::new().mode(0o700).create(&inbox) { Ok(()) => {}, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}, Err(error) => return Err(error.into()) }
        let metadata = std::fs::symlink_metadata(&inbox)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::getuid() } || metadata.mode() & 0o077 != 0 { return Err("Export staging must be a private directory".into()); }
        stream::operations::begin(&inbox, destination, &context)?;
    }
    scope::within(opened.slot, || {
        let (mut connection, lease, client) = control::attach_file(&opening)?;
        let result = (|| -> control::Result<_> {
            let request = match export {
                Some((root, _)) => serde_json::to_vec(&json!({"operation":"export","root":root}))?,
                None => serde_json::to_vec(&Request::Import { id: context.id.clone(), safe_id: id.clone(), opening: opening.nonce.clone(), name: context.name.clone() })?,
            };
            connection.write_all(&(request.len() as u32).to_be_bytes())?; connection.write_all(&request)?;
            let mut channel = Channel::new(File::from(OwnedFd::from(connection)), Duration::from_secs(3600))?;
            if let Some(source) = source {
                stream::send_path(&mut channel, &source, Limits { entries: MAX_ENTRIES, bytes: MAX_DOCUMENT_BYTES }, &context.id).map_err(Into::into)
            } else {
                let destination = destination.as_deref().ok_or("Missing export directory")?;
                stream::download(&mut channel, export.ok_or("Missing export selection")?.1, &destination.join(".oblivion-transfers"), destination, &context).map_err(Into::into)
            }
        })();
        let released = control::release_agent(&client, &id); drop(lease);
        if let Ok(receipt) = &result { println!("{}", serde_json::to_string(receipt)?); }
        released.map_err(|error| format!("File operation {} cleanup could not be confirmed ({error}). Inspect its status before retrying.", context.id))?;
        result.map_err(|error| format!("File operation {} outcome could not be confirmed ({error}). Inspect its status; do not recopy automatically.", context.id))?;
        Ok(0)
    })
}

fn manage_import(opening: &Opening, operation: &str, action: Action) -> control::Result<Status> {
    let (mut connection, lease, client) = control::attach_file(opening)?;
    let result = (|| -> control::Result<Status> {
        let request = match action {
            Action::Status => Request::Status { id: operation.into(), safe_id: opening.safe_id.clone(), opening: opening.nonce.clone() },
            Action::Recover => Request::Recover { id: operation.into(), safe_id: opening.safe_id.clone(), opening: opening.nonce.clone() },
            Action::Discard => Request::Discard { id: operation.into(), safe_id: opening.safe_id.clone(), opening: opening.nonce.clone() },
        };
        let request = serde_json::to_vec(&request)?;
        connection.write_all(&(request.len() as u32).to_be_bytes())?; connection.write_all(&request)?;
        let mut channel = Channel::new(File::from(OwnedFd::from(connection)), Duration::from_secs(60))?;
        let response: Status = oblivion_transfer::endpoint::read_message(&mut channel, 8192)?;
        response.validate(operation, &opening.safe_id, &opening.nonce)?;
        Ok(response)
    })();
    let released = control::release_agent(&client, &opening.safe_id); drop(lease); released?;
    result
}
