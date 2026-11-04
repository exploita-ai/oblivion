use oblivion_host::{control, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::{Receipt, stream};
use oblivion_transfer::native_file_events::{Identity, Outcome, Phase, Summary};
use oblivion_transfer::stream::{PreparedDownload, PreparedUpload};
use oblivion_transfer::native_files::{Action, Context, Direction, Request, Status};
use oblivion_host::autolock::Opening;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::io::IsTerminal;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;
use std::time::Instant;
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
    let mut events_output = false;
    let mut confirmed = false;
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
            "--events" => events_output = true,
            "--yes" => confirmed = true,
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
    if (events_output || confirmed) && !matches!(operation, "import" | "export") {
        return Err("--events and --yes apply only to file import or export".into());
    }
    if events_output && confirmed {
        return Err("Event copies require their reviewed approval; --yes cannot be combined with --events".into());
    }
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
    if !events_output && !confirmed && !std::io::stdin().is_terminal() {
        return Err("A file copy needs review in a terminal, --yes for an explicit unattended copy, or --events for the manager".into());
    }
    scope::within(opened.slot, || copy(opening, context, source, destination, export.map(|(root, selected)| (root.to_owned(), selected.to_owned())), events_output, confirmed))
}

enum PreparedCopy {
    Upload(PreparedUpload),
    Download(PreparedDownload),
}

impl PreparedCopy {
    fn summary(&self) -> std::io::Result<Summary> {
        match self {
            Self::Upload(prepared) => prepared.summary(),
            Self::Download(prepared) => prepared.summary(),
        }
    }
}

enum Copied {
    Complete(Receipt),
    Cancelled,
}

fn copy(
    opening: Opening,
    context: Context,
    source: Option<PathBuf>,
    destination: Option<PathBuf>,
    export: Option<(String, String)>,
    events_output: bool,
    confirmed: bool,
) -> control::Result<i32> {
    let mut events = events_output.then(|| super::file_events::Control::stdio(Identity {
        operation_id: context.id.clone(), safe_id: context.safe_id.clone(), opening: context.opening.clone(),
    }, context.direction, context.name.clone())).transpose()?;
    // Retain the exact client even if its request or source preparation fails.
    // Dropping its private lease is the last-resort revocation on process death.
    let mut attachment = None;
    let result = (|| -> control::Result<Copied> {
        let prepared = if let Some(source) = &source {
            PreparedCopy::Upload(PreparedUpload::prepare(source, context.clone(), &mut || {
                events.as_ref().map_or(Ok(()), super::file_events::Control::check)
            })?)
        } else {
            let (root, selected) = export.as_ref().ok_or("Missing export selection")?;
            let channel = file_channel(&opening, &json!({"operation":"export","root":root}), events.as_ref().map(super::file_events::Control::watch).transpose()?, &mut attachment)?;
            PreparedCopy::Download(PreparedDownload::prepare(channel, selected,
                destination.as_deref().ok_or("Missing export directory")?, context.clone())?)
        };
        let summary = prepared.summary()?;
        let digest = summary.manifest_sha256.clone();
        if let Some(events) = &mut events {
            events.review(summary.clone())?;
            if !events.wait_approval()? { return Ok(Copied::Cancelled); }
        } else if !review(&context, &summary, source.as_deref(), destination.as_deref(), export.as_ref().map(|(_, selected)| selected.as_str()), confirmed)? {
            return Ok(Copied::Cancelled);
        }
        let watch = events.as_ref().map(super::file_events::Control::watch).transpose()?;
        let mut last_progress = None;
        let mut observer = |phase, bytes| {
            if let Some(events) = &mut events { return events.progress(phase, bytes); }
            console_progress(phase, bytes, summary.bytes, &mut last_progress)
        };
        let receipt = match prepared {
            PreparedCopy::Upload(prepared) => {
                // The import destination is not contacted until this exact
                // prepared manifest has received the reviewed approval.
                let request = Request::Import { id: context.id.clone(), safe_id: context.safe_id.clone(), opening: context.opening.clone(), name: context.name.clone() };
                let mut channel = file_channel(&opening, &request, watch, &mut attachment)?;
                prepared.send(&mut channel, &digest, &mut observer)?
            }
            PreparedCopy::Download(prepared) => prepared.receive(&digest, &mut observer)?,
        };
        Ok(Copied::Complete(receipt))
    })();
    let released = if let Some((lease, client)) = attachment {
        let result = control::release_agent(&client, &opening.safe_id);
        drop(lease);
        result
    } else { Ok(()) };
    if let Some(events) = &mut events {
        let outcome = if released.is_ok() {
            match &result {
                Ok(Copied::Complete(_)) if events.check().is_ok() => Outcome::Completed,
                Ok(Copied::Cancelled) => Outcome::CancelledBeforeCopy,
                Err(_) if events.cancelled_before_copy() => Outcome::CancelledBeforeCopy,
                _ => Outcome::Interrupted,
            }
        } else { Outcome::Interrupted };
        let receipt = match result { Ok(Copied::Complete(receipt)) if outcome == Outcome::Completed => Some(receipt), _ => None };
        if let Err(error) = events.finish(outcome, receipt) {
            if outcome != Outcome::Completed { return Err(error.into()); }
            // Cancellation can arrive while releasing the owned attachment.
            // A rejected completion still gets one interrupted-outcome attempt.
            events.finish(Outcome::Interrupted, None)?;
            return Ok(1);
        }
        return Ok(match outcome { Outcome::Completed => 0, Outcome::CancelledBeforeCopy => 130, Outcome::Interrupted => 1 });
    }
    eprintln!();
    released.map_err(|error| format!("File operation {} cleanup could not be confirmed ({error}). Inspect its status before retrying.", context.id))?;
    match result.map_err(|error| format!("File operation {} outcome could not be confirmed ({error}). Inspect its status; do not recopy automatically.", context.id))? {
        Copied::Complete(receipt) => { println!("{}", serde_json::to_string(&receipt)?); Ok(0) },
        Copied::Cancelled => { eprintln!("Cancelled before copying."); Ok(130) },
    }
}

fn file_channel(
    opening: &Opening,
    request: &impl serde::Serialize,
    watch: Option<OwnedFd>,
    attachment: &mut Option<(UnixStream, String)>,
) -> control::Result<Channel> {
    let (connection, lease, client) = control::attach_file(opening)?;
    *attachment = Some((lease, client));
    let mut channel = Channel::new(File::from(OwnedFd::from(connection)), Duration::from_secs(3600))?;
    if let Some(watch) = watch { channel.watch(watch); }
    let request = serde_json::to_vec(request)?;
    channel.write_all(&(request.len() as u32).to_be_bytes())?;
    channel.write_all(&request)?;
    Ok(channel)
}

fn review(context: &Context, summary: &Summary, source: Option<&Path>, destination: Option<&Path>, selected: Option<&str>, confirmed: bool) -> control::Result<bool> {
    eprintln!("Review {} · Safe {}", if context.direction == Direction::Import { "import" } else { "export" }, context.safe_id);
    if let Some(source) = source { eprintln!("From this computer · {source:?}"); }
    if let Some(selected) = selected { eprintln!("From the Safe · {selected:?}"); }
    if let Some(destination) = destination { eprintln!("To this computer · {:?}", destination.join(&context.name)); }
    else { eprintln!("To the Safe · workspace/{:?}", context.name); }
    eprintln!("{} files · {} folders · {} bytes", summary.files, summary.directories, summary.bytes);
    eprintln!("Manifest SHA-256 {}", summary.manifest_sha256);
    if confirmed { return Ok(true); }
    eprint!("Copy these items? [y/N] ");
    std::io::stderr().flush()?;
    use std::io::BufRead;
    let mut answer = String::new();
    std::io::stdin().lock().take(16).read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn console_progress(phase: Phase, bytes: u64, total: u64, previous: &mut Option<(Phase, Instant)>) -> std::io::Result<()> {
    if phase == Phase::Copying && bytes != total && previous.as_ref().is_some_and(|(last, at)| *last == phase && at.elapsed() < Duration::from_millis(100)) { return Ok(()); }
    eprint!("\r{} · {bytes}/{total} bytes", if phase == Phase::Copying { "Copying" } else { "Finalizing" });
    std::io::stderr().flush()?;
    *previous = Some((phase, Instant::now()));
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn event_copies_cannot_bypass_their_manifest_approval_with_yes() {
        let args = ["import", "--safe", "research", "/selected", "--events", "--yes"]
            .map(str::to_owned);
        assert_eq!(run(&args).unwrap_err().to_string(),
            "Event copies require their reviewed approval; --yes cannot be combined with --events");
    }

    #[test]
    fn copy_approval_flags_are_rejected_before_non_copy_operations() {
        for action in ["list", "status", "recover", "discard"] {
            for flag in ["--events", "--yes"] {
                let args = [action, "--safe", "research", flag].map(str::to_owned);
                assert_eq!(run(&args).unwrap_err().to_string(),
                    "--events and --yes apply only to file import or export");
            }
        }
    }
}
