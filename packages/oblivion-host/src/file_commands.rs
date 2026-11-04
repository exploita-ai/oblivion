use oblivion_cli::controller::{Call, Controller};
use oblivion_cli::files;
use oblivion_host::autolock::Opening;
use oblivion_host::{control, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::native_file_events::{Identity, Outcome, Phase, Summary};
use oblivion_transfer::native_files::{
    Action, Context, Direction, Request, Status, TransfersPage, TransfersQuery,
};
use oblivion_transfer::selection::{self, Plan};
use oblivion_transfer::stream::{PreparedDownload, PreparedUpload};
use oblivion_transfer::{Receipt, stream};
use serde_json::json;
use std::fs::File;
use std::io::IsTerminal;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::Instant;

pub fn inspect(command: files::Command) -> control::Result<i32> {
    files::execute(
        &mut NativeFiles(control::Client::new()),
        command,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

struct NativeFiles(control::Client);
impl Controller for NativeFiles {
    type Slot = scope::Slot;
    fn request(&mut self, call: Call<'_, Self::Slot>) -> control::Result<String> {
        self.0.request(call)
    }
}
impl files::Backend for NativeFiles {
    fn transfers(
        &mut self,
        opening: &Opening,
        query: &TransfersQuery,
        destination: Option<&str>,
    ) -> control::Result<TransfersPage> {
        if let Some(destination) = destination {
            let destination = Path::new(destination).canonicalize()?;
            return Ok(stream::operations::inventory(
                &destination.join(".oblivion-transfers"),
                &destination,
                query,
            )?);
        }
        scope::within(opening.slot, || {
            file_query(
                opening,
                &Request::Transfers {
                    safe_id: query.safe_id.clone(),
                    opening: query.opening.clone(),
                    after: query.after.clone(),
                    limit: query.limit,
                },
            )
        })
    }
    fn manage(
        &mut self,
        opening: &Opening,
        operation: &str,
        action: Action,
        destination: Option<&str>,
    ) -> control::Result<Status> {
        if let Some(destination) = destination {
            let destination = Path::new(destination).canonicalize()?;
            return Ok(stream::operations::manage(
                &destination.join(".oblivion-transfers"),
                &destination,
                operation,
                &opening.safe_id,
                &opening.nonce,
                Direction::Export,
                action,
            )?);
        }
        let request = match action {
            Action::Status => Request::Status {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
            Action::Recover => Request::Recover {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
            Action::Discard => Request::Discard {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
        };
        scope::within(opening.slot, || file_query(opening, &request))
    }
}

/// Copy streams and local selections are the remaining Unix adapter commands.
/// Other Files grammar and orchestration have one owner in oblivion-cli.
pub fn parse(args: &[String]) -> control::Result<CopyCommand> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("Choose files import or export")?;
    if !matches!(operation, "import" | "export") {
        return Err("Choose files import or export".into());
    }
    let mut safe = None;
    let mut name = None;
    let mut paths = vec![];
    let mut sources = vec![];
    let mut selected = vec![];
    let mut operation_id = None;
    let mut expected_opening = None;
    let mut destination = None;
    let mut events_output = false;
    let mut confirmed = false;
    let mut options = args.iter().skip(1);
    while let Some(value) = options.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                safe = Some(options.next().ok_or("Missing Safe name")?.clone());
            }
            "--json" => {}
            "--events" => events_output = true,
            "--yes" => confirmed = true,
            "--operation" => {
                if operation_id.is_some() {
                    return Err("Duplicate --operation".into());
                }
                operation_id = Some(options.next().ok_or("Missing operation ID")?.clone());
            }
            "--opening" => {
                if expected_opening.is_some() {
                    return Err("Duplicate --opening".into());
                }
                expected_opening = Some(options.next().ok_or("Missing opening nonce")?.clone());
            }
            "--destination" => {
                if destination.is_some() {
                    return Err("Duplicate --destination".into());
                }
                destination = Some(
                    options
                        .next()
                        .ok_or("Missing destination directory")?
                        .clone(),
                );
            }
            "--source" => sources.push(options.next().ok_or("Missing source path")?.clone()),
            "--path" => selected.push(options.next().ok_or("Missing Safe path")?.clone()),
            "--name" => {
                if name.is_some() {
                    return Err("Duplicate --name".into());
                }
                name = Some(options.next().ok_or("Missing destination name")?.clone());
            }
            "--limit" => return Err("--limit applies only to files transfers".into()),
            "--cursor" => {
                return Err("--cursor applies to directory listing or files transfers".into());
            }
            value if value.starts_with('-') => return Err("Unknown file option".into()),
            _ => paths.push(value),
        }
    }
    if events_output && confirmed {
        return Err(
            "Event copies require their reviewed approval; --yes cannot be combined with --events"
                .into(),
        );
    }
    if operation == "import"
        && (!paths.is_empty()
            || sources.is_empty()
            || !selected.is_empty()
            || destination.is_some())
        || operation == "export"
            && (!paths.is_empty()
                || selected.is_empty()
                || !sources.is_empty()
                || destination.is_none())
    {
        return Err("Use files import --safe SAFE --source PATH [--source PATH...], or files export --safe SAFE --path workspace/PATH [--path imports/PATH...] --destination DIRECTORY".into());
    }
    for value in operation_id.iter().chain(expected_opening.iter()) {
        if !oblivion_host::managed::id(value) {
            return Err("Invalid operation or opening ID".into());
        }
    }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    let paths = if operation == "import" {
        &sources
    } else {
        &selected
    };
    if paths.len() > selection::MAX_SELECTIONS {
        return Err("selection_limit".into());
    }
    if paths.iter().map(String::len).sum::<usize>() > selection::MAX_SELECTION_BYTES {
        return Err("selection_byte_limit".into());
    }
    if paths.len() > 1 && name.is_none() {
        return Err("Choose a collection name with --name when selecting multiple paths".into());
    }
    if let Some(name) = &name {
        oblivion_transfer::native_files::validate_name(name)
            .map_err(|_| "Choose a valid destination name with --name")?;
    }
    let selection = if operation == "import" {
        CopyInput::Upload(sources)
    } else {
        selection::validate_paths(&selected)?;
        if selected
            .iter()
            .any(|path| !matches!(path.split('/').next(), Some("workspace" | "imports")))
        {
            return Err("Export paths must be under workspace or imports".into());
        }
        CopyInput::Download {
            selected,
            destination: destination.ok_or("Missing destination directory")?,
        }
    };
    Ok(CopyCommand {
        safe,
        name,
        selection,
        operation_id,
        expected_opening,
        events_output,
        confirmed,
    })
}

/// Syntax is admitted before runtime startup; filesystem resolution remains in
/// this adapter and cannot turn an unknown command into a runtime side effect.
pub struct CopyCommand {
    safe: String,
    name: Option<String>,
    selection: CopyInput,
    operation_id: Option<String>,
    expected_opening: Option<String>,
    events_output: bool,
    confirmed: bool,
}

enum CopyInput {
    Upload(Vec<String>),
    Download {
        selected: Vec<String>,
        destination: String,
    },
}

pub fn run(command: CopyCommand) -> control::Result<i32> {
    let CopyCommand {
        safe,
        name,
        selection,
        operation_id,
        expected_opening,
        events_output,
        confirmed,
    } = command;
    let exporting = matches!(&selection, CopyInput::Download { .. });
    let selection = match selection {
        CopyInput::Upload(sources) => {
            let sources = sources
                .iter()
                .map(std::path::absolute)
                .collect::<std::io::Result<Vec<_>>>()?;
            selection::validate_paths(
                &sources
                    .iter()
                    .map(|path| {
                        path.to_str()
                            .map(str::to_owned)
                            .ok_or("Source paths must be UTF-8")
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
            CopySelection::Upload(sources)
        }
        CopyInput::Download {
            selected,
            destination,
        } => CopySelection::Download {
            selected,
            destination: Path::new(&destination).canonicalize()?,
        },
    };
    let destination_name = selection.name(name.as_deref())?;
    let mut controller = control::Client::new();
    let target = files::target(&mut controller, &safe)?;
    let opening = files::opening(&mut controller, &target, expected_opening.as_deref())?;
    let id = target.safe_id().to_owned();
    let operation_id = match operation_id {
        Some(id) => id,
        None => {
            let mut random = [0; 16];
            File::open("/dev/urandom")?.read_exact(&mut random)?;
            random.iter().map(|byte| format!("{byte:02x}")).collect()
        }
    };
    let context = Context {
        id: operation_id,
        safe_id: id.clone(),
        opening: opening.nonce.clone(),
        direction: if exporting {
            Direction::Export
        } else {
            Direction::Import
        },
        name: destination_name,
    };
    context.validate()?;
    eprintln!(
        "File operation {}. Inspect with oblivion files status --safe {} --operation {}{}",
        context.id,
        id,
        context.id,
        if exporting {
            " --destination DIRECTORY"
        } else {
            ""
        }
    );
    if !events_output && !confirmed && !std::io::stdin().is_terminal() {
        return Err("A file copy needs review in a terminal, --yes for an explicit unattended copy, or --events for the manager".into());
    }
    scope::within(target.slot(), || {
        copy(opening, context, selection, events_output, confirmed)
    })
}

enum CopySelection {
    Upload(Vec<PathBuf>),
    Download {
        selected: Vec<String>,
        destination: PathBuf,
    },
}

impl CopySelection {
    fn name(&self, requested: Option<&str>) -> control::Result<String> {
        let first = match self {
            Self::Upload(sources) if sources.len() == 1 => {
                sources[0].file_name().and_then(|name| name.to_str())
            }
            Self::Download { selected, .. } if selected.len() == 1 => {
                selected[0].rsplit('/').next()
            }
            _ => None,
        };
        let name = requested
            .or(first)
            .ok_or("Choose a collection name with --name when selecting multiple paths")?;
        // Publication names preserve the user's native spelling. NFC is an
        // alias rule inside the transfer plan, not a rule for this pathname.
        oblivion_transfer::native_files::validate_name(name)
            .map_err(|_| "Choose a valid destination name with --name")?;
        Ok(name.into())
    }
}

enum PreparedCopy {
    Upload(PreparedUpload),
    Download(PreparedDownload),
}

impl PreparedCopy {
    fn plan(&self) -> &Plan {
        match self {
            Self::Upload(prepared) => prepared.plan(),
            Self::Download(prepared) => prepared.plan(),
        }
    }
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
    selection: CopySelection,
    events_output: bool,
    confirmed: bool,
) -> control::Result<i32> {
    let mut events = events_output
        .then(|| {
            super::file_events::Control::stdio(
                Identity {
                    operation_id: context.id.clone(),
                    safe_id: context.safe_id.clone(),
                    opening: context.opening.clone(),
                },
                context.direction,
                context.name.clone(),
            )
        })
        .transpose()?;
    // Retain the exact client even if its request or source preparation fails.
    // Dropping its private lease is the last-resort revocation on process death.
    let mut attachment = None;
    let result = (|| -> control::Result<Copied> {
        let prepared = match &selection {
            CopySelection::Upload(sources) => PreparedCopy::Upload(PreparedUpload::prepare(
                sources,
                context.clone(),
                &mut || {
                    events
                        .as_ref()
                        .map_or(Ok(()), super::file_events::Control::check)
                },
            )?),
            CopySelection::Download {
                selected,
                destination,
            } => {
                let channel = file_channel(
                    &opening,
                    &json!({"operation":"export"}),
                    events
                        .as_ref()
                        .map(super::file_events::Control::watch)
                        .transpose()?,
                    &mut attachment,
                )?;
                PreparedCopy::Download(PreparedDownload::prepare(
                    channel,
                    selected,
                    destination,
                    context.clone(),
                )?)
            }
        };
        let summary = prepared.summary()?;
        let digest = summary.manifest_sha256.clone();
        if let Some(events) = &mut events {
            events.plan(prepared.plan())?;
            events.review(summary.clone())?;
            if !events.wait_approval()? {
                return Ok(Copied::Cancelled);
            }
        } else if !review(&context, &summary, &selection, prepared.plan(), confirmed)? {
            return Ok(Copied::Cancelled);
        }
        let watch = events
            .as_ref()
            .map(super::file_events::Control::watch)
            .transpose()?;
        let mut last_progress = None;
        let mut observer = |phase, bytes| {
            if let Some(events) = &mut events {
                return events.progress(phase, bytes);
            }
            console_progress(phase, bytes, summary.bytes, &mut last_progress)
        };
        let receipt = match prepared {
            PreparedCopy::Upload(prepared) => {
                // The import destination is not contacted until this exact
                // prepared manifest has received the reviewed approval.
                let request = Request::Import {
                    id: context.id.clone(),
                    safe_id: context.safe_id.clone(),
                    opening: context.opening.clone(),
                    name: context.name.clone(),
                };
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
    } else {
        Ok(())
    };
    if let Some(events) = &mut events {
        let outcome = if released.is_ok() {
            match &result {
                Ok(Copied::Complete(_)) if events.check().is_ok() => Outcome::Completed,
                Ok(Copied::Cancelled) => Outcome::CancelledBeforeCopy,
                Err(_) if events.cancelled_before_copy() => Outcome::CancelledBeforeCopy,
                _ => Outcome::Interrupted,
            }
        } else {
            Outcome::Interrupted
        };
        let receipt = match result {
            Ok(Copied::Complete(receipt)) if outcome == Outcome::Completed => Some(receipt),
            _ => None,
        };
        if let Err(error) = events.finish(outcome, receipt) {
            if outcome != Outcome::Completed {
                return Err(error.into());
            }
            // Cancellation can arrive while releasing the owned attachment.
            // A rejected completion still gets one interrupted-outcome attempt.
            events.finish(Outcome::Interrupted, None)?;
            return Ok(1);
        }
        return Ok(match outcome {
            Outcome::Completed => 0,
            Outcome::CancelledBeforeCopy => 130,
            Outcome::Interrupted => 1,
        });
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
    let mut channel = Channel::new(
        File::from(OwnedFd::from(connection)),
        Duration::from_secs(3600),
    )?;
    if let Some(watch) = watch {
        channel.watch(watch);
    }
    let request = serde_json::to_vec(request)?;
    channel.write_all(&(request.len() as u32).to_be_bytes())?;
    channel.write_all(&request)?;
    Ok(channel)
}

fn review(
    context: &Context,
    summary: &Summary,
    selection: &CopySelection,
    plan: &Plan,
    confirmed: bool,
) -> control::Result<bool> {
    eprintln!(
        "Review {} · Safe {}",
        if context.direction == Direction::Import {
            "import"
        } else {
            "export"
        },
        context.safe_id
    );
    for mapping in &plan.mappings {
        let source = match selection {
            CopySelection::Upload(sources) => format!("{:?}", sources[mapping.input_index]),
            CopySelection::Download { selected, .. } => {
                format!("{:?}", selected[mapping.input_index])
            }
        };
        if let Some(owner) = mapping.covered_by {
            eprintln!(
                "  {}. {source} · included in selection {}",
                mapping.input_index + 1,
                owner + 1
            );
            continue;
        }
        let output = if plan.mappings.len() == 1 {
            context.name.clone()
        } else {
            format!(
                "{}/{}",
                context.name,
                mapping.alias.as_deref().ok_or("Invalid file mapping")?
            )
        };
        eprintln!("  {}. {source} → {output:?}", mapping.input_index + 1);
    }
    match selection {
        CopySelection::Download { destination, .. } => {
            eprintln!("To this computer · {:?}", destination.join(&context.name));
            eprintln!("Exported files use the destination filesystem's protection.");
        }
        CopySelection::Upload(_) => eprintln!("To the Safe · workspace/{:?}", context.name),
    }
    eprintln!(
        "{} files · {} folders · {} bytes",
        summary.files, summary.directories, summary.bytes
    );
    eprintln!("Manifest SHA-256 {}", summary.manifest_sha256);
    if confirmed {
        return Ok(true);
    }
    eprint!("Copy these items? [y/N] ");
    std::io::stderr().flush()?;
    use std::io::BufRead;
    let mut answer = String::new();
    std::io::stdin().lock().take(16).read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn console_progress(
    phase: Phase,
    bytes: u64,
    total: u64,
    previous: &mut Option<(Phase, Instant)>,
) -> std::io::Result<()> {
    if phase == Phase::Copying
        && bytes != total
        && previous
            .as_ref()
            .is_some_and(|(last, at)| *last == phase && at.elapsed() < Duration::from_millis(100))
    {
        return Ok(());
    }
    eprint!(
        "\r{} · {bytes}/{total} bytes",
        if phase == Phase::Copying {
            "Copying"
        } else {
            "Finalizing"
        }
    );
    std::io::stderr().flush()?;
    *previous = Some((phase, Instant::now()));
    Ok(())
}

fn file_query<T: serde::de::DeserializeOwned>(
    opening: &Opening,
    request: &Request,
) -> control::Result<T> {
    let (mut connection, lease, client) = control::attach_file(opening)?;
    let result = (|| -> control::Result<T> {
        let request = serde_json::to_vec(&request)?;
        connection.write_all(&(request.len() as u32).to_be_bytes())?;
        connection.write_all(&request)?;
        let mut channel = Channel::new(
            File::from(OwnedFd::from(connection)),
            Duration::from_secs(60),
        )?;
        Ok(oblivion_transfer::endpoint::read_message(
            &mut channel,
            8192,
        )?)
    })();
    let released = control::release_agent(&client, &opening.safe_id);
    drop(lease);
    released?;
    result
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn event_copies_cannot_bypass_their_manifest_approval_with_yes() {
        let args = [
            "import",
            "--safe",
            "research",
            "--source",
            "/selected",
            "--events",
            "--yes",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse(&args).err().unwrap().to_string(),
            "Event copies require their reviewed approval; --yes cannot be combined with --events"
        );
    }

    #[test]
    fn copy_selectors_are_explicit_and_never_reuse_the_positional_grammar() {
        for args in [
            vec!["import", "--safe", "research", "/selected"],
            vec![
                "export",
                "--safe",
                "research",
                "workspace/project",
                "/destination",
            ],
            vec![
                "import",
                "--safe",
                "research",
                "--path",
                "workspace/project",
            ],
        ] {
            assert!(
                parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .err()
                    .unwrap()
                    .to_string()
                    .starts_with("Use files import --safe SAFE --source PATH")
            );
        }
    }

    #[test]
    fn copy_grammar_keeps_selection_order_and_does_not_open_paths() {
        let args = [
            "import",
            "--safe",
            "GB",
            "--source",
            "relative/missing",
            "--source",
            "/also-missing",
            "--name",
            "collection",
            "--events",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--opening",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ]
        .map(str::to_owned);
        let command = parse(&args).unwrap();
        assert_eq!(command.safe, "GB");
        assert_eq!(command.name.as_deref(), Some("collection"));
        assert!(command.events_output && !command.confirmed);
        assert_eq!(
            command.operation_id.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            command.expected_opening.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        let super::CopyInput::Upload(sources) = command.selection else {
            panic!("expected import")
        };
        assert_eq!(sources, ["relative/missing", "/also-missing"]);
        let command = parse(
            &[
                "export",
                "--safe",
                "GB",
                "--path",
                "workspace/project",
                "--destination",
                "/missing",
                "--yes",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert!(command.confirmed && !command.events_output);
        let super::CopyInput::Download {
            selected,
            destination,
        } = command.selection
        else {
            panic!("expected export")
        };
        assert_eq!(selected, ["workspace/project"]);
        assert_eq!(destination, "/missing");
    }

    #[test]
    fn multiple_inputs_require_an_explicit_collection_name() {
        let selection = super::CopySelection::Upload(vec!["/a/notes".into(), "/b/notes".into()]);
        assert!(selection.name(None).is_err());
        assert_eq!(selection.name(Some("research")).unwrap(), "research");
        let selection = super::CopySelection::Download {
            selected: vec!["workspace/project".into(), "imports/note".into()],
            destination: "/tmp".into(),
        };
        assert!(selection.name(None).is_err());
        assert_eq!(selection.name(Some("research")).unwrap(), "research");
        let single = super::CopySelection::Upload(vec!["/a/notes".into()]);
        assert_eq!(single.name(None).unwrap(), "notes");
        assert_eq!(single.name(Some("renamed")).unwrap(), "renamed");
        assert_eq!(single.name(Some("cafe\u{301}")).unwrap(), "cafe\u{301}");
        let unsafe_name = super::CopySelection::Upload(vec!["/a/note\\draft".into()]);
        assert!(unsafe_name.name(None).is_err());
        assert_eq!(unsafe_name.name(Some("note_draft")).unwrap(), "note_draft");
    }
}
