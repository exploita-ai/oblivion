//! Windows Files orchestration. The filesystem authorities, transfer protocol
//! and consent flow are shared with the existing native Files implementation.
use crate::controller::Result;
use crate::file_copy::{CopyCommand, CopyInput};
use crate::windows::{FileAttachment, Runtime};
use crate::windows_file_events::Control;
use crate::{file_review, files, run};
use oblivion_transfer::copy_protocol;
use oblivion_transfer::native_file_events::{Identity, Outcome, Phase, Summary};
use oblivion_transfer::native_files::{Context, Direction, Request};
use oblivion_transfer::selection::Plan;
use oblivion_transfer::stream::PreparedDownload;
use oblivion_transfer::windows_source::SourceSelection;
use oblivion_transfer::{Limits, Receipt};
use oblivion_wire::idle::Opening;
use oblivion_wire::slot::Slot;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub fn run(runtime: &mut Runtime, command: CopyCommand) -> Result<i32> {
    if !command.events_output && !command.confirmed && !std::io::stdin().is_terminal() {
        return Err("A file copy needs review in a terminal, --yes for an explicit unattended copy, or --events for the manager".into());
    }
    // Lexical resolution does not follow a reparse point or contact a network
    // share. The Windows endpoint admits only local, handle-pinned drive paths.
    let selection = match command.selection {
        CopyInput::Media { .. } => return Err("USB transfers are available only on Oblivion Live".into()),
        CopyInput::Upload(paths) => Selection::Upload(
            paths
                .iter()
                .map(std::path::absolute)
                .collect::<io::Result<Vec<_>>>()?,
        ),
        CopyInput::Download {
            selected,
            destination,
        } => Selection::Download {
            selected,
            destination: std::path::absolute(destination)?,
        },
    };
    let name = selection.name(command.name.as_deref())?;
    let target = files::target(runtime, &command.safe)?;
    let opening = files::opening(runtime, &target, command.expected_opening.as_deref())?;
    let id = match command.operation_id {
        Some(id) => id,
        None => {
            let mut bytes = [0; 16];
            getrandom::getrandom(&mut bytes).map_err(|_| "file_operation_random_failed")?;
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
    };
    let context = Context {
        id,
        safe_id: target.safe_id().into(),
        opening: opening.nonce.clone(),
        direction: match selection {
            Selection::Upload(_) => Direction::Import,
            Selection::Download { .. } => Direction::Export,
        },
        name,
    };
    context.validate()?;
    eprintln!(
        "File operation {}. Inspect with oblivion files status --safe {} --operation {}{}",
        context.id,
        context.safe_id,
        context.id,
        if context.direction == Direction::Export {
            " --destination DIRECTORY"
        } else {
            ""
        }
    );
    copy(
        runtime,
        &opening,
        &context,
        &selection,
        command.events_output,
        command.confirmed,
    )
}

enum Selection {
    Upload(Vec<PathBuf>),
    Download {
        selected: Vec<String>,
        destination: PathBuf,
    },
}

impl Selection {
    fn name(&self, requested: Option<&str>) -> Result<String> {
        let first = match self {
            Self::Upload(paths) if paths.len() == 1 => {
                paths[0].file_name().and_then(|name| name.to_str())
            }
            Self::Download { selected, .. } if selected.len() == 1 => {
                selected[0].rsplit('/').next()
            }
            _ => None,
        };
        let name = requested
            .or(first)
            .ok_or("Choose a collection name with --name when selecting multiple paths")?;
        oblivion_transfer::native_files::validate_name(name)
            .map_err(|_| "Choose a valid destination name with --name")?;
        Ok(name.into())
    }
}

enum Copied {
    Complete(Receipt),
    Cancelled,
}

fn copy(
    runtime: &mut Runtime,
    opening: &Opening<Slot>,
    context: &Context,
    selection: &Selection,
    events_output: bool,
    confirmed: bool,
) -> Result<i32> {
    let mut events = events_output
        .then(|| {
            Control::stdio(
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
    // This owner outlives preparation and its borrowed download stream. Even
    // cancelled I/O retains the quiet lease until explicit controller release.
    let mut attachment = None;
    let result = match selection {
        Selection::Upload(paths) => import(
            runtime,
            opening,
            context,
            selection,
            paths,
            &mut events,
            confirmed,
            &mut attachment,
        ),
        Selection::Download {
            selected,
            destination,
        } => (|| -> Result<Copied> {
            attachment = Some(runtime.attach_file_export(opening, cancellation(&events))?);
            let prepared = PreparedDownload::prepare(
                attachment
                    .as_mut()
                    .ok_or("file_attachment_missing")?
                    .stream(),
                selected,
                destination,
                context.clone(),
            )?;
            let summary = prepared.summary()?;
            if !approve(
                runtime,
                &mut events,
                context,
                &summary,
                prepared.plan(),
                selection,
                confirmed,
            )? {
                return Ok(Copied::Cancelled);
            }
            let mut previous = None;
            Ok(Copied::Complete(prepared.receive(
                &summary.manifest_sha256,
                &mut |phase, bytes| progress(&mut events, &summary, &mut previous, phase, bytes),
            )?))
        })(),
    };
    let released = attachment
        .as_mut()
        .map_or(Ok(()), |attachment| runtime.release_file(attachment));
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

fn import(
    runtime: &mut Runtime,
    opening: &Opening<Slot>,
    context: &Context,
    selection: &Selection,
    paths: &[PathBuf],
    events: &mut Option<Control>,
    confirmed: bool,
    attachment: &mut Option<FileAttachment>,
) -> Result<Copied> {
    let mut source = SourceSelection::prepare(
        paths,
        Limits {
            entries: oblivion_transfer::MAX_ENTRIES,
            bytes: oblivion_transfer::MAX_DOCUMENT_BYTES,
        },
        &mut || events.as_ref().map_or(Ok(()), Control::check),
    )?;
    let summary = Summary::from_manifest(source.manifest(), source.plan())?;
    if !approve(
        runtime,
        events,
        context,
        &summary,
        source.plan(),
        selection,
        confirmed,
    )? {
        return Ok(Copied::Cancelled);
    }
    // Preparing and declining an import never contacts the guest receiver.
    *attachment = Some(runtime.attach_file(
        opening,
        &Request::Import {
            id: context.id.clone(),
            safe_id: context.safe_id.clone(),
            opening: context.opening.clone(),
            name: context.name.clone(),
        },
        cancellation(events),
    )?);
    let mut previous = None;
    Ok(Copied::Complete(copy_protocol::send(
        attachment
            .as_mut()
            .ok_or("file_attachment_missing")?
            .stream(),
        &mut source,
        &context.id,
        &summary.manifest_sha256,
        &mut |phase, bytes| progress(events, &summary, &mut previous, phase, bytes),
    )?))
}

fn cancellation(events: &Option<Control>) -> Arc<AtomicBool> {
    events
        .as_ref()
        .map_or_else(|| Arc::new(AtomicBool::new(false)), Control::cancellation)
}

fn approve(
    runtime: &mut Runtime,
    events: &mut Option<Control>,
    context: &Context,
    summary: &Summary,
    plan: &Plan,
    selection: &Selection,
    confirmed: bool,
) -> Result<bool> {
    if let Some(events) = events {
        events.plan(plan)?;
        events.review(summary.clone())?;
        return Ok(events.wait_approval()?);
    }
    let sources = match selection {
        Selection::Upload(paths) => paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        Selection::Download { selected, .. } => selected.clone(),
    };
    let destination = match selection {
        Selection::Upload(_) => None,
        Selection::Download { destination, .. } => Some(destination.as_path()),
    };
    file_review::write(
        &mut std::io::stderr(),
        context,
        summary,
        plan,
        &sources,
        destination,
    )?;
    if confirmed {
        return Ok(true);
    }
    run::Runtime::confirm(runtime, "copy")
}

fn progress(
    events: &mut Option<Control>,
    summary: &Summary,
    previous: &mut Option<(Phase, Instant)>,
    phase: Phase,
    bytes: u64,
) -> io::Result<()> {
    if let Some(events) = events {
        return events.progress(phase, bytes);
    }
    if phase == Phase::Copying
        && bytes != summary.bytes
        && previous
            .as_ref()
            .is_some_and(|(last, at)| *last == phase && at.elapsed() < Duration::from_millis(100))
    {
        return Ok(());
    }
    eprint!(
        "\r{} · {bytes}/{} bytes",
        if phase == Phase::Copying {
            "Copying"
        } else {
            "Finalizing"
        },
        summary.bytes
    );
    std::io::stderr().flush()?;
    *previous = Some((phase, Instant::now()));
    Ok(())
}
