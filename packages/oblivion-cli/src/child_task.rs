//! Explicit review and delivery of the immutable task saved in an open child
//! Safe. Native adapters own controller transport, terminal input and time.
use crate::controller::{self, Call, Result};
use crate::run;
use oblivion_wire::child_task::{Request, Review, Status};
use oblivion_wire::control::{Operation, valid_id};
use oblivion_wire::session_title;
use std::io::Write;
use zeroize::Zeroizing;

pub struct Command {
    action: Action,
    name: String,
    json: bool,
    expected: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Status,
    Review,
    Start,
    Retry,
    Cancel,
}

pub fn parse(args: &[String]) -> Result<Command> {
    let action = match args.first().map(String::as_str) {
        Some("status") => Action::Status,
        Some("review") => Action::Review,
        Some("start") => Action::Start,
        Some("retry") => Action::Retry,
        Some("cancel") => Action::Cancel,
        _ => return Err("Choose task status, review, start, retry or cancel".into()),
    };
    let name = args.get(1).ok_or("Choose an open Safe")?;
    session_title::validate(name)?;
    let mut command = Command {
        action,
        name: name.clone(),
        json: false,
        expected: None,
    };
    let mut options = args.iter().skip(2);
    while let Some(option) = options.next() {
        match option.as_str() {
            "--json" if !command.json => command.json = true,
            "--request"
                if command.expected.is_none()
                    && matches!(action, Action::Start | Action::Retry | Action::Cancel) =>
            {
                let value = options.next().ok_or("Missing creation request ID")?;
                if !valid_id(value) {
                    return Err("Invalid creation request ID".into());
                }
                command.expected = Some(value.clone());
            }
            _ => return Err("Unknown or duplicate task option".into()),
        }
    }
    Ok(command)
}

pub fn execute<R: run::Runtime>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
) -> Result<i32> {
    let state = controller::status(runtime)?;
    if !state.app_open || state.recovery_required {
        return Err("Unlock Oblivion and complete recovery before reviewing a saved task".into());
    }
    let id = state.find_safe(&command.name)?.ok_or("Safe not found")?;
    if !valid_id(&id) {
        return Err("invalid_safe_id".into());
    }
    let slot = state
        .open_sessions
        .iter()
        .find(|safe| safe.id.as_deref() == Some(&id))
        .ok_or("Open this Safe with oblivion safe open before reviewing its saved task")?
        .slot;
    if command.action == Action::Review {
        // The response itself contains plaintext too, not only Review.task.
        let response = Zeroizing::new(runtime.request(Call {
            operation: Operation::ChildTaskReview,
            slot: Some(slot),
            session: None,
            expected_session: Some(&id),
            secret: &[],
        })?);
        let review: Review =
            serde_json::from_str(&response).map_err(|_| "Invalid task review response")?;
        if !review.valid() || review.status.safe_id != id {
            return Err("Invalid task review response".into());
        }
        if command.json {
            serde_json::to_writer(&mut *output, &review)?;
            writeln!(output)?;
            return Ok(0);
        }
        show(&review.status, output)?;
        writeln!(
            output,
            "\nSaved task (visible control characters are escaped):"
        )?;
        escaped(&review.task, output)?;
        writeln!(output)?;
        output.flush()?;
        return Ok(0);
    }
    let before: Status = serde_json::from_str(&runtime.request(Call {
        operation: Operation::ChildTaskStatus,
        slot: Some(slot),
        session: None,
        expected_session: Some(&id),
        secret: &[],
    })?)
    .map_err(|_| "Invalid task status response")?;
    if !before.valid() || before.safe_id != id {
        return Err("Invalid task status response".into());
    }
    if command
        .expected
        .is_some_and(|request| request != before.request_id)
    {
        return Err("The saved task changed. Review it again.".into());
    }
    if command.action == Action::Status || command.action == Action::Start && !before.can_start {
        return display(&before, command.json, output);
    }
    if command.action == Action::Retry && !before.can_retry {
        return Err(
            "Retry requires a confirmed failed or cancelled attempt; inspect task status first."
                .into(),
        );
    }
    if command.action == Action::Cancel && !before.can_cancel {
        if before.job.as_ref().is_some_and(|job| job.state.terminal()) {
            return display(&before, command.json, output);
        }
        return Err(
            "No running attempt could be confirmed. Inspect task status before cancelling.".into(),
        );
    }
    if matches!(command.action, Action::Start | Action::Retry) {
        // This explicit start keeps the reviewed Safe open for provider login
        // and results; it neither infers login nor disables its idle timer.
        runtime.request(Call {
            operation: Operation::PinSafe,
            slot: Some(slot),
            session: None,
            expected_session: Some(&id),
            secret: &[],
        })?;
        run::start_agent(runtime, slot, &id)?;
    }
    let operation = match command.action {
        Action::Start => Operation::ChildTaskStart,
        Action::Retry => Operation::ChildTaskRetry,
        Action::Cancel => Operation::ChildTaskCancel,
        Action::Status | Action::Review => unreachable!(),
    };
    let next: Status = serde_json::from_str(&runtime.request(Call {
        operation,
        slot: Some(slot),
        session: None,
        expected_session: Some(&id),
        secret: &serde_json::to_vec(&Request {
            request_id: before.request_id.clone(),
        })?,
    })?)
    .map_err(|_| "Invalid task operation response; inspect task status before retrying.")?;
    if !next.valid() || next.safe_id != id || next.request_id != before.request_id {
        return Err("Invalid task operation response; inspect task status before retrying.".into());
    }
    display(&next, command.json, output)
}

fn display(status: &Status, json: bool, output: &mut impl Write) -> Result<i32> {
    if json {
        serde_json::to_writer(&mut *output, status)?;
        writeln!(output)?;
        return Ok(0);
    }
    show(status, output)?;
    Ok(0)
}

fn show(status: &Status, output: &mut impl Write) -> Result<()> {
    writeln!(
        output,
        "Safe {} · {} · attempt {}/{}",
        status.safe_id, status.agent, status.attempts, status.attempt_limit
    )?;
    if let Some(job) = &status.job {
        writeln!(output, "{:?} · job {}", job.state, job.job_id)?;
        if let Some(reason) = &job.reason {
            writeln!(output, "Reason: {reason:?}")?;
        }
        if let Some(chat) = &job.native_chat_id {
            writeln!(output, "Native conversation: {chat}")?;
        }
    } else {
        writeln!(
            output,
            "{}",
            if status.attempts == 0 {
                "Saved task has not been admitted."
            } else {
                "Admission is recorded; execution outcome needs reconciliation."
            }
        )?;
    }
    if let Some(blocked) = &status.blocked {
        write!(output, "Action unavailable: ")?;
        escaped(blocked, output)?;
        writeln!(output)?;
    }
    Ok(())
}

fn escaped(value: &str, output: &mut impl Write) -> Result<()> {
    for character in value.chars() {
        if character == '\n'
            || !character.is_control()
                && !matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(output, "{character}")?;
        } else {
            write!(output, "{}", character.escape_unicode())?;
        }
    }
    Ok(())
}
