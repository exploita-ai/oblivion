use oblivion_host::{child_task, control, managed, scope};
use std::io::Write;

pub fn run(args: &[String]) -> control::Result<i32> {
    let operation = args.first().map(String::as_str).ok_or("Choose task status, review, start, retry or cancel")?;
    if !matches!(operation, "status" | "review" | "start" | "retry" | "cancel") {
        return Err("Choose task status, review, start, retry or cancel".into());
    }
    let name = args.get(1).ok_or("Choose an open Safe")?;
    let mut json = false;
    let mut expected = None;
    let mut options = args.iter().skip(2);
    while let Some(option) = options.next() {
        match option.as_str() {
            "--json" if !json => json = true,
            "--request" if expected.is_none() && !matches!(operation, "status" | "review") => {
                let value = options.next().ok_or("Missing creation request ID")?;
                if !managed::id(value) { return Err("Invalid creation request ID".into()); }
                expected = Some(value.as_str());
            }
            _ => return Err("Unknown or duplicate task option".into()),
        }
    }
    let state = crate::status()?;
    if !state.app_open || state.recovery_required {
        return Err("Unlock Oblivion and complete recovery before reviewing a saved task".into());
    }
    let id = state.find_safe(name)?.ok_or("Safe not found")?;
    let opened = state.open_sessions.iter().find(|safe| safe.id.as_deref() == Some(&id))
        .ok_or("Open this Safe with oblivion safe open before reviewing its saved task")?;
    scope::within(opened.slot, || {
        if operation == "review" {
            let review: child_task::Review = serde_json::from_str(&control::request_for(&id, "child-task-review", None, &[])?)?;
            if !review.valid() || review.status.safe_id != id { return Err("Invalid task review response".into()); }
            if json {
                serde_json::to_writer(std::io::stdout().lock(), &review)?;
                println!();
                return Ok(0);
            }
            show(&review.status)?;
            println!("\nSaved task (visible control characters are escaped):");
            for character in review.task.chars() {
                if character == '\n' || !character.is_control() && !matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                    print!("{character}");
                } else { print!("{}", character.escape_unicode()); }
            }
            println!();
            std::io::stdout().flush()?;
            return Ok(0);
        }
        let before = status(&id)?;
        if expected.is_some_and(|request| request != before.request_id) { return Err("The saved task changed. Review it again.".into()); }
        if operation == "status" { return output(&before, json); }
        if operation == "start" && !before.can_start { return output(&before, json); }
        if operation == "retry" && !before.can_retry { return Err("Retry requires a confirmed failed or cancelled attempt; inspect task status first.".into()); }
        if operation == "cancel" && !before.can_cancel {
            if before.job.as_ref().is_some_and(|job| job.state.terminal()) { return output(&before, json); }
            return Err("No running attempt could be confirmed. Inspect task status before cancelling.".into());
        }
        if matches!(operation, "start" | "retry") {
            // This explicit user operation keeps the reviewed Safe open for
            // login/results. Output does not override its inactivity timer.
            control::request_for(&id, "pin-safe", None, &[])?;
            crate::start_agent(&id)?;
        }
        let next: child_task::Status = serde_json::from_str(&control::request_for(&id, &format!("child-task-{operation}"), None,
            &serde_json::to_vec(&child_task::Request { request_id: before.request_id.clone() })?)?)?;
        if !next.valid() || next.safe_id != id || next.request_id != before.request_id { return Err("Invalid task operation response; inspect task status before retrying.".into()); }
        output(&next, json)
    })
}

fn status(id: &str) -> control::Result<child_task::Status> {
    let status: child_task::Status = serde_json::from_str(&control::request_for(id, "child-task-status", None, &[])?)?;
    if !status.valid() || status.safe_id != id { return Err("Invalid task status response".into()); }
    Ok(status)
}

fn output(status: &child_task::Status, json: bool) -> control::Result<i32> {
    if json { println!("{}", serde_json::to_string(status)?); return Ok(0); }
    show(status)?;
    Ok(0)
}

fn show(status: &child_task::Status) -> control::Result<()> {
    println!("Safe {} · {} · attempt {}/{}", status.safe_id, status.agent, status.attempts, status.attempt_limit);
    if let Some(job) = &status.job {
        println!("{:?} · job {}", job.state, job.job_id);
        if let Some(reason) = &job.reason { println!("Reason: {reason:?}"); }
        if let Some(chat) = &job.native_chat_id { println!("Native conversation: {chat}"); }
    } else { println!("{}", if status.attempts == 0 { "Saved task has not been admitted." } else { "Admission is recorded; execution outcome needs reconciliation." }); }
    if let Some(blocked) = &status.blocked { println!("Action unavailable: {blocked}"); }
    Ok(())
}
