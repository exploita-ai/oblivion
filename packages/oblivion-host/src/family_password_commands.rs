use oblivion_host::{control, family_rotation as wire, scope};
use zeroize::Zeroizing;

const HELP: &str = "Use safe password SAFE [--confirmed-plan SHA], safe password preview SAFE --json, safe password status [--json], or safe password recover TRANSACTION --complete|--rollback";

enum Options<'a> {
    Status { json: bool },
    Preview(&'a str),
    Change { safe: &'a str, confirmed: Option<&'a str> },
    Recover { transaction: &'a str, direction: wire::Direction },
}

fn options(args: &[String]) -> control::Result<Options<'_>> {
    match args.first().map(String::as_str) {
        Some("status") if args.len() == 1 => Ok(Options::Status { json: false }),
        Some("status") if args.len() == 2 && args[1] == "--json" => Ok(Options::Status { json: true }),
        Some("preview") if args.len() == 3 && args[2] == "--json" => Ok(Options::Preview(&args[1])),
        Some("recover") if args.len() == 3 && oblivion_host::managed::id(&args[1]) => match args[2].as_str() {
            "--complete" => Ok(Options::Recover { transaction: &args[1], direction: wire::Direction::Complete }),
            "--rollback" => Ok(Options::Recover { transaction: &args[1], direction: wire::Direction::Rollback }),
            _ => Err(HELP.into()),
        },
        Some(safe) if !matches!(safe, "status" | "preview" | "recover") && args.len() == 1 => Ok(Options::Change { safe, confirmed: None }),
        Some(safe) if !matches!(safe, "status" | "preview" | "recover") && args.len() == 3 && args[1] == "--confirmed-plan"
            && args[2].len() == 64 && args[2].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {
                Ok(Options::Change { safe, confirmed: Some(&args[2]) })
            }
        _ => Err(HELP.into()),
    }
}

pub fn run(args: &[String]) -> control::Result<i32> {
    let options = options(args)?;
    let state = super::status()?;
    if !state.app_open || state.app_mode != super::AppMode::Persistent {
        return Err("Unlock writable encrypted storage before changing a Safe family's password".into());
    }
    if let Options::Status { json } = options {
        let status = status()?;
        if json { println!("{}", serde_json::to_string(&status)?); return Ok(0); }
        for entry in status.transactions {
            println!("{}\t{}\t{} Safes", entry.transaction, label(entry.outcome), entry.members.len());
        }
        return Ok(0);
    }
    scope::within(Default::default(), || {
        if let Options::Recover { transaction, direction } = options {
            let status = status()?;
            let entry = status.transactions.iter().find(|entry| entry.transaction == transaction).ok_or("Password change transaction not found")?;
            if entry.outcome != wire::Outcome::Pending { return Err("This password change has already finished".into()); }
            show(&entry.members);
            eprintln!("{} the recorded password-wrapper update for this entire local family.", if direction == wire::Direction::Complete { "Complete" } else { "Roll back" });
            if !super::init_commands::confirm(if direction == wire::Direction::Complete { "COMPLETE" } else { "ROLLBACK" })? { return Ok(130); }
            let body = serde_json::to_vec(&wire::Recover { transaction: transaction.into(), host_opening: status.host_opening, direction })?;
            return finish(control::request("family-password-recover", None, &body),
                if direction == wire::Direction::Complete { wire::Outcome::Complete } else { wire::Outcome::RolledBack });
        }
        let (safe, confirmed) = match options { Options::Preview(safe) => (safe, None), Options::Change { safe, confirmed } => (safe, confirmed), _ => unreachable!() };
        let id = super::find_safe(&state, safe)?.ok_or("Safe not found")?;
        if !state.sessions.contains(&id) { return Err("Only persistent Safe families have a changeable human password".into()); }
        let plan: wire::Plan = serde_json::from_str(&control::request_for(&id, "family-password-preview", Some(&id), &[])?)?;
        plan.validate()?;
        if plan.host_opening != current_host()? || !plan.members.iter().any(|member| member.safe_id == id) {
            return Err("Family preview no longer belongs to the current Oblivion opening".into());
        }
        if matches!(options, Options::Preview(_)) { println!("{}", serde_json::to_string(&plan)?); return Ok(0); }
        if confirmed.is_some_and(|sha| sha != plan.sha256) { return Err("The password change plan changed. Review the current family before continuing.".into()); }
        show(&plan.members);
        eprintln!("Every local Safe in this family must be closed. Existing external backups keep their previous password.");
        eprintln!("This updates the password wrapper; copied old headers and known family keys are not revoked.");
        if !super::init_commands::confirm("CHANGE")? { return Ok(130); }
        let current_password = Zeroizing::new(String::from_utf8(super::password("Current family password", false)?.to_vec())?);
        let new_password = Zeroizing::new(String::from_utf8(super::password("New family password", true)?.to_vec())?);
        let body = Zeroizing::new(serde_json::to_vec(&wire::Change { safe_id: id, host_opening: plan.host_opening,
            plan_sha256: plan.sha256, current_password, new_password })?);
        finish(control::request("family-password-change", None, &body), wire::Outcome::Complete)
    })
}

fn status() -> control::Result<wire::Status> {
    let status: wire::Status = serde_json::from_str(&control::request("family-password-status", None, &[])?)?;
    status.validate()?;
    if status.host_opening != current_host()? { return Err("Oblivion opening changed while reading password changes".into()); }
    Ok(status)
}

fn current_host() -> control::Result<String> {
    #[derive(serde::Deserialize)]
    struct Current { idle_lock: oblivion_host::autolock::Status }
    let current: Current = serde_json::from_str(&control::request("status", None, &[])?)?;
    let host = current.idle_lock.host.filter(|host| !host.closing && oblivion_host::managed::id(&host.nonce))
        .ok_or("Oblivion is closing or its opening changed")?;
    Ok(host.nonce)
}

fn show(members: &[wire::Member]) {
    eprintln!("Local family members ({}):", members.len());
    for member in members { eprintln!("  {}  {}", member.safe_id, member.title); }
}

fn label(outcome: wire::Outcome) -> &'static str {
    match outcome { wire::Outcome::Pending => "Recovery required", wire::Outcome::Complete => "Complete", wire::Outcome::RolledBack => "Rolled back" }
}

fn finish(result: control::Result<String>, expected: wire::Outcome) -> control::Result<i32> {
    let response = result.map_err(|error| {
        eprintln!("Read `oblivion safe password status` before another attempt. A pending update must be explicitly completed or rolled back.");
        error
    })?;
    let entry: wire::Entry = serde_json::from_str(&response)?;
    entry.validate()?;
    if entry.outcome != expected { return Err("Password update is not complete. Read `oblivion safe password status` for recovery.".into()); }
    println!("{}", serde_json::to_string(&entry)?);
    eprintln!("{} for {} local Safes.", label(entry.outcome), entry.members.len());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> { values.iter().map(|value| value.to_string()).collect() }

    #[test]
    fn preview_and_review_binding_have_distinct_non_bypass_forms() {
        assert!(matches!(options(&arguments(&["preview", "GB", "--json"])).unwrap(), Options::Preview("GB")));
        let sha = "a".repeat(64);
        let args = arguments(&["GB", "--confirmed-plan", &sha]);
        assert!(matches!(options(&args).unwrap(), Options::Change { safe: "GB", confirmed: Some(value) } if value == sha));
        for values in [vec!["preview", "GB"], vec!["GB", "--yes"], vec!["GB", "--confirmed-plan", "invalid"], vec!["preview", "GB", "--json", "--yes"], vec!["recover", "wrong-id", "--complete"]] {
            assert!(options(&arguments(&values)).is_err());
        }
    }
}
