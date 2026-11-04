use oblivion_host::{control, safe_access, scope};
use oblivion_transport::policy::Access;

pub fn run(args: &[String]) -> control::Result<i32> {
    let (name, policy) = options(args)?;
    if unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        return Err("Workspace requires an interactive terminal".into());
    }
    if !super::status()?.app_open {
        super::unlock(false)?;
    }
    let state = super::status()?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    let id = state.find_safe(name)?.ok_or("Safe not found")?;
    let active = state
        .open_sessions
        .iter()
        .find(|safe| safe.id.as_deref() == Some(&id));
    let slot = active
        .map(|safe| safe.slot)
        .map(Ok)
        .unwrap_or_else(|| super::free_slot(&state))?;
    scope::within(slot, || {
        if active.is_none() {
            super::open_existing(&state, &id)?;
        }
        let result = (|| {
            if let Some(mode) = policy {
                control::request_for(
                    &id,
                    "safe-access",
                    None,
                    &serde_json::to_vec(&safe_access::Command {
                        mode,
                        save: state.app_mode == super::AppMode::Persistent,
                    })?,
                )?;
            }
            super::start_agent(&id)?;
            super::attach_workspace(&id)
        })();
        if result.is_err() {
            if let Err(error) = control::request_for(&id, "close-idle", None, &[]) {
                if error.to_string() != "session_changed" {
                    return Err(error);
                }
            }
        }
        result
    })
}

fn options(args: &[String]) -> control::Result<(&str, Option<Access>)> {
    let mut safe = None;
    let mut policy = None;
    let mut args = args.iter();
    while let Some(value) = args.next() {
        match value.as_str() {
            "--safe" if safe.is_none() => {
                safe = Some(args.next().ok_or("Missing Safe name")?.as_str())
            }
            "--policy" if policy.is_none() => {
                policy = Some(match args.next().map(String::as_str) {
                    Some("open-internet") => Access::Open,
                    Some("strict") => Access::Strict,
                    Some("offline") => Access::Offline,
                    _ => return Err("Policy must be open-internet, strict or offline".into()),
                })
            }
            _ => {
                return Err(
                    "Use oblivion shell --safe SAFE [--policy open-internet|strict|offline]".into(),
                );
            }
        }
    }
    Ok((
        safe.ok_or("Choose an existing Safe with --safe NAME")?,
        policy,
    ))
}

#[cfg(test)]
mod tests {
    use super::options;
    use oblivion_transport::policy::Access;

    #[test]
    fn workspace_requires_an_explicit_existing_safe_and_only_safe_wide_policy() {
        let args = ["--safe", "GB", "--policy", "offline"].map(String::from);
        let (safe, mode) = options(&args).unwrap();
        assert_eq!(safe, "GB");
        assert_eq!(mode, Some(Access::Offline));
        for args in [
            vec![],
            vec!["codex"],
            vec!["--safe", "GB", "/bin/sh"],
            vec!["--safe", "GB", "--safe", "other"],
            vec!["--safe", "GB", "--policy", "direct"],
        ] {
            assert!(options(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
    }
}
