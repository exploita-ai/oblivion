//! The tmux Workspace uses the same Safe opening and protected startup as agents.
use crate::controller::{self, AppMode, Call, Result};
use crate::run;
use oblivion_transport::policy::{Access, Command};
use oblivion_wire::control::Operation;

#[derive(Debug, Eq, PartialEq)]
pub struct Options {
    pub safe: String,
    pub policy: Option<Access>,
}

pub fn parse(args: &[String]) -> Result<Options> {
    let mut safe = None;
    let mut policy = None;
    let mut args = args.iter();
    while let Some(value) = args.next() {
        match value.as_str() {
            "--safe" if safe.is_none() => {
                safe = Some(args.next().ok_or("Missing Safe name")?.clone());
            }
            "--policy" if policy.is_none() => {
                policy = Some(match args.next().map(String::as_str) {
                    Some("open-internet") => Access::Open,
                    Some("strict") => Access::Strict,
                    Some("offline") => Access::Offline,
                    _ => return Err("Policy must be open-internet, strict or offline".into()),
                });
            }
            _ => {
                return Err(
                    "Use oblivion shell --safe SAFE [--policy open-internet|strict|offline]".into(),
                );
            }
        }
    }
    Ok(Options {
        safe: safe.ok_or("Choose an existing Safe with --safe NAME")?,
        policy,
    })
}

/// The platform supplies the terminal fact before prompting or opening storage.
/// Pipe commands remain supported by `run`, but cannot attach a tmux Workspace.
pub fn execute<R: run::Runtime>(
    runtime: &mut R,
    options: Options,
    interactive: bool,
) -> Result<i32> {
    if !interactive {
        return Err("Workspace requires an interactive terminal".into());
    }
    if !controller::status(runtime)?.app_open {
        run::unlock(runtime, false)?;
    }
    let state = controller::status(runtime)?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    let id = state.find_safe(&options.safe)?.ok_or("Safe not found")?;
    let active = state
        .open_sessions
        .iter()
        .find(|safe| safe.id.as_deref() == Some(&id));
    let slot = match active {
        Some(safe) => safe.slot,
        None => run::free_slot(runtime, &state)?,
    };
    if active.is_none() {
        run::open_existing(runtime, &state, slot, &id)?;
    }
    let result = (|| {
        if let Some(mode) = options.policy {
            runtime.request(Call {
                operation: Operation::SafeAccess,
                slot: Some(slot),
                session: None,
                expected_session: Some(&id),
                secret: &serde_json::to_vec(&Command {
                    mode,
                    save: state.app_mode == AppMode::Persistent,
                })?,
            })?;
        }
        run::start_agent(runtime, slot, &id)?;
        runtime.attach_workspace(slot, &id)
    })();
    run::cleanup(runtime, slot, &id, result)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use oblivion_transport::policy::Access;

    #[test]
    fn workspace_requires_an_existing_safe_and_accepts_only_safe_wide_policy() {
        let args = ["--safe", "GB", "--policy", "offline"].map(String::from);
        let options = parse(&args).unwrap();
        assert_eq!(options.safe, "GB");
        assert_eq!(options.policy, Some(Access::Offline));
        assert_eq!(parse(&["--safe".into(), "GB".into()]).unwrap().policy, None);
        for args in [
            vec![],
            vec!["codex"],
            vec!["--safe", "GB", "/bin/sh"],
            vec!["--safe", "GB", "--safe", "other"],
            vec!["--safe", "GB", "--policy", "direct"],
            vec!["--safe", "GB", "--policy", "offline", "--policy", "strict"],
        ] {
            assert!(parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
    }
}
