use oblivion_host::{control, scope};
use serde_json::json;

pub fn run(args: &[String]) -> control::Result<i32> {
    if args.first().is_some_and(|action| action == "task") {
        return super::child_task_commands::run(&args[1..]);
    }
    if args.len() < 2 {
        return Err("Use safe open NAME, safe rename NAME NEW_NAME or safe grow NAME MIB".into());
    }
    if !super::status()?.app_open { super::unlock(false)?; }
    let state = super::status()?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    let id = super::find_safe(&state, &args[1])?.ok_or("Safe not found")?;
    let active = state
        .open_sessions
        .iter()
        .find(|safe| safe.id.as_deref() == Some(&id));
    let slot = active
        .map(|safe| safe.slot)
        .map(Ok)
        .unwrap_or_else(|| super::free_slot(&state))?;
    scope::within(slot, || {
        match args[0].as_str() {
            "open" if args.len() == 2 => {
                if active.is_none() {
                    super::open_existing(&state, &id)?;
                }
                // An explicitly opened offline workspace belongs to the user
                // until Close, Lock, or its inactivity policy releases it.
                control::request_for(&id, "pin-safe", None, &[])?;
                eprintln!("Safe {} opened for files and offline work", &id[..8]);
            }
            "rename" if args.len() == 3 => {
                oblivion_host::session_title::validate(&args[2])?;
                if super::find_safe(&state, &args[2])?.is_some_and(|other| other != id) {
                    return Err("A Safe with this name already exists".into());
                }
                let payload = serde_json::to_vec(&json!({"id":id,"title":args[2]}))?;
                control::request("rename-session", None, &payload)?;
            }
            "grow" if args.len() == 3 => {
                if state.agent_safes.iter().any(|safe| safe.id == id && safe.ephemeral) {
                    return Err("RAM-only Safe storage cannot be grown. Create a Safe with sufficient capacity.".into());
                }
                if active.is_some() {
                    return Err("Close the Safe before increasing its storage".into());
                }
                let mib: u64 = args[2]
                    .parse()
                    .map_err(|_| "Storage size must be a number in MiB")?;
                let request = oblivion_host::volume::Request::Grow {
                    id,
                    mib,
                    password: zeroize::Zeroizing::new(String::from_utf8(
                        super::password("Safe password", false)?.to_vec(),
                    )?),
                };
                request.validate()?;
                let payload = zeroize::Zeroizing::new(serde_json::to_vec(&request)?);
                control::request("session-storage", None, &payload)?;
                eprintln!("Safe storage increased to {mib} MiB");
            }
            _ => {
                return Err(
                    "Use safe open NAME, safe rename NAME NEW_NAME or safe grow NAME MIB".into(),
                );
            }
        }
        Ok(0)
    })
}
