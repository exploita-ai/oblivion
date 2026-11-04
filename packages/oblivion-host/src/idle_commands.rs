use oblivion_host::{autolock, control};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct View {
    #[serde(flatten)]
    timers: autolock::Status,
    storage: Storage,
    writable: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Storage { Defaults, SavedEncrypted, RamOnly }

pub fn run(args: &[String]) -> control::Result<i32> {
    if args.first().map(String::as_str) != Some("idle") {
        return Err("Use oblivion settings idle [--safe-minutes N] [--host-minutes N] [--json]".into());
    }
    let mut safe = None;
    let mut host = None;
    let mut json_output = false;
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe-minutes" if safe.is_none() => safe = Some(values.next().ok_or("Missing Safe idle minutes")?.parse::<u16>()?),
            "--host-minutes" if host.is_none() => host = Some(values.next().ok_or("Missing host idle minutes")?.parse::<u16>()?),
            "--json" if !json_output => json_output = true,
            _ => return Err("Unknown or duplicate automatic-lock option".into()),
        }
    }
    let current = read()?;
    if safe.is_some() || host.is_some() {
        let preferences = autolock::Preferences {
            version: 1, safe_minutes: safe.unwrap_or(current.timers.preferences.safe_minutes),
            host_minutes: host.unwrap_or(current.timers.preferences.host_minutes),
        };
        preferences.validate()?;
        control::request("idle-settings", None, &serde_json::to_vec(&preferences)?)?;
    }
    let current = if safe.is_some() || host.is_some() { read()? } else { current };
    if json_output { println!("{}", serde_json::to_string(&current)?); return Ok(0) }
    let minutes = |value| if value == 0 { "Disabled".to_owned() } else { format!("{value} minutes") };
    println!("Safe idle lock: {}", minutes(current.timers.preferences.safe_minutes));
    println!("Oblivion idle lock: {}", minutes(current.timers.preferences.host_minutes));
    println!("Preferences: {}", match current.storage { Storage::Defaults => "Defaults", Storage::SavedEncrypted => "Saved encrypted", Storage::RamOnly => "RAM only" });
    println!("Only human input keeps work open. Automatic locks stop agents and lock encrypted volumes.");
    Ok(0)
}

fn read() -> control::Result<View> {
    #[derive(Deserialize)]
    struct Current { idle_lock: View }
    Ok(serde_json::from_str::<Current>(&control::request("status", None, &[])?)?.idle_lock)
}
