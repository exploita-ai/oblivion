use oblivion_host::{control, egress, scope};
use oblivion_transport::Transport;
use serde_json::json;
use zeroize::Zeroizing;

pub fn run(args: &[String]) -> control::Result<i32> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("Choose network status or network set")?;
    if !matches!(action, "status" | "set") {
        return Err("Choose network status or network set".into());
    }
    let mut safe = None;
    let mut transport = None;
    let mut proxy_profile = None;
    let mut policy = None;
    let mut json_output = false;
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                safe = Some(values.next().ok_or("Missing Safe name")?);
            }
            "--json" => json_output = true,
            "--tor" => {
                if transport.is_some() || proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                transport = Some(Transport::Tor {});
            }
            "--proxy" | "-x" => {
                if transport.is_some() || proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                transport = Some(super::proxy(values.next().ok_or("Missing proxy URL")?)?);
            }
            "--proxy-profile" => {
                if transport.is_some() || proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                let name = values.next().ok_or("Missing proxy profile name")?;
                oblivion_host::proxy_profiles::valid_name(name)?;
                proxy_profile = Some(name.clone());
            }
            "--policy" => {
                if policy.is_some() {
                    return Err("Duplicate --policy".into());
                }
                policy = Some(match values.next().map(String::as_str) {
                    Some("open-internet") => "open",
                    Some("strict") => "strict",
                    Some("offline") => "offline",
                    _ => return Err("Policy must be open-internet, strict or offline".into()),
                });
            }
            _ => return Err("Unknown network option".into()),
        }
    }
    let state = super::status()?;
    if !state.app_open {
        return Err("Unlock Oblivion before selecting a Safe".into());
    }
    let id = super::find_safe(&state, safe.ok_or("Choose a Safe with --safe NAME")?)?
        .ok_or("Safe not found")?;
    let opened = state
        .open_sessions
        .iter()
        .find(|opened| opened.id.as_deref() == Some(&id))
        .ok_or("Open the Safe offline before changing its network")?;
    scope::within(opened.slot, || {
        if action == "set" {
            if [
                transport.is_some(),
                proxy_profile.is_some(),
                policy.is_some(),
            ]
            .into_iter()
            .filter(|selected| *selected)
            .count()
                != 1
            {
                return Err("Choose either a transport or a policy for this change".into());
            }
            if let Some(transport) = transport {
                eprintln!(
                    "Changing transport for Safe {}. Its active network requests will be interrupted.",
                    &id[..8]
                );
                let command = if state.app_mode != super::AppMode::Persistent {
                    egress::Command::Select { transport }
                } else {
                    egress::Command::Save { transport }
                };
                control::request_for(
                    &id,
                    "egress",
                    None,
                    &Zeroizing::new(serde_json::to_vec(&command)?),
                )?;
            }
            if let Some(name) = proxy_profile {
                eprintln!(
                    "Changing transport for Safe {}. Its active network requests will be interrupted.",
                    &id[..8]
                );
                control::request_for(
                    &id,
                    "proxy-profiles",
                    None,
                    &serde_json::to_vec(&oblivion_host::proxy_profiles::Command::Select { name })?,
                )?;
            }
            if let Some(policy) = policy {
                control::request_for(
                    &id,
                    "safe-access",
                    None,
                    &serde_json::to_vec(
                        &json!({"mode":policy,"save":state.app_mode == super::AppMode::Persistent}),
                    )?,
                )?;
            }
        } else if transport.is_some() || proxy_profile.is_some() || policy.is_some() {
            return Err("Use network set to change the selected transport or policy".into());
        }
        let output = control::request_for(&id, "status", None, &[])?;
        if json_output {
            println!("{output}");
        } else {
            let state: serde_json::Value = serde_json::from_str(&output)?;
            let network = &state["network_status"];
            let label = network["label"].as_str().unwrap_or("STATUS UNKNOWN");
            let mode = state["safe_access"]["current"]
                .as_str()
                .unwrap_or("unknown");
            println!(
                "{label} · {}",
                if mode == "open" {
                    "open-internet"
                } else {
                    mode
                }
            );
        }
        Ok(0)
    })
}
