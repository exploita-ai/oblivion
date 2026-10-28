#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod onion_network;
#[cfg(target_os = "linux")]
mod onion_supervisor;
#[cfg(target_os = "linux")]
mod tor;

fn main() {
    #[cfg(target_os = "linux")]
    match onion_supervisor::run() {
        Ok(()) => return,
        Err(error) => {
            // The production unit discards stderr. A lab may expose only
            // these fixed diagnostic codes, never a raw error/request string.
            let code = error.to_string();
            let code = match code.as_str() {
                "tor_service_failed"
                | "tor_stop_failed"
                | "unsupported_tor_version"
                | "unexpected_tor_reply"
                | "unsafe_tor_file"
                | "invalid_tor_cookie"
                | "invalid_tor_peer"
                | "isolation_lost"
                | "network_policy_failed"
                | "firewall_verification_failed"
                | "invalid_tor_state" => code.as_str(),
                _ => "service_failed",
            };
            eprintln!(
                "oblivion-onion-gateway: {code} errno={:?}",
                error.raw_os_error()
            );
        }
    }
    std::process::exit(1);
}
