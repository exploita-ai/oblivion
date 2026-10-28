//! Disposable real-Tor laboratory, never installed in a production image.
#[cfg(target_os = "linux")]
#[path = "../src/tor.rs"]
mod tor;

#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    use serde::Deserialize;
    use std::io::{self, BufRead, Write};
    use tor::{ClientAuth, OnionController, Tor};

    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
    enum Command {
        Publish { client_auth: ClientAuth },
        Revoke {},
        Drop {},
    }

    let controller = OnionController::new()?;
    println!("{{\"owned\":true,\"bootstrap\":{}}}", Tor.progress()?);
    io::stdout().flush()?;
    let mut input = io::stdin().lock();
    let mut line = String::new();
    input.read_line(&mut line)?;
    let Command::Publish { client_auth } =
        serde_json::from_str(&line).map_err(|_| io::Error::other("invalid_probe_command"))?
    else {
        return Err(io::Error::other("invalid_probe_command"));
    };
    let service = controller.publish(&client_auth)?;
    println!(
        "{}",
        serde_json::json!({"published":true,"id":service.id()})
    );
    io::stdout().flush()?;
    line.clear();
    input.read_line(&mut line)?;
    match serde_json::from_str(&line).map_err(|_| io::Error::other("invalid_probe_command"))? {
        Command::Revoke {} => {
            service.revoke()?;
            println!("{{\"revoked\":true}}");
        }
        Command::Drop {} => {
            drop(service);
            println!("{{\"dropped\":true}}");
        }
        Command::Publish { .. } => return Err(io::Error::other("invalid_probe_command")),
    }
    Ok(())
}

fn main() {
    #[cfg(target_os = "linux")]
    if run().is_ok() {
        return;
    }
    eprintln!("onion-probe: failed");
    std::process::exit(1);
}
