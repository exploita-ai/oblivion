//! Saved proxy UI. The controller owns credentials; listing exposes metadata.
use crate::controller::{Call, Result};
use crate::{proxy, run};
use oblivion_transport::Metadata;
use oblivion_wire::control::Operation;
use std::io::Write;
use zeroize::Zeroizing;

// An explicitly supplied proxy URL may carry credentials: no Debug.
pub struct Command {
    action: Action,
}
enum Action {
    List {
        json: bool,
    },
    Add {
        name: String,
        proxy: Option<proxy::Request>,
    },
    Remove {
        name: String,
    },
}

pub fn parse(args: &[String]) -> std::result::Result<Command, &'static str> {
    let action = match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 || args.len() == 2 && args[1] == "--json" => Action::List {
            json: args.len() == 2,
        },
        Some("remove") if args.len() == 2 => {
            oblivion_transport::proxy_profiles::valid_name(&args[1])?;
            Action::Remove {
                name: args[1].clone(),
            }
        }
        Some("add")
            if args.len() == 2
                || args.len() == 4 && matches!(args[2].as_str(), "--proxy" | "-x") =>
        {
            oblivion_transport::proxy_profiles::valid_name(&args[1])?;
            Action::Add {
                name: args[1].clone(),
                proxy: if args.len() == 4 {
                    Some(proxy::parse(&args[3])?)
                } else {
                    None
                },
            }
        }
        _ => {
            return Err(
                "Use proxy list [--json], proxy add NAME [-x ENDPOINT], or proxy remove NAME",
            );
        }
    };
    Ok(Command { action })
}

pub fn execute<R: run::Runtime>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    let json = matches!(&command.action, Action::List { json: true });
    let change = match command.action {
        Action::List { .. } => oblivion_transport::proxy_profiles::Command::List {},
        Action::Remove { name } => oblivion_transport::proxy_profiles::Command::Remove { name },
        Action::Add { name, proxy } => oblivion_transport::proxy_profiles::Command::Add {
            name,
            transport: match proxy {
                Some(request) => proxy::complete(request, runtime)?,
                None => proxy::read_hidden(runtime)?,
            },
        },
    };
    let response = runtime.request(Call {
        operation: Operation::ProxyProfiles,
        slot: None,
        session: None,
        expected_session: None,
        secret: &Zeroizing::new(serde_json::to_vec(&change)?),
    })?;
    match change {
        oblivion_transport::proxy_profiles::Command::List {} => {
            let status = oblivion_transport::proxy_profiles::Status::decode(response.as_bytes())?;
            if json {
                writeln!(output, "{}", serde_json::to_string(&status)?)?;
                return Ok(0);
            }
            for profile in status.entries {
                if let Metadata::Socks5 {
                    endpoint,
                    authenticated,
                } = profile.transport
                {
                    writeln!(
                        output,
                        "{}\t{}\t{}\t{}",
                        profile.name,
                        endpoint,
                        if authenticated {
                            "Authenticated"
                        } else {
                            "No authentication"
                        },
                        if profile.temporary {
                            "RAM only"
                        } else {
                            "Saved encrypted"
                        }
                    )?;
                }
            }
        }
        oblivion_transport::proxy_profiles::Command::Add { .. } => {
            writeln!(
                diagnostics,
                "Proxy profile added. Active Safes keep their current transport."
            )?;
        }
        oblivion_transport::proxy_profiles::Command::Remove { .. } => {
            writeln!(
                diagnostics,
                "Proxy profile removed. Active Safes keep their current transport."
            )?;
        }
        oblivion_transport::proxy_profiles::Command::Select { .. } => unreachable!(),
    }
    Ok(0)
}
