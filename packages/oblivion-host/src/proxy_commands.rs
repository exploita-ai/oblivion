use oblivion_host::{control, proxy_profiles};
use zeroize::Zeroizing;

pub fn run(args: &[String]) -> control::Result<i32> {
    let command = match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 || args.len() == 2 && args[1] == "--json" => {
            proxy_profiles::Command::List {}
        }
        Some("remove") if args.len() == 2 => {
            proxy_profiles::valid_name(&args[1])?;
            proxy_profiles::Command::Remove {
                name: args[1].clone(),
            }
        }
        Some("add")
            if args.len() == 2
                || args.len() == 4 && matches!(args[2].as_str(), "--proxy" | "-x") =>
        {
            proxy_profiles::valid_name(&args[1])?;
            let entered;
            let url = if args.len() == 4 {
                args[3].as_str()
            } else {
                entered = Zeroizing::new(String::from_utf8(
                    super::password("SOCKS5 URL (hidden)", false)?.to_vec(),
                )?);
                entered.as_str()
            };
            proxy_profiles::Command::Add {
                name: args[1].clone(),
                transport: super::proxy(url)?,
            }
        }
        _ => {
            return Err(
                "Use proxy list [--json], proxy add NAME [-x URL], or proxy remove NAME".into(),
            );
        }
    };
    let output = control::request(
        "proxy-profiles",
        None,
        &Zeroizing::new(serde_json::to_vec(&command)?),
    )?;
    match command {
        proxy_profiles::Command::List {} => {
            // Decode into public metadata rather than printing raw controller
            // output: credentials cannot enter the desktop listing contract.
            let profiles: proxy_profiles::Status = serde_json::from_str(&output)?;
            if args.len() == 2 {
                println!("{}", serde_json::to_string(&profiles)?);
            } else {
                for profile in profiles.entries {
                    let oblivion_transport::Metadata::Socks5 {
                        endpoint,
                        authenticated,
                    } = profile.transport
                    else {
                        continue;
                    };
                    println!(
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
                    );
                }
            }
        }
        proxy_profiles::Command::Add { .. } => {
            eprintln!("Proxy profile added. Active Safes keep their current transport.")
        }
        proxy_profiles::Command::Remove { .. } => {
            eprintln!("Proxy profile removed. Active Safes keep their current transport.")
        }
        proxy_profiles::Command::Select { .. } => unreachable!(),
    }
    Ok(0)
}
