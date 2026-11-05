use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
mod runtime;

fn main() {
    if execute().is_err() {
        eprintln!("transfer_failed");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), Box<dyn std::error::Error>> {
    runtime::harden()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [role, root, budget, mode] = args.as_slice() {
        if role == "live-media-export" && Path::new(root).is_absolute() {
            let budget = budget.parse::<u64>()?;
            if !(1..=3_600_000).contains(&budget) {
                return Err("invalid_deadline".into());
            }
            let mode = match mode.as_str() {
                "posix" => oblivion_transfer::ExportMode::Posix,
                "fat32" => oblivion_transfer::ExportMode::Fat32,
                "exfat" => oblivion_transfer::ExportMode::Portable,
                _ => return Err("invalid_export_mode".into()),
            };
            let mut channel = Channel::new(runtime::inherited(3)?, Duration::from_millis(budget))?;
            channel.watch(runtime::inherited(4)?.into());
            endpoint::export_live_media(&mut channel, Path::new(root), mode)?;
            return Ok(());
        }
    }
    if args.first().is_some_and(|role| role == "native-files") {
        if args.len() != 4 || !Path::new(&args[1]).is_absolute() || !Path::new(&args[2]).is_absolute() { return Err("invalid_arguments".into()); }
        let budget: u64 = args[3].parse()?;
        if !(1..=3_600_000).contains(&budget) { return Err("invalid_deadline".into()); }
        let mut input = Vec::new(); std::io::stdin().take(4097).read_to_end(&mut input)?;
        if input.len() > 4096 { return Err("invalid_file_request".into()); }
        let request = serde_json::from_slice(&input)?;
        let mut channel = Channel::new(runtime::inherited(3)?, Duration::from_millis(budget))?;
        oblivion_transfer::stream::operations::serve(&mut channel, Path::new(&args[1]), Path::new(&args[2]), request)?;
        return Ok(());
    }
    if args.first().is_some_and(|role| matches!(role.as_str(), "share-send" | "share-receive")) {
        let send = args[0] == "share-send";
        if args.len() != if send { 3 } else { 4 } { return Err("invalid_arguments".into()); }
        let budget = args.last().ok_or("invalid_arguments")?.parse::<u64>()?;
        if !(1..=3_600_000).contains(&budget) { return Err("invalid_deadline".into()); }
        let mut channel = Channel::new(runtime::inherited(3)?, Duration::from_millis(budget))?;
        let receipt = if send {
            oblivion_transfer::share::send(&mut channel, Path::new(&args[1]), runtime::inherited(4)?)?
        } else {
            oblivion_transfer::share::receive(&mut channel, Path::new(&args[1]), &args[2])?
        };
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|role| matches!(role.as_str(), "send-open-file" | "receive-open-file"))
    {
        if args.len() != 3 {
            return Err("invalid_arguments".into());
        }
        let maximum: u64 = args[1].parse()?;
        let budget: u64 = args[2].parse()?;
        if !(1..=3_600_000).contains(&budget) {
            return Err("invalid_deadline".into());
        }
        let mut channel = Channel::new(runtime::inherited(3)?, Duration::from_millis(budget))?;
        if args[0] == "send-open-file" {
            endpoint::send_open_file(&mut channel, runtime::inherited(4)?, maximum)?;
        } else {
            endpoint::receive_open_file(&mut channel, runtime::inherited(4)?, maximum)?;
        }
        // The relay watches this process's pidfd. Stay alive after the final
        // data acknowledgement until the controller has released the exchange.
        let mut released = [0; 9];
        channel.read_exact(&mut released)?;
        if &released != b"released\n" {
            return Err("invalid_release".into());
        }
        return Ok(());
    }
    let import = args
        .first()
        .is_some_and(|role| matches!(role.as_str(), "import" | "recover"));
    if args.len() != if import { 4 } else { 3 }
        || !matches!(
            args[0].as_str(),
            "send"
                | "send-encrypted"
                | "receive"
                | "import"
                | "recover"
                | "documents"
                | "media-source"
                | "export"
                | "export-portable"
        )
        || !Path::new(&args[1]).is_absolute()
        || (import && !Path::new(&args[2]).is_absolute())
    {
        return Err("invalid_arguments".into());
    }
    let budget: u64 = args.last().ok_or("invalid_arguments")?.parse()?;
    if !(1..=3_600_000).contains(&budget) {
        return Err("invalid_deadline".into());
    }
    // The launcher hands off an already authorized descriptor, never a socket
    // path or port supplied by the peer. Selected names stay off argv/environment.
    let mut channel = Channel::new(runtime::inherited(3)?, Duration::from_millis(budget))?;
    if args[0] == "send" {
        endpoint::send(&mut channel, Path::new(&args[1]))?;
    }
    if args[0] == "send-encrypted" {
        endpoint::send_encrypted(&mut channel, Path::new(&args[1]))?;
    }
    if args[0] == "receive" {
        endpoint::accept(&mut channel, Path::new(&args[1]))?;
    }
    if args[0] == "documents" {
        endpoint::documents(&mut channel, Path::new(&args[1]))?;
    }
    if args[0] == "media-source" {
        endpoint::media_source(&mut channel, Path::new(&args[1]))?;
    }
    if args[0] == "export" {
        endpoint::export(
            &mut channel,
            Path::new(&args[1]),
            oblivion_transfer::ExportMode::Posix,
        )?;
    }
    if args[0] == "export-portable" {
        endpoint::export(
            &mut channel,
            Path::new(&args[1]),
            oblivion_transfer::ExportMode::Portable,
        )?;
    }
    if args[0] == "import" {
        endpoint::import(&mut channel, Path::new(&args[1]), Path::new(&args[2]))?;
    }
    if args[0] == "recover" {
        endpoint::recover(&mut channel, Path::new(&args[1]), Path::new(&args[2]))?;
    }
    Ok(())
}
