use oblivion_host::{control, scope};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::{Limits, MAX_DOCUMENT_BYTES, MAX_ENTRIES, stream};
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

pub fn run(args: &[String]) -> control::Result<i32> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("Choose files import or files export")?;
    if !matches!(operation, "import" | "export" | "list") {
        return Err("Choose files import or files export".into());
    }
    let mut safe = None;
    let mut name = None;
    let mut paths = vec![];
    let mut cursor = None;
    let mut json_output = false;
    let mut options = args.iter().skip(1);
    while let Some(value) = options.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                safe = Some(options.next().ok_or("Missing Safe name")?);
            }
            "--cursor" => {
                cursor = Some(options.next().ok_or("Missing directory cursor")?.clone());
            }
            "--json" => json_output = true,
            "--name" => {
                if name.is_some() {
                    return Err("Duplicate --name".into());
                }
                name = Some(options.next().ok_or("Missing destination name")?);
            }
            value if value.starts_with('-') => return Err("Unknown file option".into()),
            _ => paths.push(value),
        }
    }
    if (operation == "list" && paths.len() > 1)
        || (operation != "list" && paths.len() != if operation == "import" { 1 } else { 2 })
    {
        return Err("Use files import --safe SAFE SOURCE, or files export --safe SAFE workspace/PATH DESTINATION".into());
    }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    let state = super::status()?;
    let id = super::find_safe(&state, safe)?.ok_or("Safe not found")?;
    let opened = state
        .open_sessions
        .iter()
        .find(|opened| opened.id.as_deref() == Some(&id))
        .ok_or("Open the Safe before copying files")?;
    if operation == "list" {
        if name.is_some() {
            return Err("--name applies to copying files".into());
        }
        let request = oblivion_transfer::browser::Request {
            path: paths
                .first()
                .map(|value| (*value).clone())
                .unwrap_or_default(),
            after: cursor,
            limit: 100,
        };
        request.validate()?;
        let output = scope::within(opened.slot, || {
            control::request_for(&id, "browse", None, &serde_json::to_vec(&request)?)
        })?;
        let reply: oblivion_transfer::browser::Response = serde_json::from_str(&output)?;
        let oblivion_transfer::browser::Response::Page(page) = reply else {
            return Err("Directory unavailable".into());
        };
        page.validate(&request)?;
        if json_output {
            let entries = page.entries.iter().map(|entry| json!({
                "name":entry.name,"path":if page.path.is_empty() { entry.name.clone() } else { format!("{}/{}",page.path,entry.name) },
                "kind":if entry.directory { "directory" } else { "file" },"bytes":entry.bytes
            })).collect::<Vec<_>>();
            println!(
                "{}",
                json!({"path":page.path,"entries":entries,"next_cursor":page.next,"skipped":page.skipped})
            );
        } else {
            for entry in page.entries {
                println!(
                    "{}{}\t{}",
                    entry.name,
                    if entry.directory { "/" } else { "" },
                    entry.bytes
                );
            }
        }
        return Ok(0);
    }
    if cursor.is_some() {
        return Err("--cursor applies to directory listing".into());
    }
    let destination_name = name
        .map(String::as_str)
        .or_else(|| {
            Path::new(paths[0])
                .file_name()
                .and_then(|name| name.to_str())
        })
        .ok_or("Choose a destination name with --name")?;
    if destination_name.is_empty()
        || destination_name.contains(['/', '\\', '\0'])
        || matches!(destination_name, "." | "..")
    {
        return Err("Destination name must be one file or directory name".into());
    }
    // Resolve local selections before obtaining a guest capability. Nothing
    // inside the Safe can nominate or enumerate a desktop source directory.
    let source = if operation == "import" {
        Some(std::path::absolute(paths[0])?)
    } else {
        None
    };
    let destination = if operation == "export" {
        Some(Path::new(paths[1]).canonicalize()?)
    } else {
        None
    };
    let export = if operation == "export" {
        let (root, selected) = paths[0]
            .split_once('/')
            .ok_or("Export a path under workspace/ or imports/")?;
        if !matches!(root, "workspace" | "imports") || selected.is_empty() {
            return Err("Export a path under workspace/ or imports/".into());
        }
        Some((root, selected))
    } else {
        None
    };
    scope::within(opened.slot, || {
        let (mut connection, lease, client) = control::attach_client("file-attach", &id)?;
        let result = (|| -> control::Result<_> {
            let request = match export {
                Some((root, _)) => json!({"operation":"export","root":root}),
                None => json!({"operation":"import","name":destination_name}),
            };
            let request = serde_json::to_vec(&request)?;
            connection.write_all(&(request.len() as u32).to_be_bytes())?;
            connection.write_all(&request)?;
            let mut channel = Channel::new(
                File::from(OwnedFd::from(connection)),
                Duration::from_secs(3600),
            )?;
            let limits = Limits {
                entries: MAX_ENTRIES,
                bytes: MAX_DOCUMENT_BYTES,
            };
            let mut random = [0; 16];
            File::open("/dev/urandom")?.read_exact(&mut random)?;
            let transfer = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let receipt = if let Some(source) = source {
                eprintln!("Importing into Safe {safe}/workspace/{destination_name}");
                stream::send_path(&mut channel, &source, limits, &transfer)?
            } else {
                let destination = destination.as_deref().ok_or("Missing export directory")?;
                let inbox = destination.join(".oblivion-transfers");
                if !inbox.exists() {
                    std::fs::DirBuilder::new().create(&inbox)?;
                    std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700))?;
                }
                let metadata = std::fs::symlink_metadata(&inbox)?;
                if !metadata.is_dir()
                    || metadata.uid() != unsafe { libc::getuid() }
                    || metadata.mode() & 0o077 != 0
                {
                    return Err("Export staging must be a private directory".into());
                }
                eprintln!(
                    "Exporting from Safe {safe} into {}",
                    destination.join(destination_name).display()
                );
                stream::download(
                    &mut channel,
                    export.ok_or("Missing export selection")?.1,
                    &inbox,
                    destination,
                    destination_name,
                    limits,
                    &transfer,
                )?
            };
            Ok(receipt)
        })();
        let released = control::release_agent(&client, &id);
        drop(lease);
        released?;
        println!("{}", serde_json::to_string(&result?)?);
        Ok(0)
    })
}
