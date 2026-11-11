//! Shared Files copy syntax. This module performs no filesystem, terminal or
//! controller I/O; native endpoints own path resolution, preparation and copy.
use crate::controller::Result;
use oblivion_transfer::selection;
use oblivion_wire::control::valid_id;

pub fn parse(args: &[String]) -> Result<CopyCommand> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("Choose files import or export")?;
    if !matches!(operation, "import" | "export") {
        return Err("Choose files import or export".into());
    }
    let mut safe = None;
    let mut name = None;
    let mut paths = vec![];
    let mut sources = vec![];
    let mut selected = vec![];
    let mut operation_id = None;
    let mut expected_opening = None;
    let mut destination = None;
    let mut device = None;
    let mut events_output = false;
    let mut confirmed = false;
    let mut options = args.iter().skip(1);
    while let Some(value) = options.next() {
        match value.as_str() {
            "--safe" => {
                if safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                safe = Some(options.next().ok_or("Missing Safe name")?.clone());
            }
            "--json" => {}
            "--events" => events_output = true,
            "--yes" => confirmed = true,
            "--operation" => {
                if operation_id.is_some() {
                    return Err("Duplicate --operation".into());
                }
                operation_id = Some(options.next().ok_or("Missing operation ID")?.clone());
            }
            "--opening" => {
                if expected_opening.is_some() {
                    return Err("Duplicate --opening".into());
                }
                expected_opening = Some(options.next().ok_or("Missing opening nonce")?.clone());
            }
            "--destination" => {
                if destination.is_some() {
                    return Err("Duplicate --destination".into());
                }
                destination = Some(
                    options
                        .next()
                        .ok_or("Missing destination directory")?
                        .clone(),
                );
            }
            "--source" => sources.push(options.next().ok_or("Missing source path")?.clone()),
            "--usb" if device.is_none() => {
                device = Some(options.next().ok_or("Missing USB device ID")?.clone());
            }
            "--path" => selected.push(options.next().ok_or("Missing Safe path")?.clone()),
            "--name" => {
                if name.is_some() {
                    return Err("Duplicate --name".into());
                }
                name = Some(options.next().ok_or("Missing destination name")?.clone());
            }
            "--limit" => return Err("--limit applies only to files transfers".into()),
            "--cursor" => {
                return Err("--cursor applies to directory listing or files transfers".into());
            }
            value if value.starts_with('-') => return Err("Unknown file option".into()),
            _ => paths.push(value),
        }
    }
    if events_output && confirmed {
        return Err(
            "Event copies require their reviewed approval; --yes cannot be combined with --events"
                .into(),
        );
    }
    let usb_export = operation == "export" && device.is_some();
    if operation == "import"
        && (!paths.is_empty()
            || sources.is_empty()
            || !selected.is_empty()
            || destination.is_some())
        || operation == "export"
            && (!paths.is_empty()
                || selected.is_empty()
                || !sources.is_empty()
                || device.is_some() == destination.is_some())
    {
        return Err("Use files import --safe SAFE --source PATH, or files export --safe SAFE --path workspace/PATH with either --destination DIRECTORY or --usb ID".into());
    }
    if usb_export && (confirmed || name.is_some()) {
        return Err("USB export requires manifest approval and uses its own operation folder. Omit --yes and --name.".into());
    }
    for value in operation_id.iter().chain(expected_opening.iter()) {
        if !valid_id(value) {
            return Err("Invalid operation or opening ID".into());
        }
    }
    let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
    let paths = if operation == "import" {
        &sources
    } else {
        &selected
    };
    if paths.len() > selection::MAX_SELECTIONS {
        return Err("selection_limit".into());
    }
    if paths.iter().map(String::len).sum::<usize>() > selection::MAX_SELECTION_BYTES {
        return Err("selection_byte_limit".into());
    }
    if paths.len() > 1 && name.is_none() && !usb_export {
        return Err("Choose a collection name with --name when selecting multiple paths".into());
    }
    if let Some(name) = &name {
        oblivion_transfer::native_files::validate_name(name)
            .map_err(|_| "Choose a valid destination name with --name")?;
    }
    let selection = if operation == "import" {
        match device {
            Some(device) => {
                validate_device(&device)?;
                for path in &sources {
                    if path.is_empty() {
                        return Err("Choose a relative file or folder on the USB".into());
                    }
                    oblivion_transfer::browser::Request {
                        path: path.clone(),
                        after: None,
                        limit: 1,
                    }
                    .validate()?;
                }
                CopyInput::MediaImport { device, sources }
            }
            None => CopyInput::Upload(sources),
        }
    } else {
        // Shared selections also admit absolute host sources. Safe exports
        // accept only logical paths within their two public roots.
        if selected
            .iter()
            .any(|path| !matches!(path.split('/').next(), Some("workspace" | "imports")))
        {
            return Err("Export paths must be under workspace or imports".into());
        }
        selection::validate_paths(&selected)?;
        match device {
            Some(device) => {
                validate_device(&device)?;
                CopyInput::MediaExport { device, selected }
            }
            None => CopyInput::Download {
                selected,
                destination: destination.ok_or("Missing destination directory")?,
            },
        }
    };
    Ok(CopyCommand {
        safe,
        name,
        selection,
        operation_id,
        expected_opening,
        events_output,
        confirmed,
    })
}

/// The shared syntax is admitted before runtime startup. Local paths remain
/// literal native strings; filesystem resolution and authorization stay native.
pub struct CopyCommand {
    pub safe: String,
    pub name: Option<String>,
    pub selection: CopyInput,
    pub operation_id: Option<String>,
    pub expected_opening: Option<String>,
    pub events_output: bool,
    pub confirmed: bool,
}

impl CopyCommand {
    pub fn needs_live_media(&self) -> bool {
        matches!(&self.selection, CopyInput::MediaImport { .. } | CopyInput::MediaExport { .. })
    }
}

pub struct MediaBrowse {
    pub safe: String,
    pub device: String,
    pub opening: String,
}

impl MediaBrowse {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut safe = None;
        let mut device = None;
        let mut opening = None;
        let mut args = args.iter();
        while let Some(key) = args.next() {
            let target = match key.as_str() {
                "--safe" => &mut safe,
                "--usb" => &mut device,
                "--opening" => &mut opening,
                _ => return Err("Unknown USB browser option".into()),
            };
            if target.is_some() {
                return Err("Duplicate USB browser option".into());
            }
            *target = Some(args.next().ok_or("Missing USB browser value")?.clone());
        }
        let safe = safe.ok_or("Choose a Safe with --safe NAME")?;
        oblivion_wire::session_title::validate(&safe)?;
        let device = device.ok_or("Choose a USB device with --usb ID")?;
        validate_device(&device)?;
        let opening = opening.filter(|value| valid_id(value)).ok_or("Invalid opening ID")?;
        Ok(Self { safe, device, opening })
    }
}

fn validate_device(device: &str) -> Result<()> {
    if !oblivion_wire::live_media::valid_device_id(device) {
        return Err("Invalid USB device ID".into());
    }
    Ok(())
}

pub enum CopyInput {
    Upload(Vec<String>),
    MediaImport { device: String, sources: Vec<String> },
    MediaExport { device: String, selected: Vec<String> },
    Download {
        selected: Vec<String>,
        destination: String,
    },
}
