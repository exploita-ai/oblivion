//! Share syntax is admitted before any native path, password or controller I/O.
use crate::controller::Result;
use std::io;

#[derive(Clone, serde::Serialize)]
pub struct Selection {
    pub paths: Vec<String>,
    pub chat_ids: Option<Vec<String>>,
    pub exclude_paths: Vec<String>,
    pub exclude_chats: Vec<String>,
    pub include_sensitive_paths: Vec<String>,
    pub include_sensitive_chats: Vec<String>,
}

/// Share has one syntax owner. Validation does not open files, prompt for
/// secrets or contact a controller; the native engine consumes the typed action.
pub struct Command(Action);

impl Command {
    pub fn into_action(self) -> Action {
        self.0
    }
}

pub enum Action {
    Export {
        selector: Selector,
        output: String,
        selection: Selection,
    },
    Import {
        file: String,
        settings: bool,
    },
    Imports {
        json: bool,
    },
    Discard {
        transaction: String,
    },
}

pub enum Selector {
    Safe(String),
    Branch(String),
    All { include_settings: bool },
}

pub fn parse(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("import") => {
            let mut file = None;
            let mut settings = false;
            for value in &args[1..] {
                match value.as_str() {
                    "--apply-settings" if !settings => settings = true,
                    value if !value.starts_with('-') && file.is_none() => file = Some(value.to_owned()),
                    _ => return Err("Use share import FILE [--apply-settings]".into()),
                }
            }
            return Ok(Command(Action::Import {
                file: file.ok_or("Choose an encrypted Share file")?, settings,
            }));
        }
        Some("imports") => {
            if args.len() != 1 && args[1..] != ["--json"] {
                return Err("Use share imports [--json]".into());
            }
            return Ok(Command(Action::Imports { json: args.len() == 2 }));
        }
        Some("discard") => {
            if args.len() != 2 {
                return Err("Use share discard TRANSACTION".into());
            }
            oblivion_share::manifest::validate_id(&args[1])?;
            return Ok(Command(Action::Discard { transaction: args[1].clone() }));
        }
        Some("export") => {}
        _ => return Err("Use share export --safe SAFE FILE, share export --branch SAFE FILE, share export --all FILE or share import FILE".into()),
    }
    let mut selector = None;
    let mut output = None;
    let mut include_settings = false;
    let mut selection = Selection {
        paths: vec![],
        chat_ids: None,
        exclude_paths: vec![],
        exclude_chats: vec![],
        include_sensitive_paths: vec![],
        include_sensitive_chats: vec![],
    };
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe" | "--branch" if selector.is_none() => {
                let name = values.next().ok_or("Missing Safe name")?.clone();
                selector = Some(if value == "--safe" {
                    Selector::Safe(name)
                } else {
                    Selector::Branch(name)
                });
            }
            "--all" if selector.is_none() => {
                selector = Some(Selector::All {
                    include_settings: false,
                })
            }
            "--include-settings" if !include_settings => include_settings = true,
            "--path" => selection
                .paths
                .push(values.next().ok_or("Missing guest path")?.clone()),
            "--chat" => selection
                .chat_ids
                .get_or_insert_with(Vec::new)
                .push(values.next().ok_or("Missing chat ID")?.clone()),
            "--no-chats" if selection.chat_ids.is_none() => selection.chat_ids = Some(Vec::new()),
            "--exclude" => selection
                .exclude_paths
                .push(values.next().ok_or("Missing excluded path")?.clone()),
            "--exclude-chat" => selection
                .exclude_chats
                .push(values.next().ok_or("Missing excluded chat ID")?.clone()),
            "--include-sensitive" => selection.include_sensitive_paths.push(
                values
                    .next()
                    .ok_or("Missing reviewed sensitive path")?
                    .clone(),
            ),
            "--include-sensitive-chat" => selection.include_sensitive_chats.push(
                values
                    .next()
                    .ok_or("Missing reviewed sensitive chat ID")?
                    .clone(),
            ),
            value if !value.starts_with('-') && output.is_none() => output = Some(value.to_owned()),
            _ => return Err("Unknown or duplicate Share option".into()),
        }
    }
    let selector = match selector.ok_or("Choose --safe NAME, --branch NAME or --all")? {
        Selector::All { .. } => Selector::All { include_settings },
        _ if include_settings => return Err("--include-settings requires --all".into()),
        selector => selector,
    };
    if !matches!(&selector, Selector::Safe(_))
        && selection
            .chat_ids
            .as_ref()
            .is_some_and(|ids| !ids.is_empty())
    {
        return Err("Use --chat with a single --safe export. --exclude-chat applies to branches and all Safes.".into());
    }
    if selection.paths.is_empty() {
        selection
            .paths
            .extend(["workspace".into(), "imports".into()]);
    }
    for path in selection
        .paths
        .iter()
        .chain(&selection.exclude_paths)
        .chain(&selection.include_sensitive_paths)
    {
        validate_path(path)?;
    }
    for chat in selection
        .chat_ids
        .iter()
        .flatten()
        .chain(&selection.exclude_chats)
        .chain(&selection.include_sensitive_chats)
    {
        validate_chat(chat)?;
    }
    Ok(Command(Action::Export {
        selector,
        output: output.ok_or("Choose an output Share file")?,
        selection,
    }))
}

pub(crate) fn validate_path(value: &str) -> io::Result<()> {
    oblivion_transfer::browser::Request {
        path: value.into(),
        after: None,
        limit: 1,
    }
    .validate()?;
    if !matches!(value.split('/').next(), Some("workspace" | "imports")) {
        return Err(io::Error::other("share_root_not_allowed"));
    }
    Ok(())
}

pub(crate) fn validate_chat(value: &str) -> io::Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(io::Error::other("invalid_portable_chat_identity"));
    }
    Ok(())
}
