use serde::{Deserialize, Serialize};
use std::io::Read;
use zeroize::Zeroizing;

pub const LIMIT: usize = 256 * 1024;
pub const LEGACY: &str = "00000000000000000000000000000000";

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Temporary {
        name: String,
        key: Zeroizing<String>,
    },
    Add {
        name: String,
        key: Zeroizing<String>,
    },
    Replace {
        id: String,
        key: Zeroizing<String>,
    },
    Rename {
        id: String,
        name: String,
    },
    Remove {
        id: String,
    },
    Default {
        id: String,
    },
    Select {
        id: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub name: String,
    key: Zeroizing<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    version: u8,
    default: Option<String>,
    entries: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub temporary: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub entries: Vec<Info>,
    pub default: Option<String>,
    pub selected: Option<String>,
}

// Keep the two archives separate: there is deliberately no combined encoder.
pub struct Keyring {
    pub saved: Archive,
    pub temporary: Archive,
    pub default: Option<Option<String>>,
}

impl Keyring {
    pub fn new(saved: Archive, temporary: Archive) -> Result<Self, &'static str> {
        if temporary
            .entries
            .iter()
            .any(|entry| saved.key(&entry.id).is_some())
        {
            return Err("key_id_exists");
        }
        Ok(Self {
            saved,
            temporary,
            default: None,
        })
    }

    pub fn key(&self, id: &str) -> Option<&str> {
        self.saved.key(id).or_else(|| self.temporary.key(id))
    }

    pub fn status(&self, selection: Option<Option<String>>) -> Status {
        let mut status = self.saved.status(None);
        status
            .entries
            .extend(self.temporary.entries.iter().map(|entry| Info {
                id: entry.id.clone(),
                name: entry.name.clone(),
                temporary: true,
            }));
        status.default = self
            .default
            .clone()
            .unwrap_or(status.default)
            .filter(|id| self.key(id).is_some());
        status.selected = selection
            .unwrap_or_else(|| status.default.clone())
            .filter(|id| self.key(id).is_some());
        status
    }
}

impl Archive {
    pub fn empty() -> Self {
        Self {
            version: 1,
            default: None,
            entries: Vec::new(),
        }
    }

    pub fn legacy(key: Zeroizing<String>) -> Result<Self, &'static str> {
        valid_key(&key)?;
        Ok(Self {
            version: 1,
            default: Some(LEGACY.to_owned()),
            entries: vec![Entry {
                id: LEGACY.to_owned(),
                name: "Importata".to_owned(),
                key,
            }],
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > LIMIT {
            return Err("key_archive_too_large");
        }
        let archive: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_key_archive")?;
        if archive.version != 1 || archive.entries.len() > 64 {
            return Err("invalid_key_archive");
        }
        let mut ids = std::collections::HashSet::new();
        for entry in &archive.entries {
            if !valid_id(&entry.id) || !ids.insert(&entry.id) {
                return Err("invalid_key_archive");
            }
            valid_name(&entry.name)?;
            valid_key(&entry.key)?;
        }
        if archive
            .default
            .as_ref()
            .is_some_and(|id| archive.key(id).is_none())
        {
            return Err("invalid_key_archive");
        }
        Ok(archive)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| "key_encode_failed")
    }

    pub fn status(&self, selection: Option<Option<String>>) -> Status {
        let selected = selection
            .unwrap_or_else(|| self.default.clone())
            .filter(|id| self.key(id).is_some());
        Status {
            entries: self
                .entries
                .iter()
                .map(|entry| Info {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    temporary: false,
                })
                .collect(),
            default: self.default.clone(),
            selected,
        }
    }

    pub fn key(&self, id: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.key.as_str())
    }

    pub fn change(&mut self, command: Command) -> Result<(), &'static str> {
        match command {
            Command::Add { name, key } => {
                valid_name(&name)?;
                valid_key(&key)?;
                if self.entries.len() >= 64 {
                    return Err("too_many_api_keys");
                }
                let mut bytes = [0u8; 16];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut file| file.read_exact(&mut bytes))
                    .map_err(|_| "random_failed")?;
                let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                if self.key(&id).is_some() {
                    return Err("key_id_exists");
                }
                if self.entries.is_empty() {
                    self.default = Some(id.clone());
                }
                self.entries.push(Entry { id, name, key });
            }
            Command::Replace { id, key } => {
                valid_key(&key)?;
                self.entries
                    .iter_mut()
                    .find(|entry| entry.id == id)
                    .ok_or("api_key_missing")?
                    .key = key;
            }
            Command::Rename { id, name } => {
                valid_name(&name)?;
                self.entries
                    .iter_mut()
                    .find(|entry| entry.id == id)
                    .ok_or("api_key_missing")?
                    .name = name;
            }
            Command::Remove { id } => {
                let index = self
                    .entries
                    .iter()
                    .position(|entry| entry.id == id)
                    .ok_or("api_key_missing")?;
                self.entries.remove(index);
                if self.default.as_ref() == Some(&id) {
                    self.default = None;
                }
            }
            Command::Default { id } => {
                self.key(&id).ok_or("api_key_missing")?;
                self.default = Some(id);
            }
            Command::Select { .. } => return Err("selection_is_volatile"),
            Command::Temporary { .. } => return Err("temporary_keys_are_volatile"),
        }
        Ok(())
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn valid_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 64
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err("invalid_key_name");
    }
    Ok(())
}

fn valid_key(key: &str) -> Result<(), &'static str> {
    if !(16..=1024).contains(&key.len()) || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("invalid_api_key");
    }
    Ok(())
}
