//! Named SOCKS5 credentials stay in the controller. Safes receive snapshots.

use oblivion_transport::Transport;
use oblivion_transport::proxy_profiles::valid_transport;
pub use oblivion_transport::proxy_profiles::{Command, Info, Status, valid_name};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const LIMIT: usize = 65536;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    transport: Transport,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    version: u8,
    entries: Vec<Entry>,
}

pub struct Registry {
    saved: Archive,
    temporary: Archive,
}

pub enum Change {
    Unchanged,
    Saved,
    Temporary,
    Select(Transport),
}

impl Archive {
    pub fn empty() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > LIMIT {
            return Err("proxy_profile_archive_too_large");
        }
        let archive: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid_proxy_profile_archive")?;
        if archive.version != 1 || archive.entries.len() > 64 {
            return Err("invalid_proxy_profile_archive");
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in &archive.entries {
            valid_name(&entry.name)?;
            valid_transport(&entry.transport)?;
            if !names.insert(&entry.name) {
                return Err("invalid_proxy_profile_archive");
            }
        }
        Ok(archive)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| "proxy_profile_encode_failed")?);
        if bytes.len() > LIMIT {
            return Err("proxy_profile_archive_too_large");
        }
        Ok(bytes)
    }
}

impl Registry {
    pub fn new(saved: Archive, temporary: Archive) -> Result<Self, &'static str> {
        if saved.entries.len() + temporary.entries.len() > 64
            || temporary
                .entries
                .iter()
                .any(|entry| saved.entries.iter().any(|saved| saved.name == entry.name))
        {
            return Err("invalid_proxy_profile_archive");
        }
        Ok(Self { saved, temporary })
    }

    pub fn saved(&self) -> &Archive {
        &self.saved
    }
    pub fn temporary(&self) -> &Archive {
        &self.temporary
    }

    pub fn status(&self) -> Status {
        let mut entries: Vec<_> = [(&self.saved, false), (&self.temporary, true)]
            .into_iter()
            .flat_map(|(archive, temporary)| {
                archive.entries.iter().map(move |entry| Info {
                    name: entry.name.clone(),
                    transport: entry.transport.metadata(),
                    temporary,
                })
            })
            .collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Status { entries }
    }

    /// The decoder owns validation; callers pass only decoded IPC commands.
    pub fn change(&mut self, command: Command, readonly: bool) -> Result<Change, &'static str> {
        match command {
            Command::List {} => Ok(Change::Unchanged),
            Command::Add { name, transport } => {
                if self
                    .saved
                    .entries
                    .iter()
                    .chain(&self.temporary.entries)
                    .any(|entry| entry.name == name)
                {
                    return Err("proxy_profile_exists");
                }
                if self.saved.entries.len() + self.temporary.entries.len() == 64 {
                    return Err("proxy_profile_limit");
                }
                let archive = if readonly {
                    &mut self.temporary
                } else {
                    &mut self.saved
                };
                archive.entries.push(Entry { name, transport });
                Ok(if readonly {
                    Change::Temporary
                } else {
                    Change::Saved
                })
            }
            Command::Remove { name } => {
                if let Some(index) = self
                    .temporary
                    .entries
                    .iter()
                    .position(|entry| entry.name == name)
                {
                    self.temporary.entries.remove(index);
                    return Ok(Change::Temporary);
                }
                let index = self
                    .saved
                    .entries
                    .iter()
                    .position(|entry| entry.name == name)
                    .ok_or("proxy_profile_not_found")?;
                if readonly {
                    return Err("proxy_profile_readonly");
                }
                self.saved.entries.remove(index);
                Ok(Change::Saved)
            }
            Command::Select { name } => {
                let entry = self
                    .saved
                    .entries
                    .iter()
                    .chain(&self.temporary.entries)
                    .find(|entry| entry.name == name)
                    .ok_or("proxy_profile_not_found")?;
                let Transport::Socks5 {
                    endpoint,
                    authentication,
                } = &entry.transport
                else {
                    unreachable!()
                };
                Ok(Change::Select(Transport::Socks5 {
                    endpoint: *endpoint,
                    authentication: authentication.as_ref().map(|authentication| {
                        oblivion_transport::Authentication {
                            username: authentication.username.clone(),
                            password: authentication.password.clone(),
                        }
                    }),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(value: serde_json::Value) -> Command {
        Command::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
    }
    fn add(name: &str) -> Command {
        command(serde_json::json!({"action":"add","name":name,"transport":{
            "mode":"socks5","endpoint":"192.0.2.5:1080","authentication":{"username":"PRIVATE_USER","password":"PRIVATE_PASSWORD"}
        }}))
    }

    #[test]
    fn metadata_never_serializes_credentials_and_selection_is_a_snapshot() {
        let mut registry = Registry::new(Archive::empty(), Archive::empty()).unwrap();
        assert!(matches!(
            registry.change(add("Office"), false).unwrap(),
            Change::Saved
        ));
        let metadata = serde_json::to_string(&registry.status()).unwrap();
        assert!(!metadata.contains("PRIVATE_"));
        assert!(metadata.contains("authenticated"));
        let Change::Select(snapshot) = registry
            .change(
                command(serde_json::json!({"action":"select","name":"Office"})),
                false,
            )
            .unwrap()
        else {
            panic!()
        };
        registry
            .change(
                command(serde_json::json!({"action":"remove","name":"Office"})),
                false,
            )
            .unwrap();
        assert!(registry.status().entries.is_empty());
        let Transport::Socks5 {
            authentication: Some(authentication),
            ..
        } = snapshot
        else {
            panic!()
        };
        assert_eq!(authentication.password.as_str(), "PRIVATE_PASSWORD");
    }

    #[test]
    fn ephemeral_changes_are_separate_and_saved_profiles_stay_readonly() {
        let mut registry = Registry::new(Archive::empty(), Archive::empty()).unwrap();
        registry.change(add("Saved"), false).unwrap();
        let original = registry.saved().encode().unwrap();
        assert!(matches!(
            registry.change(add("Temporary"), true).unwrap(),
            Change::Temporary
        ));
        assert!(
            registry
                .status()
                .entries
                .iter()
                .any(|entry| entry.temporary)
        );
        assert_eq!(
            registry
                .change(
                    command(serde_json::json!({"action":"remove","name":"Saved"})),
                    true
                )
                .err(),
            Some("proxy_profile_readonly")
        );
        assert_eq!(&*original, &*registry.saved().encode().unwrap());
        assert_eq!(
            registry.change(add("Saved"), true).err(),
            Some("proxy_profile_exists")
        );
        let loaded = Registry::new(
            Archive::decode(&original).unwrap(),
            Archive::decode(&registry.temporary().encode().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.status().entries.len(), 2);
    }

    #[test]
    fn invalid_versions_duplicates_and_non_socks_transports_are_rejected() {
        assert!(Archive::decode(br#"{"version":0,"entries":[]}"#).is_err());
        assert!(
            Command::decode(br#"{"action":"add","name":"Tor","transport":{"mode":"tor"}}"#)
                .is_err()
        );
        assert!(Command::decode(br#"{"action":"select","name":"../profile"}"#).is_err());
        assert!(Command::decode(br#"{"action":"list","path":"/tmp/outside"}"#).is_err());
        let mut saved = Registry::new(Archive::empty(), Archive::empty()).unwrap();
        saved.change(add("Same"), false).unwrap();
        assert!(
            Registry::new(
                Archive::decode(&saved.saved().encode().unwrap()).unwrap(),
                Archive::decode(&saved.saved().encode().unwrap()).unwrap()
            )
            .is_err()
        );
    }
}
