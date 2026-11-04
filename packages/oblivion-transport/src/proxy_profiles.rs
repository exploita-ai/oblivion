//! Named proxy command grammar shared by frontend and controller.
use crate::{Metadata, Transport};
use serde::{Deserialize, Serialize};

// No Debug: Add carries a transport's authentication credentials.
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    List {},
    Add { name: String, transport: Transport },
    Remove { name: String },
    Select { name: String },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub name: String,
    pub transport: Metadata,
    pub temporary: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub entries: Vec<Info>,
}

impl Status {
    /// A listing accepts public metadata only; neither credential fields nor
    /// parser diagnostics from the controller can reach frontend output.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let invalid = "invalid_proxy_profile_status";
        if bytes.len() > 65536 {
            return Err(invalid);
        }
        let status: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        if status.entries.len() > 64 {
            return Err(invalid);
        }
        let mut names = std::collections::BTreeSet::new();
        for info in &status.entries {
            valid_name(&info.name).map_err(|_| invalid)?;
            if !names.insert(&info.name) {
                return Err(invalid);
            }
            let Metadata::Socks5 { endpoint, .. } = info.transport else {
                return Err(invalid);
            };
            Transport::Socks5 {
                endpoint,
                authentication: None,
            }
            .validate()
            .map_err(|_| invalid)?;
        }
        Ok(status)
    }
}

impl Command {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > 4096 {
            return Err("invalid_proxy_profile_command");
        }
        let command: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid_proxy_profile_command")?;
        match &command {
            Self::List {} => {}
            Self::Add { name, transport } => {
                valid_name(name)?;
                valid_transport(transport)?;
            }
            Self::Select { name } | Self::Remove { name } => valid_name(name)?,
        }
        Ok(command)
    }
}

pub fn valid_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 64
        || name.trim() != name
        || name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        return Err("invalid_proxy_profile_name");
    }
    Ok(())
}

pub fn valid_transport(transport: &Transport) -> Result<(), &'static str> {
    if !matches!(transport, Transport::Socks5 { .. }) {
        return Err("proxy_profile_requires_socks5");
    }
    transport.validate()
}
