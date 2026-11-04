//! Named proxy command grammar shared by frontend and controller.
use crate::Transport;
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
