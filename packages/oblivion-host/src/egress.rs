use oblivion_transport::{Metadata, Transport};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const LIMIT: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Save { transport: Transport },
    Select { transport: Transport },
    Saved {},
}

// Persisted only in the encrypted general profile or in the private tmpfs.
// No Debug: the transport may contain proxy authentication credentials.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    version: u8,
    transport: Transport,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub saved: Metadata,
    pub selected: Metadata,
    pub temporary: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            transport: Transport::default(),
        }
    }
}

impl Profile {
    pub fn new(transport: Transport) -> Result<Self, &'static str> {
        transport.validate()?;
        Ok(Self {
            version: 1,
            transport,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > LIMIT {
            return Err("transport_profile_too_large");
        }
        let profile: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid_transport_profile")?;
        if profile.version != 1 {
            return Err("invalid_transport_profile");
        }
        profile.transport.validate()?;
        Ok(profile)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| "transport_encode_failed")
    }

    pub fn metadata(&self) -> Metadata {
        self.transport.metadata()
    }

    pub fn into_transport(self) -> Transport {
        self.transport
    }
}
