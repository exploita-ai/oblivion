//! Safe encrypted-volume commands shared by controller and native frontends.
//! Passwords and serialized requests are not diagnostic data.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MIB: u64 = 1024 * 1024;
pub const MAX_MIB: u64 = 1024 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Create {
        mib: u64,
        password: Zeroizing<String>,
    },
    Grow {
        id: String,
        mib: u64,
        password: Zeroizing<String>,
    },
    Discard {
        id: String,
    },
    Usage {},
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Create { mib, password } => {
                size(*mib)?;
                if !(16..=1024).contains(&password.len()) {
                    return Err("invalid_secret_length");
                }
            }
            Self::Grow { id, mib, password } => {
                identifier(id)?;
                size(*mib)?;
                if !(1..=1024).contains(&password.len()) {
                    return Err("invalid_secret_length");
                }
            }
            Self::Discard { id } => identifier(id)?,
            Self::Usage {} => {}
        }
        Ok(())
    }
}

pub fn size(mib: u64) -> Result<u64, &'static str> {
    if !(128..=MAX_MIB).contains(&mib) {
        return Err("invalid_session_size");
    }
    Ok(mib * MIB)
}

fn identifier(id: &str) -> Result<(), &'static str> {
    if !crate::control::valid_id(id) {
        return Err("invalid_session_id");
    }
    Ok(())
}
