use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MIB: u64 = 1024 * 1024;
pub const MAX_MIB: u64 = 1024 * 1024;
pub const RESERVE_BYTES: u64 = 64 * MIB;

#[derive(Deserialize)]
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

pub fn growth(current: u64, mib: u64, available: u64) -> Result<u64, &'static str> {
    let target = size(mib)?;
    if target <= current {
        return Err("session_growth_only");
    }
    // The original stays intact until its enlarged encrypted copy is verified.
    if available < target + RESERVE_BYTES {
        return Err("insufficient_growth_space");
    }
    Ok(target)
}

pub fn resized(target: u64, device: u64, filesystem: u64) -> bool {
    // LUKS2 reserves its header; ext4 can leave a final partial block unused.
    device > 0
        && device < target
        && target - device <= 32 * MIB
        && filesystem > 0
        && filesystem <= device
        && device - filesystem < 4096
}

fn identifier(id: &str) -> Result<(), &'static str> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("invalid_session_id");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub capacity: u64,
    pub used: u64,
    pub available: u64,
}

impl Usage {
    pub fn valid(&self) -> bool {
        self.capacity <= MAX_MIB * MIB
            && self.used <= self.capacity
            && self.available <= self.capacity - self.used
    }
}
