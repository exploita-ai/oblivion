use serde::{Deserialize, Serialize};

pub use oblivion_wire::volume::{MIB, MAX_MIB, Request, size};

pub const RESERVE_BYTES: u64 = 64 * MIB;

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
