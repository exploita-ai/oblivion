//! Trusted controller slots. Each slot owns separate hypervisor identities,
//! private wires, device mappings and service lifecycles. Slot zero preserves
//! the existing single-session names for upgrades and maintenance tooling.
use std::cell::Cell;
use serde::{Deserialize, Serialize};

pub const LIMIT: u8 = 32;
thread_local! { static CURRENT: Cell<u8> = const { Cell::new(0) }; }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Slot(u8);

impl TryFrom<u8> for Slot {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value >= LIMIT { return Err("invalid_session_slot"); }
        Ok(Self(value))
    }
}
impl From<Slot> for u8 { fn from(value: Slot) -> Self { value.0 } }

pub fn current() -> Slot { Slot(CURRENT.get()) }
pub fn within<T>(slot: Slot, action: impl FnOnce() -> T) -> T {
    struct Restore(u8);
    impl Drop for Restore { fn drop(&mut self) { CURRENT.set(self.0); } }
    let _restore = Restore(CURRENT.replace(slot.0));
    action()
}

impl Slot {
    pub fn index(self) -> u8 { self.0 }
    pub fn uid(self, base: u32) -> u32 {
        if self.0 == 0 { return base; }
        16000 + u32::from(self.0) * 16 + (base - 1100)
    }
    pub fn name(self, base: &str) -> String {
        if self.0 == 0 { return base.to_owned(); }
        format!("{base}-s{}", self.0)
    }
    pub fn owner(self, base: &str) -> String {
        if self.0 == 0 { return format!("{base}.service"); }
        format!("{base}@{}.service", self.0)
    }
    pub fn runtime(self) -> String {
        if self.0 == 0 { return "/run/oblivion".into(); }
        format!("/run/oblivion/slots/{}", self.0)
    }
    pub fn mapping(self, name: &str) -> String { self.name(name) }
    pub fn device(self, name: &str) -> String { format!("/dev/mapper/{}", self.mapping(name)) }
    /// Only controller-owned paths are expanded. Guest-visible /dev names,
    /// virtio port names and the immutable base filesystem remain unchanged.
    pub fn path(self, path: &str) -> String {
        if self.0 == 0 { return path.into(); }
        for base in ["oblivion-session", "oblivion-gateway-vm", "oblivion-import-vm", "oblivion-export-vm", "oblivion-transfer-host", "oblivion-onion-host", "oblivion-onion-uplink", "oblivion-onion-gateway-vm", "oblivion-onion-file-vm"] {
            let prefix = format!("/run/{base}");
            if let Some(tail) = path.strip_prefix(&prefix) {
                if tail.is_empty() || tail.starts_with('/') { return format!("/run/{}{tail}", self.name(base)); }
            }
        }
        if let Some(tail) = path.strip_prefix("/run/oblivion/") {
            if matches!(tail, "gateway-control.sock" | "transfer.json" | "transfer.pending" | "onion.json" | "onion.pending" | "ephemeral.luks" | "session-recovery-required") { return format!("{}/{tail}", self.runtime()); }
        }
        for name in ["oblivion-session", "oblivion-import", "oblivion-export"] {
            if path == format!("/dev/mapper/{name}") { return self.device(name); }
        }
        path.into()
    }
}

pub fn path(value: &str) -> String { current().path(value) }
pub fn uid(base: u32) -> u32 { current().uid(base) }
pub fn owner(base: &str) -> String { current().owner(base) }

/// Expand fixed launcher arguments only, never a guest command or secret.
pub fn wire(value: &str) -> String {
    let slot = current();
    if slot.index() == 0 { return value.into(); }
    let mut result = value.to_owned();
    for base in ["oblivion-session", "oblivion-gateway-vm", "oblivion-import-vm", "oblivion-export-vm", "oblivion-transfer-host", "oblivion-onion-host", "oblivion-onion-uplink", "oblivion-onion-gateway-vm", "oblivion-onion-file-vm"] {
        for separator in ["/", ":", " ", ","] {
            result = result.replace(&format!("/run/{base}{separator}"), &format!("/run/{}{separator}", slot.name(base)));
        }
        if result.ends_with(&format!("/run/{base}")) {
            result.truncate(result.len() - base.len());
            result.push_str(&slot.name(base));
        }
    }
    for name in ["oblivion-session", "oblivion-import", "oblivion-export"] {
        for separator in [":", " ", ","] {
            result = result.replace(&format!("/dev/mapper/{name}{separator}"), &format!("{}{separator}", slot.device(name)));
        }
        if result.ends_with(&format!("/dev/mapper/{name}")) {
            result.truncate(result.len() - name.len());
            result.push_str(&slot.mapping(name));
        }
    }
    for name in ["oblivion-gateway-host", "oblivion-transfer-host", "oblivion-onion-host"] {
        result = result.replace(&format!("{name}.service"), &slot.owner(name));
    }
    result
}
