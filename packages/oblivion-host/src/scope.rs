//! Trusted controller slots. Each slot owns separate hypervisor identities,
//! private wires, device mappings and service lifecycles. Slot zero is the
//! default controller maintenance slot.
use serde::{Deserialize, Serialize};
use std::cell::Cell;

pub use oblivion_wire::slot::LIMIT;
thread_local! { static CURRENT: Cell<Slot> = const { Cell::new(Slot(oblivion_wire::slot::Slot::ZERO)) }; }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Slot(oblivion_wire::slot::Slot);

impl TryFrom<u8> for Slot {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        oblivion_wire::slot::Slot::try_from(value).map(Self)
    }
}
impl From<Slot> for u8 {
    fn from(value: Slot) -> Self {
        value.index()
    }
}

pub fn current() -> Slot {
    CURRENT.get()
}
pub fn within<T>(slot: Slot, action: impl FnOnce() -> T) -> T {
    struct Restore(Slot);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.set(self.0);
        }
    }
    let _restore = Restore(CURRENT.replace(slot));
    action()
}

impl Slot {
    pub fn index(self) -> u8 {
        self.0.index()
    }
    pub fn uid(self, base: u32) -> u32 {
        if self.index() == 0 {
            return base;
        }
        16000 + u32::from(self.index()) * 16 + (base - 1100)
    }
    pub fn name(self, base: &str) -> String {
        if self.index() == 0 {
            return base.to_owned();
        }
        format!("{base}-s{}", self.index())
    }
    pub fn owner(self, base: &str) -> String {
        if self.index() == 0 {
            return format!("{base}.service");
        }
        format!("{base}@{}.service", self.index())
    }
    pub fn runtime(self) -> String {
        if self.index() == 0 {
            return "/run/oblivion".into();
        }
        format!("/run/oblivion/slots/{}", self.index())
    }
    pub fn mapping(self, name: &str) -> String {
        self.name(name)
    }
    pub fn device(self, name: &str) -> String {
        format!("/dev/mapper/{}", self.mapping(name))
    }
    /// Only controller-owned paths are expanded. Guest-visible /dev names,
    /// virtio port names and the immutable base filesystem remain unchanged.
    pub fn path(self, path: &str) -> String {
        if self.index() == 0 {
            return path.into();
        }
        for base in [
            "oblivion-session",
            "oblivion-gateway-vm",
            "oblivion-import-vm",
            "oblivion-export-vm",
            "oblivion-transfer-host",
            "oblivion-onion-host",
            "oblivion-onion-uplink",
            "oblivion-onion-gateway-vm",
            "oblivion-onion-file-vm",
        ] {
            let prefix = format!("/run/{base}");
            if let Some(tail) = path.strip_prefix(&prefix) {
                if tail.is_empty() || tail.starts_with('/') {
                    return format!("/run/{}{tail}", self.name(base));
                }
            }
        }
        if let Some(tail) = path.strip_prefix("/run/oblivion/") {
            if matches!(
                tail,
                "gateway-control.sock"
                    | "transfer.json"
                    | "transfer.pending"
                    | "onion.json"
                    | "onion.pending"
                    | "ephemeral.luks"
                    | "session-recovery-required"
            ) {
                return format!("{}/{tail}", self.runtime());
            }
        }
        for name in ["oblivion-session", "oblivion-import", "oblivion-export"] {
            if path == format!("/dev/mapper/{name}") {
                return self.device(name);
            }
        }
        path.into()
    }
}

pub fn path(value: &str) -> String {
    current().path(value)
}
pub fn uid(base: u32) -> u32 {
    current().uid(base)
}
pub fn owner(base: &str) -> String {
    current().owner(base)
}

/// Expand fixed launcher arguments only, never a guest command or secret.
pub fn wire(value: &str) -> String {
    let slot = current();
    if slot.index() == 0 {
        return value.into();
    }
    let mut result = value.to_owned();
    for base in [
        "oblivion-session",
        "oblivion-gateway-vm",
        "oblivion-import-vm",
        "oblivion-export-vm",
        "oblivion-transfer-host",
        "oblivion-onion-host",
        "oblivion-onion-uplink",
        "oblivion-onion-gateway-vm",
        "oblivion-onion-file-vm",
    ] {
        for separator in ["/", ":", " ", ","] {
            result = result.replace(
                &format!("/run/{base}{separator}"),
                &format!("/run/{}{separator}", slot.name(base)),
            );
        }
        if result.ends_with(&format!("/run/{base}")) {
            result.truncate(result.len() - base.len());
            result.push_str(&slot.name(base));
        }
    }
    for name in ["oblivion-session", "oblivion-import", "oblivion-export"] {
        for separator in [":", " ", ","] {
            result = result.replace(
                &format!("/dev/mapper/{name}{separator}"),
                &format!("{}{separator}", slot.device(name)),
            );
        }
        if result.ends_with(&format!("/dev/mapper/{name}")) {
            result.truncate(result.len() - name.len());
            result.push_str(&slot.mapping(name));
        }
    }
    for name in [
        "oblivion-gateway-host",
        "oblivion-transfer-host",
        "oblivion-onion-host",
    ] {
        result = result.replace(&format!("{name}.service"), &slot.owner(name));
    }
    result
}
