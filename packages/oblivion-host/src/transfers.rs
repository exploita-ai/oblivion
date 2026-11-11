use serde::{Deserialize, Serialize};

pub const SOCKET: &str = "/run/oblivion-transfer-host/control.sock";
pub const MAX_BYTES: u64 = oblivion_transfer::MAX_DOCUMENT_BYTES;
pub const MAX_ENTRIES: usize = oblivion_transfer::MAX_ENTRIES;
pub const BUDGET_SECONDS: u64 = 3600;

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    List,
    Import {
        source: String,
    },
    Export {
        target: String,
    },
    Backup {
        id: String,
        target: String,
        password: zeroize::Zeroizing<String>,
    },
    Restore {
        source: String,
    },
    RestoreFinish {
        id: String,
        password: zeroize::Zeroizing<String>,
    },
    RestoreDiscard {
        id: String,
    },
    Recover,
    Cancel,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub bytes: u64,
    pub kind: SourceKind,
    pub read_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Usb,
    Virtual,
}

impl SourceKind {
    pub fn detect(usb: bool, virtio: bool, serial: &str) -> Option<Self> {
        if usb {
            return Some(Self::Usb);
        }
        (virtio && matches!(serial, "oblivion-import" | "oblivion-export")).then_some(Self::Virtual)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub configured: bool,
    pub export_configured: bool,
    pub active: bool,
    pub sources: Vec<Source>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

pub fn limits() -> oblivion_transfer::Limits {
    oblivion_transfer::Limits {
        entries: MAX_ENTRIES,
        bytes: MAX_BYTES,
    }
}
