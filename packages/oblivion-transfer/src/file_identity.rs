//! A single receiver/publication identity format for native filesystem objects.
//! Stable volume identity survives device-number reassignment. It does not
//! authenticate a cloned filesystem or an attacker-controlled volume.
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum FileIdentity {
    Linux {
        kind: i64,
        uuid: Vec<u8>,
        inode: u64,
    },
    MacOs {
        kind: String,
        uuid: [u8; 16],
        inode: u64,
    },
    Windows {
        volume_guid: [u8; 16],
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

impl FileIdentity {
    pub fn of(file: &File) -> io::Result<Self> {
        crate::directory::file_identity(file)
    }

    pub fn matches(&self, file: &File) -> io::Result<bool> {
        Ok(*self == Self::of(file)?)
    }
}

#[cfg(test)]
mod tests {
    use super::FileIdentity;
    use serde_json::{Value, json};

    #[test]
    fn every_platform_has_one_flat_tagged_record_with_exact_native_fields() {
        for value in [
            json!({"platform":"linux","kind":61267,"uuid":[1,2,3,4],"inode":42}),
            json!({"platform":"mac-os","kind":"apfs","uuid":vec![1u8;16],"inode":42}),
            json!({"platform":"windows","volume_guid":vec![1u8;16],"volume_serial":123,"file_id":vec![2u8;16]}),
        ] {
            let identity: FileIdentity = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(identity).unwrap(), value);
            let mut unknown = value.clone();
            unknown
                .as_object_mut()
                .unwrap()
                .insert("other".into(), Value::Null);
            assert!(serde_json::from_value::<FileIdentity>(unknown).is_err());
        }
    }
}
