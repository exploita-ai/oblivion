//! Personal full-volume recovery, separate from sanitized portable Share.
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exported {
    pub transaction: String,
    pub safe_id: String,
    pub bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Imported {
    pub transaction: String,
    pub maximum: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    pub transaction: String,
    pub password: zeroize::Zeroizing<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finished {
    pub transaction: String,
    pub safe_id: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Export,
    Import,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Prepared,
    Copying,
    Copied,
    Committed,
    RecoveryRequired,
    Cancelled,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry<S> {
    pub transaction: String,
    pub slot: S,
    pub kind: Kind,
    pub safe_id: Option<String>,
    pub bytes: Option<u64>,
    pub outcome: Outcome,
    pub active: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status<S> {
    pub transactions: Vec<Entry<S>>,
}

/// The controller records at most 1024 personal backup transactions. Native
/// slot validation belongs to S; public metadata is validated once on decode.
impl<S> Status<S> {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.transactions.len() > 1024 {
            return Err("invalid_backup_status");
        }
        let mut ids = std::collections::BTreeSet::new();
        if self.transactions.iter().any(|entry| {
            !crate::control::valid_id(&entry.transaction)
                || !ids.insert(&entry.transaction)
                || entry
                    .safe_id
                    .as_deref()
                    .is_some_and(|id| !crate::control::valid_id(id))
                || entry.bytes.is_some_and(|bytes| !volume_size(bytes))
        }) {
            return Err("invalid_backup_status");
        }
        Ok(())
    }
}

pub fn volume_size(bytes: u64) -> bool {
    (32 * crate::volume::MIB..=crate::volume::MAX_MIB * crate::volume::MIB).contains(&bytes)
}

#[cfg(test)]
mod tests {
    use super::{Finish, Status, volume_size};
    use crate::slot::Slot;
    use serde_json::{Value, json};

    fn status() -> Value {
        json!({"transactions":[{"transaction":"a".repeat(32),"slot":3,"kind":"import",
            "safe_id":null,"bytes":null,"outcome":"copied","active":false}]})
    }

    #[test]
    fn generic_native_slots_keep_the_same_current_wire_shape_and_metadata_bounds() {
        let decoded: Status<Slot> = serde_json::from_value(status()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), status());
        assert!(volume_size(32 * 1024 * 1024));
        assert!(volume_size(1024 * 1024 * 1024 * 1024));
        assert!(!volume_size(32 * 1024 * 1024 - 1));
        assert!(!volume_size(1024 * 1024 * 1024 * 1024 + 1));
        let mut invalid = status();
        invalid["transactions"][0]["slot"] = json!(256);
        assert!(serde_json::from_value::<Status<Slot>>(invalid).is_err());
        let mut invalid = status();
        invalid["transactions"][0]["bytes"] = json!(1);
        assert!(
            serde_json::from_value::<Status<Slot>>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut invalid = status();
        invalid["transactions"]
            .as_array_mut()
            .unwrap()
            .push(status()["transactions"][0].clone());
        assert!(
            serde_json::from_value::<Status<Slot>>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn password_request_accepts_no_file_path_or_caller_claimed_volume_identity() {
        let body = json!({"transaction":"a".repeat(32),"password":"SYNTHETIC_PASSWORD"});
        assert!(serde_json::from_value::<Finish>(body.clone()).is_ok());
        for key in ["path", "safe_id", "slot", "command", "device"] {
            let mut invalid = body.clone();
            invalid[key] = json!("not authority");
            assert!(serde_json::from_value::<Finish>(invalid).is_err());
        }
    }
}
