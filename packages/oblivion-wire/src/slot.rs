//! Platform-independent controller slot identity. Linux service names and paths
//! belong to the controller adapter, not to a desktop client.
use serde::{Deserialize, Serialize};

pub const LIMIT: u8 = 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Slot(u8);

impl Slot {
    pub const ZERO: Self = Self(0);

    pub const fn index(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Slot {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value >= LIMIT {
            return Err("invalid_session_slot");
        }
        Ok(Self(value))
    }
}

impl From<Slot> for u8 {
    fn from(value: Slot) -> Self {
        value.index()
    }
}

#[cfg(test)]
mod tests {
    use super::{LIMIT, Slot};
    use crate::control::{NativeRequest, Operation, Request};

    #[test]
    fn slot_identity_has_one_bound_and_keeps_the_current_wire_number() {
        assert_eq!(Slot::default(), Slot::ZERO);
        for index in 0..LIMIT {
            let slot = Slot::try_from(index).unwrap();
            assert_eq!(slot.index(), index);
            assert_eq!(serde_json::to_string(&slot).unwrap(), index.to_string());
            assert_eq!(
                serde_json::from_str::<Slot>(&index.to_string()).unwrap(),
                slot
            );
            let request = Request {
                operation: Operation::Status,
                session: None,
                secret_len: 0,
                slot,
                expected_session: None,
            };
            let native = serde_json::to_value(NativeRequest::new(&request)).unwrap();
            assert_eq!(native["slot"], index);
        }
        for invalid in ["32", "255", "-1", "0.5", "null", "\"0\""] {
            assert!(serde_json::from_str::<Slot>(invalid).is_err());
        }
        assert_eq!(Slot::try_from(LIMIT), Err("invalid_session_slot"));
    }
}
