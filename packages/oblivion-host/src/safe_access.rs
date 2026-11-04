//! Network access belongs to an individual Safe, independently of Debian settings.
use oblivion_transport::policy::Access;
pub use oblivion_transport::policy::Command;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub current: Access,
    pub saved: Option<Access>,
    pub temporary: bool,
}

impl Status {
    pub fn new(saved: Option<Access>, selected: Option<Access>) -> Self {
        Self {
            current: selected.or(saved).unwrap_or(Access::Open),
            saved,
            temporary: selected.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Status;
    use oblivion_transport::policy::Access;

    #[test]
    fn safe_default_and_temporary_override_are_explicit() {
        let status = Status::new(None, None);
        assert_eq!(status.current, Access::Open);
        assert!(!status.temporary);
        let status = Status::new(Some(Access::Strict), Some(Access::Offline));
        assert_eq!(status.current, Access::Offline);
        assert_eq!(status.saved, Some(Access::Strict));
        assert!(status.temporary);
    }
}
