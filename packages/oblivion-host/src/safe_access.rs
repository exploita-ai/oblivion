//! Network access belongs to an individual Safe, independently of Debian settings.
use oblivion_transport::policy::Access;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub mode: Access,
    pub save: bool,
}

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
    use super::{Command, Status};
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

    #[test]
    fn command_has_no_os_preferences_or_legacy_action_shape() {
        assert!(serde_json::from_str::<Command>(r#"{"mode":"open","save":true}"#).is_ok());
        for request in [
            r#"{"action":"access","mode":"open","save":true}"#,
            r#"{"mode":"open","save":true,"keyboard":"us"}"#,
            r#"{"mode":"direct","save":false}"#,
        ] {
            assert!(serde_json::from_str::<Command>(request).is_err());
        }
    }
}
