use serde::{Deserialize, Serialize};

/// Stored inside the encrypted session, never beside the exported ciphertext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format: String,
    pub version: u32,
    pub original_id: String,
    pub title: Option<String>,
}

impl Metadata {
    pub fn valid(&self) -> bool {
        self.format == "oblivion-session"
            && self.version == 1
            && self.original_id.len() == 32
            && self
                .original_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self
                .title
                .as_ref()
                .is_none_or(|title| crate::session_title::validate(title).is_ok())
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    UnsupportedVersion,
    InvalidMetadata,
    InvalidDatabase,
}
