//! Positive portable roots over the ordinary manifest/chunk/hash protocol.
use crate::{Entry, Limits, Manifest, require};
use std::io;
#[cfg(unix)]
#[path = "share_unix.rs"]
mod unix;
#[cfg(unix)]
pub use unix::{send, receive};

pub const LIMITS: Limits = Limits { entries: crate::MAX_ENTRIES, bytes: crate::MAX_DOCUMENT_BYTES };

pub fn validate_manifest(manifest: &Manifest) -> io::Result<()> {
    for entry in manifest.entries() {
        let parts = entry.path().split('/').collect::<Vec<_>>();
        require(matches!(parts.first().copied(), Some("workspace" | "imports" | "history")), "share_root_not_allowed")?;
        if parts[0] == "history" {
            require(matches!(entry, Entry::Directory { .. }) && parts.len() == 1
                || matches!(entry, Entry::File { .. }) && parts.as_slice() == ["history", "chats.jsonl"], "share_history_not_portable")?;
            continue;
        }
        for part in parts {
            require(!matches!(part.to_ascii_lowercase().as_str(),
                ".ssh" | ".gnupg" | ".aws" | ".azure" | ".codex" | ".claude" | ".oblivion-system" | ".oblivion-history" | ".oblivion-jobs"
                | "auth.json" | "credentials.json" | "provider.keys.json" | "api-keys.json" | "proxy-profiles.json"
                | "oauth.json" | "tokens.json" | "keyring.json" | ".bash_history" | ".zsh_history" | ".python_history"), "share_credential_store_excluded")?;
        }
    }
    Ok(())
}
