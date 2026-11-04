//! Safe-scoped transport changes. Authentication remains a secret payload.
use crate::Transport;
use serde::{Deserialize, Serialize};

// No Debug: a command may carry proxy authentication credentials.
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Save { transport: Transport },
    Select { transport: Transport },
    Saved {},
}
