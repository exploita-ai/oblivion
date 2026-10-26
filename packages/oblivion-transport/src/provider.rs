use serde::{Deserialize, Serialize};

/// A remote inference provider admitted by the Oblivion gateway.
///
/// The session guest receives only this identifier and a revocable local
/// capability. Upstream origins and the real provider key remain inside the
/// gateway VM and cannot be supplied by guest configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    #[default]
    AbliterationAi,
    Refuseless,
    Openrouter,
}

impl Provider {
    pub const fn id(self) -> &'static str {
        match self {
            Self::AbliterationAi => "abliteration-ai",
            Self::Refuseless => "refuseless",
            Self::Openrouter => "openrouter",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AbliterationAi => "Abliteration.ai",
            Self::Refuseless => "Refuseless",
            Self::Openrouter => "OpenRouter (ZDR)",
        }
    }

    pub const fn host(self) -> &'static str {
        match self {
            Self::AbliterationAi => "api.abliteration.ai",
            Self::Refuseless => "api.refuseless.com",
            Self::Openrouter => "openrouter.ai",
        }
    }

    pub const fn origin(self) -> &'static str {
        match self {
            Self::AbliterationAi => "https://api.abliteration.ai/v1/chat/completions",
            Self::Refuseless => "https://api.refuseless.com/v1/chat/completions",
            Self::Openrouter => "https://openrouter.ai/api/v1/chat/completions",
        }
    }
}
