//! Credential-only handoff over private SafeAdmin channels. Never put these
//! values in status, argv, diagnostics, Share or an unsealed creation journal.
use crate::family::{Capability, TaskContext};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const LIMIT: usize = 16 * 1024;
const DOMAIN: &[u8] = b"oblivion-child-credential-v1";

// No Debug or Clone: plaintext duplication and disclosure must be explicit.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Credential {
    CodexApiKey {
        key: Zeroizing<String>,
    },
    CodexAccessToken {
        token: Zeroizing<String>,
    },
    ClaudeApiKey {
        key: Zeroizing<String>,
    },
    ClaudeSetupToken {
        token: Zeroizing<String>,
    },
    OpencodeKey {
        integration_id: String,
        key: Zeroizing<String>,
        model: String,
    },
}

impl Credential {
    pub fn agent(&self) -> &'static str {
        match self {
            Self::CodexApiKey { .. } | Self::CodexAccessToken { .. } => "codex",
            Self::ClaudeApiKey { .. } | Self::ClaudeSetupToken { .. } => "claude",
            Self::OpencodeKey { .. } => "opencode2",
        }
    }

    pub fn valid(&self) -> bool {
        match self {
            Self::CodexApiKey { key } | Self::ClaudeApiKey { key } => secret(key),
            // Ordinary ChatGPT OAuth JWTs must never be mistaken for the
            // independently provisioned, native personal access token method.
            Self::CodexAccessToken { token } => secret(token) && token.starts_with("at-"),
            Self::ClaudeSetupToken { token } => secret(token),
            Self::OpencodeKey {
                integration_id,
                key,
                model,
            } => {
                secret(key)
                    && matches!(
                        integration_id.as_str(),
                        "openai"
                            | "anthropic"
                            | "openrouter"
                            | "opencode"
                            | "xai"
                            | "cerebras"
                            | "abliteration-ai"
                    )
                    && model.len() <= 256
                    && model.chars().all(|character| !character.is_control())
                    && model
                        .strip_prefix(integration_id.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
            }
        }
    }

    pub fn decode(bytes: &[u8], agent: &str) -> Result<Self, &'static str> {
        if bytes.len() > LIMIT {
            return Err("invalid_delegated_credential");
        }
        let credential: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid_delegated_credential")?;
        if credential.agent() != agent || !credential.valid() {
            return Err("invalid_delegated_credential");
        }
        Ok(credential)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if !self.valid() {
            return Err("invalid_delegated_credential");
        }
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| "credential_encoding_failed")?);
        if bytes.len() > LIMIT {
            return Err("invalid_delegated_credential");
        }
        Ok(bytes)
    }
}

fn secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8192
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCredential {
    version: u8,
    family_id: String,
    nonce: [u8; 24],
    #[serde(serialize_with = "serialize_ciphertext")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u8,
    family_id: String,
    nonce: [u8; 24],
    ciphertext: String,
}

impl<'de> Deserialize<'de> for SealedCredential {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let decoded = (|| {
            if wire.version != 1
                || !id(&wire.family_id)
                || wire.ciphertext.len() > (LIMIT + 16).div_ceil(3) * 4
            {
                return Err("invalid_sealed_credential");
            }
            let ciphertext = STANDARD
                .decode(&wire.ciphertext)
                .map_err(|_| "invalid_sealed_credential")?;
            if !(17..=LIMIT + 16).contains(&ciphertext.len()) {
                return Err("invalid_sealed_credential");
            }
            Ok(Self {
                version: 1,
                family_id: wire.family_id,
                nonce: wire.nonce,
                ciphertext,
            })
        })();
        decoded.map_err(serde::de::Error::custom)
    }
}

impl SealedCredential {
    pub fn seal(
        capability: &Capability,
        context: &TaskContext<'_>,
        credential: &Credential,
    ) -> Result<Self, &'static str> {
        if credential.agent() != context.agent {
            return Err("invalid_credential_context");
        }
        let key = key(capability, context)?;
        let mut ciphertext = credential.encode()?;
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| "credential_random_failed")?;
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| "credential_seal_failed")?
            .encrypt_in_place(
                XNonce::from_slice(&nonce),
                &aad(capability, context)?,
                &mut *ciphertext,
            )
            .map_err(|_| "credential_seal_failed")?;
        Ok(Self {
            version: 1,
            family_id: capability.family_id().into(),
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn open(
        &self,
        capability: &Capability,
        context: &TaskContext<'_>,
    ) -> Result<Credential, &'static str> {
        if self.family_id != capability.family_id() {
            return Err("credential_unlock_failed");
        }
        let key = key(capability, context)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| "credential_unlock_failed")?
            .decrypt_in_place(
                XNonce::from_slice(&self.nonce),
                &aad(capability, context)?,
                &mut *plaintext,
            )
            .map_err(|_| "credential_unlock_failed")?;
        Credential::decode(&plaintext, context.agent)
    }
}

fn key(
    capability: &Capability,
    context: &TaskContext<'_>,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(DOMAIN), capability.root_secret())
        .expand(&aad(capability, context)?, key.as_mut())
        .map_err(|_| "credential_derivation_failed")?;
    Ok(key)
}

fn aad(capability: &Capability, context: &TaskContext<'_>) -> Result<Vec<u8>, &'static str> {
    if !id(context.safe_id)
        || !id(context.parent_id)
        || !id(context.request_id)
        || context.safe_id == context.parent_id
        || !matches!(context.agent, "codex" | "claude" | "opencode2")
    {
        return Err("invalid_credential_context");
    }
    serde_json::to_vec(&(
        DOMAIN,
        1u8,
        capability.family_id(),
        context.parent_id,
        context.safe_id,
        context.request_id,
        context.agent,
    ))
    .map_err(|_| "credential_encoding_failed")
}

fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn serialize_ciphertext<S: Serializer>(
    ciphertext: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(ciphertext))
}
