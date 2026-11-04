//! A queued child task is private Safe content, even while its small creation
//! journal lives in the separately unlocked General catalog.
use super::{Capability, identifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"oblivion-child-task-v1";
const LIMIT: usize = 16 * 1024;

pub struct TaskContext<'a> {
    pub safe_id: &'a str,
    pub parent_id: &'a str,
    pub request_id: &'a str,
    pub agent: &'a str,
}

/// No plaintext or encryption key is serialized. Fields are private and the
/// current-only reader admits a bounded, structurally valid envelope once.
#[derive(Serialize)]
pub struct SealedTask {
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

impl<'de> Deserialize<'de> for SealedTask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let decoded = (|| {
            identifier(&wire.family_id)?;
            if wire.version != 1 || wire.ciphertext.len() > (LIMIT + 16).div_ceil(3) * 4 {
                return Err("invalid_child_task");
            }
            let ciphertext = STANDARD.decode(&wire.ciphertext).map_err(|_| "invalid_child_task")?;
            if !(17..=LIMIT + 16).contains(&ciphertext.len()) {
                return Err("invalid_child_task");
            }
            Ok(Self { version: 1, family_id: wire.family_id, nonce: wire.nonce, ciphertext })
        })();
        decoded.map_err(serde::de::Error::custom)
    }
}

impl SealedTask {
    pub fn seal(capability: &Capability, context: &TaskContext<'_>, task: &str) -> Result<Self, &'static str> {
        if task.trim().is_empty() || task.len() > LIMIT || task.contains('\0') {
            return Err("invalid_child_task");
        }
        let key = key(capability, context)?;
        let mut sealed = Self { version: 1, family_id: capability.family_id().into(), nonce: [0; 24], ciphertext: Vec::new() };
        getrandom::getrandom(&mut sealed.nonce).map_err(|_| "child_task_random_failed")?;
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(task.len() + 16));
        ciphertext.extend_from_slice(task.as_bytes());
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "child_task_seal_failed")?
            .encrypt_in_place(XNonce::from_slice(&sealed.nonce), &aad(capability, context)?, &mut *ciphertext)
            .map_err(|_| "child_task_seal_failed")?;
        sealed.ciphertext = ciphertext.to_vec();
        Ok(sealed)
    }

    /// The caller must own the correct family capability. A General unlock,
    /// journal copy or another child identity grants no task access by itself.
    pub fn open(&self, capability: &Capability, context: &TaskContext<'_>) -> Result<Zeroizing<String>, &'static str> {
        if self.family_id != capability.family_id() {
            return Err("child_task_unlock_failed");
        }
        let key = key(capability, context)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "child_task_unlock_failed")?
            .decrypt_in_place(XNonce::from_slice(&self.nonce), &aad(capability, context)?, &mut *plaintext)
            .map_err(|_| "child_task_unlock_failed")?;
        Ok(Zeroizing::new(std::str::from_utf8(&plaintext).map_err(|_| "child_task_unlock_failed")?.to_owned()))
    }
}

fn key(capability: &Capability, context: &TaskContext<'_>) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut info = [0; 32];
    info[..16].copy_from_slice(&identifier(capability.family_id())?);
    info[16..].copy_from_slice(&identifier(context.safe_id)?);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(DOMAIN), capability.root_secret())
        .expand(&info, key.as_mut()).map_err(|_| "child_task_derivation_failed")?;
    Ok(key)
}

fn aad(capability: &Capability, context: &TaskContext<'_>) -> Result<Vec<u8>, &'static str> {
    identifier(context.parent_id)?;
    identifier(context.request_id)?;
    if context.safe_id == context.parent_id || !matches!(context.agent, "codex" | "claude" | "opencode2") {
        return Err("invalid_child_task_context");
    }
    serde_json::to_vec(&(DOMAIN, 1u8, capability.family_id(), context.safe_id, context.parent_id, context.request_id, context.agent))
        .map_err(|_| "child_task_encoding_failed")
}

fn serialize_ciphertext<S: Serializer>(ciphertext: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> Capability {
        Capability::from_root_secret(&"1".repeat(32), Zeroizing::new([37; 32])).unwrap()
    }

    fn context() -> TaskContext<'static> {
        TaskContext { safe_id: "22222222222222222222222222222222", parent_id: "33333333333333333333333333333333", request_id: "44444444444444444444444444444444", agent: "codex" }
    }

    #[test]
    fn journal_carries_only_bounded_ciphertext_and_context_is_authenticated() {
        let capability = capability();
        let task = "Private child task · città · canary: never store this prompt in General plaintext";
        let sealed = SealedTask::seal(&capability, &context(), task).unwrap();
        let encoded = serde_json::to_vec(&sealed).unwrap();
        assert!(!encoded.windows(10).any(|bytes| bytes == b"Private ch"));
        let sealed: SealedTask = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(sealed.open(&capability, &context()).unwrap().as_str(), task);
        for changed in [
            TaskContext { safe_id: "55555555555555555555555555555555", ..context() },
            TaskContext { parent_id: "55555555555555555555555555555555", ..context() },
            TaskContext { request_id: "55555555555555555555555555555555", ..context() },
            TaskContext { agent: "claude", ..context() },
        ] { assert!(sealed.open(&capability, &changed).is_err()); }
        let other_key = Capability::from_root_secret(capability.family_id(), Zeroizing::new([38; 32])).unwrap();
        assert!(sealed.open(&other_key, &context()).is_err());
        let other_family = Capability::from_root_secret(&"9".repeat(32), Zeroizing::new([37; 32])).unwrap();
        assert!(sealed.open(&other_family, &context()).is_err());
        let mut altered = sealed;
        altered.ciphertext[0] ^= 1;
        assert!(altered.open(&capability, &context()).is_err());
    }

    #[test]
    fn maximum_task_fits_existing_journal_and_plain_legacy_values_are_rejected() {
        let capability = capability();
        let task = "x".repeat(LIMIT);
        let first = SealedTask::seal(&capability, &context(), &task).unwrap();
        let second = SealedTask::seal(&capability, &context(), &task).unwrap();
        assert_ne!(first.nonce, second.nonce);
        let encoded = serde_json::to_vec(&first).unwrap();
        assert!(encoded.len() < 23 * 1024);
        let decoded: SealedTask = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.open(&capability, &context()).unwrap().len(), LIMIT);
        assert!(serde_json::from_str::<SealedTask>("\"raw task\"").is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        unknown["version"] = 0.into();
        assert!(serde_json::from_value::<SealedTask>(unknown).is_err());
        assert!(SealedTask::seal(&capability, &context(), &"x".repeat(LIMIT + 1)).is_err());
    }
}
