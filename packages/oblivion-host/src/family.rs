//! Password-wrapped family capabilities for independently encrypted Safes.
//!
//! A capability grants derivation access to its entire family. Keeping an old
//! descriptor and password therefore preserves access even after rewrapping.
//! Revoking that access requires a new random family and replacement LUKS slots.

mod task;
pub use task::{SealedTask, TaskContext};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const DESCRIPTOR_LIMIT: usize = 4096;
const TOKEN_TYPE: &str = "oblivion-safe-family";
const AAD_DOMAIN: &str = "oblivion-family-capability-v1";
const SAFE_DOMAIN: &[u8] = b"oblivion-safe-luks2-credential-v1";

/// Public, authenticated metadata. Deserialization is deliberately bounded.
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct Descriptor(WireDescriptor);

/// A root-controller secret, never a guest credential or a serialized object.
/// The owning daemon must discard it when its authorization is closed/locked.
pub struct Capability {
    family_id: String,
    secret: Zeroizing<[u8; 32]>,
}

pub struct SafeToken {
    pub descriptor: Descriptor,
    pub safe_id: String,
    pub keyslot: u8,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    version: u8,
    family_id: String,
    kdf: Kdf,
    salt: [u8; 16],
    nonce: [u8; 24],
    wrapped_capability: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

#[derive(Serialize)]
struct AuthenticatedMetadata<'a> {
    domain: &'static str,
    version: u8,
    family_id: &'a str,
    kdf: &'a Kdf,
    salt: &'a [u8; 16],
    nonce: &'a [u8; 24],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireToken {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    safe_id: String,
    family: WireDescriptor,
}

impl Descriptor {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        bounded(bytes)?;
        let wire = serde_json::from_slice(bytes).map_err(|_| "invalid_family_descriptor")?;
        Self::validated(wire)
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(self).map_err(|_| "family_encoding_failed")
    }

    pub fn family_id(&self) -> &str {
        &self.0.family_id
    }

    /// Import this public token into the LUKS2 header alongside its real slot.
    /// Each Safe carries its own ID; family descriptors can be shared unchanged.
    pub fn encode_token(&self, safe_id: &str, keyslot: u8) -> Result<Vec<u8>, &'static str> {
        identifier(safe_id)?;
        if keyslot >= 32 {
            return Err("invalid_family_keyslot");
        }
        serde_json::to_vec(&WireToken {
            kind: TOKEN_TYPE.to_string(),
            keyslots: vec![keyslot.to_string()],
            safe_id: safe_id.to_string(),
            family: self.0.clone(),
        })
        .map_err(|_| "family_encoding_failed")
    }

    pub fn decode_token(bytes: &[u8]) -> Result<SafeToken, &'static str> {
        bounded(bytes)?;
        let token: WireToken = serde_json::from_slice(bytes).map_err(|_| "invalid_family_token")?;
        identifier(&token.safe_id)?;
        if token.kind != TOKEN_TYPE || token.keyslots.len() != 1 {
            return Err("invalid_family_token");
        }
        let keyslot = token.keyslots[0]
            .parse::<u8>()
            .map_err(|_| "invalid_family_keyslot")?;
        if keyslot >= 32 || keyslot.to_string() != token.keyslots[0] {
            return Err("invalid_family_keyslot");
        }
        Ok(SafeToken {
            descriptor: Self::validated(token.family)?,
            safe_id: token.safe_id,
            keyslot,
        })
    }

    fn validated(wire: WireDescriptor) -> Result<Self, &'static str> {
        identifier(&wire.family_id)?;
        // One versioned production profile prevents attacker-controlled memory
        // allocation and downgrade. Future profiles require an explicit format.
        if wire.version != 1 || !wire.kdf.production() || wire.wrapped_capability.len() != 48 {
            return Err("invalid_family_descriptor");
        }
        Ok(Self(wire))
    }

    fn aad(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(&AuthenticatedMetadata {
            domain: AAD_DOMAIN,
            version: self.0.version,
            family_id: &self.0.family_id,
            kdf: &self.0.kdf,
            salt: &self.0.salt,
            nonce: &self.0.nonce,
        })
        .map_err(|_| "family_encoding_failed")
    }
}

impl Capability {
    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    /// Only for a private, inherited root-controller IPC channel. Never place
    /// these bytes in a guest, file, argument, environment, or public response.
    pub fn root_secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Reconstitutes authority received from the trusted resident controller.
    /// This does not authenticate a password or verify a LUKS keyslot.
    pub fn from_root_secret(
        family_id: &str,
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, &'static str> {
        identifier(family_id)?;
        Ok(Self {
            family_id: family_id.to_string(),
            secret,
        })
    }
}

/// The password is borrowed for this operation and is never retained.
pub fn new_family(password: &[u8]) -> Result<(Descriptor, Capability), &'static str> {
    new_family_with_kdf(password, Kdf::default())
}

/// Creates an independent password wrapper around the same family authority.
/// This does not revoke any previous wrapper or password.
pub fn wrap_descriptor(
    capability: &Capability,
    password: &[u8],
) -> Result<Descriptor, &'static str> {
    wrap_with_kdf(capability, password, Kdf::default())
}

pub fn unlock_descriptor(
    descriptor: &Descriptor,
    password: &[u8],
) -> Result<Capability, &'static str> {
    if !(1..=1024).contains(&password.len()) {
        return Err("invalid_secret_length");
    }
    let key = password_key(password, &descriptor.0.salt, &descriptor.0.kdf)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "family_unlock_failed")?;
    let mut plain = Zeroizing::new(descriptor.0.wrapped_capability.clone());
    cipher
        .decrypt_in_place(
            XNonce::from_slice(&descriptor.0.nonce),
            &descriptor.aad()?,
            &mut *plain,
        )
        .map_err(|_| "family_unlock_failed")?;
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&plain);
    Ok(Capability {
        family_id: descriptor.0.family_id.clone(),
        secret,
    })
}

/// Binary key-file material for cryptsetup, not a human password. The Safe's
/// actual LUKS volume key remains independently generated by cryptsetup.
pub fn credential_for_safe(
    capability: &Capability,
    safe_id: &str,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut info = [0; 32];
    info[..16].copy_from_slice(&identifier(&capability.family_id)?);
    info[16..].copy_from_slice(&identifier(safe_id)?);
    let mut credential = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(SAFE_DOMAIN), capability.secret.as_ref())
        .expand(&info, credential.as_mut())
        .map_err(|_| "family_derivation_failed")?;
    Ok(credential)
}

fn new_family_with_kdf(
    password: &[u8],
    kdf: Kdf,
) -> Result<(Descriptor, Capability), &'static str> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::getrandom(secret.as_mut()).map_err(|_| "family_random_failed")?;
    let mut id = [0; 16];
    getrandom::getrandom(&mut id).map_err(|_| "family_random_failed")?;
    let capability = Capability {
        family_id: id.iter().map(|byte| format!("{byte:02x}")).collect(),
        secret,
    };
    let descriptor = wrap_with_kdf(&capability, password, kdf)?;
    Ok((descriptor, capability))
}

fn wrap_with_kdf(
    capability: &Capability,
    password: &[u8],
    kdf: Kdf,
) -> Result<Descriptor, &'static str> {
    if !(16..=1024).contains(&password.len()) {
        return Err("invalid_secret_length");
    }
    let mut descriptor = Descriptor(WireDescriptor {
        version: 1,
        family_id: capability.family_id.clone(),
        kdf,
        salt: [0; 16],
        nonce: [0; 24],
        wrapped_capability: Vec::new(),
    });
    getrandom::getrandom(&mut descriptor.0.salt).map_err(|_| "family_random_failed")?;
    getrandom::getrandom(&mut descriptor.0.nonce).map_err(|_| "family_random_failed")?;
    let key = password_key(password, &descriptor.0.salt, &descriptor.0.kdf)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "family_wrap_failed")?;
    // Keep the in-place buffer zeroizing, including allocation/error paths.
    let mut wrapped = Zeroizing::new(Vec::with_capacity(48));
    wrapped.extend_from_slice(capability.secret.as_ref());
    cipher
        .encrypt_in_place(
            XNonce::from_slice(&descriptor.0.nonce),
            &descriptor.aad()?,
            &mut *wrapped,
        )
        .map_err(|_| "family_wrap_failed")?;
    descriptor.0.wrapped_capability = wrapped.to_vec();
    Ok(descriptor)
}

fn password_key(
    password: &[u8],
    salt: &[u8; 16],
    kdf: &Kdf,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|_| "invalid_family_descriptor")?;
    let mut memory = Zeroizing::new(vec![Block::new(); params.block_count()]);
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, key.as_mut(), &mut *memory)
        .map_err(|_| "family_kdf_failed")?;
    Ok(key)
}

impl Default for Kdf {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            version: 0x13,
            memory_kib: 256 * 1024,
            passes: 4,
            lanes: 1,
        }
    }
}

impl Kdf {
    fn production(&self) -> bool {
        self.algorithm == "argon2id"
            && self.version == 0x13
            && self.memory_kib == 256 * 1024
            && self.passes == 4
            && self.lanes == 1
    }
}

fn bounded(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > DESCRIPTOR_LIMIT {
        return Err("invalid_family_descriptor");
    }
    Ok(())
}

fn identifier(id: &str) -> Result<[u8; 16], &'static str> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid_family_identifier");
    }
    let mut bytes = [0; 16];
    for (index, pair) in id.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'a' + 10,
        };
        bytes[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"family-test-password";
    const SAFE: &str = "00000000000000000000000000000001";

    // Only this private constructor changes cost. The public decoder continues
    // to reject these fixtures; production defaults never depend on cfg(test).
    fn fixture() -> (Descriptor, Capability) {
        new_family_with_kdf(PASSWORD, fast_kdf()).unwrap()
    }

    fn fast_kdf() -> Kdf {
        Kdf {
            memory_kib: 8 * 1024,
            passes: 1,
            ..Kdf::default()
        }
    }

    #[test]
    fn same_family_password_recovers_distinct_stable_safe_credentials() {
        let (descriptor, capability) = fixture();
        let unlocked = unlock_descriptor(&descriptor, PASSWORD).unwrap();
        let original = credential_for_safe(&capability, SAFE).unwrap();
        assert_eq!(*original, *credential_for_safe(&unlocked, SAFE).unwrap());
        assert_ne!(
            *original,
            *credential_for_safe(&unlocked, "00000000000000000000000000000002").unwrap()
        );
        let (_, another) = fixture();
        assert_ne!(*original, *credential_for_safe(&another, SAFE).unwrap());
        assert!(credential_for_safe(&capability, "../safe").is_err());
        assert!(credential_for_safe(&capability, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn authentication_rejects_wrong_password_and_tampered_public_metadata() {
        let (descriptor, _) = fixture();
        assert!(unlock_descriptor(&descriptor, b"incorrect-password").is_err());
        for field in ["family_id", "salt", "nonce", "ciphertext"] {
            let mut tampered = descriptor.clone();
            match field {
                "family_id" => tampered.0.family_id = SAFE.to_string(),
                "salt" => tampered.0.salt[0] ^= 1,
                "nonce" => tampered.0.nonce[0] ^= 1,
                _ => tampered.0.wrapped_capability[0] ^= 1,
            }
            assert!(unlock_descriptor(&tampered, PASSWORD).is_err(), "{field}");
        }
    }

    #[test]
    fn independent_wrappers_do_not_claim_to_revoke_an_old_password() {
        let (original, capability) = fixture();
        let next = wrap_with_kdf(&capability, b"a-different-password", fast_kdf()).unwrap();
        assert_ne!(original.0.salt, next.0.salt);
        assert_ne!(original.0.nonce, next.0.nonce);
        let old = unlock_descriptor(&original, PASSWORD).unwrap();
        let new = unlock_descriptor(&next, b"a-different-password").unwrap();
        assert_eq!(
            *credential_for_safe(&old, SAFE).unwrap(),
            *credential_for_safe(&new, SAFE).unwrap()
        );
        assert!(unlock_descriptor(&next, PASSWORD).is_err());
    }

    #[test]
    fn descriptor_and_luks_token_parsers_bound_cost_and_metadata() {
        let (mut descriptor, _) = fixture();
        assert!(Descriptor::decode(&descriptor.encode().unwrap()).is_err());
        // Parsing does not execute the KDF: use a production profile to test
        // the portable format without performing expensive password work.
        descriptor.0.kdf = Kdf::default();
        let encoded = descriptor.encode().unwrap();
        assert_eq!(
            Descriptor::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        let token = descriptor.encode_token(SAFE, 31).unwrap();
        let decoded = Descriptor::decode_token(&token).unwrap();
        assert_eq!(decoded.safe_id, SAFE);
        assert_eq!(decoded.keyslot, 31);
        assert_eq!(decoded.descriptor.encode().unwrap(), encoded);
        assert!(descriptor.encode_token(SAFE, 32).is_err());
        assert!(Descriptor::decode(&vec![b' '; DESCRIPTOR_LIMIT + 1]).is_err());
        for (path, value) in [
            ("memory_kib", serde_json::json!(u32::MAX)),
            ("memory_kib", serde_json::json!(64 * 1024)),
            ("passes", serde_json::json!(1)),
            ("lanes", serde_json::json!(32)),
            ("algorithm", serde_json::json!("argon2i")),
        ] {
            let mut changed = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
            changed["kdf"][path] = value;
            assert!(Descriptor::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut invalid: serde_json::Value = serde_json::from_slice(&token).unwrap();
        invalid["keyslots"] = serde_json::json!(["01"]);
        assert!(Descriptor::decode_token(&serde_json::to_vec(&invalid).unwrap()).is_err());
        invalid["keyslots"] = serde_json::json!(["0", "1"]);
        assert!(Descriptor::decode_token(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
}
