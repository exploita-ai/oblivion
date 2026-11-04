use crate::manifest::{MAX_METADATA, validate_contents};
use crate::{Package, Safe, SecretString, invalid, require};
use age::secrecy::ExposeSecret;
use oblivion_transfer::{Limits, Manifest, relay_payload};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"OBSHARE1";
const END: &[u8; 8] = b"OBSHEND1";
// scrypt r=8 with log2(N)=18 uses approximately 256 MiB. Keep the same bound
// when reading untrusted packages rather than accepting their chosen KDF cost.
pub const KDF_MEMORY_MIB: u64 = 256;
const WORK_FACTOR: u8 = 18;

/// Opens a reviewed guest stream: Manifest::write, then Selection::send_data.
/// The adapter owns its lease and must not mount a guest filesystem locally.
pub trait Source {
    fn open<'a>(&'a mut self, safe: &Safe) -> io::Result<Box<dyn Read + 'a>>;
    fn complete(&mut self, safe: &Safe, manifest: &Manifest) -> io::Result<()>;
}

/// All writes are private staging inside new destination Safes. Neither
/// finish_safe nor begin may publish a Safe or replace existing user data.
/// Publication belongs to the caller, only after decrypt returns Verified.
pub trait Import {
    type Writer: Write;

    fn begin(&mut self, package: &Package, metadata_sha256: &str) -> io::Result<()>;
    fn begin_safe(&mut self, safe: &Safe, manifest: &Manifest) -> io::Result<Self::Writer>;
    fn finish_safe(&mut self, safe: &Safe, writer: Self::Writer) -> io::Result<()>;
    fn abort(&mut self) -> io::Result<()>;
}

/// Proof that the complete package, every payload and the final age chunk have
/// been consumed and authenticated. Constructors remain private to this module.
pub struct Verified {
    package: Package,
    package_sha256: String,
    bytes: u64,
}

impl Verified {
    pub fn package(&self) -> &Package {
        &self.package
    }
    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// The output is ciphertext from the first byte. Caller writes it to an
/// exclusive private pending file and publishes that file only on success.
pub fn encrypt(
    output: impl Write,
    passphrase: SecretString,
    package: &Package,
    source: &mut impl Source,
) -> io::Result<()> {
    package.validate()?;
    validate_passphrase(&passphrase)?;
    let metadata =
        Zeroizing::new(serde_json::to_vec(package).map_err(|_| invalid("invalid_share_metadata"))?);
    require(
        !metadata.is_empty() && metadata.len() <= MAX_METADATA,
        "share_metadata_limit",
    )?;
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(WORK_FACTOR);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|_| invalid("share_encryption_failed"))?;
    let mut writer = encryptor
        .wrap_output(output)
        .map_err(|_| invalid("share_encryption_failed"))?;
    writer.write_all(MAGIC)?;
    writer.write_all(&(metadata.len() as u32).to_be_bytes())?;
    writer.write_all(&metadata)?;
    for safe in &package.safes {
        let mut reader = source.open(safe)?;
        let manifest = Manifest::read(
            &mut reader,
            Limits {
                entries: safe.entries,
                bytes: safe.bytes,
            },
        )?;
        validate_contents(&manifest, safe)?;
        manifest.write(&mut writer)?;
        relay_payload(&mut reader, &mut writer, &manifest)?;
        drop(reader);
        // The source protocol may wait for an explicit verified receipt. Only
        // the declared payload enters the cipher; no unbounded EOF read here.
        source.complete(safe, &manifest)?;
    }
    writer.write_all(END)?;
    writer.finish()?;
    Ok(())
}

pub fn decrypt(
    input: impl Read,
    passphrase: SecretString,
    target: &mut impl Import,
) -> io::Result<Verified> {
    validate_passphrase(&passphrase)?;
    let result = (|| {
        let decryptor = age::Decryptor::new(input).map_err(|_| invalid("share_unlock_failed"))?;
        require(decryptor.is_scrypt(), "share_passphrase_required")?;
        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(WORK_FACTOR);
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| invalid("share_unlock_failed"))?;
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        require(&magic == MAGIC, "unsupported_share_format")?;
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        require(length > 0 && length <= MAX_METADATA, "share_metadata_limit")?;
        let mut metadata = Zeroizing::new(vec![0; length]);
        reader.read_exact(&mut metadata)?;
        let package: Package =
            serde_json::from_slice(&metadata).map_err(|_| invalid("invalid_share_metadata"))?;
        package.validate()?;
        let package_sha256 = format!("{:x}", Sha256::digest(&*metadata));
        target.begin(&package, &package_sha256)?;
        let mut bytes = 0u64;
        for safe in &package.safes {
            let manifest = Manifest::read(
                &mut reader,
                Limits {
                    entries: safe.entries,
                    bytes: safe.bytes,
                },
            )?;
            validate_contents(&manifest, safe)?;
            let mut writer = target.begin_safe(safe, &manifest)?;
            relay_payload(&mut reader, &mut writer, &manifest)?;
            writer.flush()?;
            target.finish_safe(safe, writer)?;
            bytes = bytes
                .checked_add(manifest.bytes())
                .ok_or_else(|| invalid("share_byte_limit"))?;
        }
        let mut end = [0; 8];
        reader.read_exact(&mut end)?;
        require(&end == END, "incomplete_share")?;
        let mut extra = [0; 1];
        require(reader.read(&mut extra)? == 0, "share_trailing_data")?;
        Ok(Verified {
            package,
            package_sha256,
            bytes,
        })
    })();
    if result.is_err() && target.abort().is_err() {
        return Err(invalid("share_cleanup_required"));
    }
    result
}

fn validate_passphrase(passphrase: &SecretString) -> io::Result<()> {
    let value = passphrase.expose_secret();
    require(
        value.len() <= 4096 && value.chars().count() >= 16,
        "share_passphrase_too_short",
    )
}
