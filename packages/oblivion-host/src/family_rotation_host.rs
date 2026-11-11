//! All-volume password rewrap with an encrypted-General recovery journal.
//! No capability or human password is persisted; old copied headers remain valid.
use crate::storage::{self, Error, Result, require};
use oblivion_host::{family, family_rotation as wire};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DIRECTORY: &str = "/run/oblivion/general/family-passwords";
const LIMIT: u64 = 1024 * 1024;
const MEMBER_LIMIT: usize = 256;

pub(crate) struct Source { pub id: String, pub title: String, pub path: PathBuf }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    transaction: String,
    family_id: String,
    members: Vec<wire::Member>,
    outcome: wire::Outcome,
    pending: Vec<Replacement>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    safe_id: String,
    device: u64,
    inode: u64,
    bytes: u64,
    metadata_sha256: String,
    old: serde_json::Value,
    new: serde_json::Value,
}

struct Observed {
    source: Source,
    token: family::SafeToken,
    json: serde_json::Value,
    metadata_sha256: String,
    stable_sha256: String,
}

fn sha256(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

fn observe(source: Source) -> Result<Observed> {
    storage::trusted_file(&source.path)?;
    let mut child = Command::new("/usr/sbin/cryptsetup")
        .args(["luksDump", "--dump-json-metadata"]).arg(&source.path)
        .env_clear().env("LC_ALL", "C").stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| Error("family_header_unavailable"))?;
    let mut bytes = Vec::new();
    let read = child.stdout.take().ok_or(Error("family_header_unavailable"))?.take(131073).read_to_end(&mut bytes);
    let status = child.wait().map_err(|_| Error("family_header_unavailable"))?;
    read.map_err(|_| Error("family_header_unavailable"))?;
    require(status.success() && bytes.len() <= 131072, "family_header_unavailable")?;
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error("family_header_unavailable"))?;
    let json = metadata.get("tokens").and_then(|tokens| tokens.get("0")).ok_or(Error("family_token_unavailable"))?.clone();
    let token = family::Descriptor::decode_token(&serde_json::to_vec(&json).map_err(|_| Error("encode_failed"))?).map_err(Error)?;
    require(token.safe_id == source.id, "safe_identity_mismatch")?;
    let metadata_sha256 = sha256(&serde_json::to_vec(&metadata).map_err(|_| Error("encode_failed"))?);
    let mut stable = metadata;
    stable.get_mut("tokens").and_then(|tokens| tokens.as_object_mut()).ok_or(Error("family_header_unavailable"))?.remove("0");
    Ok(Observed { source, token, json, metadata_sha256, stable_sha256: sha256(&serde_json::to_vec(&stable).map_err(|_| Error("encode_failed"))?) })
}

fn family_sources(sources: Vec<Source>, selected: &str) -> Result<Vec<Observed>> {
    storage::validate_id(selected)?;
    let mut observed = sources.into_iter().map(observe).collect::<Result<Vec<_>>>()?;
    let family = observed.iter().find(|source| source.source.id == selected).ok_or(Error("safe_not_found"))?.token.descriptor.family_id().to_owned();
    observed.retain(|source| source.token.descriptor.family_id() == family);
    observed.sort_by(|left, right| left.source.id.cmp(&right.source.id));
    require(!observed.is_empty() && observed.len() <= MEMBER_LIMIT, "family_member_limit")?;
    Ok(observed)
}

fn plan(host: &str, sources: &[Observed]) -> Result<wire::Plan> {
    let digest = serde_json::to_vec(&(host, sources.iter().map(|source|
        (&source.source.id, &source.source.title, &source.metadata_sha256)).collect::<Vec<_>>())).map_err(|_| Error("encode_failed"))?;
    Ok(wire::Plan {
        host_opening: host.into(), family_id: sources[0].token.descriptor.family_id().into(),
        members: sources.iter().map(|source| wire::Member { safe_id: source.source.id.clone(), title: source.source.title.clone() }).collect(),
        sha256: sha256(&digest),
    })
}

pub(crate) fn preview(id: &str) -> Result<wire::Plan> {
    let host = storage::rotation_host()?;
    let sources = family_sources(storage::rotation_sources()?, id)?;
    for source in &sources { require_available(&source.source.id)?; storage::rotation_closed(&source.source.id)?; }
    plan(&host, &sources)
}

pub(crate) fn change(request: wire::Change) -> Result<wire::Entry> {
    let host = storage::rotation_host()?;
    require_opening(&host, &request.host_opening)?;
    require(Repository::new(Path::new(DIRECTORY)).read_all()?.len() < 128, "family_journal_limit")?;
    require((1..=1024).contains(&request.current_password.len()) && (16..=1024).contains(&request.new_password.len()), "invalid_password_length")?;
    let sources = family_sources(storage::rotation_sources()?, &request.safe_id)?;
    require(plan(&host, &sources)?.sha256 == request.plan_sha256, "family_plan_changed")?;
    for source in &sources { require_available(&source.source.id)?; storage::rotation_closed(&source.source.id)?; }
    storage::rotation_admit_kdf()?;
    let source = sources.iter().find(|source| source.source.id == request.safe_id).ok_or(Error("safe_not_found"))?;
    let capability = family::unlock_descriptor(&source.token.descriptor, request.current_password.as_bytes()).map_err(Error)?;
    drop(request.current_password);
    // Verify every actual keyslot before the first journal/header mutation.
    for source in &sources {
        let key = family::credential_for_safe(&capability, &source.source.id).map_err(Error)?;
        test_key(&source.source.path, source.token.keyslot, key.as_ref())?;
    }
    let descriptor = family::wrap_descriptor(&capability, request.new_password.as_bytes()).map_err(Error)?;
    drop(request.new_password);
    drop(capability);
    let plan = plan(&host, &sources)?;
    let mut journal = Journal { version: 1, transaction: storage::random_id()?, family_id: plan.family_id,
        members: plan.members, outcome: wire::Outcome::Pending, pending: Vec::new() };
    for source in sources {
        let metadata = storage::trusted_file(&source.source.path)?.metadata().map_err(|_| Error("metadata_failed"))?;
        journal.pending.push(Replacement { safe_id: source.source.id.clone(), device: metadata.dev(), inode: metadata.ino(), bytes: metadata.len(), metadata_sha256: source.stable_sha256,
            old: source.json, new: serde_json::from_slice(&descriptor.encode_token(&source.source.id, source.token.keyslot).map_err(Error)?).map_err(|_| Error("encode_failed"))? });
    }
    Repository::new(Path::new(DIRECTORY)).write(&journal)?;
    apply(&mut journal, wire::Direction::Complete, |id| storage::persistent_safe_path(id))?;
    Ok(entry(journal))
}

pub(crate) fn status() -> Result<wire::Status> {
    let host_opening = storage::rotation_host()?;
    Ok(wire::Status { host_opening, transactions: Repository::new(Path::new(DIRECTORY)).read_all()?.into_iter().map(entry).collect() })
}

pub(crate) fn recover(request: wire::Recover) -> Result<wire::Entry> {
    require_opening(&storage::rotation_host()?, &request.host_opening)?;
    let repository = Repository::new(Path::new(DIRECTORY));
    let mut journal = repository.read(&request.transaction)?;
    require(journal.outcome == wire::Outcome::Pending, "family_rotation_finished")?;
    for member in &journal.members { storage::rotation_closed(&member.safe_id)?; }
    // Recovery is an explicit current host-opening request, never a startup replay.
    apply(&mut journal, request.direction, |id| storage::persistent_safe_path(id))?;
    Ok(entry(journal))
}

fn require_opening(current: &str, requested: &str) -> Result<()> {
    require(current == requested, "family_opening_changed")
}

pub(crate) fn require_available(id: &str) -> Result<()> {
    for journal in Repository::new(Path::new(DIRECTORY)).read_all()? {
        require(journal.outcome != wire::Outcome::Pending || !journal.members.iter().any(|member| member.safe_id == id), "family_password_recovery_required")?;
    }
    Ok(())
}

pub(crate) fn pending_safes() -> Result<Vec<String>> {
    Ok(Repository::new(Path::new(DIRECTORY)).read_all()?.into_iter()
        .filter(|journal| journal.outcome == wire::Outcome::Pending)
        .flat_map(|journal| journal.members.into_iter().map(|member| member.safe_id))
        .collect::<std::collections::BTreeSet<_>>().into_iter().collect())
}

pub(crate) fn require_family_available(family_id: &str) -> Result<()> {
    for journal in Repository::new(Path::new(DIRECTORY)).read_all()? {
        require(journal.outcome != wire::Outcome::Pending || journal.family_id != family_id, "family_password_recovery_required")?;
    }
    Ok(())
}

fn apply(journal: &mut Journal, direction: wire::Direction, resolve: impl Fn(&str) -> Result<PathBuf>) -> Result<()> {
    // Preflight the WHOLE set on each explicit recovery. A changed/replaced
    // inode or unknown header blocks every write, rather than guessing a key.
    let mut paths = Vec::new();
    for replacement in &journal.pending {
        let path = resolve(&replacement.safe_id)?;
        let metadata = storage::trusted_file(&path)?.metadata().map_err(|_| Error("metadata_failed"))?;
        require(metadata.dev() == replacement.device && metadata.ino() == replacement.inode && metadata.len() == replacement.bytes, "family_source_changed")?;
        let observed = observe(Source { id: replacement.safe_id.clone(), title: String::new(), path: path.clone() })?;
        require(observed.stable_sha256 == replacement.metadata_sha256
            && (observed.json == replacement.old || observed.json == replacement.new), "family_header_changed")?;
        paths.push(path);
    }
    for (replacement, path) in journal.pending.iter().zip(paths) {
        let target = if direction == wire::Direction::Complete { &replacement.new } else { &replacement.old };
        replace(&path, target)?;
        let observed = observe(Source { id: replacement.safe_id.clone(), title: String::new(), path })?;
        require(observed.json == *target && observed.stable_sha256 == replacement.metadata_sha256, "family_token_write_failed")?;
    }
    journal.outcome = if direction == wire::Direction::Complete { wire::Outcome::Complete } else { wire::Outcome::RolledBack };
    journal.pending.clear(); // Do not retain obsolete password wrappers in the current catalog.
    Repository::new(Path::new(DIRECTORY)).write(journal)
}

fn test_key(path: &Path, slot: u8, key: &[u8]) -> Result<()> {
    command(path, &["open", "--type", "luks2", "--test-passphrase", "--disable-external-tokens", "--key-slot", &slot.to_string(), "--key-file", "-"], key)
        .map_err(|_| Error("family_keyslot_mismatch"))
}

fn replace(path: &Path, token: &serde_json::Value) -> Result<()> {
    command(path, &["token", "import", "--token-id", "0", "--token-replace", "--json-file", "-"],
        &serde_json::to_vec(token).map_err(|_| Error("encode_failed"))?)?;
    storage::trusted_file(path)?.sync_all().map_err(|_| Error("family_header_sync_failed"))
}

fn command(path: &Path, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = Command::new("/usr/sbin/cryptsetup").args(args).arg(path).env_clear().env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_| Error("family_command_failed"))?;
    let written = child.stdin.take().ok_or(Error("family_command_failed"))?.write_all(input);
    let status = child.wait().map_err(|_| Error("family_command_failed"))?;
    written.map_err(|_| Error("family_command_failed"))?;
    require(status.success(), "family_command_failed")
}

fn entry(journal: Journal) -> wire::Entry {
    wire::Entry { transaction: journal.transaction, family_id: journal.family_id, members: journal.members, outcome: journal.outcome }
}

struct Repository<'a> { root: &'a Path }
impl<'a> Repository<'a> {
    fn new(root: &'a Path) -> Self { Self { root } }

    fn read_all(&self) -> Result<Vec<Journal>> {
        if !self.root.try_exists().map_err(|_| Error("family_journal_unavailable"))? { return Ok(Vec::new()); }
        storage::private_directory(self.root, false)?;
        let mut journals = Vec::new();
        for file in fs::read_dir(self.root).map_err(|_| Error("family_journal_unavailable"))? {
            let file = file.map_err(|_| Error("family_journal_unavailable"))?;
            let name = file.file_name();
            let name = name.to_str().ok_or(Error("invalid_family_journal"))?;
            if let Some(id) = name.strip_suffix(".json") { journals.push(self.read(id)?); }
            else { require(name.strip_suffix(".pending").is_some_and(|id| storage::validate_id(id).is_ok()), "invalid_family_journal")?; }
            require(journals.len() <= 128, "family_journal_limit")?;
        }
        journals.sort_by(|left, right| left.transaction.cmp(&right.transaction));
        Ok(journals)
    }

    fn read(&self, id: &str) -> Result<Journal> {
        storage::validate_id(id)?;
        let mut bytes = Vec::new();
        storage::trusted_file(&self.root.join(format!("{id}.json")))?.take(LIMIT + 1).read_to_end(&mut bytes).map_err(|_| Error("family_journal_unavailable"))?;
        require(bytes.len() as u64 <= LIMIT, "invalid_family_journal")?;
        let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_family_journal"))?;
        storage::validate_id(&journal.family_id)?;
        require(journal.version == 1 && journal.transaction == id && !journal.members.is_empty() && journal.members.len() <= MEMBER_LIMIT
            && if journal.outcome == wire::Outcome::Pending { journal.pending.len() == journal.members.len() } else { journal.pending.is_empty() }, "invalid_family_journal")?;
        let mut ids = std::collections::BTreeSet::new();
        for member in &journal.members { storage::validate_id(&member.safe_id)?; require(ids.insert(&member.safe_id), "invalid_family_journal")?; }
        for (replacement, member) in journal.pending.iter().zip(&journal.members) {
            require(replacement.safe_id == member.safe_id && replacement.bytes >= 32 * 1024 * 1024
                && replacement.metadata_sha256.len() == 64 && replacement.metadata_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid_family_journal")?;
            let old = family::Descriptor::decode_token(&serde_json::to_vec(&replacement.old).map_err(|_| Error("encode_failed"))?).map_err(Error)?;
            let new = family::Descriptor::decode_token(&serde_json::to_vec(&replacement.new).map_err(|_| Error("encode_failed"))?).map_err(Error)?;
            require(old.safe_id == member.safe_id && new.safe_id == member.safe_id && old.keyslot == new.keyslot
                && old.descriptor.family_id() == journal.family_id && new.descriptor.family_id() == journal.family_id, "invalid_family_journal")?;
        }
        Ok(journal)
    }

    fn write(&self, journal: &Journal) -> Result<()> {
        storage::private_directory(self.root, true)?;
        let bytes = serde_json::to_vec(journal).map_err(|_| Error("encode_failed"))?;
        require(bytes.len() as u64 <= LIMIT, "family_journal_limit")?;
        let temporary = self.root.join(format!("{}.pending", journal.transaction));
        if temporary.try_exists().map_err(|_| Error("family_journal_unavailable"))? {
            storage::trusted_file(&temporary)?;
            fs::remove_file(&temporary).map_err(|_| Error("family_journal_unavailable"))?;
        }
        let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary).map_err(|_| Error("family_journal_unavailable"))?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("family_journal_unavailable"))?;
        fs::rename(&temporary, self.root.join(format!("{}.json", journal.transaction))).map_err(|_| Error("family_journal_unavailable"))?;
        File::open(self.root).and_then(|directory| directory.sync_all()).map_err(|_| Error("family_journal_unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::io::{Seek, SeekFrom};

    const PASSWORD: &[u8] = b"synthetic-original-family-password";
    const NEW_PASSWORD: &[u8] = b"synthetic-replacement-family-password";

    fn checked<T>(result: Result<T>) -> T { result.unwrap_or_else(|error| panic!("{}", error.0)) }

    fn setup() -> PathBuf {
        assert_eq!(std::env::var("OBLIVION_FAMILY_ROTATION_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(!Path::new("/run/oblivion").exists());
        let root = PathBuf::from("/run/oblivion/family-fixture");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions("/run/oblivion", fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn image(root: &Path, id: &str, descriptor: &family::Descriptor, capability: &family::Capability) -> Source {
        let path = root.join(format!("{id}.luks"));
        let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).unwrap();
        file.set_len(32 * 1024 * 1024).unwrap();
        let key = family::credential_for_safe(capability, id).unwrap();
        checked(command(&path, &["luksFormat", "--batch-mode", "--type", "luks2", "--key-slot", "0", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-"], key.as_ref()));
        checked(replace(&path, &serde_json::from_slice(&descriptor.encode_token(id, 0).unwrap()).unwrap()));
        file.seek(SeekFrom::Start(24 * 1024 * 1024)).unwrap();
        file.write_all(&[67; 4096]).unwrap();
        file.sync_all().unwrap();
        Source { id: id.to_string(), title: format!("Fixture {id}"), path }
    }

    fn pending(sources: Vec<Observed>, descriptor: &family::Descriptor) -> Journal {
        let plan = checked(plan(&"a".repeat(32), &sources));
        Journal { version: 1, transaction: "b".repeat(32), family_id: plan.family_id, members: plan.members,
            outcome: wire::Outcome::Pending, pending: sources.into_iter().map(|source| {
                let metadata = fs::metadata(&source.source.path).unwrap();
                Replacement { safe_id: source.source.id.clone(), device: metadata.dev(), inode: metadata.ino(), bytes: metadata.len(), metadata_sha256: source.stable_sha256,
                    old: source.json, new: serde_json::from_slice(&descriptor.encode_token(&source.source.id, source.token.keyslot).unwrap()).unwrap() }
            }).collect() }
    }

    #[test]
    fn stale_host_opening_cannot_authorize_change_or_recovery() {
        checked(require_opening(&"a".repeat(32), &"a".repeat(32)));
        assert_eq!(require_opening(&"b".repeat(32), &"a".repeat(32)).err().unwrap().0, "family_opening_changed");
        assert!(serde_json::from_value::<wire::Recover>(serde_json::json!({
            "transaction":"b".repeat(32),"host_opening":"a".repeat(32),"direction":"complete","paths":["/not-authorized"]
        })).is_err());
    }

    #[test]
    #[ignore = "isolated root tmpfs /run and real cryptsetup, no mappings or VM"]
    fn interrupted_rewrap_fences_family_and_recovers_original_keys_and_standalone_child() {
        let root = setup();
        let (old, capability) = family::new_family(PASSWORD).unwrap();
        let new = family::wrap_descriptor(&capability, NEW_PASSWORD).unwrap();
        let first = image(&root, &"1".repeat(32), &old, &capability);
        let child = image(&root, &"2".repeat(32), &old, &capability);
        let external = root.join("external-before.luks");
        fs::copy(&child.path, &external).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
        let paths = std::collections::BTreeMap::from([(first.id.clone(), first.path.clone()), (child.id.clone(), child.path.clone())]);
        let mut journal = pending(vec![checked(observe(first)), checked(observe(child))], &new);
        let repository = Repository::new(Path::new(DIRECTORY));
        checked(repository.write(&journal));
        // A process/power interruption after member one leaves mixed wrappers.
        checked(replace(&paths[&journal.pending[0].safe_id], &journal.pending[0].new));
        drop(journal);
        journal = checked(repository.read(&"b".repeat(32)));
        for member in &journal.members { assert_eq!(require_available(&member.safe_id).err().unwrap().0, "family_password_recovery_required"); }
        assert_eq!(require_family_available(capability.family_id()).err().unwrap().0, "family_password_recovery_required");
        checked(require_available(&"f".repeat(32)));
        checked(apply(&mut journal, wire::Direction::Complete, |id| Ok(paths[id].clone())));
        assert!(checked(repository.read(&journal.transaction)).pending.is_empty());
        assert!(journal.outcome == wire::Outcome::Complete);
        for member in &journal.members {
            checked(require_available(&member.safe_id));
            let token = checked(storage::safe_family_token(&paths[&member.safe_id]));
            assert!(family::unlock_descriptor(&token.descriptor, PASSWORD).is_err());
            let unlocked = family::unlock_descriptor(&token.descriptor, NEW_PASSWORD).unwrap();
            let key = family::credential_for_safe(&unlocked, &member.safe_id).unwrap();
            assert_eq!(*key, *family::credential_for_safe(&capability, &member.safe_id).unwrap());
            checked(test_key(&paths[&member.safe_id], token.keyslot, key.as_ref()));
            let mut data = File::open(&paths[&member.safe_id]).unwrap();
            data.seek(SeekFrom::Start(24 * 1024 * 1024)).unwrap();
            let mut sentinel = [0;4096]; data.read_exact(&mut sentinel).unwrap(); assert_eq!(sentinel, [67;4096]);
        }
        // A new standalone child copy unlocks without the mother's catalog.
        let standalone = root.join("standalone-after.luks");
        fs::copy(&paths[&"2".repeat(32)], &standalone).unwrap();
        fs::set_permissions(&standalone, fs::Permissions::from_mode(0o600)).unwrap();
        let token = checked(storage::safe_family_token(&standalone));
        let unlocked = family::unlock_descriptor(&token.descriptor, NEW_PASSWORD).unwrap();
        checked(test_key(&standalone, token.keyslot, family::credential_for_safe(&unlocked, &token.safe_id).unwrap().as_ref()));
        let old_copy = checked(storage::safe_family_token(&external));
        assert!(family::unlock_descriptor(&old_copy.descriptor, PASSWORD).is_ok());
    }

    #[test]
    #[ignore = "isolated root tmpfs /run and real cryptsetup, no mappings or VM"]
    fn unknown_member_header_prevents_every_write_and_explicit_rollback_restores_all() {
        let root = setup();
        let (old, capability) = family::new_family(PASSWORD).unwrap();
        let new = family::wrap_descriptor(&capability, NEW_PASSWORD).unwrap();
        let first = image(&root, &"1".repeat(32), &old, &capability);
        let child = image(&root, &"2".repeat(32), &old, &capability);
        let paths = std::collections::BTreeMap::from([(first.id.clone(), first.path.clone()), (child.id.clone(), child.path.clone())]);
        let mut journal = pending(vec![checked(observe(first)), checked(observe(child))], &new);
        let repository = Repository::new(Path::new(DIRECTORY));
        checked(repository.write(&journal));
        checked(replace(&paths[&journal.pending[0].safe_id], &journal.pending[0].new));
        let (foreign, _) = family::new_family(b"another-synthetic-family-password").unwrap();
        let foreign_token = serde_json::from_slice(&foreign.encode_token(&journal.pending[1].safe_id, 0).unwrap()).unwrap();
        checked(replace(&paths[&journal.pending[1].safe_id], &foreign_token));
        assert_eq!(apply(&mut journal, wire::Direction::Rollback, |id| Ok(paths[id].clone())).err().unwrap().0, "family_header_changed");
        let first_after = checked(observe(Source { id: journal.pending[0].safe_id.clone(), title: String::new(), path: paths[&journal.pending[0].safe_id].clone() }));
        assert_eq!(first_after.json, journal.pending[0].new);
        checked(replace(&paths[&journal.pending[1].safe_id], &journal.pending[1].old));
        checked(apply(&mut journal, wire::Direction::Rollback, |id| Ok(paths[id].clone())));
        assert!(journal.outcome == wire::Outcome::RolledBack);
        assert!(checked(repository.read(&journal.transaction)).pending.is_empty());
        for member in &journal.members {
            let token = checked(storage::safe_family_token(&paths[&member.safe_id]));
            assert!(family::unlock_descriptor(&token.descriptor, PASSWORD).is_ok());
            assert!(family::unlock_descriptor(&token.descriptor, NEW_PASSWORD).is_err());
        }
    }
}
