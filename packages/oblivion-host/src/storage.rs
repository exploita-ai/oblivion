use oblivion_host::scope;
use oblivion_host::{egress, family, network, proxy_profiles, safe_access, transfers};
use oblivion_transport::policy::{Access, Policy, Session, Tools};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const GENERAL: &str = "/dev/mapper/oblivion-general";
const SESSION: &str = "/dev/mapper/oblivion-session";
const RUN: &str = "/run/oblivion";
const RECOVERY: &str = "/run/oblivion/recovery-required";
const MOUNT: &str = "/run/oblivion/general";
const PROFILE: &str = "/run/oblivion/general/profile";
const EPHEMERAL: &str = "/run/oblivion/ephemeral.luks";
const MIB: u64 = 1024 * 1024;
const RAM_PROFILE_RESERVE_MIB: u64 = 16;
const CHILD_LIMIT: usize = 128;
const CHILD_DIRECT_LIMIT: usize = 8;
const CHILD_BRANCH_LIMIT: usize = 32;
const CHILD_DEPTH_LIMIT: usize = 4;
const CHILD_RECORD_LIMIT: usize = 24 * 1024;

fn share_imports() -> crate::share_import::Repository {
    crate::share_import::Repository::new(Path::new(MOUNT))
}

fn raw_restores() -> crate::raw_restore::Repository { crate::raw_restore::Repository::new(Path::new(MOUNT)) }

fn collection_directory(id: &str) -> Result<Option<PathBuf>> {
    let imported = share_imports().imported()?.into_iter().find(|safe| safe.id == id).map(|safe| safe.directory);
    let restored = raw_restores().restored()?.into_iter().find(|safe| safe.metadata.safe_id == id).map(|safe| safe.directory);
    require(imported.is_none() || restored.is_none(), "duplicate_safe_identity")?;
    Ok(imported.or(restored))
}

pub(crate) fn persistent_safe_import(id: &str) -> Result<Option<crate::share_import::Imported>> {
    validate_id(id)?;
    Ok(share_imports().imported()?.into_iter().find(|safe| safe.id == id))
}

pub(crate) fn persistent_safe_parents() -> Result<Vec<(String, String)>> {
    Ok(safe_relations(&agent_safe_records()?)?.into_iter().map(|relation| (relation.id, relation.parent)).collect())
}

/// Created volumes, portable collections and personal restores share one
/// current identity contract. Pending collections are never resolved here.
pub(crate) fn persistent_safe_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    let ordinary = Path::new(MOUNT).join(format!("sessions/{id}.luks"));
    if let Some(directory) = collection_directory(id)? {
        require(!ordinary.try_exists().map_err(|_| Error("image_check_failed"))?, "duplicate_safe_identity")?;
        return Ok(directory.join("volume.luks"));
    }
    Ok(ordinary)
}

pub(crate) fn persistent_safe_profile(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(match collection_directory(id)? {
        Some(directory) => directory.join("profile"),
        None => Path::new(PROFILE).join("sessions").join(id),
    })
}

fn persistent_safe_title(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(match collection_directory(id)? {
        Some(directory) => directory.join("title"),
        None => Path::new(MOUNT).join(format!("sessions/{id}.title")),
    })
}

fn default_ephemeral_mib() -> u64 { 512 }

pub struct Error(pub &'static str);
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSafeRequest {
    agent: String,
    task: Zeroizing<String>,
    request_id: String,
    creator_chat_id: Option<String>,
}

impl AgentSafeRequest {
    fn validate(&self) -> Result<()> {
        validate_id(&self.request_id)?;
        require(matches!(self.agent.as_str(), "codex" | "claude" | "opencode2")
            && !self.task.trim().is_empty() && self.task.len() <= 16384 && !self.task.contains('\0')
            && self.creator_chat_id.as_ref().is_none_or(|id| !id.is_empty() && id.len() <= 256
                && !id.chars().any(char::is_control)), "invalid_safe_child_request")
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AgentSafeState {
    Creating,
    AwaitingStart,
    Failed,
    RecoveryRequired,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentSafeRecord {
    version: u8,
    id: String,
    parent: String,
    created_by_agent: bool,
    agent: String,
    creator_chat_id: Option<String>,
    request_id: String,
    // Delivery needs this Safe's family capability. Personal backup checkpoints
    // the ciphertext and context inside the Safe; portable Share excludes it.
    sealed_task: family::SealedTask,
    attempts: Vec<String>,
    ephemeral: bool,
    mib: u64,
    state: AgentSafeState,
}

#[derive(Serialize)]
struct AgentSafeInfo {
    id: String,
    parent: String,
    created_by_agent: bool,
    agent: String,
    creator_chat_id: Option<String>,
    request_id: String,
    ephemeral: bool,
    mib: u64,
    state: AgentSafeState,
}

#[derive(Serialize)]
struct AgentSafeLimits {
    direct_children: usize,
    descendants: usize,
    depth: usize,
    records: usize,
}

impl AgentSafeRecord {
    fn from_origin(origin: oblivion_host::safe_origin::AgentCreated, mib: u64) -> Self {
        Self { version: 1, id: origin.safe_id, parent: origin.parent_id, created_by_agent: true,
            agent: origin.agent, creator_chat_id: origin.creator_chat_id, request_id: origin.request_id,
            sealed_task: origin.sealed_task, attempts: origin.attempts, ephemeral: false, mib, state: AgentSafeState::AwaitingStart }
    }
    fn origin(&self) -> oblivion_host::safe_origin::AgentCreated {
        oblivion_host::safe_origin::AgentCreated {
            safe_id: self.id.clone(), parent_id: self.parent.clone(), request_id: self.request_id.clone(),
            agent: self.agent.clone(), creator_chat_id: self.creator_chat_id.clone(),
            sealed_task: self.sealed_task.clone(), attempts: self.attempts.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        validate_id(&self.parent)?;
        validate_id(&self.request_id)?;
        oblivion_host::volume::size(self.mib).map_err(Error)?;
        require(self.version == 1 && self.created_by_agent && self.id != self.parent
            && matches!(self.agent.as_str(), "codex" | "claude" | "opencode2")
            && oblivion_host::safe_origin::attempts_valid(&self.request_id, &self.attempts)
            && self.creator_chat_id.as_ref().is_none_or(|id| !id.is_empty() && id.len() <= 256
                && !id.chars().any(char::is_control)), "invalid_safe_provenance")
    }

    fn info(&self) -> AgentSafeInfo {
        AgentSafeInfo {
            id: self.id.clone(), parent: self.parent.clone(), created_by_agent: true,
            agent: self.agent.clone(), creator_chat_id: self.creator_chat_id.clone(),
            request_id: self.request_id.clone(), ephemeral: self.ephemeral, mib: self.mib,
            // Seeing an unfinished journal outside its locked creation request
            // is recovery work, never evidence that an agent is running.
            state: if matches!(self.state, AgentSafeState::Creating) {
                AgentSafeState::RecoveryRequired
            } else { self.state },
        }
    }

    fn directory(&self) -> PathBuf {
        if self.ephemeral { Path::new(RUN).join("agent-safes/provenance") }
        else { Path::new(PROFILE).join("safe-provenance") }
    }

    fn image(&self, pending: bool) -> PathBuf {
        let directory = if self.ephemeral { Path::new(RUN).join("agent-safes/images") }
            else { Path::new(MOUNT).join("sessions") };
        directory.join(format!("{}.{}", self.id, if pending { "pending" } else { "luks" }))
    }
}

pub(crate) fn private_directory(path: &Path, create: bool) -> Result<bool> {
    if !path.try_exists().map_err(|_| Error("safe_profile_unavailable"))? {
        if !create { return Ok(false) }
        fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
            .map_err(|_| Error("safe_profile_unavailable"))?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Error("safe_profile_unavailable"))?;
    require(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0, "unsafe_safe_profile")?;
    Ok(true)
}

fn agent_safe_records() -> Result<Vec<AgentSafeRecord>> {
    let mut records = Vec::new();
    let mut directories = vec![(Path::new(RUN).join("agent-safes/provenance"), true)];
    if mount_mode()? != MountMode::Closed {
        directories.push((Path::new(PROFILE).join("safe-provenance"), false));
    }
    for (directory, ephemeral) in directories {
        if !private_directory(&directory, false)? { continue }
        let mut entries = 0;
        for entry in fs::read_dir(&directory).map_err(|_| Error("safe_profile_unavailable"))? {
            entries += 1;
            require(entries <= CHILD_LIMIT * 2, "safe_provenance_limit")?;
            let entry = entry.map_err(|_| Error("safe_profile_unavailable"))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error("invalid_safe_provenance"))?;
            if name.ends_with(".pending") { continue }
            let id = name.strip_suffix(".json").ok_or(Error("invalid_safe_provenance"))?;
            validate_id(id)?;
            let mut bytes = Zeroizing::new(Vec::new());
            trusted_file(&entry.path())?.take(CHILD_RECORD_LIMIT as u64 + 1).read_to_end(&mut bytes)
                .map_err(|_| Error("safe_profile_unavailable"))?;
            require(bytes.len() <= CHILD_RECORD_LIMIT, "invalid_safe_provenance")?;
            let record: AgentSafeRecord = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_safe_provenance"))?;
            record.validate()?;
            require(record.id == id && record.ephemeral == ephemeral
                && !records.iter().any(|existing: &AgentSafeRecord| existing.id == id), "invalid_safe_provenance")?;
            records.push(record);
            require(records.len() <= CHILD_LIMIT, "safe_provenance_limit")?;
        }
    }
    for restored in raw_restores().restored()? {
        if let oblivion_host::safe_origin::Origin::AgentCreated { record: origin } = restored.metadata.origin {
            require(!records.iter().any(|record| record.id == origin.safe_id), "duplicate_safe_identity")?;
            let bytes = trusted_file(&restored.directory.join("volume.luks"))?.metadata().map_err(|_| Error("metadata_failed"))?.len();
            require(bytes % MIB == 0, "invalid_session_size")?;
            let record = AgentSafeRecord::from_origin(origin, bytes / MIB);
            record.validate()?;
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));
    for record in &records { safe_ancestors(&records, &record.id)?; }
    Ok(records)
}

fn write_agent_safe(record: &AgentSafeRecord) -> Result<()> {
    if raw_restores().restored()?.iter().any(|safe| safe.metadata.safe_id == record.id) {
        return raw_restores().write_agent_origin(record.origin());
    }
    let directory = record.directory();
    private_directory(&directory, true)?;
    let pending = directory.join(format!("{}.pending", record.id));
    let path = directory.join(format!("{}.json", record.id));
    let bytes = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error("encode_failed"))?);
    require(bytes.len() <= CHILD_RECORD_LIMIT, "invalid_safe_provenance")?;
    for existing in [&pending, &path] {
        if existing.try_exists().map_err(|_| Error("safe_profile_unavailable"))? { trusted_file(existing)?; }
    }
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending)
        .map_err(|_| Error("safe_profile_write_failed"))?;
    file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("safe_profile_write_failed"))?;
    fs::rename(&pending, &path).map_err(|_| Error("safe_profile_write_failed"))?;
    sync_directory(&directory)
}

/// The caller holds storage.lock. Opening nonces and real ownership are
/// rechecked; this returns only the sealed journal, never its plaintext task.
pub(crate) fn task_origin(opening: &oblivion_host::autolock::Opening) -> Result<oblivion_host::safe_origin::AgentCreated> {
    require(opening.slot == scope::current() && idle_opening()?.as_ref() == Some(opening), "session_changed")?;
    require_safe_branch_open(&opening.safe_id)?;
    require(session_info()?.is_some_and(|entry| matches!(entry.1.as_str(), "documents" | "agent"))
        && !crate::vm::stopped()?, "session_not_open")?;
    let records = agent_safe_records()?;
    let record = records.iter().find(|record| record.id == opening.safe_id).ok_or(Error("safe_not_agent_created"))?;
    require(matches!(record.state, AgentSafeState::AwaitingStart), "child_safe_not_available")?;
    Ok(record.origin())
}

/// Prior Info must come from the trusted guest/managed-job inspection by the
/// dispatcher, not from a public request. No derived job status is journaled.
pub(crate) fn task_attempt(opening: &oblivion_host::autolock::Opening, prior: Option<&oblivion_host::managed::Info>, retry: bool) -> Result<String> {
    let origin = task_origin(opening)?;
    let records = agent_safe_records()?;
    let mut record = records.into_iter().find(|record| record.id == opening.safe_id).ok_or(Error("safe_not_agent_created"))?;
    let attempt = match origin.attempts.last() {
        None => { require(!retry, "task_retry_not_confirmed")?; record.request_id.clone() }
        Some(last) if !retry => return Ok(last.clone()),
        Some(last) => {
            require(origin.attempts.len() < oblivion_host::safe_origin::ATTEMPT_LIMIT, "task_attempt_limit")?;
            let info = prior.ok_or(Error("task_retry_not_confirmed"))?;
            require(info.valid() && info.request_id == *last && info.agent == origin.agent
                && matches!(info.state, oblivion_host::managed::State::Failed | oblivion_host::managed::State::Cancelled), "task_retry_not_confirmed")?;
            random_id()?
        }
    };
    require(!record.attempts.contains(&attempt), "task_attempt_conflict")?;
    record.attempts.push(attempt.clone());
    write_agent_safe(&record)?;
    Ok(attempt)
}

struct SafeRelation { id: String, parent: String }

fn safe_relations(records: &[AgentSafeRecord]) -> Result<Vec<SafeRelation>> {
    let mut relations: Vec<_> = records.iter().map(|record| SafeRelation { id: record.id.clone(), parent: record.parent.clone() }).collect();
    for imported in share_imports().imported()? {
        require(!records.iter().any(|record| record.id == imported.id), "duplicate_safe_identity")?;
        if let Some(parent) = imported.parent { relations.push(SafeRelation { id: imported.id, parent }); }
    }
    for restored in raw_restores().restored()? {
        if let oblivion_host::safe_origin::Origin::Shared { parent_id: Some(parent), .. } = restored.metadata.origin {
            require(!relations.iter().any(|relation| relation.id == restored.metadata.safe_id), "duplicate_safe_identity")?;
            relations.push(SafeRelation { id: restored.metadata.safe_id, parent });
        }
    }
    Ok(relations)
}

fn safe_ancestors(records: &[AgentSafeRecord], id: &str) -> Result<Vec<String>> {
    relation_ancestors(&safe_relations(records)?, id)
}

fn relation_ancestors(records: &[SafeRelation], id: &str) -> Result<Vec<String>> {
    let mut ancestors = Vec::new();
    let mut current = id;
    while let Some(record) = records.iter().find(|record| record.id == current) {
        require(record.parent != id && !ancestors.contains(&record.parent), "invalid_safe_provenance")?;
        ancestors.push(record.parent.clone());
        require(ancestors.len() <= CHILD_DEPTH_LIMIT, "safe_depth_limit")?;
        current = &record.parent;
    }
    Ok(ancestors)
}

fn safe_branch(records: &[AgentSafeRecord], root: &str) -> Result<Vec<(String, usize)>> {
    relation_branch(&safe_relations(records)?, root)
}

fn relation_branch(records: &[SafeRelation], root: &str) -> Result<Vec<(String, usize)>> {
    let mut branch = vec![(root.to_string(), 0)];
    for record in records {
        if let Some(depth) = relation_ancestors(records, &record.id)?.iter().position(|parent| parent == root) {
            branch.push((record.id.clone(), depth + 1));
        }
    }
    branch.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    Ok(branch)
}

fn validate_child_limits(records: &[AgentSafeRecord], parent: &str) -> Result<()> {
    let relations = safe_relations(records)?;
    let ancestors = relation_ancestors(&relations, parent)?;
    require(records.len() < CHILD_LIMIT, "safe_provenance_limit")?;
    require(relations.iter().filter(|record| record.parent == parent).count() < CHILD_DIRECT_LIMIT, "safe_child_limit")?;
    require(ancestors.len() < CHILD_DEPTH_LIMIT, "safe_depth_limit")?;
    for ancestor in ancestors.iter().map(String::as_str).chain(std::iter::once(parent)) {
        require(relation_branch(&relations, ancestor)?.len() <= CHILD_BRANCH_LIMIT, "safe_branch_limit")?;
    }
    Ok(())
}

fn branch_latches() -> Result<Vec<(String, PathBuf)>> {
    let directory = Path::new(RUN).join("closing-branches");
    if !private_directory(&directory, false)? { return Ok(Vec::new()) }
    let mut latches = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|_| Error("branch_latch_failed"))? {
        require(latches.len() < 512, "branch_latch_failed")?;
        let entry = entry.map_err(|_| Error("branch_latch_failed"))?;
        let name = entry.file_name();
        let (id, nonce) = name.to_str().and_then(|name| name.split_once('-')).ok_or(Error("branch_latch_failed"))?;
        validate_id(id)?;
        validate_id(nonce)?;
        trusted_file(&entry.path())?;
        latches.push((id.to_string(), entry.path()));
    }
    Ok(latches)
}

fn mark_branch_closing(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    let directory = Path::new(RUN).join("closing-branches");
    private_directory(&directory, true)?;
    let path = directory.join(format!("{id}-{}", random_id()?));
    OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)
        .map_err(|_| Error("branch_latch_failed"))?;
    Ok(path)
}

fn mark_recovery() -> Result<()> {
    runtime()?;
    OpenOptions::new().write(true).create(true).truncate(false).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(RECOVERY)
        .map_err(|_| Error("recovery_marker_failed"))?;
    Ok(())
}

fn require_branch_open(records: &[AgentSafeRecord], id: &str) -> Result<()> {
    let mut ancestry = safe_ancestors(records, id)?;
    ancestry.push(id.to_string());
    require(!branch_latches()?.iter().any(|(root, _)| ancestry.contains(root)), "safe_branch_closing")?;
    for target in crate::idle_controller::fences()? {
        if let crate::idle_controller::Target::Safe { opening } = target {
            let current = scope::within(opening.slot, idle_opening)?;
            let applies = if crate::share_host::is_maintenance(&opening)? { id == opening.safe_id } else { ancestry.contains(&opening.safe_id) };
            require(!applies || current.as_ref() != Some(&opening), "safe_branch_closing")?;
        }
    }
    Ok(())
}

pub(crate) fn require_safe_branch_open(id: &str) -> Result<()> {
    require(!recovery_required()? && !runtime_record("session-recovery-required").exists(), "recovery_required")?;
    require_branch_open(&agent_safe_records()?, id)
}

fn read_nonce(path: &Path) -> Result<Option<String>> {
    if !path.try_exists().map_err(|_| Error("idle_opening_unavailable"))? { return Ok(None) }
    let mut nonce = String::new();
    trusted_file(path)?.take(33).read_to_string(&mut nonce).map_err(|_| Error("idle_opening_unavailable"))?;
    validate_id(&nonce)?;
    Ok(Some(nonce))
}

pub(crate) fn idle_opening() -> Result<Option<oblivion_host::autolock::Opening>> {
    let Some((safe_id, _)) = session_info()? else { return Ok(None) };
    let nonce = read_nonce(&runtime_record("opening-nonce"))?.ok_or(Error("idle_opening_unknown"))?;
    Ok(Some(oblivion_host::autolock::Opening { slot: scope::current(), safe_id, nonce }))
}

fn ephemeral_child_id() -> Result<Option<String>> {
    read_nonce(&runtime_record("ephemeral-child"))
}

fn ephemeral_session() -> Result<bool> {
    Ok(Path::new(&scope::path(EPHEMERAL)).try_exists().map_err(|_| Error("ephemeral_check_failed"))?
        || ephemeral_child_id()?.is_some())
}

fn available_child<'a>(records: &'a [AgentSafeRecord], id: &str) -> Result<&'a AgentSafeRecord> {
    let record = records.iter().find(|record| record.id == id).ok_or(Error("child_safe_not_found"))?;
    require(matches!(record.state, AgentSafeState::AwaitingStart), "child_safe_not_available")?;
    Ok(record)
}

/// Called through the private root worker channel while storage.lock is held.
/// Neither a guest nor a frontend chooses the source slot or parent identity.
pub(crate) fn child_family_source(child: &str) -> Result<oblivion_host::autolock::Opening> {
    validate_id(child)?;
    require(mount_mode()? != MountMode::Closed && !recovery_required()?, "general_not_open")?;
    let records = agent_safe_records()?;
    let record = available_child(&records, child)?;
    require(if record.ephemeral { matches!(mount_mode()?, MountMode::ReadOnly | MountMode::RamOnly) }
        else { mount_mode()? == MountMode::ReadWrite }, "child_storage_mode_changed")?;
    require_branch_open(&records, child)?;
    let parent = open_sessions()?.into_iter().find(|entry| entry.id.as_deref() == Some(&record.parent))
        .ok_or(Error("parent_safe_not_open"))?;
    scope::within(parent.slot, || {
        require(!parent.recovery_required && matches!(parent.mode.as_deref(), Some("documents" | "agent"))
            && ephemeral_session()? == record.ephemeral && !runtime_record("session-recovery-required").exists(), "parent_safe_not_open")?;
        let owner = crate::vm::session_owner()?;
        require(crate::safe_tools::owner_alive(&owner)?, "parent_safe_not_open")?;
        idle_opening()?.ok_or(Error("parent_safe_not_open"))
    })
}

/// Callers hold storage.lock. The immutable creation receipt, live parent VM
/// and opening nonce all belong to the controller, never to guest parameters.
pub(crate) fn require_child_source(parent: &oblivion_host::autolock::Opening, child: &str, request: &str) -> Result<()> {
    validate_id(child)?;
    validate_id(request)?;
    let records = agent_safe_records()?;
    let record = available_child(&records, child)?;
    require(record.parent == parent.safe_id && record.request_id == request
        && child_family_source(child)? == *parent, "parent_safe_changed")
}

/// The opening worker rechecks the vacant mapping under its operation lock.
/// A competing opener can make this choice fail; it cannot be replaced.
pub(crate) fn child_launch_target(parent: &oblivion_host::autolock::Opening, child: &str, request: &str) -> Result<scope::Slot> {
    require_child_source(parent, child, request)?;
    let opened = open_sessions()?;
    require(!opened.iter().any(|entry| entry.recovery_required), "recovery_required")?;
    require(!opened.iter().any(|entry| entry.id.as_deref() == Some(child)), "session_already_open")?;
    for index in 0..scope::LIMIT {
        let slot = scope::Slot::try_from(index).map_err(Error)?;
        if opened.iter().any(|entry| entry.slot == slot) { continue; }
        let vacant = scope::within(slot, || -> Result<bool> {
            Ok(session_info()?.is_none() && !mapping_open("oblivion-session")?
                && !runtime_record("session-recovery-required").exists() && crate::vm::stopped()?)
        })?;
        if vacant { return Ok(slot); }
    }
    Err(Error("no_safe_slots"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildStartAuthority {
    parent: oblivion_host::autolock::Opening,
    request_id: String,
    opening: oblivion_host::autolock::Opening,
}

fn require_child_start(authority: Option<&ChildStartAuthority>, opening: &oblivion_host::autolock::Opening) -> Result<()> {
    let Some(authority) = authority else { return Ok(()) };
    require(crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
    crate::ipc::require_tool_owner()?;
    require(authority.opening == *opening && idle_opening()?.as_ref() == Some(opening), "session_changed")?;
    require_child_source(&authority.parent, &opening.safe_id, &authority.request_id)
}

pub(crate) fn require_current_idle_activity(activity: &oblivion_host::autolock::Activity) -> Result<()> {
    require(read_nonce(&Path::new(RUN).join("host-opening"))?.as_deref() == Some(&activity.host)
        && !recovery_required()?, "idle_opening_changed")?;
    if let Some(opening) = &activity.safe {
        scope::within(opening.slot, || -> Result<()> {
            require(idle_opening()?.as_ref() == Some(opening), "idle_opening_changed")?;
            require_safe_branch_open(&opening.safe_id)
        })?;
    }
    Ok(())
}

/// Caller holds storage.lock. Observations never count as human activity.
pub(crate) fn idle_snapshot() -> Result<crate::idle_controller::Snapshot> {
    use crate::idle_controller::Target;
    let mode = mount_mode()?;
    let general_open = mapping_open("oblivion-general")? || matches!(mode, MountMode::ReadOnly | MountMode::ReadWrite);
    let app_open = general_open || mode == MountMode::RamOnly;
    let mut host = if app_open {
        Some(read_nonce(&Path::new(RUN).join("host-opening"))?.ok_or(Error("idle_opening_unknown"))?)
    } else { None };
    let mut safes = Vec::new();
    for entry in open_sessions()? {
        let opening = scope::within(entry.slot, idle_opening)?.ok_or(Error("idle_opening_unknown"))?;
        safes.push(opening);
    }
    let physical = safes.clone();
    let mut fences = Vec::new();
    let targets = crate::idle_controller::fences()?;
    let records = if targets.iter().any(|target| matches!(target, Target::Safe { .. })) { agent_safe_records()? } else { Vec::new() };
    let branches = branch_latches()?;
    for target in targets {
        let keep = match &target {
            Target::Host { nonce } => {
                if host.is_none() && !general_open && Path::new(RECOVERY).exists() { host = Some(nonce.clone()); }
                host.as_deref() == Some(nonce)
            }
            Target::Safe { opening } => {
                if physical.contains(opening) { true } else {
                    let recovering = if crate::share_host::is_maintenance(opening)? {
                        !physical.iter().any(|current| current.slot == opening.slot || current.safe_id == opening.safe_id)
                    } else {
                        let branch = safe_branch(&records, &opening.safe_id)?;
                        !physical.iter().any(|current| current.safe_id == opening.safe_id)
                            && branches.iter().any(|entry| entry.0 == opening.safe_id)
                            && (physical.iter().any(|current| branch.iter().any(|entry| entry.0 == current.safe_id))
                                || scope::within(opening.slot, || runtime_record("session-recovery-required").exists()))
                    };
                    if recovering { safes.push(opening.clone()); }
                    recovering
                }
            }
        };
        if keep { fences.push(target) } else { crate::idle_controller::clear_fence(&target)?; }
    }
    let mut roots = Vec::new();
    for target in &fences {
        if let Target::Safe { opening } = target {
            if !crate::share_host::is_maintenance(opening)? { roots.push(opening.safe_id.clone()); }
        }
    }
    for current in &physical {
        let mut ancestry = safe_ancestors(&records, &current.safe_id)?;
        ancestry.push(current.safe_id.clone());
        if roots.iter().any(|root| ancestry.contains(root))
            && !fences.iter().any(|target| matches!(target, Target::Safe { opening } if opening == current)) {
            fences.push(Target::Safe { opening: current.clone() });
        }
    }
    Ok(crate::idle_controller::Snapshot { host, safes, fences, general_open, writable: mode == MountMode::ReadWrite })
}

fn discard_ephemeral_children() -> Result<()> {
    let mut failure = None;
    for record in &agent_safe_records()? {
        let result = (|| {
            let mapping = format!("oblivion-safe-create-{}", record.id);
            if mapping_open(&mapping)? { crypt_close(&mapping)?; }
            if record.ephemeral { discard_ephemeral_child(record)?; }
            Ok(())
        })();
        if let Err(error) = result { failure = Some(error); }
    }
    if let Some(error) = failure { return Err(error) }
    for (_, path) in branch_latches()? { fs::remove_file(path).map_err(|_| Error("branch_latch_failed"))?; }
    Ok(())
}

fn discard_ephemeral_child(record: &AgentSafeRecord) -> Result<()> {
    let mapping = format!("oblivion-safe-create-{}", record.id);
    if mapping_open(&mapping)? { crypt_close(&mapping)?; }
    for path in [record.image(true), record.image(false),
        record.directory().join(format!("{}.json", record.id)),
        record.directory().join(format!("{}.pending", record.id))] {
        if path.try_exists().map_err(|_| Error("ephemeral_cleanup_failed"))? {
            trusted_file(&path)?;
            fs::remove_file(path).map_err(|_| Error("ephemeral_cleanup_failed"))?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    general_image: PathBuf,
    general_mib: u64,
    session_mib: u64,
    #[serde(default = "default_ephemeral_mib")]
    ephemeral_mib: u64,
    pbkdf_memory_kib: u32,
    manager_uid: u32,
    vm: Option<crate::vm::Config>,
    gateway: Option<crate::vm::Config>,
    import: Option<crate::vm::Config>,
    export: Option<crate::vm::Config>,
    onion: Option<crate::onion_host::Config>,
    #[serde(default)]
    gateway_network: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentStart {
    pub started: bool,
    pub opening: oblivion_host::autolock::Opening,
}

#[derive(Serialize)]
struct Status {
    slot: scope::Slot,
    app_open: bool,
    app_mode: MountMode,
    open_sessions: Vec<OpenSession>,
    session_slot_limit: u8,
    general_present: bool,
    general_incomplete: bool,
    general_bytes: u64,
    general_open: bool,
    general_mounted: bool,
    general_readonly: bool,
    session_open: bool,
    session_mode: Option<String>,
    active_session: Option<String>,
    sessions: Vec<String>,
    session_titles: std::collections::BTreeMap<String, String>,
    incomplete_sessions: Vec<String>,
    available_bytes: Option<u64>,
    session_bytes: u64,
    ephemeral_session_bytes: u64,
    session_sizes: std::collections::BTreeMap<String, u64>,
    pending_growth: Vec<String>,
    family_password_pending: Vec<String>,
    vm_state: Option<String>,
    laboratory_emulation: bool,
    recovery_required: bool,
    egress: Option<egress::Status>,
    network_policy: Option<network::Status>,
    gateway_state: Option<String>,
    gateway_vm_state: Option<String>,
    gateway_network: bool,
    transfers_configured: bool,
    safe_access: safe_access::Status,
    network_status: network::Observation,
    system: crate::system_info::Status,
    debug_available: bool,
    agent_safes: Vec<AgentSafeInfo>,
    safe_parents: Vec<oblivion_host::sharing::Parent>,
    agent_safe_limits: AgentSafeLimits,
    closing_branches: Vec<String>,
}

pub fn main() -> Result<()> {
    secure_process()?;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(position) = args.iter().position(|value| value == "--family-channel") {
        args.remove(position);
    }
    if let Some(position) = args.iter().position(|value| value == "--safe-tools-owner") {
        args.remove(position);
    }
    let slot = if let Some(position) = args.iter().position(|value| value == "--slot") {
        let value = args.get(position + 1).ok_or(Error("invalid_session_slot"))?
            .parse::<u8>().map_err(|_| Error("invalid_session_slot"))?;
        args.drain(position..position + 2);
        oblivion_host::scope::Slot::try_from(value).map_err(Error)?
    } else { Default::default() };
    let expected = if let Some(position) = args.iter().position(|value| value == "--expected-session") {
        let id = args.get(position + 1).ok_or(Error("invalid_session_id"))?.clone();
        validate_id(&id)?;
        args.drain(position..position + 2);
        Some(id)
    } else { None };
    oblivion_host::scope::within(slot, || execute(args, expected.as_deref()))
}

fn share_slot_allows_operation(op: &str, mode: MountMode) -> bool {
    matches!(op, "status" | "share-release" | "share-export-cancel" | "share-export-cleanup" | "close" | "leave"
        | "force-leave" | "lock" | "recover" | "idle-close" | "idle-lock" | "share-import-finish"
        | "share-import-abort" | "share-import-discard" | "share-import-status")
        // A persistent title is catalog metadata, not a write through this
        // slot's maintenance VM. Temporary titles still belong to its opening.
        || op == "rename-session" && mode == MountMode::ReadWrite
}

fn execute(args: Vec<String>, expected: Option<&str>) -> Result<()> {
    runtime()?;
    if scope::current().index() != 0 {
        fs::create_dir_all(scope::current().runtime()).map_err(|_| Error("runtime_directory_failed"))?;
    }
    require(args.len() >= 3 && args[0] == "--config", "usage")?;
    let config = Config::read(Path::new(&args[1]))?;
    if args.len() == 3 && args[2] == "serve" {
        return crate::ipc::serve(Path::new(&args[1]), config.manager_uid);
    }
    let op = args[2].as_str();
    if args.len() == 3 && op == "debug" {
        return crate::debug::run(&password(false)?);
    }
    // The worker's stop hook runs while the controller may hold storage.lock
    // waiting for systemd stop. It must not reacquire that lock and deadlock.
    if args.len() == 3 && op == "transfer-cleanup" {
        return crate::transfer_host::cleanup();
    }
    if args.len() == 3 && op == "onion-cleanup" {
        return crate::onion_host::cleanup();
    }
    if args.len() == 3 && op == "onion-host-run" {
        require(
            !recovery_required()? && mount_mode()? != MountMode::Closed,
            "general_not_open",
        )?;
        return crate::onion_host::serve(
            config.onion.as_ref().ok_or(Error("onion_not_configured"))?,
            config.manager_uid,
        );
    }
    if args.len() == 3 && op == "transfer-host-run" {
        require(
            !recovery_required()?
                && (crate::transfer_host::archiving()?
                    || mapping_open("oblivion-session")? && !crate::vm::stopped()?),
            "session_not_open",
        )?;
        return crate::transfer_host::serve(
            config.import.as_ref(),
            config.export.as_ref(),
            config.manager_uid,
        );
    }
    if args.len() == 3 && op == "gateway-host-run" {
        require(!recovery_required()?, "recovery_required")?;
        require(!session_info()?.is_some_and(|entry| entry.1 == "share"), "safe_maintenance_active")?;
        require(mount_mode()? != MountMode::Closed, "general_not_open")?;
        let gateway = config
            .gateway
            .as_ref()
            .ok_or(Error("gateway_not_configured"))?;
        let (saved, selected) = transport_profiles()?;
        return crate::gateway::serve(
            gateway,
            selected.unwrap_or(saved).into_transport(),
            config.gateway_network,
        );
    }
    require(
        args.len()
            == if matches!(
                op,
                "open" | "enter" | "enter-documents" | "discard-session-pending" | "agent-release" | "live-media-release" | "branch-recover"
                    | "backup-export-begin" | "backup-discard" | "family-password-preview"
                    | "open-child-documents" | "open-agent-child" | "share-export-source-open" | "share-release" | "share-import-finish"
            ) {
                4
            } else {
                3
            },
        "usage",
    )?;
    // A separate marker per request prevents a stale callback from clearing
    // another valid close's latch. Its SafeID comes from the explicit callback,
    // never the slot's potentially newer occupant.
    let branch_latch = if matches!(op, "close" | "leave" | "force-leave") {
        expected.map(mark_branch_closing).transpose()?
    } else { None };
    // Latch before taking the operation lock: a worker may still be completing
    // when the manager dies. Its completion must not permit another opening.
    if matches!(op, "lock" | "recover") {
        mark_recovery()?;
    }
    let _lock = if matches!(op, "lock" | "recover" | "child-start-close" | "share-release" | "share-export-cancel" | "share-export-cleanup" | "share-import-finish" | "share-import-abort" | "share-import-discard") || branch_latch.is_some() {
        recovery_lock()?
    } else {
        lock()?
    };
    // A delayed view callback cannot operate on a new session which reused
    // its old slot. Verify under the same lock as the operation itself.
    require(!matches!(op, "share-export-source-open" | "backup-export-begin" | "family-password-preview") || expected.is_some(), "expected_session_required")?;
    require(!matches!(op, "share-import-open" | "share-import-finish") || expected.is_some(), "expected_session_required")?;
    require(!matches!(op, "open-child-documents" | "open-agent-child") || expected == args.get(3).map(String::as_str), "expected_session_required")?;
    if let Some(id) = expected {
        if op == "family-password-preview" {
            require(args[3] == id, "session_changed")?;
        } else if matches!(op, "share-export-source-open" | "open-child-documents" | "open-agent-child" | "backup-export-begin") {
            crate::share_host::require_closed_target(&args[3], id, session_info()?.as_ref().map(|entry| entry.0.as_str()))?;
        } else if op == "share-import-open" {
            require(session_info()?.is_none(), "session_changed")?;
        } else if op != "idle-close" && !session_info()?.is_some_and(|info| info.0 == id) {
            if let Some(path) = &branch_latch {
                if path.try_exists().map_err(|_| Error("branch_latch_failed"))? {
                    fs::remove_file(path).map_err(|_| Error("branch_latch_failed"))?;
                }
            }
            return Err(Error("session_changed"));
        }
    }
    if matches!(op, "safe-child-create" | "safe-tools-status" | "managed-release") {
        require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
        crate::ipc::require_tool_owner()?;
    }
    if session_info()?.is_some_and(|entry| entry.1 == "share") {
        let mode = if op == "rename-session" { mount_mode()? } else { MountMode::Closed };
        require(share_slot_allows_operation(op, mode), "safe_maintenance_active")?;
    }
    // A broken transfer record must not prevent teardown from revoking the
    // current grant. Admission guards apply to new work, not close/recovery.
    if !matches!(
        op,
        "status"
            | "transfers"
            | "onion"
            | "safe-access"
            | "network-policy"
            | "close"
            | "close-idle"
            | "live-media-release"
            | "idle-close"
            | "idle-lock"
            | "native-start-failed"
            | "child-start-close"
            | "share-release"
            | "share-export-cancel"
            | "share-export-cleanup"
            | "share-import-finish" | "share-import-abort" | "share-import-discard" | "share-import-status"
            | "branch-recover"
            | "leave"
            | "force-leave"
            | "lock"
            | "recover"
    ) {
        require(
            !crate::transfer_host::archiving()? && !crate::onion_host::archiving()?,
            "backup_active",
        )?;
    }
    if matches!(
        op,
        "init-general"
            | "unlock"
            | "unlock-read-only"
            | "enter-ram"
            | "share-export-source-open"
            | "backup-export-begin" | "backup-import-begin" | "backup-import-finish"
            | "share-import-begin" | "share-import-open" | "share-import-commit"
            | "open-child-documents"
            | "open-agent-child"
            | "create"
            | "safe-child-create"
            | "rename-session"
            | "session-storage"
            | "open"
            | "enter-documents"
            | "enter-documents-ephemeral"
            | "start-agent"
            | "start-child-agent"
            | "discard-general-pending"
            | "discard-session-pending"
            | "egress"
            | "proxy-profiles"
            | "network-policy"
            | "safe-access"
    ) {
        require(!recovery_required()?, "recovery_required")?;
    }
    match op {
        "family-password-preview" => {
            let plan = crate::family_rotation_host::preview(&args[3])?;
            println!("{}", serde_json::to_string(&plan).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "family-password-change" => {
            let bytes = read_storage_request(oblivion_host::family_rotation::CHANGE_LIMIT)?;
            let request = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_family_password_request"))?;
            drop(bytes);
            let result = crate::family_rotation_host::change(request)?;
            println!("{}", serde_json::to_string(&result).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "family-password-status" => {
            let result = crate::family_rotation_host::status()?;
            println!("{}", serde_json::to_string(&result).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "family-password-recover" => {
            let bytes = read_storage_request(4096)?;
            let request = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_family_password_request"))?;
            let result = crate::family_rotation_host::recover(request)?;
            println!("{}", serde_json::to_string(&result).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "backup-export-begin" => {
            config.prepare_backup(&args[3], &password(false)?)?;
            let source = closed_session_file(&args[3])?;
            let result = crate::backup_host::begin_export(&args[3], &source)?;
            println!("{}", serde_json::to_string(&result).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "backup-import-begin" => {
            let result = crate::backup_host::begin_import()?;
            println!("{}", serde_json::to_string(&result).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "backup-import-finish" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin().take(4097).read_to_end(&mut bytes).map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_secret_length")?;
            let request: oblivion_host::backup::Finish = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_backup_request"))?;
            crate::backup_host::ready_import(&request.transaction)?;
            let safe_id = config.finish_restore(&request.transaction, request.password.as_bytes())?;
            crate::backup_host::committed(&request.transaction, &safe_id)?;
            println!("{}", serde_json::to_string(&oblivion_host::backup::Finished { transaction: request.transaction, safe_id }).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "backup-discard" => {
            backup_catalog_open()?;
            crate::backup_host::discard(&args[3])
        }
        "open-agent-child" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Authority { parent: oblivion_host::autolock::Opening, request_id: String, opening: oblivion_host::autolock::Opening }
            require(crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
            crate::ipc::require_tool_owner()?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_child_task_request"))?;
            require(bytes.len() <= 1024, "invalid_child_task_request")?;
            let authority: Authority = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_child_task_request"))?;
            require(authority.opening.slot == scope::current() && authority.opening.safe_id == args[3], "session_changed")?;
            validate_id(&authority.opening.nonce)?;
            let record = agent_safe_records()?;
            let record = available_child(&record, &args[3])?;
            require(record.parent == authority.parent.safe_id && record.request_id == authority.request_id
                && child_family_source(&args[3])? == authority.parent, "parent_safe_changed")?;
            config.open_child_documents(&args[3], Some(&authority.opening.nonce))?;
            let authorized = (|| {
                crate::ipc::require_tool_owner()?;
                require(child_family_source(&args[3])? == authority.parent
                    && idle_opening()?.as_ref() == Some(&authority.opening), "parent_safe_changed")
            })();
            if authorized.is_err() { require(config.close_slot(true)?, "child_cleanup_required")?; }
            authorized?;
            let opening = idle_opening()?.ok_or(Error("idle_opening_unknown"))?;
            println!("{}", serde_json::to_string(&opening).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "open-child-documents" => {
            require(crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
            config.open_child_documents(&args[3], None)
        }
        "child-start-close" => {
            require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_child_task_request"))?;
            require(bytes.len() <= 1024, "invalid_child_task_request")?;
            let opening: oblivion_host::autolock::Opening = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_child_task_request"))?;
            require(opening.slot == scope::current() && expected == Some(opening.safe_id.as_str())
                && idle_opening()?.as_ref() == Some(&opening), "session_changed")?;
            // A task might have created descendants before its acknowledgement
            // was lost. Stop the owned branch without deleting RAM volumes;
            // explicit branch/host lock still discards ephemeral work.
            require(config.close_branch_owners(&opening.safe_id, true, None, false)?, "child_cleanup_required")
        }
        "share-import-begin" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let request = crate::share_import::request::<oblivion_host::sharing::Begin>(oblivion_share::manifest::MAX_METADATA + 4096)?;
            let begun = config.begin_share_import(request)?;
            println!("{}", serde_json::to_string(&begun).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "share-import-open" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let request = crate::share_import::request::<oblivion_host::sharing::Open>(4096)?;
            let opening = config.open_share_import(request, expected.ok_or(Error("expected_session_required"))?)?;
            println!("{}", serde_json::to_string(&opening).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "share-import-finish" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            config.finish_share_import(crate::share_import::request(4096)?, &args[3], expected.ok_or(Error("expected_session_required"))?)
        }
        "share-import-commit" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let committed = config.commit_share_import(crate::share_import::request(1024)?)?;
            println!("{}", serde_json::to_string(&committed).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "share-import-abort" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let request = crate::share_import::request::<oblivion_host::sharing::Abort>(1024)?;
            let batch = share_imports().read(&request.transaction)?;
            batch.authorize(&request.nonce)?;
            config.discard_share_import(batch, true)
        }
        "share-import-discard" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let request = crate::share_import::request::<oblivion_host::sharing::Discard>(1024)?;
            require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
            match share_imports().read(&request.transaction) {
                Ok(batch) => config.discard_share_import(batch, false),
                Err(_) => share_imports().discard_initial_metadata(&request.transaction),
            }
        }
        "share-import-status" => {
            let status = if mount_mode()? == MountMode::Closed { Vec::new() } else { share_imports().status()? };
            println!("{}", serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "share-export-source-open" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let request: crate::share_export::ExportOpen = serde_json::from_reader(std::io::stdin().take(4097))
                .map_err(|_| Error("invalid_share_request"))?;
            let metadata = config.open_export_share(&args[3], &request)?;
            println!("{}", serde_json::to_string(&metadata).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "share-export-cleanup" => {
            require(crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let opening: oblivion_host::autolock::Opening = serde_json::from_reader(std::io::stdin().take(1025))
                .map_err(|_| Error("invalid_share_release"))?;
            require(expected == Some(opening.safe_id.as_str()) && idle_opening()?.as_ref() == Some(&opening)
                && crate::share_host::is_maintenance(&opening)?, "session_changed")?;
            require(config.close_slot(true)?, "share_cleanup_required")
        }
        "share-release" => {
            require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let opening = crate::share_host::client(&args[3])?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_share_release"))?;
            require(bytes.len() <= 1024, "invalid_share_release")?;
            if !bytes.is_empty() {
                let callback: oblivion_host::autolock::Opening = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_share_release"))?;
                require(callback == opening, "session_changed")?;
            }
            require(expected == Some(opening.safe_id.as_str()) && idle_opening()?.as_ref() == Some(&opening)
                && session_info()?.is_some_and(|entry| entry.1 == "share"), "session_changed")?;
            let _detached = crate::vm::remove_copy_port(&args[3]);
            require(config.close_slot(false)?, "locked_without_tor_state")
        }
        "share-export-cancel" => {
            require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_share_channel_required")?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_share_release"))?;
            require(!bytes.is_empty() && bytes.len() <= 1024, "invalid_share_release")?;
            let opening: oblivion_host::autolock::Opening = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_share_release"))?;
            require(opening.slot == scope::current() && expected == Some(opening.safe_id.as_str())
                && idle_opening()?.as_ref() == Some(&opening)
                && session_info()?.is_some_and(|entry| entry.1 == "share"), "session_changed")?;
            require(!crate::share_host::occupied()?, "share_attached")?;
            require(config.close_slot(false)?, "locked_without_tor_state")
        }
        "idle-close" | "idle-lock" => {
            require(crate::ipc::family_channel_available(), "trusted_idle_channel_required")?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_idle_request"))?;
            require(bytes.len() <= 1024, "invalid_idle_request")?;
            let target: crate::idle_controller::Target = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_idle_request"))?;
            target.validate()?;
            require(crate::idle_controller::fenced(&target)?, "idle_opening_changed")?;
            let result = match &target {
                crate::idle_controller::Target::Host { nonce } => {
                    require(op == "idle-lock" && expected.is_none(), "invalid_idle_request")?;
                    let current = read_nonce(&Path::new(RUN).join("host-opening"))?;
                    if current.as_deref() != Some(nonce) && !(current.is_none() && Path::new(RECOVERY).exists()) {
                        crate::idle_controller::clear_fence(&target)?;
                        return Err(Error("idle_opening_changed"));
                    }
                    mark_recovery()?;
                    config.close_all()
                }
                crate::idle_controller::Target::Safe { opening } => {
                    require(op == "idle-close" && opening.slot == scope::current()
                        && expected == Some(opening.safe_id.as_str()), "invalid_idle_request")?;
                    let current = idle_opening()?;
                    if crate::share_host::is_maintenance(opening)? {
                        if current.as_ref().is_some_and(|current| current != opening) {
                            crate::idle_controller::clear_fence(&target)?;
                            return Err(Error("idle_opening_changed"));
                        }
                        // A maintenance timeout owns this opening only. A
                        // separately opened descendant keeps its own timer.
                        let result = require(config.close_slot(true)?, "locked_without_tor_state");
                        if result.is_ok() { crate::idle_controller::clear_fence(&target)?; }
                        return result;
                    }
                    let recovering = !open_sessions()?.iter().any(|entry| entry.id.as_ref() == Some(&opening.safe_id))
                        && branch_latches()?.iter().any(|entry| entry.0 == opening.safe_id);
                    if current.as_ref() != Some(opening) && !recovering {
                        crate::idle_controller::clear_fence(&target)?;
                        return Err(Error("idle_opening_changed"));
                    }
                    require(config.close_branch_id(&opening.safe_id, true, None)?, "locked_without_tor_state")
                }
            };
            if result.is_ok() { crate::idle_controller::clear_fence(&target)?; }
            result
        }
        "proxy-profiles" => {
            let mode = mount_mode()?;
            require(mode != MountMode::Closed, "general_not_open")?;
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin().take(4097).read_to_end(&mut bytes)
                .map_err(|_| Error("invalid_proxy_profile_command"))?;
            let command = proxy_profiles::Command::decode(&bytes).map_err(Error)?;
            let mut registry = proxy_profiles::Registry::new(
                read_proxy_profile_archive(&Path::new(PROFILE).join("proxy-profiles.json"))?,
                read_proxy_profile_archive(&Path::new(RUN).join("proxy-profiles.json"))?,
            ).map_err(Error)?;
            match registry.change(command, mode != MountMode::ReadWrite).map_err(Error)? {
                proxy_profiles::Change::Unchanged => {}
                proxy_profiles::Change::Saved => write_proxy_profile_archive(
                    &Path::new(PROFILE).join("proxy-profiles.json"), registry.saved())?,
                proxy_profiles::Change::Temporary => write_proxy_profile_archive(
                    &Path::new(RUN).join("proxy-profiles.json"), registry.temporary())?,
                proxy_profiles::Change::Select(transport) => {
                    require(expected.is_some(), "expected_session_required")?;
                    require(session_info()?.is_some(), "session_not_open")?;
                    config.change_transport(if mode != MountMode::ReadWrite {
                        egress::Command::Select { transport }
                    } else { egress::Command::Save { transport } })?;
                }
            }
            println!("{}", serde_json::to_string(&registry.status()).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "safe-child-create" => {
            require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin().take(CHILD_RECORD_LIMIT as u64 + 1).read_to_end(&mut bytes)
                .map_err(|_| Error("invalid_safe_child_request"))?;
            require(bytes.len() <= CHILD_RECORD_LIMIT, "invalid_safe_child_request")?;
            let request: AgentSafeRequest = serde_json::from_slice(&bytes)
                .map_err(|_| Error("invalid_safe_child_request"))?;
            request.validate()?;
            let child = config.create_agent_safe(request)?;
            println!("{}", serde_json::to_string(&child).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "safe-tools-status" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Selection { offset: u8 }
            let mut bytes = Vec::new();
            std::io::stdin().take(129).read_to_end(&mut bytes).map_err(|_| Error("invalid_safe_tools_request"))?;
            require(bytes.len() <= 128, "invalid_safe_tools_request")?;
            let selection: Selection = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_safe_tools_request"))?;
            require(usize::from(selection.offset) <= CHILD_BRANCH_LIMIT, "invalid_safe_tools_offset")?;
            let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
            require(mode == "agent", "agent_safe_required")?;
            let records = agent_safe_records()?;
            let branch = safe_branch(&records, &id)?;
            let mut ancestors = safe_ancestors(&records, &id)?;
            ancestors.push(id.clone());
            let children: Vec<_> = records.iter().filter(|record| record.id != id
                && branch.iter().any(|entry| entry.0 == record.id)).collect();
            let offset = usize::from(selection.offset);
            println!("{}", serde_json::to_string(&serde_json::json!({
                "safe_id":id,"mode":mode,
                "children":children.iter().skip(offset).take(16).map(|record| record.info()).collect::<Vec<_>>(),
                "next_offset":if offset + 16 < children.len() { Some(offset + 16) } else { None },
                "limits":AgentSafeLimits { direct_children:CHILD_DIRECT_LIMIT,descendants:CHILD_BRANCH_LIMIT,depth:CHILD_DEPTH_LIMIT,records:CHILD_LIMIT },
                "closing":recovery_required()? || branch_latches()?.iter().any(|entry| ancestors.contains(&entry.0)),
            })).map_err(|_| Error("encode_failed"))?);
            Ok(())
        }
        "branch-recover" => {
            require(expected.is_none(), "unexpected_session_argument")?;
            let root = &args[3];
            validate_id(root)?;
            let records = agent_safe_records()?;
            let opened = open_sessions()?;
            let known = records.iter().any(|record| record.id == *root || record.parent == *root)
                || opened.iter().any(|entry| entry.id.as_ref() == Some(root))
                || (mount_mode()? == MountMode::ReadWrite && sessions(".luks")?.contains(root));
            require(known && branch_latches()?.iter().any(|entry| entry.0 == *root), "branch_recovery_unavailable")?;
            require(config.close_branch_id(root, true, None)?, "locked_without_tor_state")
        }
        "onion" => {
            let mut payload = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut payload)
                .map_err(|_| Error("invalid_onion_request"))?;
            require(payload.len() <= 4096, "invalid_onion_request")?;
            let command: oblivion_host::onion::Command =
                serde_json::from_slice(&payload).map_err(|_| Error("invalid_onion_request"))?;
            command.validate().map_err(Error)?;
            if matches!(
                command,
                oblivion_host::onion::Command::Receive { .. }
                    | oblivion_host::onion::Command::Share { .. }
                    | oblivion_host::onion::Command::PrepareBackup { .. }
                    | oblivion_host::onion::Command::Prepare { .. }
            ) {
                require(
                    crate::safe_access_store::status(true)?.current != Access::Offline,
                    "network_offline",
                )?;
            }
            let status = match command {
                oblivion_host::onion::Command::Status {} => {
                    crate::onion_host::status(config.onion.is_some())?
                }
                oblivion_host::onion::Command::Receive { client_auth } => {
                    require(
                        config.onion.is_some()
                            && !recovery_required()?
                            && mount_mode()? != MountMode::Closed,
                        "general_not_open",
                    )?;
                    crate::onion_host::receive(client_auth)?
                }
                oblivion_host::onion::Command::Access {} => {
                    let access = crate::onion_host::access()?;
                    println!(
                        "{}",
                        serde_json::to_string(&access).map_err(|_| Error("encode_failed"))?
                    );
                    return Ok(());
                }
                oblivion_host::onion::Command::Freeze {} => crate::onion_host::freeze()?,
                oblivion_host::onion::Command::Import {} => crate::onion_host::import()?,
                oblivion_host::onion::Command::Stage {} => crate::onion_host::stage()?,
                oblivion_host::onion::Command::Share { client_auth } => {
                    crate::onion_host::share(client_auth)?
                }
                oblivion_host::onion::Command::Cancel {} => {
                    let _checkpoint = crate::onion_host::shutdown()?;
                    oblivion_host::onion::Status::closed(config.onion.is_some())
                }
                oblivion_host::onion::Command::PrepareBackup {
                    id,
                    password,
                    ttl_seconds,
                } => {
                    require(config.onion.is_some(), "onion_not_configured")?;
                    require(
                        !crate::onion_host::prepared()? && !crate::transfer_host::prepared()?,
                        "transfer_active",
                    )?;
                    config.prepare_backup(&id, password.as_bytes())?;
                    crate::onion_host::start(id, ttl_seconds, true)?
                }
                oblivion_host::onion::Command::Prepare { ttl_seconds } => {
                    require(config.onion.is_some(), "onion_not_configured")?;
                    require(
                        !recovery_required()? && mount_mode()? != MountMode::Closed,
                        "general_not_open",
                    )?;
                    let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
                    require(
                        matches!(mode.as_str(), "documents" | "agent") && !crate::vm::stopped()?,
                        "session_not_open",
                    )?;
                    crate::onion_host::start(id, ttl_seconds, false)?
                }
            };
            println!(
                "{}",
                serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "init-general" => config.initialize(&password(true)?),
        "discard-general-pending" => {
            require(
                !config
                    .general_image
                    .try_exists()
                    .map_err(|_| Error("image_check_failed"))?,
                "general_already_exists",
            )?;
            require(
                !mapping_open("oblivion-general")? && mount_mode()? == MountMode::Closed,
                "volume_busy",
            )?;
            discard_pending(&config.pending_general())
        }
        "discard-session-pending" => {
            validate_id(&args[3])?;
            require(
                mount_mode()? == MountMode::ReadWrite,
                "general_not_writable",
            )?;
            discard_personal_restore(&args[3])
        }
        "enter-ram" => config.enter_ram(),
        "unlock" | "unlock-read-only" => {
            config.unlock(&password(false)?, op == "unlock-read-only")?;
            crate::idle_controller::clear_temporary()?;
            clear_key_file("proxy-profiles.json")?;
            clear_transport_selection()?;
            clear_network_selection()?;
            Ok(())
        }
        "create" => config.create(&password(true)?, config.session_mib),
        "session-storage" => {
            let request: oblivion_host::volume::Request =
                serde_json::from_slice(&read_storage_request(4096)?)
                    .map_err(|_| Error("invalid_storage_request"))?;
            request.validate().map_err(Error)?;
            match request {
                oblivion_host::volume::Request::Create { mib, password } => {
                    config.create(password.as_bytes(), mib)
                }
                oblivion_host::volume::Request::Grow { id, mib, password } => {
                    config.grow(&id, mib, password.as_bytes())
                }
                oblivion_host::volume::Request::Discard { id } => discard_growth(&id),
                oblivion_host::volume::Request::Usage {} => {
                    let response = session_admin(oblivion_host::safe_admin::Command::Usage {})?;
                    println!(
                        "{}",
                        serde_json::to_string(&response).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
            }
        }
        "rename-session" => {
            let command: oblivion_host::session_title::Rename =
                serde_json::from_slice(&password(false)?)
                    .map_err(|_| Error("invalid_session_title"))?;
            validate_id(&command.id)?;
            oblivion_host::session_title::validate(&command.title).map_err(Error)?;
            let mode = mount_mode()?;
            require(mode != MountMode::Closed, "general_not_open")?;
            if mode != MountMode::ReadWrite {
                require(
                    session_info()?.is_some_and(|(id, _)| id == command.id),
                    "session_not_open",
                )?;
                return write_key_file("session-title", command.title.as_bytes());
            }
            trusted_file(&persistent_safe_path(&command.id)?)?;
            write_session_title(&command.id, &command.title)
        }
        "enter-documents" | "enter-documents-ephemeral" => {
            let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
            vm.validate()?;
            require(crate::vm::stopped()?, "vm_already_running")?;
            let id = if op == "enter-documents" {
                args[3].clone()
            } else {
                random_id()?
            };
            if op == "enter-documents" {
                config.open(&id, &password(false)?)?;
            } else {
                config.open_ephemeral()?;
            }
            write_session_info(&id, "starting")?;
            if let Err(error) = vm.start_documents() {
                crate::vm::stop(true)?;
                close_session()?;
                clear_key_file("session-info")?;
                return Err(error);
            }
            write_session_info(&id, "documents")
        }
        "shutdown-runtime" | "shutdown-idle" => {
            require(fs::read_to_string("/proc/cmdline").map_err(|_| Error("runtime_unavailable"))?
                .split_whitespace().any(|arg| arg == "oblivion.runtime=1"), "native_runtime_required")?;
            require(open_sessions()?.is_empty(), "runtime_busy")?;
            if op == "shutdown-idle" {
                require(!crate::backup_host::pending()?, "runtime_busy")?;
                mark_recovery()?;
                config.close_all()?;
            }
            require(mount_mode()? == MountMode::Closed, "runtime_busy")?;
            run("/usr/bin/systemctl", &["poweroff", "--no-block"], None)
        }
        "pin-safe" => {
            require(!recovery_required()?, "recovery_required")?;
            require(session_info()?.is_some() && !crate::vm::stopped()?, "session_not_open")?;
            write_key_file("manual-owner", b"1")
        }
        "managed-release" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Lease { opening: oblivion_host::autolock::Opening, client: String }
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_managed_release"))?;
            require(bytes.len() <= 1024, "invalid_managed_release")?;
            let lease: Lease = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_managed_release"))?;
            validate_id(&lease.client)?;
            require(lease.opening.slot == scope::current() && expected == Some(lease.opening.safe_id.as_str())
                && idle_opening()?.as_ref() == Some(&lease.opening), "session_changed")?;
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            let path = clients.join(&lease.client);
            if path.exists() { fs::remove_file(path).map_err(|_| Error("client_release_failed"))?; }
            crate::vm::remove_copy_port(&lease.client)?;
            if !runtime_record("manual-owner").exists() && clients.exists()
                && fs::read_dir(&clients).map_err(|_| Error("client_release_failed"))?.next().is_none()
                && !crate::ipc::live_media_active()? {
                crate::ipc::release_family()?;
                require(config.close_branch(false, None)?, "locked_without_tor_state")?;
            }
            Ok(())
        }
        "agent-release" => {
            validate_id(&args[3])?;
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            let path = clients.join(&args[3]);
            if path.exists() {
                fs::remove_file(path).map_err(|_| Error("client_release_failed"))?;
            }
            crate::vm::remove_copy_port(&args[3])?;
            if !runtime_record("manual-owner").exists() && clients.exists()
                && fs::read_dir(&clients).map_err(|_| Error("client_release_failed"))?.next().is_none()
                && !crate::ipc::live_media_active()? {
                crate::ipc::release_family()?;
                require(config.close_branch(false, None)?, "locked_without_tor_state")?;
            }
            Ok(())
        }
        "native-start-failed" => {
            require(expected.is_some() && crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
            let mut bytes = Vec::new();
            std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_agent_start"))?;
            require(bytes.len() <= 1024, "invalid_agent_start")?;
            let opening: oblivion_host::autolock::Opening = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_agent_start"))?;
            require(opening.slot == scope::current() && expected == Some(opening.safe_id.as_str())
                && idle_opening()?.as_ref() == Some(&opening), "session_changed")?;
            require(session_info()?.is_some_and(|entry| entry.1 == "agent"), "agent_not_running")?;
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            require(!clients.exists() || fs::read_dir(clients).map_err(|_| Error("client_check_failed"))?.next().is_none(), "agent_clients_active")?;
            write_key_file("session-recovery-required", b"1")?;
            // No newly booted agent is handed to the user until its private
            // tool channel is ready. Revoke first, then stop that pinned VM.
            if config.gateway.is_some() { crate::gateway::revoke()?; }
            if crate::ipc::tool_owner_alive()? {
                crate::ipc::require_tool_owner()?;
                crate::vm::stop(false)?;
            }
            require(!crate::ipc::tool_owner_alive()?, "original_vm_still_running")?;
                    clear_key_file("native-offline")?;
            let branch = require_branch_open(&agent_safe_records()?, &opening.safe_id);
            if recovery_required()? || matches!(branch, Err(Error("safe_branch_closing"))) {
                return require(config.close_slot(true)?, "locked_without_tor_state");
            }
            branch?;
            config.vm.as_ref().ok_or(Error("vm_not_configured"))?.start_documents()?;
            write_session_info(&opening.safe_id, "documents")?;
            clear_key_file("session-recovery-required")
        }
        "start-agent" | "start-child-agent" => {
            let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
            let opening = idle_opening()?.ok_or(Error("idle_opening_unknown"))?;
            let authority: Option<ChildStartAuthority> = if op == "start-child-agent" {
                require(expected == Some(id.as_str()) && crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
                let mut bytes = Vec::new();
                std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_child_task_request"))?;
                require(bytes.len() <= 1024, "invalid_child_task_request")?;
                Some(serde_json::from_slice(&bytes).map_err(|_| Error("invalid_child_task_request"))?)
            } else { None };
            require_child_start(authority.as_ref(), &opening)?;
            if mode == "agent" {
                println!("{}", serde_json::to_string(&AgentStart { started: false, opening }).map_err(|_| Error("encode_failed"))?);
                return Ok(());
            }
            require(mode == "documents", "documents_not_open")?;
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            require(!clients.exists() || fs::read_dir(clients).map_err(|_| Error("client_check_failed"))?.next().is_none(), "transfer_active")?;
            require(!crate::ipc::live_media_active()?, "transfer_active")?;
            require(!crate::onion_host::prepared()? && !crate::transfer_host::prepared()?, "transfer_active")?;
            let access = crate::safe_access_store::status(true)?.current;
            if access == Access::Offline {
                config.admit_agent(false)?;
                let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
                write_session_info(&id, "starting")?;
                let result = (|| {
                    crate::vm::stop(false)?;
                    vm.start_agent_offline()?;
                    write_key_file("native-offline", b"1")?;
                    write_session_info(&id, "agent")
                })();
                if result.is_err() { recover_agent_start(&config)?; }
                if let Err(error) = require_child_start(authority.as_ref(), &opening) {
                    require(config.close_slot(true)?, "child_cleanup_required")?;
                    return Err(error);
                }
                if result.is_ok() { println!("{}", serde_json::to_string(&AgentStart { started: true, opening }).map_err(|_| Error("encode_failed"))?); }
                return result;
            }
            require(config.gateway.is_some(), "gateway_not_configured")?;
            let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
            let tools = session_policy(&id, access)?;
            config.prepare_agent_gateway(&id)?;
            let result = (|| {
                crate::vm::stop(false)?;
                let token = crate::gateway::prepare()?;
                vm.start_agent(&token, if access == Access::Open { "open" } else { "strict" }, tools)?;
                write_session_info(&id, "agent")
            })();
            if result.is_err() {
                recover_agent_start(&config)?;
                crate::gateway::shutdown()?;
            }
            if let Err(error) = require_child_start(authority.as_ref(), &opening) {
                require(config.close_slot(true)?, "child_cleanup_required")?;
                return Err(error);
            }
            if result.is_ok() { println!("{}", serde_json::to_string(&AgentStart { started: true, opening }).map_err(|_| Error("encode_failed"))?); }
            result
        }
        "browse" => {
            require(
                !recovery_required()?
                    && mapping_open("oblivion-session")?
                    && !crate::vm::stopped()?,
                "session_not_open",
            )?;
            let request: oblivion_transfer::browser::Request =
                serde_json::from_reader(std::io::stdin().take(4096))
                    .map_err(|_| Error("invalid_directory_request"))?;
            request
                .validate()
                .map_err(|_| Error("invalid_directory_request"))?;
            require(
                request.path.is_empty()
                    || matches!(
                        request.path.split('/').next(),
                        Some("workspace" | "imports")
                    ),
                "invalid_document_root",
            )?;
            let id = random_id()?;
            let result = (|| {
                use oblivion_transfer::endpoint::{read_message, write_message};
                let stream = crate::vm::copy_port(&id, true)?;
                let mut channel = oblivion_host::channel::Channel::new(
                    &stream,
                    std::time::Duration::from_secs(90),
                );
                let mut ready = [0; 6];
                channel
                    .read_exact(&mut ready)
                    .map_err(|_| Error("documents_not_ready"))?;
                require(&ready == b"ready\n", "invalid_transfer_guest")?;
                channel
                    .write_all(b"G")
                    .map_err(|_| Error("documents_not_ready"))?;
                write_message(&mut channel, &serde_json::json!({"browse": &request}))
                    .map_err(|_| Error("directory_request_failed"))?;
                let response: oblivion_transfer::browser::Response =
                    read_message(&mut channel, 64 * 1024)
                        .map_err(|_| Error("directory_read_failed"))?;
                let oblivion_transfer::browser::Response::Page(page) = response else {
                    return Err(Error("directory_unavailable"));
                };
                page.validate(&request)
                    .map_err(|_| Error("invalid_directory_page"))?;
                Ok(page)
            })();
            let cleanup = crate::vm::remove_copy_port(&id);
            let page = result?;
            cleanup?;
            println!(
                "{}",
                serde_json::to_string(&page).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "diagnostics" => {
            let request: oblivion_host::diagnostics::Request =
                serde_json::from_reader(std::io::stdin().take(1024))
                    .map_err(|_| Error("invalid_diagnostics_request"))?;
            let report = diagnostic_report()?;
            let output = match request {
                oblivion_host::diagnostics::Request::Preview => serde_json::to_string(&report),
                oblivion_host::diagnostics::Request::Export => serde_json::to_string(
                    &session_admin(oblivion_host::safe_admin::Command::Diagnostics { report })?,
                ),
            }
            .map_err(|_| Error("encode_failed"))?;
            println!("{output}");
            Ok(())
        }
        "safe-access" => {
            let command: safe_access::Command = serde_json::from_slice(&password(false)?)
                .map_err(|_| Error("invalid_safe_access"))?;
            config.change_access(command.mode, command.save)
        }
        "egress" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(egress::LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= egress::LIMIT, "invalid_secret_length")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_transport_command"))?;
            config.change_transport(command)
        }
        "network-policy" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_secret_length")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_network_command"))?;
            config.change_network_policy(command)
        }
        "transfers" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("transfer_request_failed"))?;
            require(bytes.len() <= 4096, "transfer_request_too_large")?;
            let command: transfers::Command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_transfer_request"))?;
            if !matches!(
                command,
                transfers::Command::List | transfers::Command::Cancel
            ) {
                require(!crate::onion_host::prepared()?, "transfer_active")?;
            }
            if !matches!(command, transfers::Command::Cancel) {
                require(
                    !recovery_required()? && mount_mode()? != MountMode::Closed,
                    "general_not_open",
                )?;
            }
            if matches!(
                command,
                transfers::Command::Import { .. }
                    | transfers::Command::Export { .. }
                    | transfers::Command::Recover
            ) {
                require(
                    !recovery_required()?
                        && mapping_open("oblivion-session")?
                        && !crate::vm::stopped()?,
                    "session_not_open",
                )?;
            }
            match command {
                transfers::Command::List => {
                    let status = crate::transfer_host::status(
                        config.import.is_some(),
                        config.export.is_some(),
                        &config.general_image,
                    )?;
                    println!(
                        "{}",
                        serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Import { source } => {
                    config
                        .import
                        .as_ref()
                        .ok_or(Error("transfers_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start(&source, &config.general_image, false)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Export { target } => {
                    config
                        .export
                        .as_ref()
                        .ok_or(Error("exports_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start(&target, &config.general_image, true)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Backup {
                    id,
                    target,
                    password,
                } => {
                    config
                        .export
                        .as_ref()
                        .ok_or(Error("exports_not_configured"))?
                        .validate()?;
                    crate::transfer_host::idle()?;
                    config.prepare_backup(&id, password.as_bytes())?;
                    drop(password);
                    let started =
                        crate::transfer_host::start_backup(&id, &target, &config.general_image)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Restore { source } => {
                    config
                        .import
                        .as_ref()
                        .ok_or(Error("transfers_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start_restore(&source, &config.general_image)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::RestoreFinish { id, password } => {
                    crate::transfer_host::idle()?;
                    config.finish_restore(&id, password.as_bytes()).map(|id| println!("{id}"))
                }
                transfers::Command::RestoreDiscard { id } => {
                    crate::transfer_host::idle()?;
                    closed_archive()?;
                    discard_personal_restore(&id)
                }
                transfers::Command::Recover => {
                    let started = crate::transfer_host::start_recovery()?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Cancel => crate::transfer_host::stop(),
            }
        }
        "open" => config.open(&args[3], &password(false)?),
        "close" | "leave" | "force-leave" => require(config.close_branch(op == "force-leave", branch_latch.as_deref())?, "locked_without_tor_state"),
        "close-idle" | "live-media-release" => {
            require(expected.is_some(), "expected_session_required")?;
            if op == "live-media-release" {
                require(crate::ipc::family_channel_available(), "trusted_safe_channel_required")?;
                validate_id(&args[3])?;
                let mut bytes = Vec::new();
                std::io::stdin().take(1025).read_to_end(&mut bytes).map_err(|_| Error("invalid_live_media_release"))?;
                require(bytes.len() <= 1024, "invalid_live_media_release")?;
                let authority: oblivion_host::autolock::Activity = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_live_media_release"))?;
                require(authority.safe.as_ref().is_some_and(|opening| opening.slot == scope::current()
                    && expected == Some(opening.safe_id.as_str())), "session_changed")?;
                require_current_idle_activity(&authority)?;
            }
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            let occupied = clients.try_exists().map_err(|_| Error("client_release_failed"))?
                && fs::read_dir(&clients).map_err(|_| Error("client_release_failed"))?.next().is_some();
            if occupied || runtime_record("manual-owner").exists() || crate::ipc::live_media_active()? { return Ok(()) }
            crate::ipc::release_family()?;
            require(config.close_branch(false, None)?, "locked_without_tor_state")
        }
        "lock" | "recover" => config.close_all(),
        "status" => {
            let mode = mount_mode()?;
            let status = Status {
                slot: scope::current(),
                app_open: mode != MountMode::Closed,
                app_mode: mode,
                open_sessions: open_sessions()?,
                session_slot_limit: scope::LIMIT,
                system: crate::system_info::status(),
                debug_available: crate::debug::available(),
                agent_safes: agent_safe_records()?.iter().map(AgentSafeRecord::info).collect(),
                safe_parents: persistent_safe_parents()?.into_iter().map(|(id, parent)| oblivion_host::sharing::Parent { id, parent }).collect(),
                agent_safe_limits: AgentSafeLimits { direct_children: CHILD_DIRECT_LIMIT,
                    descendants: CHILD_BRANCH_LIMIT, depth: CHILD_DEPTH_LIMIT, records: CHILD_LIMIT },
                family_password_pending: crate::family_rotation_host::pending_safes()?,
                closing_branches: {
                    let mut roots: Vec<_> = branch_latches()?.into_iter().map(|entry| entry.0).collect();
                    roots.sort(); roots.dedup(); roots
                },
                network_status: network_observation(
                    session_info()?.as_ref().map(|(_, mode)| mode.as_str()),
                ),
                session_mode: session_info()?.map(|(_, mode)| mode),
                active_session: session_info()?.map(|(id, _)| id),
                safe_access: crate::safe_access_store::status(mode != MountMode::Closed)?,
                general_present: config.general_image.try_exists().map_err(|_| Error("image_check_failed"))?,
                general_incomplete: config.pending_general().try_exists().map_err(|_| Error("image_check_failed"))?,
                general_bytes: config.general_mib * MIB,
                general_open: mapping_open("oblivion-general")?,
                general_mounted: matches!(mode, MountMode::ReadOnly | MountMode::ReadWrite),
                general_readonly: mode == MountMode::ReadOnly,
                session_open: mapping_open("oblivion-session")?,
                session_titles: session_titles(&mode)?,
                sessions: if mode == MountMode::ReadWrite {
                    sessions(".luks")?
                } else {
                    Vec::new()
                },
                incomplete_sessions: if mode == MountMode::ReadWrite {
                    sessions(".pending")?
                } else {
                    Vec::new()
                },
                available_bytes: if mode == MountMode::ReadWrite {
                    Some(available_bytes()?)
                } else {
                    None
                },
                session_bytes: config.session_mib * MIB,
                ephemeral_session_bytes: config.ephemeral_mib * MIB,
                session_sizes: if mode == MountMode::ReadWrite {
                    sessions(".luks")?
                        .into_iter()
                        .map(|id| {
                            let bytes = trusted_file(
                                &persistent_safe_path(&id)?,
                            )?
                            .metadata()
                            .map_err(|_| Error("image_check_failed"))?
                            .len();
                            Ok((id, bytes))
                        })
                        .collect::<Result<_>>()?
                } else {
                    Default::default()
                },
                pending_growth: if mode == MountMode::ReadWrite {
                    sessions(".growing")?
                } else {
                    Vec::new()
                },
                vm_state: if config.vm.is_some() {
                    Some(crate::vm::state()?)
                } else {
                    None
                },
                laboratory_emulation: cfg!(feature = "lab-emulation"),
                transfers_configured: config.import.is_some() || config.export.is_some(),
                gateway_network: config.gateway_network,
                recovery_required: recovery_required()?
                    || runtime_record("session-recovery-required").exists()
                    || session_info()?.is_some_and(|(_, mode)| mode == "starting"),
                gateway_state: if config.gateway.is_some() {
                    Some(crate::gateway::state()?)
                } else {
                    None
                },
                gateway_vm_state: if config.gateway.is_some() {
                    Some(crate::vm::state_role(crate::vm::Role::Gateway)?)
                } else {
                    None
                },
                network_policy: {
                    let (saved, selected) = policy_profiles()?;
                    Some(network::Status::new(saved, selected))
                },
                egress: {
                    let (saved, selected) = transport_profiles()?;
                    Some(egress::Status {
                        saved: saved.metadata(),
                        selected: selected.as_ref().unwrap_or(&saved).metadata(),
                        temporary: selected.is_some(),
                    })
                },
            };
            println!(
                "{}",
                serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        _ => Err(Error("unknown_operation")),
    }
}

impl Config {
    fn begin_share_import(&self, request: oblivion_host::sharing::Begin) -> Result<oblivion_host::sharing::Begun> {
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        let titles = session_titles(&MountMode::ReadWrite)?.into_values().collect();
        let host = share_import_host()?.ok_or(Error("share_import_authority_expired"))?;
        let batch = crate::share_import::Batch::new(request.package, request.metadata_sha256, titles, host)?;
        require(sessions(".luks")?.len() + batch.destinations.len() <= oblivion_share::manifest::MAX_SAFES, "share_import_safe_limit")?;
        require(available_bytes()? >= batch.bytes() + oblivion_host::volume::RESERVE_BYTES, "insufficient_import_space")?;
        for destination in &batch.destinations {
            require(!persistent_safe_path(&destination.safe_id)?.try_exists().map_err(|_| Error("image_check_failed"))?, "safe_already_exists")?;
        }
        share_imports().create(&batch)?;
        Ok(batch.started())
    }

    fn open_share_import(&self, request: oblivion_host::sharing::Open, expected: &str) -> Result<oblivion_host::autolock::Opening> {
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        require((16..=1024).contains(&request.password.len()), "invalid_password_length")?;
        validate_id(&request.request_id)?;
        let mut batch = share_imports().read(&request.transaction)?;
        batch.authorize(&request.nonce)?;
        let destination = batch.destination(&request.package_id)?;
        require(destination.safe_id == expected && matches!(destination.progress, crate::share_import::Progress::Awaiting), "share_import_changed")?;
        require(!mapping_open("oblivion-session")? && crate::vm::stopped()?, "safe_must_be_closed")?;
        require(!open_sessions()?.iter().any(|entry| entry.id.as_deref() == Some(expected)), "session_already_open")?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        self.admit_session(false)?;
        self.admit_family()?;
        let family_root = destination.family_root.clone();
        let mib = destination.mib;
        let path = share_imports().volume(&batch, destination);
        let (descriptor, capability) = match batch.families.get(&family_root) {
            Some(bytes) => {
                let descriptor = family::Descriptor::decode(bytes).map_err(Error)?;
                let capability = family::unlock_descriptor(&descriptor, request.password.as_bytes()).map_err(Error)?;
                (descriptor, capability)
            }
            None => {
                let (descriptor, capability) = family::new_family(request.password.as_bytes()).map_err(Error)?;
                batch.families.insert(family_root, descriptor.encode().map_err(Error)?);
                share_imports().write(&batch)?;
                (descriptor, capability)
            }
        };
        drop(request.password);
        let credential = family::credential_for_safe(&capability, expected).map_err(Error)?;
        drop(capability);
        let result = (|| {
            create_image(&path, mib)?;
            format_safe(&path, credential.as_ref(), &descriptor, expected)?;
            crypt_open_keyslot(&path, "oblivion-session", credential.as_ref(), false, Some(0))?;
            drop(credential);
            format_session()?;
            write_key_file("opening-nonce", random_id()?.as_bytes())?;
            write_key_file("session-info", &serde_json::to_vec(&(expected, "share")).map_err(|_| Error("encode_failed"))?)?;
            let opening = idle_opening()?.ok_or(Error("idle_opening_unknown"))?;
            crate::share_host::begin(&opening)?;
            write_key_file("share-import", batch.transaction.as_bytes())?;
            batch.receiving(&request.package_id, opening.clone(), request.request_id)?;
            share_imports().write(&batch)?;
            vm.start_share()?;
            require(crate::vm::network_devices()? == 0, "unsafe_share_network")?;
            Ok(opening)
        })();
        if result.is_err() { require(self.close_slot(true)?, "share_import_cleanup_required")?; }
        result
    }

    fn finish_share_import(&self, request: oblivion_host::sharing::Finish, client: &str, expected: &str) -> Result<()> {
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        let mut batch = share_imports().read(&request.transaction)?;
        batch.authorize(&request.nonce)?;
        let destination = batch.destination(&request.package_id)?;
        let crate::share_import::Progress::Receiving { opening, .. } = &destination.progress else { return Err(Error("share_import_changed")) };
        require(destination.safe_id == expected && crate::share_host::import_client(client)? == *opening
            && idle_opening()?.as_ref() == Some(opening)
            && crate::share_host::is_maintenance(opening)?, "share_import_changed")?;
        // Validate the actual guest receipt before teardown, but persist Ready
        // only after every guest/block owner is confirmed stopped.
        batch.ready(&request.package_id, request.receipt)?;
        require(self.close_slot(false)?, "share_import_cleanup_required")?;
        share_imports().write(&batch)
    }

    fn commit_share_import(&self, request: oblivion_host::sharing::Commit) -> Result<oblivion_host::sharing::Committed> {
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        let batch = share_imports().read(&request.transaction)?;
        batch.authorize(&request.nonce)?;
        batch.ready_to_publish(&request.metadata_sha256)?;
        let opened = open_sessions()?;
        let titles = session_titles(&MountMode::ReadWrite)?;
        for destination in &batch.destinations {
            require(!opened.iter().any(|entry| entry.id.as_deref() == Some(&destination.safe_id)), "share_import_busy")?;
            require(!titles.values().any(|title| title == &destination.title), "share_import_title_conflict")?;
            require(!persistent_safe_path(&destination.safe_id)?.try_exists().map_err(|_| Error("image_check_failed"))?, "safe_already_exists")?;
        }
        share_imports().commit(&batch, &request.metadata_sha256)?;
        Ok(oblivion_host::sharing::Committed { transaction: batch.transaction.clone(),
            metadata_sha256: batch.metadata_sha256.clone(), destinations: batch.choices() })
    }

    fn discard_share_import(&self, batch: crate::share_import::Batch, cancel: bool) -> Result<()> {
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        let opened = open_sessions()?;
        for destination in &batch.destinations {
            if let crate::share_import::Progress::Receiving { opening, .. } = &destination.progress {
                scope::within(opening.slot, || -> Result<()> {
                    let current = idle_opening()?;
                    if current.as_ref() == Some(opening) {
                        require(cancel, "share_import_busy")?;
                        let mut transaction = String::new();
                        trusted_file(&runtime_record("share-import"))?.take(33).read_to_string(&mut transaction).map_err(|_| Error("share_import_changed"))?;
                        require(transaction == batch.transaction && crate::share_host::is_maintenance(opening)?, "share_import_changed")?;
                        require(self.close_slot(true)?, "share_import_cleanup_required")?;
                    } else if current.is_none() {
                        // An unidentified live owner is never assumed dead.
                        require(!mapping_open("oblivion-session")? && crate::vm::stopped()?, "share_import_busy")?;
                        if cancel && crate::share_host::is_maintenance(opening)? {
                            // A previous close may have removed its nonce only
                            // after stopping the VM/DM, then failed metadata cleanup.
                            require(self.close_slot(true)?, "share_import_cleanup_required")?;
                        } else { require(!crate::share_host::occupied()?, "share_import_busy")?; }
                    } else {
                        require(!opened.iter().any(|entry| entry.id.as_deref() == Some(&destination.safe_id)), "share_import_busy")?;
                    }
                    Ok(())
                })?;
            } else {
                require(!opened.iter().any(|entry| entry.id.as_deref() == Some(&destination.safe_id)), "share_import_busy")?;
            }
        }
        share_imports().discard(&batch.transaction)
    }
}

fn session_policy(id: &str, access: Access) -> Result<Tools> {
    let (saved, selected) = policy_profiles()?;
    Ok(Tools {
        session: Session::new(id).map_err(Error)?,
        policy: selected.or(saved).unwrap_or_default(),
        access,
    })
}

fn backup_origin(id: &str) -> Result<oblivion_host::safe_origin::Origin> {
    if let Some(record) = agent_safe_records()?.into_iter().find(|record| record.id == id) {
        return Ok(oblivion_host::safe_origin::Origin::AgentCreated { record: record.origin() });
    }
    if let Some(restored) = raw_restores().restored()?.into_iter().find(|safe| safe.metadata.safe_id == id) {
        return Ok(restored.metadata.origin);
    }
    if let Some(imported) = persistent_safe_import(id)? {
        return Ok(oblivion_host::safe_origin::Origin::Shared { parent_id: imported.parent,
            provenance: imported.source.provenance, source_policy: imported.source.policy, required_proxy: imported.source.required_proxy });
    }
    Ok(oblivion_host::safe_origin::Origin::Local {})
}

fn authenticate_backup_origin(origin: &oblivion_host::safe_origin::Origin, capability: &family::Capability) -> Result<()> {
    if let oblivion_host::safe_origin::Origin::AgentCreated { record } = origin {
        let task = record.sealed_task.open(capability, &record.context()).map_err(Error)?;
        drop(task);
    }
    Ok(())
}

fn validate_restore_relations(id: &str, origin: &oblivion_host::safe_origin::Origin, records: &[AgentSafeRecord]) -> Result<()> {
    let mut relations = safe_relations(records)?;
    let parent = match origin {
        oblivion_host::safe_origin::Origin::AgentCreated { record } => Some(&record.parent_id),
        oblivion_host::safe_origin::Origin::Shared { parent_id, .. } => parent_id.as_ref(),
        _ => None,
    };
    if let Some(parent) = parent {
        require_branch_open(records, parent)?;
        require(!relations.iter().any(|relation| relation.id == id), "safe_provenance_conflict")?;
        relations.push(SafeRelation { id: id.into(), parent: parent.clone() });
    }
    for relation in &relations { relation_ancestors(&relations, &relation.id)?; }
    Ok(())
}

fn share_proxy_requirement(transport: Option<&egress::Profile>, unresolved: Option<&str>) -> Option<String> {
    match transport {
        Some(profile) => matches!(profile.transport(), oblivion_transport::Transport::Socks5 { .. }).then(|| "SOCKS5 proxy".to_owned()),
        None => unresolved.map(str::to_owned),
    }
}

impl Config {
    fn open_export_share(&self, id: &str, request: &crate::share_export::ExportOpen) -> Result<crate::share_host::Metadata> {
        self.open_share_using(id, || {
            self.admit_session(false)?;
            let path = persistent_safe_path(id)?;
            let token = safe_family_token(&path)?;
            require(token.safe_id == id, "safe_identity_mismatch")?;
            let cached = crate::ipc::export_capability(&request.export_id, id, token.descriptor.family_id())?;
            let capability = match cached {
                Some(capability) => capability,
                None => family::unlock_descriptor(&token.descriptor,
                    request.password.as_ref().ok_or(Error("share_password_required"))?.as_bytes()).map_err(Error)?,
            };
            let key = family::credential_for_safe(&capability, id).map_err(Error)?;
            crypt_open_keyslot(&path, "oblivion-session", key.as_ref(), false, Some(token.keyslot))?;
            let opened = (|| {
                write_key_file("opening-nonce", random_id()?.as_bytes())?;
                write_session_info(id, "share")?;
                crate::ipc::retain_export_capability(&request.export_id, id, &capability)?;
                crate::ipc::export_opened(&request.export_id, &idle_opening()?.ok_or(Error("idle_opening_unknown"))?)
            })();
            if opened.is_err() { self.close_slot(true)?; }
            opened
        })
    }

    fn open_share_using(&self, id: &str, open: impl FnOnce() -> Result<()>) -> Result<crate::share_host::Metadata> {
        crate::family_rotation_host::require_available(id)?;
        crate::backup_host::require_safe_available(id)?;
        validate_id(id)?;
        require(mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        require(!mapping_open("oblivion-session")? && crate::vm::stopped()?, "safe_must_be_closed")?;
        require(!open_sessions()?.iter().any(|entry| entry.id.as_deref() == Some(id)), "safe_must_be_closed")?;
        let records = agent_safe_records()?;
        require_branch_open(&records, id)?;
        let title = session_titles(&MountMode::ReadWrite)?.remove(id).unwrap_or_else(|| "Untitled Safe".into());
        let origin = backup_origin(id)?;
        let (created_by_agent, requested_agent, parent_not_included, unresolved_proxy) = match &origin {
            oblivion_host::safe_origin::Origin::Local {} => (false, None, false, None),
            oblivion_host::safe_origin::Origin::AgentCreated { record } => (true, Some(match record.agent.as_str() {
                "codex" => oblivion_share::Agent::Codex,
                "claude" => oblivion_share::Agent::Claude,
                "opencode2" => oblivion_share::Agent::Opencode2,
                _ => return Err(Error("invalid_share_agent")),
            }), true, None),
            oblivion_host::safe_origin::Origin::Shared { parent_id, provenance, required_proxy, .. } => (
                provenance.as_ref().is_some_and(|origin| origin.created_by_agent),
                provenance.as_ref().and_then(|origin| origin.requested_agent.clone()),
                parent_id.is_some() || provenance.as_ref().is_some_and(|origin| origin.parent_not_included), required_proxy.as_deref(),
            ),
        };
        let profile = persistent_safe_profile(id)?;
        let access = crate::safe_access_store::read_profile(&profile.join("access.json"))?.unwrap_or(Access::Open);
        let transport = read_transport_profile(&profile.join("transport.json"))?;
        let required_proxy = share_proxy_requirement(transport.as_ref(), unresolved_proxy);
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        open()?;
        let result = (|| {
            // Maintenance owns no provider snapshot, transport grant, token,
            // agent, terminal or source-writable OS overlay.
            write_key_file("session-info", &serde_json::to_vec(&(id, "share")).map_err(|_| Error("encode_failed"))?)?;
            crate::share_host::begin(&idle_opening()?.ok_or(Error("idle_opening_unknown"))?)?;
            vm.start_share()?;
            require(crate::vm::network_devices()? == 0, "unsafe_share_network")?;
            Ok(crate::share_host::Metadata {
                opening: idle_opening()?.ok_or(Error("idle_opening_unknown"))?, title,
                created_by_agent, requested_agent, parent_not_included,
                policy: match access { Access::Offline => oblivion_share::Policy::Offline, Access::Strict => oblivion_share::Policy::Strict, Access::Open => oblivion_share::Policy::OpenInternet },
                required_proxy,
            })
        })();
        if result.is_err() { require(self.close_slot(true)?, "share_cleanup_required")?; }
        result
    }
    fn change_access(&self, access: Access, save: bool) -> Result<()> {
        require(mount_mode()? != MountMode::Closed, "general_not_open")?;
        require(session_info()?.is_some(), "session_not_open")?;
        require(
            !save || mount_mode()? == MountMode::ReadWrite,
            "general_not_writable",
        )?;
        require(
            !session_info()?.is_some_and(|(_, mode)| mode == "starting"),
            "agent_starting",
        )?;
        // An offline native VM has no network device. Changing a label cannot
        // attach an uplink or restart active agent processes behind the user.
        require(access == Access::Offline || !runtime_record("native-offline").exists(),
            "close_offline_safe_before_enabling_network")?;
        let gateway = crate::gateway::state()?;
        if gateway == "active" {
            if let Some((id, _)) = session_info()?.filter(|(_, mode)| mode == "agent") {
                crate::gateway::policy(session_policy(&id, access)?)?;
            } else {
                crate::gateway::stop()?;
            }
        } else if gateway != "inactive" && access == Access::Offline {
            crate::gateway::stop()?;
        }
        if access == Access::Offline {
            // Separate OnionShare uplinks must obey the same global switch.
            require(crate::onion_host::shutdown()?, "onion_shutdown_unconfirmed")?;
        }
        if let Err(error) = crate::safe_access_store::set(access, save) {
            crate::gateway::destroy()?;
            return Err(error);
        }
        Ok(())
    }

    fn change_network_policy(&self, command: network::Command) -> Result<()> {
        let mode = mount_mode()?;
        require(mode != MountMode::Closed, "general_not_open")?;
        require(
            !session_info()?.is_some_and(|(_, mode)| mode == "starting"),
            "agent_starting",
        )?;
        let (saved, selected) = policy_profiles()?;
        let restore = matches!(command, network::Command::Saved {});
        let mut policy = if restore { saved } else { selected.or(saved) }.unwrap_or_default();
        let save = match command {
            network::Command::Saved {} => false,
            network::Command::Put { rule, save } => {
                require(
                    !save || mode == MountMode::ReadWrite,
                    "general_not_writable",
                )?;
                policy.put(rule).map_err(Error)?;
                save
            }
            network::Command::Remove { rule, save } => {
                require(
                    !save || mode == MountMode::ReadWrite,
                    "general_not_writable",
                )?;
                policy.remove(&rule).map_err(Error)?;
                save
            }
        };
        // Revoke existing tunnels before publishing the new rules. A failed
        // acknowledgement destroys the gateway instead of retaining old access.
        if crate::gateway::state()? == "active" {
            if let Some((id, _)) = session_info()?.filter(|(_, mode)| mode == "agent") {
                crate::gateway::policy(Tools {
                    session: Session::new(&id).map_err(Error)?,
                    policy: policy.clone(),
                    access: crate::safe_access_store::status(true)?.current,
                })?;
            }
        }
        let result = (|| {
            if restore {
                return clear_network_selection();
            }
            let path = if save { network_profile()?.join("network-policy.json") } else { runtime_record("network-policy-selection.json") };
            write_network_policy(&path, &policy, save)?;
            if save {
                clear_network_selection()?;
            }
            Ok(())
        })();
        if result.is_err() {
            crate::gateway::destroy()?;
        }
        result
    }

    fn change_transport(&self, command: egress::Command) -> Result<()> {
        let mode = mount_mode()?;
        require(mode != MountMode::Closed, "general_not_open")?;
        let save = matches!(command, egress::Command::Save { .. });
        let temporary = matches!(command, egress::Command::Select { .. });
        require(
            !save || mode == MountMode::ReadWrite,
            "general_not_writable",
        )?;
        require(!session_info()?.is_some_and(|(_, mode)| mode == "starting"), "agent_starting")?;
        let (saved, _) = transport_profiles()?;
        let profile = match command {
            egress::Command::Save { transport } | egress::Command::Select { transport } => {
                egress::Profile::new(transport).map_err(Error)?
            }
            egress::Command::Saved {} => saved,
        };
        require(
            self.gateway_network
                || matches!(profile.metadata(), oblivion_transport::Metadata::Tor {}),
            "external_proxy_requires_network",
        )?;
        // Close delegated connections before changing either stored or volatile
        // credentials. Any failed write leaves the gateway stopped.
        if self.gateway.is_some() {
            if session_info()?.is_some_and(|(_, mode)| mode == "agent")
                && crate::gateway::state()? == "active" {
                crate::gateway::change_transport(profile.transport())?;
            } else {
                crate::gateway::stop()?;
            }
        }
        let saved = (|| -> Result<()> {
        if temporary {
            write_transport_profile(
                &runtime_record("transport-selection.json"),
                &profile,
                false,
            )?;
        } else {
            clear_transport_selection()?;
            if save {
                write_transport_profile(
                    &network_profile()?.join("transport.json"),
                    &profile,
                    true,
                )?;
            }
        }
        Ok(())
        })();
        if saved.is_err() { crate::gateway::destroy()?; }
        saved
    }

    fn read(path: &Path) -> Result<Self> {
        let file = trusted_file(path)?;
        require(
            file.metadata()
                .map_err(|_| Error("config_unavailable"))?
                .len()
                <= 4096,
            "config_too_large",
        )?;
        let config: Self =
            serde_json::from_reader(file).map_err(|_| Error("invalid_config"))?;
        require(config.general_image.is_absolute(), "invalid_image_path")?;
        require(config.manager_uid > 0, "manager_must_not_be_root")?;
        require(
            config.general_mib >= 512 && config.general_mib <= 1024 * 1024,
            "invalid_general_size",
        )?;
        require(
            config.session_mib >= 128 && config.session_mib < config.general_mib,
            "invalid_session_size",
        )?;
        require((128..=config.general_mib).contains(&config.ephemeral_mib), "invalid_ephemeral_size")?;
        require(
            (65536..=1048576).contains(&config.pbkdf_memory_kib),
            "invalid_kdf_memory",
        )?;
        Ok(config)
    }

    fn initialize(&self, secret: &[u8]) -> Result<()> {
        require(
            mount_mode()? == MountMode::Closed
                && !mapping_open("oblivion-general")? && !mapping_open("oblivion-session")?,
            "volume_busy",
        )?;
        // Only a NEW regular file can be initialized. Physical devices and existing
        // files cannot be formatted through this interface, even with a bad password.
        require(
            !self
                .general_image
                .try_exists()
                .map_err(|_| Error("image_check_failed"))?,
            "general_already_exists",
        )?;
        let path = self.pending_general();
        create_image(&path, self.general_mib)?;
        self.format(&path, secret)?;
        crypt_open(&path, "oblivion-general", secret, false)?;
        let formatted = run(
            "/usr/sbin/mkfs.ext4",
            &[
                "-q",
                "-m",
                "0",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
                GENERAL,
            ],
            None,
        );
        let closed = crypt_close("oblivion-general");
        formatted?;
        closed?;
        publish(&path, &self.general_image)
    }

    fn pending_general(&self) -> PathBuf {
        let mut path = self.general_image.as_os_str().to_owned();
        path.push(".pending");
        PathBuf::from(path)
    }

    fn unlock(&self, secret: &[u8], readonly: bool) -> Result<()> {
        require(
            !mapping_open("oblivion-general")? && mount_mode()? == MountMode::Closed,
            "general_already_open",
        )?;
        trusted_file(&self.general_image)?;
        crypt_open(&self.general_image, "oblivion-general", secret, readonly)?;
        fs::create_dir_all(MOUNT).map_err(|_| Error("mount_directory_failed"))?;
        let result = run(
            "/usr/bin/mount",
            &[
                "-t",
                "ext4",
                "-o",
                if readonly {
                    "ro,noload,nodev,nosuid,noexec"
                } else {
                    "nodev,nosuid,noexec"
                },
                GENERAL,
                MOUNT,
            ],
            None,
        );
        if result.is_err() {
            crypt_close("oblivion-general")?;
            return result;
        }
        if let Err(error) = write_key_file("host-opening", random_id()?.as_bytes()) {
            run("/usr/bin/umount", &[MOUNT], None)?;
            crypt_close("oblivion-general")?;
            return Err(error);
        }
        if readonly {
            return Ok(());
        }
        fs::set_permissions(MOUNT, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("permissions_failed"))?;
        fs::create_dir_all(format!("{MOUNT}/sessions")).map_err(|_| Error("directory_failed"))?;
        fs::create_dir_all(format!("{MOUNT}/profile")).map_err(|_| Error("directory_failed"))?;
        Ok(())
    }

    fn enter_ram(&self) -> Result<()> {
        require(mount_mode()? == MountMode::Closed && !mapping_open("oblivion-general")?, "general_already_open")?;
        require(open_sessions()?.is_empty() && physical_safe_owners_stopped()?, "runtime_busy")?;
        self.admit_memory(0, RAM_PROFILE_RESERVE_MIB, RAM_PROFILE_RESERVE_MIB, "insufficient_ephemeral_memory")?;
        for index in 0..scope::LIMIT {
            scope::within(scope::Slot::try_from(index).map_err(Error)?, crate::ipc::release_family)?;
        }
        // This is an explicit application mode, never a recovery fallback for
        // failed persistent storage. The physical archive remains untouched.
        create_ram_profile()
    }

    fn create(&self, secret: &[u8], mib: u64) -> Result<()> {
        let bytes = oblivion_host::volume::size(mib).map_err(Error)?;
        require(
            mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
            "general_not_writable",
        )?;
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        require(
            available_bytes()? >= bytes + oblivion_host::volume::RESERVE_BYTES,
            "insufficient_space",
        )?;
        self.admit_family()?;
        let (descriptor, capability) = family::new_family(secret).map_err(Error)?;
        let id = random_id()?;
        let path = PathBuf::from(format!("{MOUNT}/sessions/{id}.pending"));
        create_image(&path, mib)?;
        let credential = family::credential_for_safe(&capability, &id).map_err(Error)?;
        format_safe(&path, credential.as_ref(), &descriptor, &id)?;
        crypt_open_keyslot(&path, "oblivion-session", credential.as_ref(), false, Some(0))?;
        let formatted = format_session();
        let closed = crypt_close("oblivion-session");
        formatted?;
        closed?;
        publish(&path, &PathBuf::from(format!("{MOUNT}/sessions/{id}.luks")))?;
        println!("{id}");
        Ok(())
    }

    fn admit_family(&self) -> Result<()> {
        self.admit_memory(self.reserved_mib(&open_sessions()?)?, 0, 256, "insufficient_family_memory")
    }

    fn create_agent_safe(&self, request: AgentSafeRequest) -> Result<AgentSafeInfo> {
        let (parent, mode) = session_info()?.ok_or(Error("session_not_open"))?;
        require(mode == "agent" && mapping_open("oblivion-session")?
            && !runtime_record("session-recovery-required").exists() && !crate::vm::stopped()?, "agent_safe_required")?;
        let records = agent_safe_records()?;
        require_branch_open(&records, &parent)?;
        // An acknowledged request identifies its first child even if a caller
        // retries with different text. It never allocates a second volume.
        if let Some(existing) = records.iter().find(|record| record.parent == parent && record.request_id == request.request_id) {
            return Ok(existing.info());
        }
        validate_child_limits(&records, &parent)?;
        let ephemeral = ephemeral_session()?;
        require(ephemeral || mount_mode()? == MountMode::ReadWrite, "general_not_writable")?;
        let mib = if ephemeral { self.ephemeral_mib } else { self.session_mib };
        let bytes = oblivion_host::volume::size(mib).map_err(Error)?;
        if ephemeral {
            let runtime = File::open(RUN).map_err(|_| Error("runtime_check_failed"))?;
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            require(unsafe { libc::fstatvfs(runtime.as_raw_fd(), stats.as_mut_ptr()) } == 0, "runtime_check_failed")?;
            let stats = unsafe { stats.assume_init() };
            require(stats.f_bavail.saturating_mul(stats.f_frsize) >= bytes + 16 * MIB, "insufficient_ephemeral_storage")?;
            self.admit_memory(self.reserved_mib(&open_sessions()?)?, mib, mib, "insufficient_ephemeral_memory")?;
            private_directory(&Path::new(RUN).join("agent-safes/images"), true)?;
        } else {
            require(available_bytes()? >= bytes + oblivion_host::volume::RESERVE_BYTES, "insufficient_space")?;
        }
        let capability = match crate::ipc::authorized_family(&parent)? {
            Some(capability) => capability,
            None if ephemeral => {
                let mut secret = Zeroizing::new([0; 32]);
                File::open("/dev/urandom").and_then(|mut random| random.read_exact(secret.as_mut()))
                    .map_err(|_| Error("random_failed"))?;
                let capability = family::Capability::from_root_secret(&random_id()?, secret).map_err(Error)?;
                crate::ipc::retain_family(&parent, &capability)?;
                capability
            }
            None => return Err(Error("family_not_authorized")),
        };
        let descriptor = if ephemeral { None } else {
            let token = safe_family_token(&persistent_safe_path(&parent)?)?;
            require(token.safe_id == parent && token.descriptor.family_id() == capability.family_id(), "safe_identity_mismatch")?;
            Some(token.descriptor)
        };
        let id = random_id()?;
        let sealed_task = family::SealedTask::seal(&capability, &family::TaskContext {
            safe_id: &id, parent_id: &parent, request_id: &request.request_id, agent: &request.agent,
        }, &request.task).map_err(Error)?;
        drop(request.task);
        let mut record = AgentSafeRecord {
            version: 1, id, parent, created_by_agent: true,
            agent: request.agent, creator_chat_id: request.creator_chat_id,
            request_id: request.request_id, sealed_task, attempts: Vec::new(),
            ephemeral, mib, state: AgentSafeState::Creating,
        };
        write_agent_safe(&record)?;
        let credential = family::credential_for_safe(&capability, &record.id).map_err(Error)?;
        let mapping = format!("oblivion-safe-create-{}", record.id);
        let result = (|| {
            create_image(&record.image(true), mib)?;
            if let Some(descriptor) = &descriptor {
                format_safe(&record.image(true), credential.as_ref(), descriptor, &record.id)?;
            } else {
                format_derived_volume(&record.image(true), credential.as_ref())?;
            }
            crypt_open_keyslot(&record.image(true), &mapping, credential.as_ref(), false, Some(0))?;
            let formatted = format_device(&format!("/dev/mapper/{mapping}"));
            let closed = crypt_close(&mapping);
            formatted?;
            closed?;
            publish(&record.image(true), &record.image(false))
        })();
        if let Err(error) = result {
            let closed = if mapping_open(&mapping)? { crypt_close(&mapping) } else { Ok(()) };
            record.state = if closed.is_ok() { AgentSafeState::Failed } else { AgentSafeState::RecoveryRequired };
            if closed.is_ok() && record.image(true).exists() {
                trusted_file(&record.image(true))?;
                fs::remove_file(record.image(true)).map_err(|_| Error("child_cleanup_required"))?;
            }
            write_agent_safe(&record)?;
            closed.map_err(|_| Error("child_cleanup_required"))?;
            return Err(error);
        }
        record.state = AgentSafeState::AwaitingStart;
        write_agent_safe(&record)?;
        Ok(record.info())
    }

    fn close_branch(&self, force: bool, latch: Option<&Path>) -> Result<bool> {
        let Some((root, _)) = session_info()? else { return self.close_slot(force) };
        self.close_branch_id(&root, force, latch)
    }

    fn close_all(&self) -> Result<()> {
        let backups = crate::ipc::stop_backups();
        let mut failure = backups.as_ref().err().map(|error| Error(error.0));
        let mut checkpoint = true;
        for value in 0..scope::LIMIT {
            match scope::within(scope::Slot::try_from(value).map_err(Error)?, || self.close_slot(true)) {
                Err(error) => failure = Some(error),
                Ok(saved) => checkpoint &= saved,
            }
        }
        if let Some(error) = failure { return Err(error) }
        if let Err(error) = discard_ephemeral_children() {
            // Corrupt provenance cannot keep a fully stopped archive open.
            // Preserve the recovery marker and return the metadata failure.
            if physical_safe_owners_stopped()? { close_general()?; }
            return Err(error);
        }
        close_general()?;
        clear_key_file("proxy-profiles.json")?;
        crate::idle_controller::clear_temporary()?;
        scope::within(Default::default(), || -> Result<()> {
            clear_transport_selection()?;
            clear_network_selection()
        })?;
        require(backups?, "backup_metadata_recovery_required")?;
        if Path::new(RECOVERY).exists() {
            fs::remove_file(RECOVERY).map_err(|_| Error("recovery_clear_failed"))?;
        }
        require(checkpoint, "locked_without_tor_state")
    }

    fn close_branch_id(&self, root: &str, force: bool, latch: Option<&Path>) -> Result<bool> {
        self.close_branch_owners(root, force, latch, true)
    }

    fn close_branch_owners(&self, root: &str, force: bool, latch: Option<&Path>, discard_ram: bool) -> Result<bool> {
        if latch.is_none() { mark_branch_closing(&root)?; }
        let records = agent_safe_records()?;
        let branch = safe_branch(&records, &root)?;
        let opened = open_sessions()?;
        let mut failure = None;
        let mut checkpoint = true;
        for (id, _) in &branch {
            for entry in opened.iter().filter(|entry| entry.id.as_ref() == Some(id)) {
                match scope::within(entry.slot, || self.close_slot(force)) {
                    Ok(saved) => checkpoint &= saved,
                    Err(error) => failure = Some(error),
                }
            }
            if let Some(record) = records.iter().find(|record| record.id == *id) {
                let result = (|| { if record.ephemeral && discard_ram {
                    // Never discard an ephemeral volume whose VM/mapping
                    // failed to close. Other branch owners still get a turn.
                    if opened.iter().any(|entry| entry.id.is_none() || entry.id.as_ref() == Some(id)
                        && scope::within(entry.slot, || mapping_open("oblivion-session")).unwrap_or(true)) {
                        Err(Error("child_cleanup_required"))
                    } else { discard_ephemeral_child(record) }
                } else {
                    let mapping = format!("oblivion-safe-create-{}", record.id);
                    if mapping_open(&mapping)? { crypt_close(&mapping) } else { Ok(()) }
                } })();
                if let Err(error) = result { failure = Some(error); }
            }
        }
        if let Some(error) = failure { return Err(error) }
        for (id, path) in branch_latches()? {
            if branch.iter().any(|entry| entry.0 == id) {
                fs::remove_file(path).map_err(|_| Error("branch_latch_failed"))?;
            }
        }
        Ok(checkpoint)
    }

    fn grow(&self, id: &str, mib: u64, secret: &[u8]) -> Result<()> {
        let mut original = closed_session_file(id)?;
        let current = original
            .metadata()
            .map_err(|_| Error("metadata_failed"))?
            .len();
        let target =
            oblivion_host::volume::growth(current, mib, available_bytes()?).map_err(Error)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        let path = persistent_safe_path(id)?;
        let candidate = path.with_extension("growing");
        require(
            !candidate
                .try_exists()
                .map_err(|_| Error("image_check_failed"))?,
            "pending_session_growth",
        )?;
        // Reject a bad password before allocating or copying anything.
        self.admit_family()?;
        let credential = safe_credential(&path, Some(id), secret)?;
        crypt_open_keyslot(&path, "oblivion-session", credential.key.as_ref(), false, Some(credential.token.keyslot))?;
        crypt_close("oblivion-session")?;
        create_image(&candidate, mib)?;
        let result = (|| {
            let mut copy = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&candidate)
                .map_err(|_| Error("growth_copy_failed"))?;
            require(
                std::io::copy(&mut original, &mut copy).map_err(|_| Error("growth_copy_failed"))?
                    == current,
                "growth_copy_failed",
            )?;
            copy.sync_all().map_err(|_| Error("sync_failed"))?;
            self.admit_memory(self.reserved_mib(&open_sessions()?)?, vm.reservation_mib(), vm.reservation_mib(), "insufficient_session_memory")?;
            crypt_open_keyslot(&candidate, "oblivion-session", credential.key.as_ref(), false, Some(credential.token.keyslot))?;
            // Only the copy is exposed to the networkless maintenance guest.
            let resized = vm.resize_session(target);
            close_maintenance_session()?;
            resized
        })();
        result?;
        trusted_file(&candidate)?
            .sync_all()
            .map_err(|_| Error("sync_failed"))?;
        let source = CString::new(candidate.as_os_str().as_encoded_bytes())
            .map_err(|_| Error("invalid_path"))?;
        let destination =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
        // A crash sees either the original or the verified replacement at .luks.
        // The other copy stays at .growing until the directory commit is durable.
        require(
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    libc::RENAME_EXCHANGE,
                )
            } == 0,
            "growth_publish_failed",
        )?;
        sync_directory(path.parent().ok_or(Error("invalid_path"))?)?;
        discard_growth(id)
    }

    fn prepare_backup(&self, id: &str, secret: &[u8]) -> Result<()> {
        require((1..=1024).contains(&secret.len()), "invalid_secret_length")?;
        closed_session_file(id)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        let metadata = oblivion_host::safe_admin::Metadata {
            format: "oblivion-safe".into(),
            version: 1,
            safe_id: id.into(),
            title: session_titles(&MountMode::ReadWrite)?.remove(id),
            origin: backup_origin(id)?,
        };
        let result = (|| {
            let credential = self.open_credential(id, secret)?;
            authenticate_backup_origin(&metadata.origin, &credential.capability)?;
            drop(credential);
            self.start_personal_maintenance(id)?;
            match session_admin(oblivion_host::safe_admin::Command::Checkpoint { metadata })? {
                oblivion_host::safe_admin::Response::Metadata { .. } => Ok(()),
                oblivion_host::safe_admin::Response::Rejected { error } => {
                    Err(Error(match error {
                        oblivion_host::safe_admin::Rejection::UnsupportedVersion => {
                            "unsupported_backup_version"
                        }
                        oblivion_host::safe_admin::Rejection::InvalidMetadata => {
                            "invalid_backup_metadata"
                        }
                    }))
                }
                _ => Err(Error("invalid_backup_metadata")),
            }
        })();
        require(self.close_slot(result.is_err())?, "backup_cleanup_required")?;
        result
    }

    fn start_personal_maintenance(&self, id: &str) -> Result<()> {
        write_key_file("opening-nonce", random_id()?.as_bytes())?;
        write_key_file("session-info", &serde_json::to_vec(&(id, "share")).map_err(|_| Error("encode_failed"))?)?;
        crate::share_host::begin(&idle_opening()?.ok_or(Error("idle_opening_unknown"))?)?;
        self.vm.as_ref().ok_or(Error("vm_not_configured"))?.start_share()?;
        require(crate::vm::network_devices()? == 0, "unsafe_backup_network")
    }

    fn finish_restore(&self, id: &str, secret: &[u8]) -> Result<String> {
        require((1..=1024).contains(&secret.len()), "invalid_secret_length")?;
        closed_archive()?;
        require(!raw_restores().committed(id)?, "restore_already_committed")?;
        require(!raw_restores().staged(id)?, "restore_staged_recovery_required")?;
        restore_receipt(id)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
        let bytes = trusted_file(&path)?.metadata().map_err(|_| Error("metadata_failed"))?.len();
        require(bytes % MIB == 0, "invalid_session_size")?;
        oblivion_host::volume::size(bytes / MIB).map_err(Error)?;
        self.admit_family()?;
        let credential = safe_credential(&path, None, secret)?;
        require(!persistent_safe_path(&credential.token.safe_id)?.try_exists().map_err(|_| Error("image_check_failed"))?, "safe_already_exists")?;
        require(!agent_safe_records()?.iter().any(|record| record.id == credential.token.safe_id), "safe_provenance_conflict")?;
        let result = (|| {
            self.admit_memory(self.reserved_mib(&open_sessions()?)?, vm.reservation_mib(), vm.reservation_mib(), "insufficient_session_memory")?;
            write_key_file("personal-restore", id.as_bytes())?;
            crypt_open_keyslot(&path, "oblivion-session", credential.key.as_ref(), false, Some(credential.token.keyslot))?;
            self.start_personal_maintenance(&credential.token.safe_id)?;
            match session_admin(oblivion_host::safe_admin::Command::Inspect {})? {
                oblivion_host::safe_admin::Response::Metadata { metadata } => Ok(metadata),
                oblivion_host::safe_admin::Response::Rejected { error } => {
                    Err(Error(match error {
                        oblivion_host::safe_admin::Rejection::UnsupportedVersion => {
                            "unsupported_backup_version"
                        }
                        oblivion_host::safe_admin::Rejection::InvalidMetadata => {
                            "invalid_backup_metadata"
                        }
                    }))
                }
                _ => Err(Error("invalid_backup_metadata")),
            }
        })();
        require(self.close_slot(result.is_err())?, "restore_cleanup_required")?;
        let metadata = result?;
        require(metadata.safe_id == credential.token.safe_id, "invalid_backup_metadata")?;
        authenticate_backup_origin(&metadata.origin, &credential.capability)?;
        require(!recovery_required()?, "recovery_required")?;
        let records = agent_safe_records()?;
        require_branch_open(&records, &metadata.safe_id)?;
        validate_restore_relations(&metadata.safe_id, &metadata.origin, &records)?;
        raw_restores().publish(id, &path, metadata)?;
        discard_restore_record(id)?;
        Ok(credential.token.safe_id)
    }

    fn open_child_documents(&self, id: &str, nonce: Option<&str>) -> Result<()> {
        crate::family_rotation_host::require_available(id)?;
        crate::backup_host::require_safe_available(id)?;
        let records = agent_safe_records()?;
        let record = available_child(&records, id)?;
        require(if record.ephemeral { matches!(mount_mode()?, MountMode::ReadOnly | MountMode::RamOnly) }
            else { mount_mode()? == MountMode::ReadWrite }, "child_storage_mode_changed")?;
        require_branch_open(&records, id)?;
        require(!mapping_open("oblivion-session")? && crate::vm::stopped()?
            && !runtime_record("session-info").exists() && !runtime_record("session-recovery-required").exists(), "safe_must_be_closed")?;
        let opened = open_sessions()?;
        require(!opened.iter().any(|entry| entry.id.as_deref() == Some(id)), "session_already_open")?;
        require(!opened.iter().any(|entry| entry.recovery_required), "recovery_required")?;
        runtime()?;
        let path = if record.ephemeral { record.image(false) } else { persistent_safe_path(id)? };
        let bytes = trusted_file(&path)?.metadata().map_err(|_| Error("metadata_failed"))?.len();
        require(bytes % MIB == 0 && bytes >= record.mib * MIB
            && (!record.ephemeral || bytes == record.mib * MIB), "child_safe_volume_changed")?;
        oblivion_host::volume::size(bytes / MIB).map_err(Error)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        // The child volume already exists. Only a guest is new; no replacement
        // volume, password prompt or extra family KDF is needed for delegation.
        let guest = vm.reservation_mib();
        self.admit_memory(self.reserved_mib(&opened)?, guest, guest,
            if record.ephemeral { "insufficient_ephemeral_memory" } else { "insufficient_session_memory" })?;
        let parent = child_family_source(id)?;
        let capability = crate::ipc::authorized_child_family(id)?.ok_or(Error("parent_family_not_authorized"))?;
        require(child_family_source(id)? == parent, "parent_safe_changed")?;
        let credential = family::credential_for_safe(&capability, id).map_err(Error)?;
        if !record.ephemeral {
            let token = safe_family_token(&path)?;
            require(token.safe_id == id && token.descriptor.family_id() == capability.family_id(), "safe_identity_mismatch")?;
        }
        crypt_open_keyslot(&path, "oblivion-session", credential.as_ref(), false, Some(0))?;
        drop(credential);
        let result = (|| {
            if record.ephemeral { write_key_file("ephemeral-child", id.as_bytes())?; }
            write_key_file("opening-nonce", nonce.map_or_else(random_id, |value| Ok(value.to_owned()))?.as_bytes())?;
            crate::ipc::retain_family(id, &capability)?;
            write_session_info(id, "starting")?;
            vm.start_documents()?;
            require(child_family_source(id)? == parent, "parent_safe_changed")?;
            write_session_info(id, "documents")
        })();
        drop(capability);
        if result.is_err() { require(self.close_slot(true)?, "child_cleanup_required")?; }
        result
    }

    fn open_ephemeral(&self) -> Result<()> {
        require(matches!(mount_mode()?, MountMode::ReadOnly | MountMode::RamOnly), "ephemeral_requires_ephemeral_mode")?;
        self.admit_session(true)?;
        require(
            mount_mode()? != MountMode::Closed,
            "general_not_open",
        )?;
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        // runtime() checks tmpfs; secure_process() rejects swap. Reuse the same
        // block mapping/interlock, with a new random secret that is never saved.
        runtime()?;
        let mut secret = Zeroizing::new(vec![0; 64]);
        File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut secret))
            .map_err(|_| Error("random_failed"))?;
        create_image(Path::new(&scope::path(EPHEMERAL)), self.ephemeral_mib)?;
        self.format(Path::new(&scope::path(EPHEMERAL)), &secret)?;
        crypt_open(Path::new(&scope::path(EPHEMERAL)), "oblivion-session", &secret, false)?;
        drop(secret);
        write_key_file("opening-nonce", random_id()?.as_bytes())?;
        format_session()
    }

    fn open(&self, id: &str, secret: &[u8]) -> Result<()> {
        self.open_credential(id, secret).map(|_| ())
    }

    fn open_credential(&self, id: &str, secret: &[u8]) -> Result<SafeCredential> {
        crate::family_rotation_host::require_available(id)?;
        crate::backup_host::require_safe_available(id)?;
        validate_id(id)?;
        require_branch_open(&agent_safe_records()?, id)?;
        require(!open_sessions()?.iter().any(|entry| entry.id.as_deref() == Some(id)), "session_already_open")?;
        self.admit_session(false)?;
        require(
            mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
            "general_not_writable",
        )?;
        // Kernel mapping is the interlock, not a JSON state file that can become stale.
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        let path = persistent_safe_path(id)?;
        trusted_file(&path)?;
        self.admit_family()?;
        let credential = safe_credential(&path, Some(id), secret)?;
        crypt_open_keyslot(&path, "oblivion-session", credential.key.as_ref(), false, Some(credential.token.keyslot))?;
        if let Err(error) = write_key_file("opening-nonce", random_id()?.as_bytes()) {
            crypt_close("oblivion-session")?;
            return Err(error);
        }
        if let Err(error) = crate::ipc::retain_family(id, &credential.capability) {
            crypt_close("oblivion-session")?;
            return Err(error);
        }
        Ok(credential)
    }

    fn format(&self, path: &Path, secret: &[u8]) -> Result<()> {
        run(
            "/usr/sbin/cryptsetup",
            &[
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--pbkdf",
                "argon2id",
                "--pbkdf-memory",
                &self.pbkdf_memory_kib.to_string(),
                "--pbkdf-parallel",
                "1",
                // Keep LUKS setup deterministic across bare metal and virtual
                // machines. cryptsetup's time calibration can take minutes on
                // Apple Virtualization before it writes the first keyslot.
                // Four Argon2id passes at the configured memory cost retain a
                // deliberately expensive KDF without making setup look hung.
                "--pbkdf-force-iterations",
                "4",
                "--key-file",
                "-",
                path.to_str().ok_or(Error("invalid_path"))?,
            ],
            Some(secret),
        )
    }
}

fn profile_directory() -> Result<bool> {
    let directory = match fs::symlink_metadata(PROFILE) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error("profile_unavailable")),
        Ok(directory) => directory,
    };
    require(
        directory.is_dir() && directory.uid() == 0 && directory.mode() & 0o077 == 0,
        "unsafe_profile",
    )?;
    Ok(true)
}

fn read_proxy_profile_archive(path: &Path) -> Result<proxy_profiles::Archive> {
    if !path.try_exists().map_err(|_| Error("proxy_profile_unavailable"))? {
        return Ok(proxy_profiles::Archive::empty());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?.take(proxy_profiles::LIMIT as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| Error("proxy_profile_unavailable"))?;
    proxy_profiles::Archive::decode(&bytes).map_err(Error)
}

fn write_proxy_profile_archive(path: &Path, archive: &proxy_profiles::Archive) -> Result<()> {
    let bytes = archive.encode().map_err(Error)?;
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        if existing.try_exists().map_err(|_| Error("proxy_profile_unavailable"))? { trusted_file(existing)?; }
    }
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending)
        .map_err(|_| Error("proxy_profile_write_failed"))?;
    file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| Error("proxy_profile_write_failed"))?;
    fs::rename(&pending, path).map_err(|_| Error("proxy_profile_write_failed"))?;
    sync_directory(path.parent().ok_or(Error("invalid_path"))?)
}

fn clear_key_file(name: &str) -> Result<()> {
    for name in [name.to_owned(), format!("{name}.pending")] {
        let path = runtime_record(&name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_key_file(name: &str, bytes: &[u8]) -> Result<()> {
    let path = runtime_record(name);
    let pending = runtime_record(&format!("{name}.pending"));
    for existing in [&path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("selection_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("selection_write_failed"))?;
    file.write_all(bytes)
        .map_err(|_| Error("selection_write_failed"))?;
    fs::rename(pending, path).map_err(|_| Error("selection_write_failed"))
}

fn transport_profiles() -> Result<(egress::Profile, Option<egress::Profile>)> {
    let saved = if profile_directory()? {
        read_transport_profile(&network_profile()?.join("transport.json"))?.unwrap_or_default()
    } else {
        egress::Profile::default()
    };
    // A corrupt saved profile is never hidden by a volatile override.
    Ok((
        saved,
        read_transport_profile(&runtime_record("transport-selection.json"))?,
    ))
}

fn policy_profiles() -> Result<(Option<Policy>, Option<Policy>)> {
    let saved = if profile_directory()? {
        read_network_policy(&network_profile()?.join("network-policy.json"))?
    } else {
        None
    };
    Ok((
        saved,
        read_network_policy(&runtime_record("network-policy-selection.json"))?,
    ))
}

fn read_network_policy(path: &Path) -> Result<Option<Policy>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("network_policy_unavailable")),
        Ok(_) => {}
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?
        .take(network::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("network_policy_unavailable"))?;
    require(bytes.len() <= network::LIMIT, "invalid_network_policy")?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error("invalid_network_policy"))
}

fn clear_network_selection() -> Result<()> {
    for name in [
        "network-policy-selection.json",
        "network-policy-selection.json.pending",
    ] {
        let path = runtime_record(&name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_network_policy(path: &Path, policy: &Policy, durable: bool) -> Result<()> {
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("network_policy_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(policy).map_err(|_| Error("network_policy_encode_failed"))?,
    );
    require(bytes.len() <= network::LIMIT, "invalid_network_policy")?;
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("network_policy_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("network_policy_write_failed"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("network_policy_write_failed"))?;
    if durable {
        file.sync_all()
            .map_err(|_| Error("network_policy_write_failed"))?;
    }
    fs::rename(pending, path).map_err(|_| Error("network_policy_write_failed"))?;
    if durable {
        sync_directory(path.parent().ok_or(Error("invalid_path"))?)?;
    }
    Ok(())
}

fn read_transport_profile(path: &Path) -> Result<Option<egress::Profile>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("transport_profile_unavailable")),
        Ok(_) => {}
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?
        .take(egress::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("transport_profile_unavailable"))?;
    Ok(Some(egress::Profile::decode(&bytes).map_err(Error)?))
}

fn clear_transport_selection() -> Result<()> {
    for name in [
        "transport-selection.json",
        "transport-selection.json.pending",
    ] {
        let path = runtime_record(&name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_transport_profile(path: &Path, profile: &egress::Profile, durable: bool) -> Result<()> {
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("transport_profile_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("transport_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("transport_write_failed"))?;
    file.write_all(&profile.encode().map_err(Error)?)
        .map_err(|_| Error("transport_write_failed"))?;
    if durable {
        file.sync_all()
            .map_err(|_| Error("transport_write_failed"))?;
    }
    fs::rename(pending, path).map_err(|_| Error("transport_write_failed"))?;
    if durable {
        sync_directory(path.parent().ok_or(Error("invalid_path"))?)?;
    }
    Ok(())
}

pub(crate) fn tor_state(
    purpose: oblivion_host::tor_profile::Purpose,
) -> Result<Option<oblivion_tor_state::State>> {
    oblivion_host::tor_profile::load(&network_profile()?, purpose).map_err(Error)
}

pub(crate) fn tor_state_writable() -> Result<bool> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::statvfs(c"/run/oblivion/general/profile".as_ptr(), &mut stat) } == 0,
        "profile_unavailable",
    )?;
    Ok(stat.f_flag & libc::ST_RDONLY == 0)
}

pub(crate) fn save_tor_state(
    purpose: oblivion_host::tor_profile::Purpose,
    state: &oblivion_tor_state::State,
) -> Result<()> {
    require(tor_state_writable()?, "general_not_writable")?;
    oblivion_host::tor_profile::save(&network_profile()?, purpose, state).map_err(Error)
}

fn close_session() -> Result<()> {
    // Closing revokes family creation authority even if device cleanup fails.
    crate::ipc::release_family()?;
    clear_key_file("session-title")?;
    if mapping_open("oblivion-session")? {
        // No deferred removal: a live guest/block handle keeps the interlock.
        crypt_close("oblivion-session")?;
    }
    require(!mapping_open("oblivion-session")?, "session_still_open")?;
    clear_key_file("opening-nonce")?;
    if Path::new(&scope::path(EPHEMERAL))
        .try_exists()
        .map_err(|_| Error("ephemeral_check_failed"))?
    {
        trusted_file(Path::new(&scope::path(EPHEMERAL)))?;
        fs::remove_file(scope::path(EPHEMERAL)).map_err(|_| Error("ephemeral_cleanup_failed"))?;
    }
    clear_key_file("ephemeral-child")?;
    Ok(())
}

pub(crate) fn closed_session_file(id: &str) -> Result<File> {
    validate_id(id)?;
    crate::family_rotation_host::require_available(id)?;
    crate::backup_host::require_safe_available(id)?;
    require(!open_sessions()?.iter().any(|entry| entry.id.as_deref() == Some(id)), "session_already_open")?;
    closed_archive()?;
    trusted_file(&persistent_safe_path(id)?)
}

pub(crate) fn backup_source_closed(id: &str) -> Result<()> {
    require(!open_sessions()?.iter().any(|entry| entry.id.as_deref() == Some(id)), "safe_must_be_closed")
}

pub(crate) fn rotation_host() -> Result<String> {
    require(!recovery_required()?, "recovery_required")?;
    backup_catalog_open()?;
    backup_host_nonce()?.ok_or(Error("idle_opening_unknown"))
}

pub(crate) fn rotation_sources() -> Result<Vec<crate::family_rotation_host::Source>> {
    rotation_host()?;
    let titles = session_titles(&MountMode::ReadWrite)?;
    sessions(".luks")?.into_iter().map(|id| Ok(crate::family_rotation_host::Source {
        title: titles.get(&id).cloned().unwrap_or_else(|| id.clone()), path: persistent_safe_path(&id)?, id,
    })).collect()
}

pub(crate) fn rotation_closed(id: &str) -> Result<()> {
    // Unlike normal admission this must remain usable for an already fenced
    // family's explicit roll-forward/rollback. Never bypass backup/VM owners.
    rotation_host()?;
    backup_source_closed(id)?;
    crate::backup_host::require_safe_available(id)?;
    let path = persistent_safe_path(id)?;
    trusted_file(&path)?;
    require(!path.with_extension("growing").try_exists().map_err(|_| Error("image_check_failed"))?, "session_growth_pending")
}

pub(crate) fn rotation_admit_kdf() -> Result<()> {
    memory_admission(&fs::read_to_string("/proc/meminfo").map_err(|_| Error("memory_unavailable"))?, 0, 0, 256, "insufficient_family_memory")
}

fn closed_archive() -> Result<()> {
    require(!recovery_required()?, "recovery_required")?;
    require(
        mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
        "general_not_writable",
    )?;
    require(
        !mapping_open("oblivion-session")? && crate::vm::stopped()?,
        "session_must_be_closed",
    )
}

pub(crate) fn restore_budget() -> Result<u64> {
    closed_archive()?;
    let bytes = available_bytes()?
        .saturating_sub(16 * MIB)
        .min(oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES);
    require(bytes >= 32 * MIB, "insufficient_restore_space")?;
    Ok(bytes)
}

pub(crate) fn create_restore_copy(id: &str) -> Result<File> {
    validate_id(id)?;
    closed_archive()?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(MOUNT).join(format!("sessions/{id}.pending")))
        .map_err(|_| Error("restore_create_failed"))
}

pub(crate) fn open_restore_copy(id: &str) -> Result<File> {
    validate_id(id)?;
    closed_archive()?;
    let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
    require(trusted_file(&path)?.metadata().map_err(|_| Error("metadata_failed"))?.len() == 0, "backup_destination_not_empty")?;
    OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).map_err(|_| Error("restore_record_failed"))
}

pub(crate) fn backup_catalog_open() -> Result<()> {
    require(mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?, "general_not_writable")
}

pub(crate) fn backup_host_nonce() -> Result<Option<String>> { read_nonce(&Path::new(RUN).join("host-opening")) }

pub(crate) fn committed_personal_restore(id: &str) -> Result<Option<String>> {
    validate_id(id)?;
    Ok(raw_restores().restored()?.into_iter().find(|restored| restored.directory.file_name().is_some_and(|name| name == id))
        .map(|restored| restored.metadata.safe_id))
}

pub(crate) fn record_backup_receipt(receipt: &oblivion_transfer::Receipt) -> Result<()> {
    if Path::new(MOUNT).join(format!("sessions/{}.restore", receipt.id)).try_exists().map_err(|_| Error("restore_record_failed"))? {
        require(restore_receipt(&receipt.id)? == *receipt, "restore_copy_changed")
    } else { complete_restore_copy(receipt) }
}

pub(crate) fn complete_restore_copy(receipt: &oblivion_transfer::Receipt) -> Result<()> {
    let path = Path::new(MOUNT).join(format!("sessions/{}.restore-tmp", receipt.id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| Error("restore_record_failed"))?;
    file.write_all(&serde_json::to_vec(receipt).map_err(|_| Error("encode_failed"))?)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error("restore_record_failed"))?;
    publish(
        &path,
        &Path::new(MOUNT).join(format!("sessions/{}.restore", receipt.id)),
    )
}

fn restore_receipt(id: &str) -> Result<oblivion_transfer::Receipt> {
    validate_id(id)?;
    let receipt: oblivion_transfer::Receipt = serde_json::from_reader(
        trusted_file(&Path::new(MOUNT).join(format!("sessions/{id}.restore")))?.take(1025),
    )
    .map_err(|_| Error("invalid_restore_record"))?;
    require(
        receipt.id == id
            && receipt.entries == 1
            && (32 * MIB..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES).contains(&receipt.bytes)
            && receipt.manifest_sha256.len() == 64
            && receipt
                .manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_restore_record",
    )?;
    require(
        trusted_file(&Path::new(MOUNT).join(format!("sessions/{id}.pending")))?
            .metadata()
            .map_err(|_| Error("metadata_failed"))?
            .len()
            == receipt.bytes,
        "restore_copy_changed",
    )?;
    Ok(receipt)
}

pub(crate) fn cleanup_restore(id: &str) -> Result<()> {
    validate_id(id)?;
    if raw_restores().committed(id)? { return discard_restore_record(id) }
    if raw_restores().staged(id)? { return Ok(()) }
    if Path::new(MOUNT)
        .join(format!("sessions/{id}.restore"))
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        restore_receipt(id)?;
        return Ok(());
    }
    let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
    if path
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        discard_pending(&path)?;
    }
    discard_restore_record(id)
}

pub(crate) fn discard_personal_restore(id: &str) -> Result<()> {
    validate_id(id)?;
    for index in 0..scope::LIMIT {
        let slot = scope::Slot::try_from(index).map_err(Error)?;
        require(scope::within(slot, || read_nonce(&runtime_record("personal-restore")))?.as_deref() != Some(id), "restore_cleanup_required")?;
    }
    require(!raw_restores().committed(id)?, "restore_already_committed")?;
    raw_restores().discard(id)?;
    let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
    if path.try_exists().map_err(|_| Error("restore_record_failed"))? { discard_pending(&path)?; }
    discard_restore_record(id)
}

fn discard_restore_record(id: &str) -> Result<()> {
    validate_id(id)?;
    for extension in ["restore", "restore-tmp"] {
        let path = Path::new(MOUNT).join(format!("sessions/{id}.{extension}"));
        if path
            .try_exists()
            .map_err(|_| Error("restore_record_failed"))?
        {
            trusted_file(&path)?;
            fs::remove_file(path).map_err(|_| Error("restore_record_failed"))?;
        }
    }
    if !Path::new(MOUNT)
        .join(format!("sessions/{id}.luks"))
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        for extension in ["title", "title-tmp"] {
            let path = Path::new(MOUNT).join(format!("sessions/{id}.{extension}"));
            if path
                .try_exists()
                .map_err(|_| Error("restore_record_failed"))?
            {
                trusted_file(&path)?;
                fs::remove_file(path).map_err(|_| Error("restore_record_failed"))?;
            }
        }
    }
    sync_directory(&Path::new(MOUNT).join("sessions"))
}

fn close_maintenance_session() -> Result<()> {
    let stopped = crate::vm::stop(false);
    let closed = if stopped.is_ok() {
        close_session()
    } else {
        Err(Error("vm_still_running"))
    };
    if stopped.is_err() || closed.is_err() {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(RECOVERY)
            .map_err(|_| Error("recovery_marker_failed"))?;
        return Err(Error("maintenance_cleanup_required"));
    }
    clear_key_file("session-info")
}

fn discard_growth(id: &str) -> Result<()> {
    closed_session_file(id)?;
    discard_pending(&persistent_safe_path(id)?.with_extension("growing"))
}

fn format_session() -> Result<()> {
    format_device(&scope::path(SESSION))
}

fn format_device(device: &str) -> Result<()> {
    // The host formats the block device but never mounts a session filesystem.
    run(
        "/usr/sbin/mkfs.ext4",
        &[
            "-q",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            device,
        ],
        None,
    )
}

fn close_general() -> Result<()> {
    close_session()?;
    if mount_mode()? == MountMode::RamOnly {
        require(!mapping_open("oblivion-general")? && physical_safe_owners_stopped()?, "runtime_busy")?;
        // Every Safe owner is gone before application metadata or its mode
        // marker disappears. This tree is exclusively on verified /run tmpfs.
        for entry in fs::read_dir(MOUNT).map_err(|_| Error("ram_profile_cleanup_failed"))? {
            let entry = entry.map_err(|_| Error("ram_profile_cleanup_failed"))?;
            if entry.file_type().map_err(|_| Error("ram_profile_cleanup_failed"))?.is_dir() {
                fs::remove_dir_all(entry.path()).map_err(|_| Error("ram_profile_cleanup_failed"))?;
            } else { fs::remove_file(entry.path()).map_err(|_| Error("ram_profile_cleanup_failed"))?; }
        }
        clear_key_file("ram-only")?;
        return clear_key_file("host-opening");
    }
    if mount_mode()? != MountMode::Closed {
        run("/usr/bin/umount", &[MOUNT], None)?;
    }
    if mapping_open("oblivion-general")? {
        crypt_close("oblivion-general")?;
    }
    require(
        mount_mode()? == MountMode::Closed && !mapping_open("oblivion-general")?,
        "general_still_open",
    )?;
    clear_key_file("host-opening")
}

fn physical_safe_owners_stopped() -> Result<bool> {
    let mut units = Vec::new();
    let mut mappings = Vec::new();
    for index in 0..scope::LIMIT {
        scope::within(scope::Slot::try_from(index).map_err(Error)?, || {
            for name in ["oblivion-session", "oblivion-import", "oblivion-export"] {
                mappings.push(scope::current().mapping(name));
            }
            for role in [crate::vm::Role::Session, crate::vm::Role::Gateway,
                crate::vm::Role::Import, crate::vm::Role::Export, crate::vm::Role::OnionUplink,
                crate::vm::Role::OnionGateway, crate::vm::Role::OnionFile] {
                units.push(format!("{}.service", role.runtime().trim_start_matches("/run/")));
            }
            for owner in ["oblivion-gateway-host", "oblivion-transfer-host", "oblivion-onion-host"] {
                units.push(scope::current().owner(owner));
            }
        });
    }
    for entry in fs::read_dir("/sys/block").map_err(|_| Error("mapping_check_failed"))? {
        let entry = entry.map_err(|_| Error("mapping_check_failed"))?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"dm-") { continue }
        let name = fs::read_to_string(entry.path().join("dm/name"))
            .map_err(|_| Error("mapping_check_failed"))?;
        if mappings.iter().any(|mapping| mapping == name.trim())
            || name.trim().strip_prefix("oblivion-safe-create-").is_some_and(|id| validate_id(id).is_ok()) {
            return Ok(false);
        }
    }
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", "--property=Id,LoadState,ActiveState,MainPID,ControlPID"]).args(&units)
        .env_clear().env("LC_ALL", "C")
        .stdin(Stdio::null()).stderr(Stdio::null()).output()
        .map_err(|_| Error("vm_state_unavailable"))?;
    require(output.status.success(), "vm_state_unavailable")?;
    let output = String::from_utf8(output.stdout).map_err(|_| Error("invalid_vm_state"))?;
    owners_observed_stopped(&output, &units)
}

fn owners_observed_stopped(output: &str, units: &[String]) -> Result<bool> {
    let mut observed = std::collections::BTreeSet::new();
    for block in output.trim().split("\n\n") {
        let mut fields = std::collections::BTreeMap::new();
        for line in block.lines() {
            let (key, value) = line.split_once('=').ok_or(Error("invalid_vm_state"))?;
            require(fields.insert(key, value).is_none(), "invalid_vm_state")?;
        }
        let id = *fields.get("Id").ok_or(Error("invalid_vm_state"))?;
        require(units.iter().any(|unit| unit == id) && observed.insert(id), "invalid_vm_state")?;
        let absent = *fields.get("LoadState").ok_or(Error("invalid_vm_state"))? == "not-found";
        match fields.get("ActiveState").copied() {
            Some("inactive" | "failed") => {}
            None if absent => {}
            _ => return Ok(false),
        }
        for key in ["MainPID", "ControlPID"] {
            match fields.get(key) {
                Some(value) if value.parse::<u32>().ok() == Some(0) => {}
                None if absent => {}
                _ => return Ok(false),
            }
        }
    }
    require(observed.len() == units.len(), "invalid_vm_state")?;
    Ok(true)
}

struct SafeCredential {
    token: family::SafeToken,
    capability: family::Capability,
    key: Zeroizing<[u8; 32]>,
}

fn safe_credential(path: &Path, expected: Option<&str>, password: &[u8]) -> Result<SafeCredential> {
    let token = safe_family_token(path)?;
    crate::family_rotation_host::require_family_available(token.descriptor.family_id())?;
    if let Some(expected) = expected {
        require(token.safe_id == expected, "safe_identity_mismatch")?;
    }
    let capability = family::unlock_descriptor(&token.descriptor, password).map_err(Error)?;
    let key = family::credential_for_safe(&capability, &token.safe_id).map_err(Error)?;
    Ok(SafeCredential { token, capability, key })
}

pub(crate) fn safe_family_token(path: &Path) -> Result<family::SafeToken> {
    trusted_file(path)?;
    let mut child = Command::new("/usr/sbin/cryptsetup")
        .args(["token", "export", "--token-id", "0", "--json-file", "-"])
        .arg(path)
        .env_clear().env("LC_ALL", "C")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| Error("family_token_unavailable"))?;
    let mut bytes = Vec::new();
    let read = child.stdout.take().ok_or(Error("family_token_unavailable"))?
        .take(family::DESCRIPTOR_LIMIT as u64 + 1).read_to_end(&mut bytes);
    let status = child.wait().map_err(|_| Error("family_token_unavailable"))?;
    read.map_err(|_| Error("family_token_unavailable"))?;
    require(status.success(), "family_token_unavailable")?;
    family::Descriptor::decode_token(&bytes).map_err(Error)
}

// Safe v1 stores its password-wrapped family descriptor and stable SafeID in
// public LUKS2 token0. Only a derived random key enters the actual LUKS slot.
// The general archive keeps its independent human-password LUKS format.
fn format_safe(path: &Path, credential: &[u8], descriptor: &family::Descriptor, safe_id: &str) -> Result<()> {
    format_derived_volume(path, credential)?;
    let token = descriptor.encode_token(safe_id, 0).map_err(Error)?;
    run("/usr/sbin/cryptsetup", &["token", "import", "--token-id", "0", "--json-file", "-",
        path.to_str().ok_or(Error("invalid_path"))?], Some(&token))?;
    let verified = safe_family_token(path)?;
    require(verified.safe_id == safe_id && verified.keyslot == 0
        && verified.descriptor.encode().map_err(Error)? == descriptor.encode().map_err(Error)?, "family_token_write_failed")
}

fn format_derived_volume(path: &Path, credential: &[u8]) -> Result<()> {
    run("/usr/sbin/cryptsetup", &[
        "luksFormat", "--batch-mode", "--type", "luks2", "--cipher", "aes-xts-plain64",
        "--key-size", "512", "--key-slot", "0", "--pbkdf", "pbkdf2",
        // Password hardening is in the Argon2id wrapper. This slot receives
        // a uniformly random 256-bit derivation rather than a human password.
        "--pbkdf-force-iterations", "1000", "--key-file", "-",
        path.to_str().ok_or(Error("invalid_path"))?,
    ], Some(credential))
}

#[cfg(test)]
mod ram_only_tests {
    use super::*;

    #[test]
    #[ignore = "requires isolated root tmpfs /run and a read-only userdata fixture"]
    fn ram_profile_needs_no_archive_and_keeps_userdata_untouched() {
        assert_eq!(std::env::var("OBLIVION_RAM_ONLY_TEST").as_deref(), Ok("1"));
        let sentinel = Path::new("/userdata/general.luks");
        let before = fs::read(sentinel).unwrap();
        assert!(OpenOptions::new().write(true).open(sentinel).is_err());
        fs::DirBuilder::new().recursive(true).mode(0o700).create(RUN).unwrap();
        runtime().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(fs::read_dir(RUN).unwrap().next().is_none());
        create_ram_profile().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(mount_mode().is_ok_and(|mode| mode == MountMode::RamOnly));
        assert_eq!(serde_json::to_string(&MountMode::RamOnly).unwrap(), "\"ram-only\"");
        assert!(!mapping_open("oblivion-general").unwrap_or(true));
        let snapshot = idle_snapshot().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(snapshot.host.is_some() && !snapshot.general_open && !snapshot.writable);
        let nonce = snapshot.host.unwrap();
        assert_eq!(create_ram_profile().err().map(|error| error.0), Some("general_already_open"));
        assert_eq!(read_nonce(&Path::new(RUN).join("host-opening")).unwrap_or(None).as_deref(), Some(nonce.as_str()));
        let config = Config {
            general_image: sentinel.into(), general_mib: 512, session_mib: 128, ephemeral_mib: 128,
            pbkdf_memory_kib: 65536, manager_uid: 1000, vm: None, gateway: None, import: None,
            export: None, onion: None, gateway_network: false,
        };
        assert_eq!(config.initialize(b"not-a-persistent-password").err().map(|error| error.0), Some("volume_busy"));
        assert_eq!(config.create(b"not-a-persistent-password", 128).err().map(|error| error.0), Some("general_not_writable"));
        assert_eq!(config.unlock(b"not-a-persistent-password", true).err().map(|error| error.0), Some("general_already_open"));
        let mut proxies = proxy_profiles::Registry::new(proxy_profiles::Archive::empty(), proxy_profiles::Archive::empty()).unwrap();
        let command = proxy_profiles::Command::decode(br#"{"action":"add","name":"Fixture","transport":{"mode":"socks5","endpoint":"192.0.2.22:1080","authentication":null}}"#).unwrap();
        assert!(matches!(proxies.change(command, true).unwrap(), proxy_profiles::Change::Temporary));
        write_proxy_profile_archive(&Path::new(RUN).join("proxy-profiles.json"), proxies.temporary())
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(proxies.status().entries.iter().all(|entry| entry.temporary));
        let idle = crate::idle_controller::Controller::new().unwrap_or_else(|error| panic!("{}", error.0));
        idle.configure(oblivion_host::autolock::Preferences { version: 1, safe_minutes: 5, host_minutes: 10 })
            .unwrap_or_else(|error| panic!("{}", error.0));
        let idle = serde_json::to_value(idle.status().unwrap_or_else(|error| panic!("{}", error.0))).unwrap();
        assert_eq!(idle["storage"], "ram-only");
        assert_eq!(idle["writable"], false);
        assert!(fs::read_dir(PROFILE).unwrap().next().is_none());
        // This container has no service manager. Unknown physical ownership
        // must keep application state open rather than erase its marker.
        mark_recovery().unwrap_or_else(|error| panic!("{}", error.0));
        assert!(close_general().is_err());
        assert!(mount_mode().is_ok_and(|mode| mode == MountMode::RamOnly));
        assert!(recovery_required().unwrap_or(false));
        assert_eq!(fs::read(sentinel).unwrap(), before);
        assert!(!Path::new("/userdata/general.luks.pending").exists());
    }
}

#[cfg(test)]
mod family_storage_tests {
    use super::*;

    #[test]
    #[ignore = "requires root and installed cryptsetup; uses a disposable image"]
    fn production_family_roundtrips_through_real_luks_header() {
        let password = b"disposable-family-test-password";
        let id = "00000000000000000000000000000001";
        let directory = std::env::temp_dir().join(format!("oblivion-family-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("safe.luks");
        create_image(&path, 64).unwrap_or_else(|error| panic!("{}", error.0));
        let (descriptor, capability) = family::new_family(password).unwrap();
        let key = family::credential_for_safe(&capability, id).unwrap();
        format_safe(&path, key.as_ref(), &descriptor, id)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let recovered = safe_credential(&path, Some(id), password)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(*recovered.key, *key);
        assert!(safe_credential(&path, Some("00000000000000000000000000000002"), password).is_err());
        run("/usr/sbin/cryptsetup", &[
            "open", "--test-passphrase", "--disable-external-tokens", "--key-slot", "0", "--key-file", "-",
            path.to_str().unwrap(),
        ], Some(recovered.key.as_ref())).unwrap_or_else(|error| panic!("{}", error.0));
        let other = family::credential_for_safe(&capability, "00000000000000000000000000000002").unwrap();
        assert!(run("/usr/sbin/cryptsetup", &[
            "open", "--test-passphrase", "--disable-external-tokens", "--key-slot", "0", "--key-file", "-",
            path.to_str().unwrap(),
        ], Some(other.as_ref())).is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}

#[cfg(test)]
mod agent_safe_tests {
    use super::*;

    fn record(id: u8, parent: u8) -> AgentSafeRecord {
        let id = format!("{id:032x}");
        let parent = format!("{parent:032x}");
        let capability = family::Capability::from_root_secret("ffffffffffffffffffffffffffffffff", Zeroizing::new([7; 32])).unwrap();
        let sealed_task = family::SealedTask::seal(&capability, &family::TaskContext {
            safe_id: &id, parent_id: &parent, request_id: &id, agent: "codex",
        }, "private child task").unwrap();
        AgentSafeRecord {
            version: 1, id: id.clone(), parent,
            created_by_agent: true, agent: "codex".into(), creator_chat_id: Some("explicit-native-chat-id".into()),
            request_id: id, sealed_task, attempts: Vec::new(),
            ephemeral: false, mib: 512, state: AgentSafeState::AwaitingStart,
        }
    }

    #[test]
    fn only_the_requested_ready_child_can_be_opened() {
        for ephemeral in [false, true] {
            let mut child = record(2, 1);
            child.ephemeral = ephemeral;
            let records = vec![child];
            assert_eq!(available_child(&records, &format!("{:032x}", 2)).unwrap_or_else(|error| panic!("{}", error.0)).id, format!("{:032x}", 2));
            assert!(available_child(&records, &format!("{:032x}", 3)).is_err());
            for state in [AgentSafeState::Creating, AgentSafeState::Failed, AgentSafeState::RecoveryRequired] {
                let mut child = record(2, 1); child.ephemeral = ephemeral; child.state = state;
                assert!(available_child(&[child], &format!("{:032x}", 2)).is_err());
            }
        }
    }

    #[test]
    #[ignore = "requires isolated root-owned tmpfs /run; no production state"]
    fn closed_ram_child_is_counted_once_and_parent_close_fences_private_lookup() {
        assert_eq!(std::env::var("OBLIVION_RAM_CHILD_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fs::DirBuilder::new().recursive(true).mode(0o700).create(RUN).unwrap();
        create_ram_profile().unwrap_or_else(|error| panic!("{}", error.0));
        let mut child = record(2, 1); child.ephemeral = true; child.mib = 128;
        write_agent_safe(&child).unwrap_or_else(|error| panic!("{}", error.0));
        private_directory(&child.image(false).parent().unwrap(), true).unwrap_or_else(|error| panic!("{}", error.0));
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(child.image(false)).unwrap();
        file.set_len(child.mib * MIB).unwrap();
        let config = Config { general_image: "/unused/general.luks".into(), general_mib: 512, session_mib: 128, ephemeral_mib: 128,
            pbkdf_memory_kib: 65536, manager_uid: 1000, vm: None, gateway: None, import: None, export: None,
            onion: None, gateway_network: false };
        let closed = config.reserved_mib(&[]).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(closed, RAM_PROFILE_RESERVE_MIB + 128);
        let slot = scope::Slot::try_from(1).unwrap();
        private_directory(Path::new(&slot.runtime()), true).unwrap_or_else(|error| panic!("{}", error.0));
        scope::within(slot, || {
            write_key_file("ephemeral-child", child.id.as_bytes()).unwrap_or_else(|error| panic!("{}", error.0));
            assert!(ephemeral_session().unwrap_or(false));
            assert!(!Path::new(&scope::path(EPHEMERAL)).exists());
        });
        let opened = [OpenSession { slot, id: Some(child.id.clone()), mode: Some("documents".into()), recovery_required: false }];
        assert_eq!(config.reserved_mib(&opened).unwrap_or_else(|error| panic!("{}", error.0)), closed);
        // No real parent VM exists: a cached family alone cannot grant access.
        assert!(matches!(child_family_source(&child.id), Err(Error("parent_safe_not_open"))));
        mark_branch_closing(&child.parent).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(matches!(child_family_source(&child.id), Err(Error("safe_branch_closing"))));
        crate::ipc::assert_child_lookup_is_fenced(&child.id, &child.parent);
    }

    #[test]
    fn branch_order_is_descendant_first_and_excludes_another_family() {
        let records = vec![record(2, 1), record(3, 2), record(5, 4)];
        let branch = safe_branch(&records, &format!("{:032x}", 1)).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(branch, vec![(format!("{:032x}", 3), 2), (format!("{:032x}", 2), 1), (format!("{:032x}", 1), 0)]);
        let mut cyclic = vec![record(2, 3), record(3, 2)];
        assert!(safe_branch(&cyclic, &format!("{:032x}", 2)).is_err());
        cyclic[1].parent = format!("{:032x}", 1);
        assert!(safe_branch(&cyclic, &format!("{:032x}", 1)).is_ok());
    }

    #[test]
    fn child_admission_checks_count_and_depth_before_allocation() {
        let parent = format!("{:032x}", 1);
        let mut records: Vec<_> = (2..10).map(|id| record(id, 1)).collect();
        assert!(validate_child_limits(&records, &parent).is_err());
        records.pop();
        assert!(validate_child_limits(&records, &parent).is_ok());
        let records = vec![record(2, 1), record(3, 2), record(4, 3), record(5, 4)];
        assert!(validate_child_limits(&records, &format!("{:032x}", 4)).is_ok());
        assert!(validate_child_limits(&records, &format!("{:032x}", 5)).is_err());
    }

    #[test]
    fn provenance_status_never_exposes_task_or_claims_an_agent_started() {
        let mut record = record(2, 1);
        record.state = AgentSafeState::Creating;
        let encoded = serde_json::to_value(record.info()).unwrap();
        assert!(encoded.get("task").is_none());
        assert!(encoded.get("sealed_task").is_none());
        let stored = serde_json::to_string(&record).unwrap();
        assert!(!stored.contains("private child task"));
        assert!(!stored.contains("\"task\":"));
        let mut old: serde_json::Value = serde_json::from_str(&stored).unwrap();
        old.as_object_mut().unwrap().remove("sealed_task");
        old["task"] = "private child task".into();
        assert!(serde_json::from_value::<AgentSafeRecord>(old).is_err());
        assert_eq!(encoded["state"], "recovery-required");
        record.state = AgentSafeState::AwaitingStart;
        assert_eq!(serde_json::to_value(record.info()).unwrap()["state"], "awaiting-start");
        let request: AgentSafeRequest = serde_json::from_value(serde_json::json!({
            "agent":"claude", "task":"an explicit task", "request_id":format!("{:032x}", 1),
            "creator_chat_id":"native-chat-id",
        })).unwrap();
        assert!(request.validate().is_ok());
        assert!(serde_json::from_value::<AgentSafeRequest>(serde_json::json!({
            "agent":"claude", "task":"an explicit task", "request_id":format!("{:032x}", 1), "parent":"forged",
        })).is_err());
    }

    #[test]
    fn maximum_child_task_stays_encrypted_within_the_bounded_provenance_record() {
        let mut record = record(2, 1);
        record.creator_chat_id = Some("x".repeat(256));
        let capability = family::Capability::from_root_secret("ffffffffffffffffffffffffffffffff", Zeroizing::new([7; 32])).unwrap();
        let task = "s".repeat(16384);
        record.sealed_task = family::SealedTask::seal(&capability, &family::TaskContext {
            safe_id: &record.id, parent_id: &record.parent, request_id: &record.request_id, agent: &record.agent,
        }, &task).unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(bytes.len() <= CHILD_RECORD_LIMIT);
        assert!(!String::from_utf8_lossy(&bytes).contains(&task));
        let reopened: AgentSafeRecord = serde_json::from_slice(&bytes).unwrap();
        let task = reopened.sealed_task.open(&capability, &family::TaskContext {
            safe_id: &reopened.id, parent_id: &reopened.parent, request_id: &reopened.request_id, agent: &reopened.agent,
        }).unwrap();
        assert_eq!(task.len(), 16384);
    }

    #[test]
    fn personal_restore_authenticates_standalone_task_context_before_publication() {
        let record = record(2, 1);
        let capability = family::Capability::from_root_secret("ffffffffffffffffffffffffffffffff", Zeroizing::new([7; 32])).unwrap();
        let mut origin = record.origin();
        assert!(authenticate_backup_origin(&oblivion_host::safe_origin::Origin::AgentCreated { record: origin.clone() }, &capability).is_ok());
        origin.parent_id = format!("{:032x}", 3);
        assert!(authenticate_backup_origin(&oblivion_host::safe_origin::Origin::AgentCreated { record: origin }, &capability).is_err());
        let wrong_capability = family::Capability::from_root_secret("ffffffffffffffffffffffffffffffff", Zeroizing::new([8; 32])).unwrap();
        assert!(authenticate_backup_origin(&oblivion_host::safe_origin::Origin::AgentCreated { record: record.origin() }, &wrong_capability).is_err());
        assert!(validate_restore_relations(&record.id, &oblivion_host::safe_origin::Origin::AgentCreated { record: record.origin() }, &[]).is_ok());
        assert!(validate_restore_relations(&record.id, &oblivion_host::safe_origin::Origin::AgentCreated { record: record.origin() }, &[self::record(1, 2)]).is_err());
    }

    #[test]
    #[ignore = "requires isolated root-owned tmpfs /run; no production state"]
    fn personal_restore_discard_cannot_unlink_a_different_slots_maintenance_volume() {
        assert_eq!(std::env::var("OBLIVION_PERSONAL_RESTORE_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let id = "a".repeat(32);
        private_directory(&Path::new(MOUNT).join("sessions"), true).unwrap_or_else(|error| panic!("{}", error.0));
        let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
        OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).unwrap().write_all(b"encrypted pending source").unwrap();
        let owner = scope::Slot::try_from(2).unwrap();
        private_directory(Path::new(&owner.runtime()), true).unwrap_or_else(|error| panic!("{}", error.0));
        scope::within(owner, || write_key_file("personal-restore", id.as_bytes())).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(matches!(discard_personal_restore(&id), Err(Error("restore_cleanup_required"))));
        assert_eq!(fs::read(path).unwrap(), b"encrypted pending source");
    }

    #[test]
    fn failed_unit_with_a_remaining_pid_is_not_a_stopped_owner() {
        let units = vec!["oblivion-session.service".to_string()];
        let stopped = "Id=oblivion-session.service\nLoadState=loaded\nActiveState=failed\nMainPID=0\nControlPID=0\n";
        assert!(owners_observed_stopped(stopped, &units).unwrap_or(false));
        assert!(!owners_observed_stopped(&stopped.replace("MainPID=0", "MainPID=42"), &units).unwrap_or(false));
        assert!(!owners_observed_stopped(&stopped.replace("ControlPID=0", "ControlPID=43"), &units).unwrap_or(false));
        assert!(owners_observed_stopped("Id=oblivion-session.service\nLoadState=not-found\n", &units).unwrap_or(false));
        assert!(owners_observed_stopped(stopped, &["another.service".into()]).is_err());
    }
}

fn crypt_open(path: &Path, name: &str, secret: &[u8], readonly: bool) -> Result<()> {
    crypt_open_keyslot(path, name, secret, readonly, None)
}

fn crypt_open_keyslot(path: &Path, name: &str, secret: &[u8], readonly: bool, keyslot: Option<u8>) -> Result<()> {
    let scoped = if name == "oblivion-session" { scope::current().mapping(name) } else { name.to_owned() };
    let name = scoped.as_str();
    let mut args = vec![
        "open",
        "--type",
        "luks2",
        "--disable-external-tokens",
        "--key-file",
        "-",
        path.to_str().ok_or(Error("invalid_path"))?,
        name,
    ];
    if readonly {
        args.push("--readonly");
    }
    let keyslot = keyslot.map(|slot| slot.to_string());
    if let Some(keyslot) = &keyslot {
        args.extend(["--key-slot", keyslot]);
    }
    run("/usr/sbin/cryptsetup", &args, Some(secret)).map_err(|_| Error("volume_unlock_failed"))
}

fn crypt_close(name: &str) -> Result<()> {
    let scoped = if name == "oblivion-session" { scope::current().mapping(name) } else { name.to_owned() };
    let name = scoped.as_str();
    run("/usr/sbin/cryptsetup", &["close", name], None)
}

fn run(program: &str, args: &[&str], secret: Option<&[u8]>) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if secret.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("command_start_failed"))?;
    let input = match secret {
        Some(bytes) => child
            .stdin
            .take()
            .ok_or(Error("secret_pipe_failed"))?
            .write_all(bytes),
        None => Ok(()),
    };
    let status = child.wait().map_err(|_| Error("command_wait_failed"))?;
    input.map_err(|_| Error("secret_pipe_failed"))?;
    require(status.success(), "operation_failed")
}

fn secure_process() -> Result<()> {
    // These settings apply only to this process and its children, never the host OS.
    unsafe {
        require(libc::geteuid() == 0, "root_required")?;
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        require(
            libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0,
            "core_limit_failed",
        )?;
        require(
            libc::prctl(libc::PR_SET_DUMPABLE, 0) == 0,
            "dump_protection_failed",
        )?;
    }
    let swaps = fs::read_to_string("/proc/swaps").map_err(|_| Error("swap_check_failed"))?;
    require(swaps.lines().count() == 1, "swap_must_be_disabled")
}

fn lock() -> Result<File> {
    lock_named("storage.lock")
}

pub(crate) fn recovery_lock() -> Result<File> {
    // A status poll may still own the operation lock when the display exits.
    // Recovery is latched already: wait for that worker, never skip teardown.
    // A stuck worker still leaves recovery required after this bounded wait.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match lock() {
            Err(Error("controller_busy")) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            result => return result,
        }
    }
}

pub(crate) fn lock_named(name: &str) -> Result<File> {
    runtime()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if matches!(name, "storage.lock" | "daemon.lock") { Path::new(RUN).join(name) } else { runtime_record(name) })
        .map_err(|_| Error("lock_failed"))?;
    unsafe {
        require(
            libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0,
            "controller_busy",
        )?;
        // Trusted workers inherit the lock so a killed parent cannot release it
        // while cryptsetup or mkfs is still modifying a volume.
        require(
            libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) == 0,
            "lock_inheritance_failed",
        )?;
    }
    Ok(file)
}

pub(crate) fn recovery_required() -> Result<bool> {
    if Path::new(RECOVERY)
        .try_exists()
        .map_err(|_| Error("recovery_check_failed"))? { return Ok(true) }
    let Some(nonce) = read_nonce(&Path::new(RUN).join("host-opening"))? else { return Ok(false) };
    crate::idle_controller::fenced(&crate::idle_controller::Target::Host { nonce })
}

fn runtime() -> Result<()> {
    fs::create_dir_all(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    let meta = fs::symlink_metadata(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    require(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "unsafe_runtime_directory",
    )?;
    let runtime = File::open(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    unsafe {
        require(
            libc::fstatfs(runtime.as_raw_fd(), stats.as_mut_ptr()) == 0,
            "runtime_check_failed",
        )?;
        require(
            stats.assume_init().f_type == libc::TMPFS_MAGIC,
            "runtime_must_be_tmpfs",
        )?;
    }
    Ok(())
}

pub(crate) fn trusted_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("file_unavailable"))?;
    let meta = file.metadata().map_err(|_| Error("metadata_failed"))?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.nlink() == 1,
        "unsafe_file",
    )?;
    Ok(file)
}

fn create_image(path: &Path, mib: u64) -> Result<()> {
    let parent = path.parent().ok_or(Error("invalid_image_path"))?;
    let meta = fs::symlink_metadata(parent).map_err(|_| Error("image_parent_unavailable"))?;
    require(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "unsafe_image_parent",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("image_exists_or_unavailable"))?;
    file.set_len(mib * MIB)
        .map_err(|_| Error("image_size_failed"))?;
    // Reserve space up front: a sparse inner vault must not exhaust the general
    // filesystem while the guest believes it still has free disk blocks.
    // posix_fallocate returns an error number directly; it does not set errno.
    match unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, (mib * MIB) as libc::off_t) } {
        0 => {}
        libc::ENOSPC | libc::EDQUOT => return Err(Error("insufficient_space")),
        _ => return Err(Error("image_allocation_failed")),
    }
    file.sync_all().map_err(|_| Error("sync_failed"))?;
    sync_directory(parent)
}

fn publish(pending: &Path, destination: &Path) -> Result<()> {
    trusted_file(pending)?
        .sync_all()
        .map_err(|_| Error("sync_failed"))?;
    let source =
        CString::new(pending.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
    let target = CString::new(destination.as_os_str().as_encoded_bytes())
        .map_err(|_| Error("invalid_path"))?;
    // Publication is atomic and must never replace an existing archive.
    require(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "publish_failed",
    )?;
    sync_directory(destination.parent().ok_or(Error("invalid_path"))?)
}

fn discard_pending(path: &Path) -> Result<()> {
    require(!mapping_open("oblivion-session")?, "volume_busy")?;
    trusted_file(path)?;
    fs::remove_file(path).map_err(|_| Error("discard_failed"))?;
    sync_directory(path.parent().ok_or(Error("invalid_path"))?)
}

fn available_bytes() -> Result<u64> {
    let file = File::open(MOUNT).map_err(|_| Error("space_check_failed"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(
        unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } == 0,
        "space_check_failed",
    )?;
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error("sync_failed"))
}

fn mapping_open(name: &str) -> Result<bool> {
    let scoped = if name == "oblivion-session" { scope::current().mapping(name) } else { name.to_owned() };
    let name = scoped.as_str();
    // Device symlinks are managed asynchronously by userspace. Only the kernel's
    // device-mapper table can tell us that the mapping is really gone.
    for entry in fs::read_dir("/sys/block").map_err(|_| Error("mapping_check_failed"))? {
        let entry = entry.map_err(|_| Error("mapping_check_failed"))?;
        if !entry.file_name().to_string_lossy().starts_with("dm-") {
            continue;
        }
        let active = fs::read_to_string(entry.path().join("dm/name"))
            .map_err(|_| Error("mapping_check_failed"))?;
        if active.trim() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, PartialEq, Serialize)]
enum MountMode {
    #[serde(rename = "locked")]
    Closed,
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "persistent")]
    ReadWrite,
    #[serde(rename = "ram-only")]
    RamOnly,
}

fn create_ram_profile() -> Result<()> {
    runtime()?;
    require(mount_mode()? == MountMode::Closed && !mapping_open("oblivion-general")?, "general_already_open")?;
    private_directory(Path::new(MOUNT), true)?;
    require(fs::read_dir(MOUNT).map_err(|_| Error("ram_profile_unavailable"))?.next().is_none(), "ram_profile_not_empty")?;
    let nonce = random_id()?;
    write_key_file("host-opening", nonce.as_bytes())?;
    if let Err(error) = write_key_file("ram-only", nonce.as_bytes()) {
        clear_key_file("host-opening")?;
        clear_key_file("ram-only.pending")?;
        return Err(error);
    }
    let result = (|| {
        private_directory(Path::new(PROFILE), true)?;
        clear_key_file("proxy-profiles.json")?;
        crate::idle_controller::clear_temporary()?;
        scope::within(Default::default(), || -> Result<()> {
            clear_transport_selection()?;
            clear_network_selection()
        })?;
        Ok(())
    })();
    if result.is_err() { mark_recovery()?; }
    result
}

fn mount_mode() -> Result<MountMode> {
    let ram = read_nonce(&Path::new(RUN).join("ram-only"))?;
    let mounts =
        fs::read_to_string("/proc/self/mountinfo").map_err(|_| Error("mount_check_failed"))?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.get(4) == Some(&MOUNT) {
            require(ram.is_none(), "mixed_app_storage")?;
            let separator = fields
                .iter()
                .position(|field| *field == "-")
                .ok_or(Error("mount_check_failed"))?;
            require(
                fields.get(separator + 2) == Some(&GENERAL),
                "unexpected_general_mount",
            )?;
            let readonly = fields
                .get(5)
                .ok_or(Error("mount_check_failed"))?
                .split(',')
                .any(|option| option == "ro");
            return Ok(if readonly {
                MountMode::ReadOnly
            } else {
                MountMode::ReadWrite
            });
        }
    }
    if let Some(nonce) = ram {
        require(!mapping_open("oblivion-general")?
            && read_nonce(&Path::new(RUN).join("host-opening"))?.as_deref() == Some(&nonce), "invalid_ram_profile")?;
        require(private_directory(Path::new(MOUNT), false)?, "ram_profile_unavailable")?;
        let directory = File::open(MOUNT).map_err(|_| Error("ram_profile_unavailable"))?;
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
        require(unsafe { libc::fstatfs(directory.as_raw_fd(), stats.as_mut_ptr()) } == 0
            && unsafe { stats.assume_init().f_type } == libc::TMPFS_MAGIC, "ram_profile_must_be_tmpfs")?;
        return Ok(MountMode::RamOnly);
    }
    Ok(MountMode::Closed)
}

fn write_session_title(id: &str, title: &str) -> Result<()> {
    let path = persistent_safe_title(id)?;
    let directory = path.parent().ok_or(Error("invalid_path"))?;
    let pending = path.with_extension("title-tmp");
    for existing in [&path, &pending] {
        if fs::symlink_metadata(existing).is_ok() {
            trusted_file(existing)?;
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("session_title_write_failed"))?;
    file.write_all(title.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| Error("session_title_write_failed"))?;
    fs::rename(pending, &path).map_err(|_| Error("session_title_write_failed"))?;
    sync_directory(&directory)
}

fn session_titles(mode: &MountMode) -> Result<std::collections::BTreeMap<String, String>> {
    let mut titles = std::collections::BTreeMap::new();
    let paths: Vec<_> = match mode {
        MountMode::Closed => Vec::new(),
        MountMode::ReadWrite => sessions(".luks")?
            .into_iter()
            .map(|id| Ok((id.clone(), persistent_safe_title(&id)?)))
            .collect::<Result<_>>()?,
        MountMode::ReadOnly | MountMode::RamOnly => open_sessions()?.into_iter()
            .filter_map(|entry| entry.id.map(|id| (id, Path::new(&entry.slot.runtime()).join("session-title"))))
            .collect(),
    };
    for (id, path) in paths {
        if !path
            .try_exists()
            .map_err(|_| Error("session_title_read_failed"))?
        {
            continue;
        }
        let mut title = String::new();
        trusted_file(&path)?
            .take(257)
            .read_to_string(&mut title)
            .map_err(|_| Error("session_title_read_failed"))?;
        oblivion_host::session_title::validate(&title).map_err(Error)?;
        titles.insert(id, title);
    }
    Ok(titles)
}

pub(crate) fn share_export_host() -> Result<String> {
    require(mount_mode()? == MountMode::ReadWrite && !recovery_required()?, "general_not_writable")?;
    read_nonce(&Path::new(RUN).join("host-opening"))?.ok_or(Error("idle_opening_unknown"))
}

/// Only a current, unfenced host unlock can authorize import mutations. This
/// identity is read from root RAM, never accepted from a frontend payload.
pub(crate) fn share_import_host() -> Result<Option<String>> {
    if recovery_required()? { return Ok(None) }
    read_nonce(&Path::new(RUN).join("host-opening"))
}

/// The selected set comes from the encrypted controller catalog, not a guest.
pub(crate) fn share_export_sources(selection: crate::share_export::ExportSelection) -> Result<Vec<crate::share_export::ExportSource>> {
    share_export_host()?;
    let all = sessions(".luks")?;
    let records = agent_safe_records()?;
    let parents = persistent_safe_parents()?;
    let selected = match selection {
        crate::share_export::ExportSelection::All => all.clone(),
        crate::share_export::ExportSelection::Safe { safe_id } => { validate_id(&safe_id)?; vec![safe_id] },
        crate::share_export::ExportSelection::Branch { safe_id } => {
            validate_id(&safe_id)?;
            require(all.contains(&safe_id), "safe_not_found")?;
            let mut selected = vec![safe_id.clone()];
            for id in all.iter().filter(|id| **id != safe_id) {
                let mut current = id;
                let mut seen = std::collections::BTreeSet::new();
                while let Some((_, parent)) = parents.iter().find(|entry| &entry.0 == current) {
                    require(seen.insert(parent.clone()) && seen.len() <= oblivion_share::manifest::MAX_SAFES, "invalid_share_parent")?;
                    if parent == &safe_id { selected.push(id.clone()); break }
                    current = parent;
                }
            }
            selected
        }
    };
    require(!selected.is_empty() && selected.len() <= oblivion_share::manifest::MAX_SAFES, "share_safe_limit")?;
    let open = open_sessions()?;
    for id in &selected {
        require(all.contains(id) && !open.iter().any(|entry| entry.id.as_ref() == Some(id)), "safe_must_be_closed")?;
        require_branch_open(&records, id)?;
        trusted_file(&persistent_safe_path(id)?)?;
    }
    Ok(selected.iter().map(|id| crate::share_export::ExportSource {
        id: id.clone(), parent: parents.iter().find(|entry| &entry.0 == id)
            .map(|entry| entry.1.clone()).filter(|parent| selected.contains(parent)),
    }).collect())
}

pub(crate) fn share_export_opening_closed(opening: &oblivion_host::autolock::Opening) -> Result<bool> {
    scope::within(opening.slot, || Ok(idle_opening()?.as_ref() != Some(opening)
        && !mapping_open("oblivion-session")? && crate::vm::stopped()?))
}

fn sessions(extension: &str) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for entry in
        fs::read_dir(format!("{MOUNT}/sessions")).map_err(|_| Error("session_list_failed"))?
    {
        let entry = entry.map_err(|_| Error("session_list_failed"))?;
        let name = entry.file_name();
        if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(extension)) {
            validate_id(id)?;
            trusted_file(&entry.path())?;
            ids.push(id.to_owned());
        }
    }
    if matches!(extension, ".luks" | ".growing") {
        for imported in share_imports().imported()? {
            let path = imported.directory.join("volume.luks");
            if extension == ".growing" && !path.with_extension("growing").try_exists().map_err(|_| Error("session_list_failed"))? { continue }
            require(!ids.contains(&imported.id), "duplicate_safe_identity")?;
            trusted_file(&if extension == ".growing" { path.with_extension("growing") } else { path })?;
            ids.push(imported.id);
        }
        for restored in raw_restores().restored()? {
            let path = restored.directory.join("volume.luks");
            if extension == ".growing" && !path.with_extension("growing").try_exists().map_err(|_| Error("session_list_failed"))? { continue }
            require(!ids.contains(&restored.metadata.safe_id), "duplicate_safe_identity")?;
            trusted_file(&if extension == ".growing" { path.with_extension("growing") } else { path })?;
            ids.push(restored.metadata.safe_id);
        }
    }
    if extension == ".pending" {
        for transfer in raw_restores().staged_ids()? {
            if !ids.contains(&transfer) { ids.push(transfer); }
        }
    }
    ids.sort();
    Ok(ids)
}

pub(crate) fn validate_id(id: &str) -> Result<()> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_session_id",
    )
}

pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| Error("random_failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn password(creating: bool) -> Result<Zeroizing<Vec<u8>>> {
    // Binary stdin is a private pipe from the trusted UI, never argv, environment,
    // shell history or a temporary key file. Newline is part of the password.
    let mut bytes = Zeroizing::new(Vec::with_capacity(1025));
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("secret_read_failed"))?;
    require(
        bytes.len() <= 1024 && bytes.len() >= if creating { 16 } else { 1 },
        "invalid_password_length",
    )?;
    Ok(bytes)
}

fn read_storage_request(limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("secret_read_failed"))?;
    require(bytes.len() <= limit, "invalid_storage_request")?;
    Ok(bytes)
}

pub(crate) fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        return Ok(());
    }
    Err(Error(code))
}

// Display metadata is RAM-only. The kernel mapping remains the ownership interlock.
// Keep the already-unlocked volume, but revoke the failed chat before returning
// it to an offline guest. Any incomplete cleanup leaves recovery latched.
fn recover_agent_start(config: &Config) -> Result<()> {
    let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
    require(mode == "starting", "agent_not_starting")?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&scope::path("/run/oblivion/session-recovery-required"))
        .map_err(|_| Error("recovery_marker_failed"))?;
    if crate::gateway::revoke().is_err() {
        crate::gateway::shutdown()?;
    }
    crate::vm::stop(false)?;
    clear_key_file("native-offline")?;
    config
        .vm
        .as_ref()
        .ok_or(Error("vm_not_configured"))?
        .start_documents()?;
    write_session_info(&id, "documents")?;
    fs::remove_file(&scope::path("/run/oblivion/session-recovery-required")).map_err(|_| Error("recovery_clear_failed"))
}

pub(crate) fn session_info() -> Result<Option<(String, String)>> {
    if !mapping_open("oblivion-session")? {
        return Ok(None);
    }
    let path = runtime_record("session-info");
    if !path.exists() {
        return Ok(None);
    }
    let value: (String, String) = serde_json::from_reader(trusted_file(&path)?.take(256))
        .map_err(|_| Error("invalid_session_state"))?;
    validate_id(&value.0)?;
    require(
        matches!(value.1.as_str(), "documents" | "starting" | "agent" | "share"),
        "invalid_session_state",
    )?;
    Ok(Some(value))
}
fn write_session_info(id: &str, mode: &str) -> Result<()> {
    let fresh = session_info()?.is_none();
    write_key_file(
        "session-info",
        &serde_json::to_vec(&(id, mode)).map_err(|_| Error("encode_failed"))?,
    )?;
    if fresh {
        let profile = network_profile()?;
        // Snapshot the host defaults once. Later host changes must not alter an
        // existing session; ephemeral defaults may themselves be RAM-only.
        if !profile.join("transport.json").exists() {
            let transport = read_transport_profile(&Path::new(RUN).join("transport-selection.json"))?
                .or(read_transport_profile(&Path::new(PROFILE).join("transport.json"))?).unwrap_or_default();
            write_transport_profile(&profile.join("transport.json"), &transport, mount_mode()? == MountMode::ReadWrite)?;
        }
        if !profile.join("network-policy.json").exists() {
            let policy = read_network_policy(&Path::new(RUN).join("network-policy-selection.json"))?
                .or(read_network_policy(&Path::new(PROFILE).join("network-policy.json"))?).unwrap_or_default();
            write_network_policy(&profile.join("network-policy.json"), &policy, mount_mode()? == MountMode::ReadWrite)?;
        }
        if !profile.join("access.json").exists() {
            crate::safe_access_store::write(&profile.join("access.json"), Access::Open)?;
        }
    }
    Ok(())
}
pub(crate) fn session_admin(command: oblivion_host::safe_admin::Command) -> Result<oblivion_host::safe_admin::Response> {
    require(!recovery_required()? && mapping_open("oblivion-session")? && !crate::vm::stopped()?, "session_not_open")?;
    let budget = if matches!(command, oblivion_host::safe_admin::Command::Job { .. }) { 4 } else { 65 };
    let request = oblivion_host::safe_admin::Request::new(command);
    require(request.valid(), "invalid_safe_admin_request")?;
    let id = random_id()?;
    let result = (|| {
        let stream = crate::vm::safe_admin_port(&id)?;
        let mut channel = oblivion_host::channel::Channel::new(&stream, std::time::Duration::from_secs(budget));
        oblivion_host::safe_admin::exchange(&mut channel, &request).map_err(|_| Error("safe_admin_failed"))
    })();
    let cleanup = crate::vm::remove_copy_port(&id);
    let response = result?;
    cleanup?;
    Ok(response)
}

fn diagnostic_report() -> Result<oblivion_host::diagnostics::Report> {
    use oblivion_host::diagnostics::{Architecture, Report, Session, Transport};
    let session = session_info()?;
    let observation = network_observation(session.as_ref().map(|(_, mode)| mode.as_str()));
    let system = crate::system_info::status();
    Ok(Report {
        version: 1,
        controller_version: env!("CARGO_PKG_VERSION").into(),
        architecture: match std::env::consts::ARCH {
            "aarch64" => Architecture::Aarch64,
            "x86_64" => Architecture::X86_64,
            _ => Architecture::Unknown,
        },
        cpu_cores: system.cores,
        memory_mib: system.memory_total / MIB,
        ephemeral: matches!(mount_mode()?, MountMode::ReadOnly | MountMode::RamOnly),
        general_open: mapping_open("oblivion-general")?,
        session: if recovery_required()? {
            Session::Recovery
        } else {
            match session.as_ref().map(|(_, mode)| mode.as_str()) {
                Some("documents") => Session::Documents,
                Some("agent") => Session::Agent,
                Some("starting") => Session::Starting,
                _ => Session::Locked,
            }
        },
        transport: match observation.label.as_str() {
            "NOT STARTED" => Transport::NotStarted,
            "CONNECTING" => Transport::Connecting,
            "TOR READY" => Transport::Tor,
            "SOCKS5 READY" => Transport::Socks5,
            "OFFLINE" | "OFFLINE · NO NETWORK DEVICE" => Transport::Offline,
            _ => Transport::Unknown,
        },
        direct_access_blocked: observation.direct_blocked,
        observation_age_ms: observation.age_ms,
        tor_bootstrap: observation.tor_progress,
        laboratory: cfg!(feature = "lab-emulation"),
    })
}

fn network_observation(mode: Option<&str>) -> network::Observation {
    let host_link = fs::read_dir("/sys/class/net").ok().map(|entries| {
        entries.flatten().any(|entry| {
            entry.file_name() != "lo"
                && fs::read_to_string(entry.path().join("operstate"))
                    .is_ok_and(|state| state.trim() == "up")
        })
    });
    let mut result = network::Observation {
        label: "STATUS UNKNOWN".into(),
        host_link: match host_link {
            Some(true) => "CONNECTED",
            Some(false) => "OFFLINE",
            None => "STATUS UNKNOWN",
        }
        .into(),
        direct_blocked: false,
        age_ms: 0,
        tor_progress: None,
    };
    if matches!(mode, Some("documents" | "share")) || runtime_record("native-offline").exists() {
        if crate::vm::network_devices().is_ok_and(|count| count == 0) {
            result.label = "OFFLINE · NO NETWORK DEVICE".into();
            result.direct_blocked = true;
        }
        if let Ok(observed) = crate::gateway::observation() {
            if observed.age_ms <= 10000 {
                result.tor_progress = observed.tor_progress;
            }
        }
        return result;
    }
    let Ok(state) = crate::gateway::state() else {
        return result;
    };
    if matches!(state.as_str(), "inactive" | "failed") {
        result.label = if mode.is_some() {
            "OFFLINE"
        } else {
            "NOT STARTED"
        }
        .into();
        return result;
    }
    let Ok(observed) = crate::gateway::observation() else {
        return result;
    };
    result.age_ms = observed.age_ms;
    if observed.age_ms > 10000 {
        return result;
    }
    result.tor_progress = observed.tor_progress;
    result.direct_blocked = observed.isolated
        && (mode.is_none() || crate::vm::network_devices().is_ok_and(|count| count == 1));
    result.label = if !result.direct_blocked {
        "STATUS UNKNOWN"
    } else if crate::safe_access_store::status(true)
        .is_ok_and(|status| status.current == Access::Offline)
    {
        "OFFLINE"
    } else if !observed.ready {
        "CONNECTING"
    } else if observed.tor {
        "TOR READY"
    } else {
        "SOCKS5 READY"
    }
    .into();
    result
}

#[derive(Serialize)]
struct OpenSession {
    slot: scope::Slot,
    id: Option<String>,
    mode: Option<String>,
    recovery_required: bool,
}

fn open_sessions() -> Result<Vec<OpenSession>> {
    let mut result = Vec::new();
    for index in 0..scope::LIMIT {
        let slot = scope::Slot::try_from(index).map_err(Error)?;
        scope::within(slot, || -> Result<()> {
            if !mapping_open("oblivion-session")? { return Ok(()); }
            let info = session_info()?;
            result.push(OpenSession {
                slot,
                recovery_required: info.is_none() || Path::new(&scope::path("/run/oblivion/session-recovery-required")).exists(),
                id: info.as_ref().map(|entry| entry.0.clone()),
                mode: info.map(|entry| entry.1),
            });
            Ok(())
        })?;
    }
    Ok(result)
}

pub(crate) fn runtime_record(name: &str) -> PathBuf {
    // Proxy profiles and application-opening markers belong to the host.
    // Per-opening selections and gateway records belong to the explicit slot.
    let base = if matches!(name.trim_end_matches(".pending"), "proxy-profiles.json" | "host-opening" | "ram-only") {
        RUN.to_owned()
    } else { scope::current().runtime() };
    Path::new(&base).join(name)
}

pub(crate) fn network_profile() -> Result<PathBuf> {
    let Some((id, mode)) = session_info()? else { return Ok(PathBuf::from(PROFILE)); };
    // Gateway owners see the general mount read-only, even for a persistent
    // session. Its private profile subtree remains writable in that namespace.
    let path = if mode == "share" || ephemeral_session()? {
        Path::new(&scope::current().runtime()).join("network-profile").join(id)
    } else {
        persistent_safe_profile(&id)?
    };
    fs::create_dir_all(&path).map_err(|_| Error("profile_unavailable"))?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| Error("profile_unavailable"))?;
    require(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0, "unsafe_profile")?;
    Ok(path)
}

fn gateway_reserved() -> Result<bool> {
    if !crate::vm::stopped_role(crate::vm::Role::Gateway)? { return Ok(true); }
    Ok(!matches!(crate::gateway::state()?.as_str(), "inactive" | "failed"))
}

fn memory_admission(memory: &str, reserved: u64, additional: u64, peak: u64, error: &'static str) -> Result<()> {
    let kib = |name: &str| -> Result<u64> {
        memory.lines().find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.split_whitespace().next()).and_then(|value| value.parse().ok())
            .ok_or(Error("memory_unavailable"))
    };
    require(kib("MemAvailable:")? >= (peak + 256) * 1024
        && kib("MemTotal:")? >= (reserved + additional + 512) * 1024, error)
}

impl Config {
    fn admit_session(&self, ephemeral: bool) -> Result<()> {
        require(mapping_open("oblivion-session")?
            || !(runtime_record("session-recovery-required").exists() || runtime_record("session-info").exists()), "recovery_required")?;
        let opened = open_sessions()?;
        require(!opened.iter().any(|entry| entry.recovery_required), "recovery_required")?;
        let vm = self.vm.as_ref().map_or(0, crate::vm::Config::reservation_mib);
        let ram_disk = if ephemeral { self.ephemeral_mib } else { 0 };
        if ephemeral {
            let runtime = File::open(RUN).map_err(|_| Error("runtime_check_failed"))?;
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            require(unsafe { libc::fstatvfs(runtime.as_raw_fd(), stats.as_mut_ptr()) } == 0, "runtime_check_failed")?;
            let stats = unsafe { stats.assume_init() };
            require(stats.f_bavail.saturating_mul(stats.f_frsize) >= (ram_disk + 16) * MIB, "insufficient_ephemeral_storage")?;
        }
        // The KDF and the new guest do not run together. A RAM-backed volume
        // does remain resident through both phases and must fit in full.
        let peak = ram_disk + vm.max(u64::from(self.pbkdf_memory_kib).div_ceil(1024).max(256));
        self.admit_memory(self.reserved_mib(&opened)?, ram_disk + vm, peak,
            if ephemeral { "insufficient_ephemeral_memory" } else { "insufficient_session_memory" })
    }

    fn admit_agent(&self, network: bool) -> Result<()> {
        let opened = open_sessions()?;
        require(!opened.iter().any(|entry| entry.recovery_required), "recovery_required")?;
        let additional = if network && !gateway_reserved()? {
            self.gateway.as_ref().map_or(0, crate::vm::Config::reservation_mib)
        } else { 0 };
        self.admit_memory(self.reserved_mib(&opened)?, additional, additional, "insufficient_gateway_memory")
    }

    fn prepare_agent_gateway(&self, id: &str) -> Result<()> {
        // Documents keeps its offline VM until capacity and the transport are
        // ready. A failed preflight must release any partly started gateway.
        let result = (|| {
            self.admit_agent(true)?;
            if matches!(crate::gateway::state()?.as_str(), "inactive" | "failed") {
                crate::gateway::start(false)?;
            }
            require(crate::gateway::state()? == "active", "gateway_not_ready")?;
            crate::gateway::ready()?;
            write_session_info(id, "starting")
        })();
        if let Err(error) = result {
            // The native launcher retries asynchronous guest/Tor bootstrap.
            // Keep its reservation and offline Documents VM while it waits.
            if error.0 == "gateway_not_ready" { return Err(error); }
            if let Err(cleanup) = crate::gateway::shutdown() {
                write_key_file("session-recovery-required", b"1")?;
                return Err(cleanup);
            }
            return Err(error);
        }
        Ok(())
    }

    fn reserved_mib(&self, opened: &[OpenSession]) -> Result<u64> {
        let guest = self.vm.as_ref().map_or(0, crate::vm::Config::reservation_mib);
        let gateway = self.gateway.as_ref().map_or(0, crate::vm::Config::reservation_mib);
        let profile = if mount_mode()? == MountMode::RamOnly { RAM_PROFILE_RESERVE_MIB } else { 0 };
        let children = agent_safe_records()?.into_iter().filter(|record| record.ephemeral)
            .try_fold(0u64, |total, record| -> Result<u64> {
                let image = if record.image(false).try_exists().map_err(|_| Error("ephemeral_check_failed"))? { record.image(false) } else { record.image(true) };
                let bytes = if image.try_exists().map_err(|_| Error("ephemeral_check_failed"))? {
                    trusted_file(&image)?.metadata().map_err(|_| Error("metadata_failed"))?.len().div_ceil(MIB)
                } else { 0 };
                Ok(total + bytes)
            })?;
        opened.iter().try_fold(profile + children, |total, entry| scope::within(entry.slot, || {
            let ram_disk = match fs::symlink_metadata(scope::path(EPHEMERAL)) {
                Ok(metadata) => metadata.len().div_ceil(MIB),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(_) => return Err(Error("ephemeral_check_failed")),
            };
            // An open volume commits one guest even while it is rebooting.
            // A gateway is committed only once its owner/VM has started.
            Ok(total + guest + ram_disk + if gateway != 0 && gateway_reserved()? { gateway } else { 0 })
        }))
    }

    fn admit_memory(&self, reserved: u64, additional: u64, peak: u64, error: &'static str) -> Result<()> {
        let memory = fs::read_to_string("/proc/meminfo").map_err(|_| Error("memory_unavailable"))?;
        memory_admission(&memory, reserved, additional, peak, error)
    }

    fn close_slot(&self, force: bool) -> Result<bool> {
        crate::ipc::revoke_live_media()?;
        crate::ipc::release_family()?;
        if !mapping_open("oblivion-session")?
            && !Path::new(&crate::vm::Role::Gateway.runtime()).exists()
            && !Path::new(&crate::vm::Role::Session.runtime()).exists()
            && !Path::new(&scope::path(EPHEMERAL)).exists()
            && ephemeral_child_id()?.is_none()
            && !runtime_record("session-recovery-required").exists()
            && !runtime_record("session-info").exists()
            && !runtime_record("personal-restore").exists()
            && crate::share_host::maintenance_opening()?.is_none()
            && !crate::transfer_host::prepared()? && !crate::onion_host::prepared()? {
            return Ok(true);
        }
        // Each independent stop is attempted even when another fails. Nothing
        // unmaps the volume until all its owners are confirmed stopped.
        let gateway = self.gateway.as_ref().map_or(Ok(true), |_| crate::gateway::shutdown());
        let onion = if self.onion.is_some() || crate::onion_host::prepared()? { crate::onion_host::shutdown() } else { Ok(true) };
        let transfers = crate::transfer_host::stop();
        let session = self.vm.as_ref().map_or(Ok(()), |_| crate::vm::stop(force));
        let result = (|| {
            let saved_gateway = gateway?;
            let saved_onion = onion?;
            if transfers.is_err() && force { crate::transfer_host::stop()?; } else { transfers?; }
            session?;
            close_session()?;
            let ephemeral_profiles = Path::new(&scope::current().runtime()).join("network-profile");
            if ephemeral_profiles.exists() { fs::remove_dir_all(ephemeral_profiles).map_err(|_| Error("profile_cleanup_failed"))?; }
            clear_key_file("session-info")?;
            clear_key_file("access.json")?;
            clear_key_file("native-offline")?;
            clear_key_file("share-import")?;
            clear_key_file("personal-restore")?;
            clear_key_file("manual-owner")?;
            let clients = Path::new(&scope::current().runtime()).join("agent-clients");
            if clients.exists() { fs::remove_dir_all(clients).map_err(|_| Error("client_cleanup_failed"))?; }
            crate::share_host::clear()?;
            clear_key_file("session-recovery-required")?;
            clear_transport_selection()?;
            clear_network_selection()?;
            Ok(saved_gateway && saved_onion)
        })();
        if result.is_err() { write_key_file("session-recovery-required", b"1")?; }
        result
    }
}

#[cfg(test)]
mod share_metadata_tests {
    use super::*;

    #[test]
    fn share_maintenance_allows_only_persistent_catalog_rename_without_guest_access() {
        assert!(share_slot_allows_operation("rename-session", MountMode::ReadWrite));
        for mode in [MountMode::ReadOnly, MountMode::RamOnly, MountMode::Closed] {
            assert!(!share_slot_allows_operation("rename-session", mode));
            assert!(share_slot_allows_operation("close", mode));
            assert!(share_slot_allows_operation("status", mode));
        }
        for op in ["enter-documents", "start-agent", "session-storage", "egress"] {
            assert!(!share_slot_allows_operation(op, MountMode::ReadWrite));
        }
    }

    #[test]
    fn unresolved_imported_proxy_label_survives_only_until_transport_is_configured() {
        assert_eq!(share_proxy_requirement(None, Some("Research proxy")), Some("Research proxy".into()));
        assert_eq!(share_proxy_requirement(None, None), None);
        let tor = egress::Profile::default();
        assert_eq!(share_proxy_requirement(Some(&tor), Some("Research proxy")), None);
        let socks = egress::Profile::new(oblivion_transport::Transport::Socks5 {
            endpoint: "192.0.2.20:1080".parse().unwrap(), authentication: None,
        }).unwrap();
        assert_eq!(share_proxy_requirement(Some(&socks), Some("Research proxy")), Some("SOCKS5 proxy".into()));
    }
}

#[cfg(test)]
mod admission_tests {
    use super::memory_admission;

    fn memory(total: u64, available: u64) -> String {
        format!("MemTotal: {} kB\nMemAvailable: {} kB\n", total * 1024, available * 1024)
    }

    #[test]
    fn offline_safes_commit_guests_without_unstarted_gateways() {
        assert!(memory_admission(&memory(6144, 3072), 2304, 1152, 1152, "insufficient_session_memory").is_ok());
    }

    #[test]
    fn gateway_promotion_checks_new_commitment_and_available_memory() {
        assert!(memory_admission(&memory(6144, 2048), 3456, 896, 896, "insufficient_gateway_memory").is_ok());
        assert_eq!(memory_admission(&memory(6144, 2048), 5248, 896, 896, "insufficient_gateway_memory").err().unwrap().0, "insufficient_gateway_memory");
        assert_eq!(memory_admission(&memory(6144, 1024), 1152, 896, 896, "insufficient_gateway_memory").err().unwrap().0, "insufficient_gateway_memory");
    }

    #[test]
    fn ephemeral_disk_memory_stays_resident_during_guest_start() {
        assert!(memory_admission(&memory(6144, 2048), 0, 1664, 1664, "insufficient_ephemeral_memory").is_ok());
        assert_eq!(memory_admission(&memory(6144, 1800), 0, 1664, 1664, "insufficient_ephemeral_memory").err().unwrap().0, "insufficient_ephemeral_memory");
    }

    #[test]
    fn missing_kernel_memory_observation_fails_closed() {
        assert_eq!(memory_admission("MemTotal: 6291456 kB\n", 0, 1152, 1152, "insufficient_session_memory").err().unwrap().0, "memory_unavailable");
    }
}
