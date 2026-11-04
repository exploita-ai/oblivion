use crate::storage::{Error, Result, lock_named, require};
use oblivion_host::channel::Channel;
use oblivion_host::family::Capability;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const SOCKET: &str = "/run/oblivion-control.sock";

struct CachedFamily {
    safe_id: String,
    capability: Capability,
}

type Families = Arc<Mutex<BTreeMap<u8, CachedFamily>>>;

thread_local! {
    static WORKER_CHANNEL: RefCell<Option<UnixStream>> = const { RefCell::new(None) };
    static TOOL_OWNER: RefCell<Option<OwnedFd>> = const { RefCell::new(None) };
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum FamilyRequest {
    Retain { safe_id: String, family_id: String },
    Lookup { safe_id: String },
    ChildLookup { child_id: String },
    Release { slot: oblivion_host::scope::Slot },
    ExportLookup { export_id: String, safe_id: String, family_id: String },
    ExportRetain { export_id: String, safe_id: String, family_id: String },
    ExportOpened { export_id: String, opening: oblivion_host::autolock::Opening },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FamilyResponse {
    safe_id: String,
    family_id: String,
}

/// FD3 exists only in a controller-spawned worker. Mark it close-on-exec before
/// any cryptsetup, systemd or hypervisor subprocess can inherit family access.
pub fn init_worker_channel() -> Result<()> {
    if !std::env::args().any(|argument| argument == "--family-channel") {
        return Ok(());
    }
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    unsafe {
        require(libc::geteuid() == 0, "root_required")?;
        require(libc::getsockopt(3, libc::SOL_SOCKET, libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(), &mut length) == 0, "family_channel_failed")?;
        let peer = peer.assume_init();
        require(peer.uid == 0 && peer.pid == libc::getppid(), "family_channel_failed")?;
        require(libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) == 0, "family_channel_failed")?;
        WORKER_CHANNEL.with(|channel| *channel.borrow_mut() = Some(UnixStream::from_raw_fd(3)));
        if std::env::args().any(|argument| argument == "--safe-tools-owner") {
            require(libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) == 0, "safe_tools_owner_unknown")?;
            TOOL_OWNER.with(|owner| *owner.borrow_mut() = Some(OwnedFd::from_raw_fd(4)));
        }
    }
    Ok(())
}

pub(crate) fn retain_family(safe_id: &str, capability: &Capability) -> Result<()> {
    WORKER_CHANNEL.with(|channel| {
        let binding = channel.borrow();
        let Some(stream) = binding.as_ref() else { return Ok(()) };
        let mut channel = Channel::new(stream, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::Retain {
            safe_id: safe_id.to_string(), family_id: capability.family_id().to_string(),
        })?;
        channel.write_all(capability.root_secret()).map_err(|_| Error("family_channel_failed"))?;
        family_ack(&mut channel)
    })
}

pub(crate) fn release_family() -> Result<()> {
    WORKER_CHANNEL.with(|channel| {
        let binding = channel.borrow();
        let Some(stream) = binding.as_ref() else { return Ok(()) };
        let mut channel = Channel::new(stream, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::Release { slot: oblivion_host::scope::current() })?;
        family_ack(&mut channel)
    })
}

/// Only the current authorized Safe's family may be requested by its worker.
pub(crate) fn authorized_family(safe_id: &str) -> Result<Option<Capability>> {
    crate::storage::validate_id(safe_id)?;
    WORKER_CHANNEL.with(|channel| {
        let binding = channel.borrow();
        let Some(stream) = binding.as_ref() else { return Ok(None) };
        let mut channel = Channel::new(stream, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::Lookup { safe_id: safe_id.to_string() })?;
        let response: Option<FamilyResponse> = family_read(&mut channel)?;
        let Some(response) = response else { return Ok(None) };
        let mut secret = Zeroizing::new([0; 32]);
        channel.read_exact(secret.as_mut()).map_err(|_| Error("family_channel_failed"))?;
        require(response.safe_id == safe_id, "family_authorization_changed")?;
        Ok(Some(Capability::from_root_secret(&response.family_id, secret).map_err(Error)?))
    })
}

/// Only a root worker can ask for an existing child's derived credential.
/// The daemon discovers and verifies its live parent; no parent slot is input.
pub(crate) fn authorized_child_family(child_id: &str) -> Result<Option<Capability>> {
    crate::storage::validate_id(child_id)?;
    WORKER_CHANNEL.with(|binding| {
        let binding = binding.borrow();
        let stream = binding.as_ref().ok_or(Error("trusted_safe_channel_required"))?;
        let mut channel = Channel::new(stream, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::ChildLookup { child_id: child_id.to_owned() })?;
        let response: Option<FamilyResponse> = family_read(&mut channel)?;
        let Some(response) = response else { return Ok(None) };
        require(response.safe_id == child_id, "family_authorization_changed")?;
        let mut secret = Zeroizing::new([0; 32]);
        channel.read_exact(secret.as_mut()).map_err(|_| Error("family_channel_failed"))?;
        Ok(Some(Capability::from_root_secret(&response.family_id, secret).map_err(Error)?))
    })
}

pub(crate) fn family_channel_available() -> bool {
    WORKER_CHANNEL.with(|channel| channel.borrow().is_some())
}

pub(crate) fn export_capability(export_id: &str, safe_id: &str, family_id: &str) -> Result<Option<Capability>> {
    WORKER_CHANNEL.with(|binding| {
        let binding = binding.borrow();
        let stream = binding.as_ref().ok_or(Error("trusted_share_channel_required"))?;
        let mut channel = Channel::new(stream, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::ExportLookup { export_id: export_id.into(), safe_id: safe_id.into(), family_id: family_id.into() })?;
        let response: Option<FamilyResponse> = family_read(&mut channel)?;
        let Some(response) = response else { return Ok(None) };
        require(response.safe_id == safe_id && response.family_id == family_id, "share_source_not_authorized")?;
        let mut secret = Zeroizing::new([0; 32]);
        channel.read_exact(secret.as_mut()).map_err(|_| Error("family_channel_failed"))?;
        Ok(Some(Capability::from_root_secret(family_id, secret).map_err(Error)?))
    })
}

pub(crate) fn retain_export_capability(export_id: &str, safe_id: &str, capability: &Capability) -> Result<()> {
    WORKER_CHANNEL.with(|binding| {
        let binding = binding.borrow();
        let mut channel = Channel::new(binding.as_ref().ok_or(Error("trusted_share_channel_required"))?, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::ExportRetain { export_id: export_id.into(), safe_id: safe_id.into(), family_id: capability.family_id().into() })?;
        channel.write_all(capability.root_secret()).map_err(|_| Error("family_channel_failed"))?;
        family_ack(&mut channel)
    })
}

pub(crate) fn export_opened(export_id: &str, opening: &oblivion_host::autolock::Opening) -> Result<()> {
    WORKER_CHANNEL.with(|binding| {
        let binding = binding.borrow();
        let mut channel = Channel::new(binding.as_ref().ok_or(Error("trusted_share_channel_required"))?, Duration::from_secs(10));
        family_write(&mut channel, &FamilyRequest::ExportOpened { export_id: export_id.into(), opening: opening.clone() })?;
        family_ack(&mut channel)
    })
}

pub(crate) fn require_tool_owner() -> Result<()> {
    TOOL_OWNER.with(|binding| {
        let binding = binding.borrow();
        let owner = binding.as_ref().ok_or(Error("trusted_safe_channel_required"))?;
        require(unsafe { libc::syscall(libc::SYS_pidfd_send_signal, owner.as_raw_fd(), 0,
            std::ptr::null::<libc::siginfo_t>(), 0) } == 0 && crate::safe_tools::owner_alive(owner)?, "safe_tools_owner_expired")
    })
}

pub(crate) fn tool_owner_alive() -> Result<bool> {
    TOOL_OWNER.with(|binding| {
        let binding = binding.borrow();
        crate::safe_tools::owner_alive(binding.as_ref().ok_or(Error("safe_tools_owner_unknown"))?)
    })
}

fn family_ack(channel: &mut Channel<'_>) -> Result<()> {
    let mut ack = [0];
    channel.read_exact(&mut ack).map_err(|_| Error("family_channel_failed"))?;
    require(ack == [b'K'], "family_channel_failed")
}

fn family_write(channel: &mut Channel<'_>, message: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(message).map_err(|_| Error("family_channel_failed"))?;
    require((1..=512).contains(&bytes.len()), "family_channel_failed")?;
    channel.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| channel.write_all(&bytes)).map_err(|_| Error("family_channel_failed"))
}

fn family_read<T: serde::de::DeserializeOwned>(channel: &mut Channel<'_>) -> Result<T> {
    let mut length = [0; 4];
    channel.read_exact(&mut length).map_err(|_| Error("family_channel_failed"))?;
    let length = u32::from_be_bytes(length) as usize;
    require((1..=512).contains(&length), "family_channel_failed")?;
    let mut bytes = vec![0; length];
    channel.read_exact(&mut bytes).map_err(|_| Error("family_channel_failed"))?;
    serde_json::from_slice(&bytes).map_err(|_| Error("family_channel_failed"))
}

fn serve_families(stream: UnixStream, families: Families, slot: u8) -> Result<()> {
    let result = (|| {
    loop {
        // Idle workers may be bootstrapping a VM for longer than an exchange.
        // EOF closes this private channel when that worker exits.
        stream.set_read_timeout(None).map_err(|_| Error("family_channel_failed"))?;
        let mut first = [0];
        let count = unsafe { libc::recv(stream.as_raw_fd(), first.as_mut_ptr().cast(), 1, libc::MSG_PEEK) };
        require(count >= 0, "family_channel_failed")?;
        if count == 0 { return Ok(()) }
        let mut channel = Channel::new(&stream, Duration::from_secs(10));
        match family_read::<FamilyRequest>(&mut channel)? {
            FamilyRequest::ChildLookup { child_id } => {
                let parent = crate::storage::child_family_source(&child_id)?;
                let cached = families.lock().map_err(|_| Error("family_cache_failed"))?
                    .get(&parent.slot.index()).filter(|cached| cached.safe_id == parent.safe_id).map(|cached| (
                        FamilyResponse { safe_id: child_id, family_id: cached.capability.family_id().to_owned() },
                        Zeroizing::new(*cached.capability.root_secret()),
                    ));
                family_write(&mut channel, &cached.as_ref().map(|entry| &entry.0))?;
                if let Some((_, secret)) = cached { channel.write_all(secret.as_ref()).map_err(|_| Error("family_channel_failed"))?; }
            }
            FamilyRequest::ExportLookup { export_id, safe_id, family_id } => {
                let host = crate::storage::share_export_host()?;
                if let Some(opening) = crate::share_export::registry().current(&export_id, &host, &safe_id)? {
                    require(crate::storage::share_export_opening_closed(&opening)?, "share_source_active")?;
                    crate::share_export::registry().closed(&opening)?;
                }
                let cached = crate::share_export::registry().lookup(&export_id, &host, &safe_id, &family_id)?;
                family_write(&mut channel, &cached.as_ref().map(|_| FamilyResponse { safe_id, family_id }))?;
                if let Some(capability) = cached { channel.write_all(capability.root_secret()).map_err(|_| Error("family_channel_failed"))?; }
            }
            FamilyRequest::ExportRetain { export_id, safe_id, family_id } => {
                let mut secret = Zeroizing::new([0; 32]);
                channel.read_exact(secret.as_mut()).map_err(|_| Error("family_channel_failed"))?;
                crate::share_export::registry().retain(&export_id, &crate::storage::share_export_host()?, &safe_id,
                    Capability::from_root_secret(&family_id, secret).map_err(Error)?)?;
                channel.write_all(b"K").map_err(|_| Error("family_channel_failed"))?;
            }
            FamilyRequest::ExportOpened { export_id, opening } => {
                require(opening.slot.index() == slot, "session_changed")?;
                crate::share_export::registry().opened(&export_id, &crate::storage::share_export_host()?, opening)?;
                channel.write_all(b"K").map_err(|_| Error("family_channel_failed"))?;
            }
            FamilyRequest::Retain { safe_id, family_id } => {
                crate::storage::validate_id(&safe_id)?;
                let mut secret = Zeroizing::new([0; 32]);
                channel.read_exact(secret.as_mut()).map_err(|_| Error("family_channel_failed"))?;
                let capability = Capability::from_root_secret(&family_id, secret).map_err(Error)?;
                families.lock().map_err(|_| Error("family_cache_failed"))?
                    .insert(slot, CachedFamily { safe_id, capability });
                channel.write_all(b"K").map_err(|_| Error("family_channel_failed"))?;
            }
            FamilyRequest::Release { slot: target } => {
                // One trusted branch/global cleanup worker may close several
                // slots. Its release target follows that explicit inner scope.
                families.lock().map_err(|_| Error("family_cache_failed"))?.remove(&target.index());
                channel.write_all(b"K").map_err(|_| Error("family_channel_failed"))?;
            }
            FamilyRequest::Lookup { safe_id } => {
                crate::storage::validate_id(&safe_id)?;
                let cached = families.lock().map_err(|_| Error("family_cache_failed"))?
                    .get(&slot).filter(|cached| cached.safe_id == safe_id).map(|cached| (
                        FamilyResponse { safe_id: cached.safe_id.clone(), family_id: cached.capability.family_id().to_string() },
                        Zeroizing::new(*cached.capability.root_secret()),
                    ));
                family_write(&mut channel, &cached.as_ref().map(|entry| &entry.0))?;
                if let Some((_, secret)) = cached {
                    channel.write_all(secret.as_ref()).map_err(|_| Error("family_channel_failed"))?;
                }
            }
        }
    }
    })();
    if result.is_err() {
        families.lock().map_err(|_| Error("family_cache_failed"))?.remove(&slot);
    }
    result
}

#[cfg(test)]
pub(crate) fn assert_child_lookup_is_fenced(child: &str, parent: &str) {
    let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
    families.lock().unwrap().insert(0, CachedFamily { safe_id: parent.to_owned(),
        capability: Capability::from_root_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Zeroizing::new([7; 32])).unwrap() });
    let (server, client) = UnixStream::pair().unwrap();
    let cache = Arc::clone(&families);
    let daemon = std::thread::spawn(move || serve_families(server, cache, 1));
    WORKER_CHANNEL.with(|binding| *binding.borrow_mut() = Some(client));
    let result = oblivion_host::scope::within(1.try_into().unwrap(), || authorized_child_family(child));
    WORKER_CHANNEL.with(|binding| binding.borrow_mut().take());
    assert!(result.is_err());
    assert!(matches!(daemon.join().unwrap(), Err(Error("safe_branch_closing"))));
    let cache = families.lock().unwrap();
    assert_eq!(cache.len(), 1);
    assert_eq!(cache[&0].capability.root_secret(), &[7; 32]);
}

fn worker_output(mut command: Command, input: Zeroizing<Vec<u8>>, families: &Families, slot: u8, owner: Option<Arc<OwnedFd>>) -> Result<Output> {
    let deadline = owner.as_ref().map(|_| Instant::now() + Duration::from_secs(150));
    let (parent, worker) = UnixStream::pair().map_err(|_| Error("family_channel_failed"))?;
    command.arg("--family-channel").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if owner.is_some() { command.arg("--safe-tools-owner"); }
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(worker.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(owner) = &owner {
                if libc::dup2(owner.as_raw_fd(), 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| Error("operation_start_failed"))?;
    // Drop the parent's copy of the worker endpoint; EOF must track the worker.
    drop(command);
    let families = Arc::clone(families);
    let server = std::thread::spawn(move || serve_families(parent, families, slot));
    let output = if let Some(deadline) = deadline {
        tool_output(child, input, deadline)
    } else {
        let sent = child.stdin.take().ok_or(Error("secret_pipe_failed"))?.write_all(&input);
        drop(input);
        let output = child.wait_with_output().map_err(|_| Error("operation_wait_failed"));
        match sent { Ok(()) => output, Err(_) => Err(Error("secret_pipe_failed")) }
    };
    let served = server.join().map_err(|_| Error("family_channel_failed"))?;
    // A killed worker can close a partially consumed private exchange. Preserve
    // the unknown outcome rather than reclassifying it as a failed creation.
    if output.as_ref().is_err_and(|error| error.0 == "safe_tool_outcome_unknown") { return output }
    served?;
    output
}

fn tool_output(mut child: std::process::Child, input: Zeroizing<Vec<u8>>, deadline: Instant) -> Result<Output> {
    // These two tools have small bounded replies. Drain both pipes while
    // enforcing one monotonic deadline, including input and worker exit.
    let stdout = child.stdout.take().ok_or(Error("invalid_safe_tools_response"))?;
    let stderr = child.stderr.take().ok_or(Error("invalid_safe_tools_response"))?;
    let stdout = std::thread::spawn(move || { let mut bytes = Vec::new(); stdout.take(crate::safe_tools::LIMIT as u64 + 1).read_to_end(&mut bytes).map(|_| bytes) });
    let stderr = std::thread::spawn(move || { let mut bytes = Vec::new(); stderr.take(1025).read_to_end(&mut bytes).map(|_| bytes) });
    let sent = send_tool_input(child.stdin.take().ok_or(Error("secret_pipe_failed"))?, &input, deadline);
    drop(input);
    let mut timed_out = sent.is_err();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| Error("operation_wait_failed"))? { break status }
        if timed_out || Instant::now() >= deadline {
            timed_out = true;
            // The formatter inherits storage.lock, but not FD3/FD4 or
            // these output pipes. Killing this worker cannot unlock a
            // volume while its formatter is still modifying the image.
            let _ = child.kill();
            break child.wait().map_err(|_| Error("operation_wait_failed"))?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().map_err(|_| Error("invalid_safe_tools_response"))?
        .map_err(|_| Error("invalid_safe_tools_response"))?;
    let stderr = stderr.join().map_err(|_| Error("invalid_safe_tools_response"))?
        .map_err(|_| Error("invalid_safe_tools_response"))?;
    if timed_out { Err(Error("safe_tool_outcome_unknown")) }
    else { Ok(Output { status, stdout, stderr }) }
}

fn send_tool_input(mut input: std::process::ChildStdin, bytes: &[u8], deadline: Instant) -> Result<()> {
    let fd = input.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    require(flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0, "secret_pipe_failed")?;
    let mut offset = 0;
    while offset < bytes.len() {
        let left = deadline.checked_duration_since(Instant::now()).ok_or(Error("safe_tool_outcome_unknown"))?;
        let mut event = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        let ready = unsafe { libc::poll(&mut event, 1, left.as_millis().clamp(1, i32::MAX as u128) as i32) };
        require(ready > 0 && event.revents & libc::POLLOUT != 0, "safe_tool_outcome_unknown")?;
        match input.write(&bytes[offset..]) {
            Ok(0) => return Err(Error("safe_tool_outcome_unknown")),
            Ok(size) => offset += size,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
            Err(_) => return Err(Error("secret_pipe_failed")),
        }
    }
    Ok(())
}

fn tool_worker(config: &Path, families: &Families, jobs: &Arc<crate::chat_jobs::Registry>, context: &crate::safe_tools::Context,
    request: &crate::safe_tools::Request) -> crate::safe_tools::DispatchResult {
    if matches!(request.call, crate::safe_tools::Call::ChatCreate { .. } | crate::safe_tools::Call::ChatStatus { .. } | crate::safe_tools::Call::ChatCancel { .. }) {
        let config = config.to_owned();
        let families = Arc::clone(families);
        return jobs.call(context, request, Arc::new(move |context, client| managed_release(&config, &families, context, client)));
    }
    #[derive(Serialize)]
    struct Selection { offset: u8 }
    #[derive(Serialize)]
    struct Creation<'a> {
        agent: &'a str,
        task: &'a str,
        request_id: &'a str,
        creator_chat_id: Option<&'a str>,
    }
    let creating = matches!(request.call, crate::safe_tools::Call::SafeCreate { .. });
    let (operation, input) = match &request.call {
        crate::safe_tools::Call::ChatCreate { .. } | crate::safe_tools::Call::ChatStatus { .. } | crate::safe_tools::Call::ChatCancel { .. } => unreachable!(),
        crate::safe_tools::Call::SafeStatus { offset } => ("safe-tools-status", serde_json::to_vec(&Selection { offset:*offset })),
        crate::safe_tools::Call::SafeCreate { agent, task, creator_chat_id } => ("safe-child-create", serde_json::to_vec(&Creation {
            agent,task,request_id:&request.request_id,creator_chat_id:creator_chat_id.as_deref(),
        })),
    };
    let input = Zeroizing::new(input.map_err(|_| "invalid_safe_tools_request".to_string())?);
    let mut command = Command::new(std::env::current_exe().map_err(|_| "executable_unavailable".to_string())?);
    command.arg("--config").arg(config).arg(operation)
        .args(["--slot", &context.slot.index().to_string(), "--expected-session", &context.safe_id])
        .env_clear().current_dir("/");
    let output = worker_output(command, input, families, context.slot.index(), Some(Arc::clone(&context.owner)))
        .map_err(|error| if creating { "safe_tool_outcome_unknown".to_string() } else { error.0.to_string() })?;
    if !output.status.success() {
        let code = String::from_utf8(output.stderr).unwrap_or_default();
        let code = code.trim();
        if creating && !matches!(code,
            "safe_child_limit" | "safe_depth_limit" | "safe_branch_limit" | "safe_provenance_limit"
            | "insufficient_space" | "insufficient_ephemeral_storage" | "insufficient_ephemeral_memory"
            | "safe_branch_closing" | "session_changed" | "agent_safe_required" | "family_not_authorized"
            | "trusted_safe_channel_required" | "safe_tools_owner_expired" | "recovery_required"
            | "controller_busy" | "invalid_safe_child_request" | "general_not_writable") {
            return Err("safe_tool_outcome_unknown".into());
        }
        return Err(if (1..=96).contains(&code.len())
            && code.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
            code.to_string()
        } else { "safe_tool_operation_failed".to_string() });
    }
    if output.stdout.len() > crate::safe_tools::LIMIT {
        return Err(if creating { "safe_tool_outcome_unknown" } else { "invalid_safe_tools_response" }.into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| if creating {
        "safe_tool_outcome_unknown".into()
    } else { "invalid_safe_tools_response".into() })
}

fn managed_release(config: &Path, families: &Families, context: &crate::safe_tools::Context, client: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut command = Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
        command.arg("--config").arg(config).arg("managed-release")
            .args(["--slot", &context.slot.index().to_string(), "--expected-session", &context.safe_id])
            .env_clear().current_dir("/");
        let body = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"opening":context.opening,"client":client})).map_err(|_| Error("encode_failed"))?);
        match worker_output(command, body, families, context.slot.index(), Some(Arc::clone(&context.owner))) {
            Ok(output) if output.status.success() || output.stderr == b"session_changed\n" => return Ok(()),
            Ok(output) if output.stderr == b"controller_busy\n" && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => return Err(Error("chat_job_cleanup_required")),
        }
    }
}

fn cleanup_export(config: &Path, families: &Families, opening: Option<oblivion_host::autolock::Opening>) -> Result<()> {
    let Some(opening) = opening else { return Ok(()) };
    let mut command = Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
    command.arg("--config").arg(config).arg("share-export-cleanup")
        .args(["--slot", &opening.slot.index().to_string(), "--expected-session", &opening.safe_id]).env_clear();
    let output = worker_output(command, Zeroizing::new(serde_json::to_vec(&opening).map_err(|_| Error("encode_failed"))?), families, opening.slot.index(), None)?;
    if output.status.success() || output.stderr == b"session_changed\n" { return Ok(()) }
    crate::idle_controller::latch(&crate::idle_controller::Target::Safe { opening })?;
    Err(Error("share_cleanup_required"))
}

fn idle_worker(config: &Path, families: &Families, target: &crate::idle_controller::Target) -> Result<()> {
    use crate::idle_controller::Target;
    target.validate()?;
    let mut command = Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
    command.arg("--config").arg(config).env_clear().current_dir("/");
    let slot = match target {
        Target::Host { .. } => { crate::share_export::registry().end(None)?; command.args(["idle-lock", "--slot", "0"]); 0 }
        Target::Safe { opening } => {
            crate::share_export::registry().revoke_opening(opening)?;
            command.args(["idle-close", "--slot", &opening.slot.index().to_string(), "--expected-session", &opening.safe_id]);
            opening.slot.index()
        }
    };
    let input = Zeroizing::new(serde_json::to_vec(target).map_err(|_| Error("encode_failed"))?);
    let output = worker_output(command, input, families, slot, None)?;
    if output.status.success() { return Ok(()) }
    let code = std::str::from_utf8(&output.stderr).map_err(|_| Error("invalid_response"))?.trim();
    Err(Error(match code {
        "idle_opening_changed" | "session_changed" => "idle_opening_changed",
        "controller_busy" => "controller_busy",
        "locked_without_tor_state" => "locked_without_tor_state",
        _ => "idle_cleanup_required",
    }))
}

fn rollback_agent_start(config: &Path, families: &Families, opening: &oblivion_host::autolock::Opening,
    owner: Option<Arc<OwnedFd>>) -> Result<()> {
    let mut command = Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
    command.arg("--config").arg(config).arg("native-start-failed")
        .args(["--slot", &opening.slot.index().to_string(), "--expected-session", &opening.safe_id])
        .env_clear().current_dir("/");
    let input = Zeroizing::new(serde_json::to_vec(opening).map_err(|_| Error("encode_failed"))?);
    let output = worker_output(command, input, families, opening.slot.index(), owner);
    if output.as_ref().is_ok_and(|output| output.status.success()
        || output.stderr == b"session_changed\n") { return Ok(()) }
    // A failed cleanup fences only this opening. The resident monitor can
    // finish locking it; a replacement opening has a different nonce.
    crate::idle_controller::latch(&crate::idle_controller::Target::Safe { opening: opening.clone() })?;
    Err(Error("native_start_cleanup_required"))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    InitGeneral,
    PrepareUsb,
    SafeAccess,
    ClaimIntro,
    OpenDocuments,
    OpenChildDocuments,
    OpenDocumentsEphemeral,
    StartAgent,
    PinSafe,
    AgentAttach,
    FileAttach,
    AgentRelease,
    ShareAttach,
    ShareRelease,
    ShareExportCancel,
    ShareExportBegin,
    ShareExportLease,
    ShareExportEnd,
    ShareExportSourceOpen,
    ShareImportBegin,
    ShareImportOpen,
    ShareImportAttach,
    ShareImportFinish,
    ShareImportCommit,
    ShareImportAbort,
    ShareImportDiscard,
    ShareImportStatus,
    ShutdownRuntime,
    ShutdownIdle,
    Browse,
    Diagnostics,
    DiscardGeneralPending,
    DiscardSessionPending,
    Unlock,
    UnlockReadOnly,
    EnterRam,
    Create,
    RenameSession,
    SessionStorage,
    Close,
    CloseIdle,
    ForceClose,
    Lock,
    Status,
    Activity,
    IdleSettings,
    Debug,
    Egress,
    ProxyProfiles,
    NetworkPolicy,
    Transfers,
    Onion,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: Operation,
    session: Option<String>,
    secret_len: u32,
    expected_session: Option<String>,
    #[serde(default)]
    slot: oblivion_host::scope::Slot,
}

fn secret_limit(operation: &Operation) -> u32 {
    match operation {
        Operation::ShareImportBegin => (oblivion_share::manifest::MAX_METADATA + 4096) as u32,
        Operation::SessionStorage | Operation::Browse | Operation::PrepareUsb | Operation::SafeAccess
            | Operation::Egress | Operation::ProxyProfiles | Operation::NetworkPolicy | Operation::Transfers
            | Operation::Onion | Operation::ShareExportSourceOpen | Operation::ShareImportOpen | Operation::ShareImportFinish => 4096,
        _ => 1024,
    }
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    output: String,
    error: Option<String>,
    #[serde(skip)]
    console: Option<UnixStream>,
    #[serde(skip)]
    lease: Option<ClientLease>,
}

struct ClientLease {
    slot: oblivion_host::scope::Slot,
    id: String,
    safe_id: String,
    operation: &'static str,
    secret: Zeroizing<Vec<u8>>,
    export: Option<String>,
    _hold: Option<UnixStream>,
    timeout: Option<Duration>,
}

pub fn serve(config: &Path, uid: u32) -> Result<()> {
    let _lock = lock_named("daemon.lock")?;
    let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
    let tools = Arc::new(crate::safe_tools::Registry::default());
    let ordinary = Arc::new(Mutex::new(()));
    let connections = Arc::new(AtomicUsize::new(0));
    let idle = crate::idle_controller::Controller::new()?;
    let worker_config = config.to_owned();
    let worker_families = Arc::clone(&families);
    idle.start(move |target| idle_worker(&worker_config, &worker_families, target));
    // /run is root-owned. The lock prevents unlinking the socket of a live daemon.
    // A manager can connect but cannot replace its inode or choose another path.
    if Path::new(SOCKET).exists() {
        fs::remove_file(SOCKET).map_err(|_| Error("socket_cleanup_failed"))?;
    }
    let listener = UnixListener::bind(SOCKET).map_err(|_| Error("socket_bind_failed"))?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("socket_permissions_failed"))?;
    unsafe {
        require(
            libc::chown(c"/run/oblivion-control.sock".as_ptr(), uid, !0) == 0,
            "socket_owner_failed",
        )?;
    }
    notify_ready()?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if connections.fetch_add(1, Ordering::AcqRel) >= 32 {
            connections.fetch_sub(1, Ordering::Release);
            continue;
        }
        let permit = ConnectionPermit(Arc::clone(&connections));
        let config = config.to_owned();
        let families = Arc::clone(&families);
        let tools = Arc::clone(&tools);
        let idle = idle.clone();
        let ordinary = Arc::clone(&ordinary);
        std::thread::spawn(move || {
            let _permit = permit;
            serve_connection(stream, config, uid, families, tools, idle, ordinary);
        });
    }
    Err(Error("listener_stopped"))
}

// Ordinary operations stay serialized. At most 32 short/deadline-bounded
// frontend handlers permit actual human activity to bypass long bootstraps.
struct ConnectionPermit(Arc<AtomicUsize>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Release); }
}

fn serve_connection(mut stream: UnixStream, config: std::path::PathBuf, uid: u32, families: Families,
    tools: Arc<crate::safe_tools::Registry>, idle: crate::idle_controller::Controller, ordinary: Arc<Mutex<()>>) {
        let response = match handle(&mut stream, &config, uid, &families, &tools, &idle, &ordinary) {
            Ok(response) => response,
            Err(error) => Response {
                ok: false,
                output: String::new(),
                error: Some(error.0.to_owned()),
                console: None,
                lease: None,
            },
        };
        let mut channel = Channel::new(&stream, Duration::from_secs(10));
        if let Some(lease) = response.lease {
            let delivered = response.console.as_ref().is_some_and(|console| {
                channel.prepare_write().is_ok() && send_console(&stream, console).is_ok()
                    && channel.write_all(lease.id.as_bytes()).is_ok()
            });
            let config = config.to_owned();
            let families = Arc::clone(&families);
            std::thread::spawn(move || {
                // Keep the descriptor peer alive for a transaction-only lease;
                // disjoint closure capture would otherwise drop it here.
                let _hold = lease._hold;
                // A held local connection owns this client. Register cleanup
                // even if the launcher disappeared during descriptor delivery.
                if delivered && stream.set_read_timeout(lease.timeout).is_ok() {
                    let mut byte = [0];
                    let _ = stream.read(&mut byte);
                }
                if let Some(export) = &lease.export {
                    if let Ok(opening) = crate::share_export::registry().end(Some(export)) {
                        let _ = cleanup_export(&config, &families, opening);
                    }
                    return;
                }
                let deadline = Instant::now() + Duration::from_secs(10);
                while let Ok(exe) = std::env::current_exe() {
                    let mut command = Command::new(exe);
                    command.arg("--config").arg(&config)
                        .args([lease.operation, &lease.id, "--slot", &lease.slot.index().to_string(), "--expected-session", &lease.safe_id])
                        .env_clear();
                    let body = Zeroizing::new(lease.secret.to_vec());
                    match worker_output(command, body, &families, lease.slot.index(), None) {
                        Ok(output) if output.stderr == b"controller_busy\n" && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        _ => break,
                    }
                }
            });
            return;
        }
        // Delegate only a connected terminal, never the hypervisor monitor.
        if let Some(console) = &response.console {
            if channel.prepare_write().is_err() || send_console(&stream, console).is_err() {
                return;
            }
        }
        // One request per connection; neither payloads nor errors are logged.
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = channel.write_all(&bytes);
        }
}

fn handle(stream: &mut UnixStream, config: &Path, uid: u32, families: &Families, tools: &crate::safe_tools::Registry,
    idle: &crate::idle_controller::Controller, ordinary: &Mutex<()>) -> Result<Response> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    unsafe {
        require(
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut length,
            ) == 0,
            "peer_check_failed",
        )?;
        require(peer.assume_init().uid == uid, "unauthorized_peer")?;
    }
    let mut channel = Channel::new(stream, Duration::from_secs(10));
    let mut size = [0; 4];
    channel
        .read_exact(&mut size)
        .map_err(|_| Error("invalid_frame"))?;
    let size = u32::from_be_bytes(size) as usize;
    require((1..=1024).contains(&size), "invalid_frame_length")?;
    let mut header = vec![0; size];
    channel
        .read_exact(&mut header)
        .map_err(|_| Error("invalid_frame"))?;
    let request: Request = serde_json::from_slice(&header).map_err(|_| Error("invalid_request"))?;
    require(!matches!(request.operation, Operation::EnterRam)
        || request.expected_session.is_none() && request.slot.index() == 0, "invalid_ram_request")?;
    require(!matches!(request.operation, Operation::CloseIdle) || request.expected_session.is_some(), "expected_session_required")?;
    require(!matches!(request.operation, Operation::StartAgent) || request.expected_session.is_some(), "expected_session_required")?;
    require(!matches!(request.operation, Operation::OpenChildDocuments)
        || request.expected_session.is_some() && request.session == request.expected_session, "expected_session_required")?;
    require(!matches!(request.operation, Operation::ShareAttach | Operation::ShareRelease | Operation::ShareExportCancel
        | Operation::ShareExportSourceOpen | Operation::ShareImportOpen | Operation::ShareImportAttach | Operation::ShareImportFinish)
        || request.expected_session.is_some(), "expected_session_required")?;
    require(
        request.secret_len <= secret_limit(&request.operation),
        "invalid_secret_length",
    )?;
    require(
        matches!(
            request.operation,
            Operation::OpenDocuments | Operation::OpenChildDocuments | Operation::DiscardSessionPending | Operation::AgentRelease
                | Operation::ShareRelease | Operation::ShareExportSourceOpen
                | Operation::ShareExportLease | Operation::ShareImportFinish
        ) == request.session.is_some(),
        "invalid_session_argument",
    )?;
    for id in request.session.iter().chain(request.expected_session.iter()) {
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid_session_id",
        )?;
    }
    oblivion_host::scope::within(request.slot, || {
    let needs_secret = matches!(
        request.operation,
        Operation::InitGeneral
            | Operation::PrepareUsb
            | Operation::Unlock
            | Operation::UnlockReadOnly
            | Operation::Create
            | Operation::RenameSession
            | Operation::SessionStorage
            | Operation::OpenDocuments
            | Operation::ShareExportCancel
            | Operation::ShareExportBegin
            | Operation::ShareExportEnd
            | Operation::ShareExportSourceOpen
            | Operation::ShareImportBegin
            | Operation::ShareImportOpen
            | Operation::ShareImportFinish
            | Operation::ShareImportCommit
            | Operation::ShareImportAbort
            | Operation::ShareImportDiscard
            | Operation::Egress
            | Operation::ProxyProfiles
            | Operation::NetworkPolicy
            | Operation::Transfers
            | Operation::Onion
            | Operation::SafeAccess
            | Operation::Browse
            | Operation::Diagnostics
            | Operation::Debug
            | Operation::Activity
            | Operation::IdleSettings
            | Operation::DiscardGeneralPending
    );
    require(
        needs_secret == (request.secret_len > 0),
        "unexpected_secret",
    )?;
    let mut secret = Zeroizing::new(vec![0; request.secret_len as usize]);
    channel
        .read_exact(&mut secret)
        .map_err(|_| Error("incomplete_secret"))?;
    let _ordinary = if matches!(request.operation, Operation::Activity) { None }
        else { Some(ordinary.lock().map_err(|_| Error("controller_queue_failed"))?) };
    if matches!(request.operation, Operation::Activity | Operation::IdleSettings) {
        require(request.expected_session.is_none(), "invalid_idle_request")?;
        match request.operation {
            Operation::Activity => {
                let activity: oblivion_host::autolock::Activity = serde_json::from_slice(&secret)
                    .map_err(|_| Error("invalid_idle_activity"))?;
                require(request.slot == activity.safe.as_ref().map_or(Default::default(), |safe| safe.slot), "invalid_idle_request")?;
                idle.activity(activity)?;
            }
            Operation::IdleSettings => {
                let preferences: oblivion_host::autolock::Preferences = serde_json::from_slice(&secret)
                    .map_err(|_| Error("invalid_idle_preferences"))?;
                idle.configure(preferences)?;
            }
            _ => unreachable!(),
        }
        return Ok(Response { ok: true, output: String::new(), error: None, console: None, lease: None });
    }
    if matches!(request.operation, Operation::ShareExportBegin) {
        require(request.expected_session.is_none(), "invalid_share_request")?;
        let _lock = lock_named("storage.lock")?;
        let selection: crate::share_export::Selection = serde_json::from_slice(&secret).map_err(|_| Error("invalid_share_request"))?;
        let settings = if matches!(&selection, crate::share_export::Selection::All) {
            idle.observe(crate::storage::idle_snapshot()?)?;
            let preferences = idle.status()?.state.preferences;
            Some(oblivion_share::Settings { safe_idle_minutes: preferences.safe_minutes, host_idle_minutes: preferences.host_minutes })
        } else { None };
        let sources = crate::storage::share_export_sources(selection)?;
        let mut started = crate::share_export::registry().begin(crate::storage::random_id()?, crate::storage::share_export_host()?, sources)?;
        started.settings = settings;
        return Ok(Response { ok: true, output: serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?, error: None, console: None, lease: None });
    }
    if matches!(request.operation, Operation::ShareExportLease) {
        require(request.expected_session.is_none(), "invalid_share_request")?;
        let id = request.session.as_ref().ok_or(Error("invalid_share_request"))?;
        let budget = crate::share_export::registry().lease(id, &crate::storage::share_export_host()?)?;
        let (console, hold) = UnixStream::pair().map_err(|_| Error("share_lease_failed"))?;
        stream.set_read_timeout(Some(budget)).map_err(|_| Error("share_lease_failed"))?;
        return Ok(Response { ok: true, output: String::new(), error: None, console: Some(console),
            lease: Some(ClientLease { slot: request.slot, id: id.clone(), safe_id: String::new(), operation: "",
                secret: Zeroizing::new(Vec::new()), export: Some(id.clone()), _hold: Some(hold), timeout: Some(budget) }) });
    }
    if matches!(request.operation, Operation::ShareExportEnd) {
        require(request.expected_session.is_none(), "invalid_share_request")?;
        let identity: crate::share_export::Identity = serde_json::from_slice(&secret).map_err(|_| Error("invalid_share_request"))?;
        cleanup_export(config, families, crate::share_export::registry().end(Some(&identity.export_id))?)?;
        return Ok(Response { ok: true, output: String::new(), error: None, console: None, lease: None });
    }
    if matches!(request.operation, Operation::ShareAttach | Operation::ShareImportAttach) {
        let _lock = lock_named("storage.lock")?;
        require(!crate::storage::recovery_required()?, "recovery_required")?;
        let expected = request.expected_session.as_deref().ok_or(Error("expected_session_required"))?;
        let (console, id, opening) = if matches!(request.operation, Operation::ShareImportAttach) {
            crate::share_host::attach_import(expected)?
        } else { crate::share_host::attach(expected)? };
        let secret = Zeroizing::new(serde_json::to_vec(&opening).map_err(|_| Error("encode_failed"))?);
        return Ok(Response { ok: true, output: String::new(), error: None, console: Some(console),
            lease: Some(ClientLease { slot: request.slot, id, safe_id: expected.to_owned(), operation: "share-release", secret, export: None, _hold: None, timeout: None }) });
    }
    if matches!(request.operation, Operation::AgentAttach | Operation::FileAttach) {
        let _lock = lock_named("storage.lock")?;
        require(!crate::storage::recovery_required()?, "recovery_required")?;
        let (session, mode) = crate::storage::session_info()?.ok_or(Error("session_not_open"))?;
        require((mode == "agent" || matches!(request.operation, Operation::FileAttach) && mode == "documents")
            && request.expected_session.as_deref() == Some(&session), "session_changed")?;
        crate::storage::require_safe_branch_open(&session)?;
        let id = crate::storage::random_id()?;
        let clients = Path::new(&oblivion_host::scope::current().runtime()).join("agent-clients");
        fs::create_dir_all(&clients).map_err(|_| Error("client_register_failed"))?;
        fs::write(clients.join(&id), b"").map_err(|_| Error("client_register_failed"))?;
        let console = match if matches!(request.operation, Operation::FileAttach) { crate::vm::file_port(&id) } else { crate::vm::agent_port(&id) } {
            Ok(port) => {
                let mut ready = [0; 6];
                let result = Channel::new(&port, Duration::from_secs(60)).read_exact(&mut ready);
                if result.is_err() || &ready != b"ready\n" {
                    let _ = fs::remove_file(clients.join(&id));
                    let _ = crate::vm::remove_copy_port(&id);
                    return Err(Error("agent_not_ready"));
                }
                port.set_read_timeout(None).map_err(|_| Error("agent_not_ready"))?;
                port
            },
            Err(error) => {
                let _ = fs::remove_file(clients.join(&id));
                let _ = crate::vm::remove_copy_port(&id);
                return Err(error);
            }
        };
        return Ok(Response { ok: true, output: String::new(), error: None,
            console: Some(console),
            lease: Some(ClientLease { slot: request.slot, id, safe_id: session,
                operation: "agent-release", secret: Zeroizing::new(Vec::new()), export: None, _hold: None, timeout: None }) });
    }
    if matches!(request.operation, Operation::Lock | Operation::ShutdownRuntime | Operation::ShutdownIdle) {
        crate::share_export::registry().end(None)?;
        families.lock().map_err(|_| Error("family_cache_failed"))?.clear();
    }
    let attach_tools = matches!(request.operation, Operation::StartAgent);
    let operation = match request.operation {
        Operation::InitGeneral => "init-general",
        Operation::PrepareUsb => "prepare-usb",
        Operation::SafeAccess => "safe-access",
        Operation::ClaimIntro => "claim-intro",
        Operation::OpenDocuments => "enter-documents",
        Operation::OpenChildDocuments => "open-child-documents",
        Operation::OpenDocumentsEphemeral => "enter-documents-ephemeral",
        Operation::StartAgent => "start-agent",
        Operation::PinSafe => "pin-safe",
        Operation::AgentRelease => "agent-release",
        Operation::ShareRelease => "share-release",
        Operation::ShareExportCancel => "share-export-cancel",
        Operation::ShareExportSourceOpen => "share-export-source-open",
        Operation::ShareImportBegin => "share-import-begin",
        Operation::ShareImportOpen => "share-import-open",
        Operation::ShareImportFinish => "share-import-finish",
        Operation::ShareImportCommit => "share-import-commit",
        Operation::ShareImportAbort => "share-import-abort",
        Operation::ShareImportDiscard => "share-import-discard",
        Operation::ShareImportStatus => "share-import-status",
        Operation::ShutdownRuntime => "shutdown-runtime",
        Operation::ShutdownIdle => "shutdown-idle",
        Operation::Browse => "browse",
        Operation::Diagnostics => "diagnostics",
        Operation::DiscardGeneralPending => "discard-general-pending",
        Operation::DiscardSessionPending => "discard-session-pending",
        Operation::Unlock => "unlock",
        Operation::UnlockReadOnly => "unlock-read-only",
        Operation::EnterRam => "enter-ram",
        Operation::Create => "create",
        Operation::RenameSession => "rename-session",
        Operation::SessionStorage => "session-storage",
        Operation::Close => "leave",
        Operation::CloseIdle => "close-idle",
        Operation::ForceClose => "force-leave",
        Operation::Lock => "lock",
        Operation::Status => "status",
        Operation::Debug => "debug",
        Operation::Egress => "egress",
        Operation::ProxyProfiles => "proxy-profiles",
        Operation::NetworkPolicy => "network-policy",
        Operation::Transfers => "transfers",
        Operation::Onion => "onion",
        Operation::AgentAttach | Operation::FileAttach | Operation::ShareAttach | Operation::ShareImportAttach
            | Operation::ShareExportBegin | Operation::ShareExportLease | Operation::ShareExportEnd
            | Operation::Activity | Operation::IdleSettings => unreachable!(),
    };
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
    command
        .args(["--config"])
        .arg(config)
        .arg(operation)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.args(["--slot", &request.slot.index().to_string()]);
    if let Some(id) = &request.expected_session { command.args(["--expected-session", id]); }
    if let Some(id) = request.session {
        command.arg(id);
    }
    let output = worker_output(command, secret, families, request.slot.index(), None)?;
    if output.status.success() && attach_tools {
        let startup: crate::storage::AgentStart = serde_json::from_slice(&output.stdout).map_err(|_| Error("invalid_response"))?;
        require(startup.opening.slot == request.slot
            && request.expected_session.as_deref() == Some(startup.opening.safe_id.as_str()), "session_changed")?;
        let owner = if startup.started { (|| {
            let _lock = crate::storage::recovery_lock()?;
            require(crate::storage::idle_opening()?.as_ref() == Some(&startup.opening), "session_changed")?;
            crate::vm::session_owner().map(|owner| Some(Arc::new(owner)))
        })() } else { Ok(None) };
        let attach = match &owner {
            Ok(_) => {
                let worker_config = config.to_owned();
                let worker_families = Arc::clone(families);
                let jobs = tools.jobs();
                tools.attach(&startup.opening,
                    move |context, request| tool_worker(&worker_config, &worker_families, &jobs, context, request))
            }
            Err(error) => Err(Error(error.0)),
        };
        if let Err(error) = attach {
            if startup.started { rollback_agent_start(config, families, &startup.opening, owner.ok().flatten())?; }
            return Err(error);
        }
    }
    let stdout = if output.status.success() && matches!(request.operation, Operation::Status) {
        let mut value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| Error("invalid_response"))?;
        value.as_object_mut().ok_or(Error("invalid_response"))?.insert("idle_lock".into(),
            serde_json::to_value(idle.status()?).map_err(|_| Error("encode_failed"))?);
        serde_json::to_string(&value).map_err(|_| Error("encode_failed"))?
    } else { String::from_utf8(output.stdout).map_err(|_| Error("invalid_response"))? };
    Ok(Response {
        console: None,
        lease: None,
        ok: output.status.success(),
        output: stdout,
        error: if output.status.success() {
            None
        } else {
            Some(
                String::from_utf8(output.stderr)
                    .map_err(|_| Error("invalid_response"))?
                    .trim()
                    .to_owned(),
            )
        },
    })
    })
}

fn send_console(stream: &UnixStream, console: &UnixStream) -> Result<()> {
    // usize storage gives cmsghdr its required alignment on both target architectures.
    let mut control = [0usize; 8];
    let mut byte = b'F';
    let mut data = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize };
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), console.as_raw_fd());
        require(
            libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) == 1,
            "console_transfer_failed",
        )
    }
}

pub fn notify_ready() -> Result<()> {
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        let address = if let Some(name) = path.as_bytes().strip_prefix(b"@") {
            SocketAddr::from_abstract_name(name)
        } else {
            SocketAddr::from_pathname(path)
        }
        .map_err(|_| Error("notify_address_failed"))?;
        UnixDatagram::unbound()
            .and_then(|socket| socket.send_to_addr(b"READY=1", &address))
            .map_err(|_| Error("notify_failed"))?;
    }
    Ok(())
}

#[cfg(test)]
mod family_tests {
    use super::*;

    #[test]
    fn child_open_rejects_slot_identity_swap_and_any_password_before_starting_a_worker() {
        for (session, expected, secret_len, error) in [
            (SAFE, "00000000000000000000000000000002", 0, "expected_session_required"),
            (SAFE, SAFE, 1, "unexpected_secret"),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
            let cache = Arc::clone(&families);
            let task = std::thread::spawn(move || serve_connection(server, "/must-not-start-worker".into(), unsafe { libc::geteuid() }, cache,
                Arc::new(crate::safe_tools::Registry::default()), crate::idle_controller::Controller::new().unwrap_or_else(|error| panic!("{}", error.0)),
                Arc::new(Mutex::new(()))));
            let header = serde_json::to_vec(&serde_json::json!({"operation":"open-child-documents","session":session,
                "expected_session":expected,"slot":1,"secret_len":secret_len})).unwrap();
            client.write_all(&(header.len() as u32).to_be_bytes()).unwrap();
            client.write_all(&header).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut output = Vec::new();
            client.read_to_end(&mut output).unwrap();
            task.join().unwrap();
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&output).unwrap()["error"], error);
            assert!(families.lock().unwrap().is_empty());
        }
        assert!(serde_json::from_value::<FamilyRequest>(serde_json::json!({"operation":"child-lookup","child_id":SAFE,"parent_slot":0})).is_err());
    }

    #[test]
    fn share_import_large_metadata_is_the_only_expanded_authenticated_body() {
        let request: Request = serde_json::from_value(serde_json::json!({
            "operation":"share-import-begin", "session":null,"expected_session":null,
            "secret_len":70000, "slot":0,
        })).unwrap();
        assert!(request.secret_len > u16::MAX as u32);
        assert_eq!(secret_limit(&request.operation), (oblivion_share::manifest::MAX_METADATA + 4096) as u32);
        assert_eq!(secret_limit(&Operation::ShareImportOpen),4096);
        assert_eq!(secret_limit(&Operation::ShareImportFinish),4096);
        assert_eq!(secret_limit(&Operation::ShareImportCommit),1024);
        assert_eq!(secret_limit(&Operation::Unlock),1024);
        assert_eq!(secret_limit(&Operation::Egress),4096);
        assert!(serde_json::from_value::<Request>(serde_json::json!({
            "operation":"share-export-open", "session":null,"expected_session":null,
            "secret_len":0,"slot":0,
        })).is_err());
    }

    const SAFE: &str = "00000000000000000000000000000001";
    const FAMILY: &str = "11111111111111111111111111111111";

    #[test]
    #[ignore = "requires an isolated root-owned tmpfs /run; no production state"]
    fn idle_activity_bypasses_slow_ordinary_request() {
        use std::os::unix::fs::DirBuilderExt;
        use crate::idle_controller::{Controller, Snapshot, Target};
        assert_eq!(std::env::var("OBLIVION_IDLE_CONTROLLER_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fs::DirBuilder::new().recursive(true).mode(0o700).create("/run/oblivion").unwrap();
        assert!(fs::read_dir("/run/oblivion").unwrap().next().is_none());
        fs::write("/run/oblivion/host-opening", FAMILY).unwrap();
        fs::set_permissions("/run/oblivion/host-opening", fs::Permissions::from_mode(0o600)).unwrap();
        let idle = Controller::new().unwrap_or_else(|error| panic!("{}", error.0));
        let snapshot = |fences| Snapshot { host: Some(FAMILY.into()), safes: Vec::new(), fences, general_open: false, writable: false };
        idle.observe(snapshot(Vec::new())).unwrap_or_else(|error| panic!("{}", error.0));
        let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
        let tools = Arc::new(crate::safe_tools::Registry::default());
        let ordinary = Arc::new(Mutex::new(()));
        let queued = ordinary.lock().unwrap();
        let storage = lock_named("storage.lock").unwrap_or_else(|error| panic!("{}", error.0));
        let call = |operation: &str, body: &str| {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let config = Path::new("/unused").to_owned();
            let families = Arc::clone(&families);
            let tools = Arc::clone(&tools);
            let idle = idle.clone();
            let ordinary = Arc::clone(&ordinary);
            let task = std::thread::spawn(move || serve_connection(server, config, 0, families, tools, idle, ordinary));
            let header = serde_json::to_vec(&serde_json::json!({"operation":operation,"secret_len":body.len(),"slot":0})).unwrap();
            client.write_all(&(header.len() as u32).to_be_bytes()).unwrap();
            client.write_all(&header).unwrap();
            client.write_all(body.as_bytes()).unwrap();
            (client, task)
        };
        let (mut waiting, worker) = call("idle-settings", r#"{"version":1,"safe_minutes":1,"host_minutes":2}"#);
        let activity = format!(r#"{{"host":"{FAMILY}","safe":null}}"#);
        let (mut client, task) = call("activity", &activity);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        task.join().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["ok"], true);
        let status = serde_json::to_value(idle.status().unwrap_or_else(|error| panic!("{}", error.0))).unwrap();
        assert!(status["host"]["remaining_seconds"].as_u64().unwrap() >= 14 * 60);
        let (mut stale, task) = call("activity", &format!(r#"{{"host":"{SAFE}","safe":null}}"#));
        bytes.clear(); stale.read_to_end(&mut bytes).unwrap(); task.join().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"], "idle_opening_changed");
        let fence = Target::Host { nonce: FAMILY.into() };
        crate::idle_controller::latch(&fence).unwrap_or_else(|error| panic!("{}", error.0));
        idle.observe(snapshot(vec![fence.clone()])).unwrap_or_else(|error| panic!("{}", error.0));
        let (mut closing, task) = call("activity", &activity);
        bytes.clear(); closing.read_to_end(&mut bytes).unwrap(); task.join().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"], "idle_opening_changed");
        drop(storage); drop(queued);
        bytes.clear(); waiting.read_to_end(&mut bytes).unwrap(); worker.join().unwrap();
        crate::idle_controller::clear_fence(&fence).unwrap_or_else(|error| panic!("{}", error.0));
    }

    fn worker(families: &Families, slot: u8, task: impl FnOnce()) {
        let (parent, child) = UnixStream::pair().unwrap();
        let cache = Arc::clone(families);
        let server = std::thread::spawn(move || serve_families(parent, cache, slot));
        WORKER_CHANNEL.with(|channel| *channel.borrow_mut() = Some(child));
        oblivion_host::scope::within(oblivion_host::scope::Slot::try_from(slot).unwrap(), task);
        WORKER_CHANNEL.with(|channel| channel.borrow_mut().take());
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn resident_family_channel_preserves_authority_until_release_and_isolates_slots() {
        let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
        worker(&families, 0, || {
            assert!(authorized_family(SAFE).unwrap_or_else(|error| panic!("{}", error.0)).is_none());
            let capability = Capability::from_root_secret(FAMILY, Zeroizing::new([7; 32])).unwrap();
            assert!(retain_family(SAFE, &capability).is_ok());
        });
        worker(&families, 1, || {
            assert!(authorized_family(SAFE).unwrap_or_else(|error| panic!("{}", error.0)).is_none());
            let capability = Capability::from_root_secret(FAMILY, Zeroizing::new([9; 32])).unwrap();
            assert!(retain_family("00000000000000000000000000000002", &capability).is_ok());
        });
        worker(&families, 0, || {
            let capability = authorized_family(SAFE).unwrap_or_else(|error| panic!("{}", error.0)).unwrap();
            assert_eq!(capability.root_secret(), &[7; 32]);
            assert!(release_family().is_ok());
            assert!(authorized_family(SAFE).unwrap_or_else(|error| panic!("{}", error.0)).is_none());
        });
        worker(&families, 1, || {
            assert!(authorized_family(SAFE).unwrap_or_else(|error| panic!("{}", error.0)).is_none());
            assert_eq!(authorized_family("00000000000000000000000000000002").unwrap_or_else(|error| panic!("{}", error.0)).unwrap().root_secret(), &[9; 32]);
            assert!(release_family().is_ok());
        });
        assert!(families.lock().unwrap().is_empty());
    }

    #[test]
    fn invalid_private_frame_discards_cached_authority() {
        let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
        worker(&families, 0, || {
            let capability = Capability::from_root_secret(FAMILY, Zeroizing::new([7; 32])).unwrap();
            assert!(retain_family(SAFE, &capability).is_ok());
        });
        let (parent, mut child) = UnixStream::pair().unwrap();
        let cache = Arc::clone(&families);
        let server = std::thread::spawn(move || serve_families(parent, cache, 0));
        child.write_all(&513u32.to_be_bytes()).unwrap();
        assert!(server.join().unwrap().is_err());
        assert!(families.lock().unwrap().is_empty());
    }

    #[test]
    fn branch_cleanup_releases_the_descendant_slot_not_the_worker_slot() {
        let families: Families = Arc::new(Mutex::new(BTreeMap::new()));
        for slot in [0, 1] {
            worker(&families, slot, || {
                let capability = Capability::from_root_secret(FAMILY, Zeroizing::new([7; 32])).unwrap();
                assert!(retain_family(SAFE, &capability).is_ok());
            });
        }
        worker(&families, 0, || {
            oblivion_host::scope::within(oblivion_host::scope::Slot::try_from(1).unwrap(), || {
                assert!(release_family().is_ok());
            });
        });
        let cached = families.lock().unwrap();
        assert!(cached.contains_key(&0));
        assert!(!cached.contains_key(&1));
    }

    #[test]
    fn tool_authority_expires_with_the_original_vm_process() {
        let mut process = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, process.id(), 0) };
        assert!(fd >= 0);
        TOOL_OWNER.with(|owner| *owner.borrow_mut() = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
        assert!(require_tool_owner().is_ok());
        assert!(tool_owner_alive().unwrap_or_else(|error| panic!("{}", error.0)));
        process.kill().unwrap();
        process.wait().unwrap();
        assert!(require_tool_owner().is_err());
        assert!(!tool_owner_alive().unwrap_or_else(|error| panic!("{}", error.0)));
        TOOL_OWNER.with(|owner| owner.borrow_mut().take());
        assert!(tool_owner_alive().is_err());
    }

    #[test]
    fn a_tool_worker_deadline_returns_unknown_and_stops_only_its_worker() {
        let process = Command::new("/usr/bin/sleep").arg("30")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let started = Instant::now();
        let result = tool_output(process, Zeroizing::new(Vec::new()), started + Duration::from_millis(40));
        assert!(matches!(result, Err(Error("safe_tool_outcome_unknown"))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
