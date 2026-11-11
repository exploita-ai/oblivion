//! The guest chooses an operation and explicit task, never its host authority.
//! An opening is bound to its private QEMU socket and pinned process lifetime.

use crate::storage::{Error, Result, require};
use oblivion_host::channel::{self, Channel};
use oblivion_host::scope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const LIMIT: usize = 24 * 1024;
pub(crate) type DispatchResult = std::result::Result<Value, String>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub version: u8,
    pub request_id: String,
    pub call: Call,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Call {
    SafeStatus {
        offset: u8,
    },
    ChatCreate { agent: String, task: Zeroizing<String>, request_id: String },
    ChatStatus { job_id: Option<String>, request_id: Option<String> },
    ChatCancel { job_id: String },
    SafeCreate {
        agent: String,
        task: Zeroizing<String>,
        creator_chat_id: Option<String>,
    },
}

impl Request {
    fn validate(&self) -> Result<()> {
        require(self.version == 1, "unsupported_safe_tools_version")?;
        crate::storage::validate_id(&self.request_id)?;
        match &self.call {
            Call::ChatCreate { agent, task, request_id } => {
                crate::storage::validate_id(request_id)?;
                require(matches!(agent.as_str(), "codex" | "claude" | "opencode2") && !task.trim().is_empty() && task.len() <= 16384 && !task.contains('\0'), "invalid_chat_job_request")
            }
            Call::ChatStatus { job_id, request_id } => {
                require(job_id.is_some() != request_id.is_some(), "invalid_chat_job_request")?;
                crate::storage::validate_id(job_id.as_ref().or(request_id.as_ref()).ok_or(Error("invalid_chat_job_request"))?)
            }
            Call::ChatCancel { job_id } => crate::storage::validate_id(job_id),
            Call::SafeStatus { offset } => require(*offset <= 32, "invalid_safe_tools_offset"),
            Call::SafeCreate {
                agent,
                task,
                creator_chat_id,
            } => require(
                matches!(agent.as_str(), "codex" | "claude" | "opencode2")
                    && !task.trim().is_empty()
                    && task.len() <= 16384
                    && !task.contains('\0')
                    && creator_chat_id.as_ref().is_none_or(|id| {
                        !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
                    }),
                "invalid_safe_child_request",
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Context {
    pub slot: scope::Slot,
    pub safe_id: String,
    pub owner: Arc<OwnedFd>,
    pub opening: oblivion_host::autolock::Opening,
}

struct Opening {
    context: Context,
    failed: Arc<AtomicBool>,
}

#[derive(Default)]
pub(crate) struct Registry {
    openings: Mutex<BTreeMap<u8, Opening>>,
    jobs: Arc<crate::chat_jobs::Registry>,
}

#[derive(Serialize)]
struct Capabilities {
    version: u8,
    kind: &'static str,
    operations: [&'static str; 5],
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    kind: String,
}

#[derive(Serialize)]
struct Response<'a> {
    version: u8,
    request_id: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

impl Registry {
    pub(crate) fn jobs(&self) -> Arc<crate::chat_jobs::Registry> { Arc::clone(&self.jobs) }
    pub(crate) fn attach(
        &self,
        generation: &oblivion_host::autolock::Opening,
        dispatch: impl Fn(&Context, &Request) -> DispatchResult + Send + 'static,
    ) -> Result<()> {
        let _lock = crate::storage::recovery_lock()?;
        let slot = generation.slot;
        let safe_id = generation.safe_id.as_str();
        scope::within(slot, || -> Result<()> {
            require(crate::storage::idle_opening()?.as_ref() == Some(generation), "session_changed")?;
            require(
                crate::storage::session_info()?
                    .is_some_and(|info| info.0 == safe_id && info.1 == "agent"),
                "session_changed",
            )?;
            crate::storage::require_safe_branch_open(safe_id)?;
            let mut openings = self
                .openings
                .lock()
                .map_err(|_| Error("safe_tools_unavailable"))?;
            if let Some(opening) = openings.get(&slot.index()) {
                if owner_alive(&opening.context.owner)? {
                    require(
                        opening.context.safe_id == safe_id
                            && !opening.failed.load(Ordering::Acquire),
                        "safe_tools_unavailable",
                    )?;
                    return Ok(());
                }
            }
            // The namespace and UID are fixed by the controller's slot, not
            // fields in the guest RPC. The process is pinned before handshake.
            let stream = channel::connect(
                Path::new(&scope::path("/run/oblivion-session/safe-tools.sock")),
                Duration::from_secs(2),
            )
            .map_err(|_| Error("safe_tools_unavailable"))?;
            crate::gateway::peer(&stream, scope::uid(crate::vm::VM_UID))?;
            let file = File::from(OwnedFd::from(
                stream
                    .try_clone()
                    .map_err(|_| Error("safe_tools_unavailable"))?,
            ));
            let owner = Arc::new(
                oblivion_transfer::relay::peer_process(&file)
                    .map_err(|_| Error("safe_tools_unavailable"))?,
            );
            require(owner_alive(&owner)?, "safe_tools_owner_expired")?;
            handshake(&stream)?;
            let context = Context {
                slot,
                safe_id: safe_id.to_string(),
                owner,
                opening: generation.clone(),
            };
            let failed = Arc::new(AtomicBool::new(false));
            openings.insert(
                slot.index(),
                Opening {
                    context: context.clone(),
                    failed: Arc::clone(&failed),
                },
            );
            std::thread::spawn(move || {
                let _ = serve(stream, &context, dispatch);
                failed.store(true, Ordering::Release);
            });
            Ok(())
        })
    }
}

pub(crate) fn owner_alive(owner: &OwnedFd) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: owner.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    require(result >= 0, "safe_tools_owner_unknown")?;
    Ok(result == 0)
}

fn handshake(stream: &UnixStream) -> Result<()> {
    let mut channel = Channel::new(stream, Duration::from_secs(30));
    let mut ready = [0; 6];
    channel
        .read_exact(&mut ready)
        .map_err(|_| Error("safe_tools_not_ready"))?;
    require(&ready == b"tools\n", "invalid_safe_tools_handshake")?;
    write_frame(
        &mut channel,
        &Capabilities {
            version: 1,
            kind: "capabilities",
            operations: ["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"],
            limit: LIMIT,
        },
    )?;
    let ready: Ready = read_frame(&mut channel)?;
    require(
        ready.version == 1 && ready.kind == "ready",
        "invalid_safe_tools_handshake",
    )
}

fn serve(
    stream: UnixStream,
    context: &Context,
    dispatch: impl Fn(&Context, &Request) -> DispatchResult,
) -> Result<()> {
    loop {
        let mut events = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: context.owner.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = unsafe { libc::poll(events.as_mut_ptr(), events.len() as libc::nfds_t, -1) };
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(
            count > 0 && events[1].revents == 0,
            "safe_tools_owner_expired",
        )?;
        let mut channel = Channel::new(&stream, Duration::from_secs(180));
        let request: Request = read_frame(&mut channel)?;
        request.validate()?;
        require(owner_alive(&context.owner)?, "safe_tools_owner_expired")?;
        let (result, error) = match dispatch(context, &request) {
            Ok(result) => (Some(result), None),
            Err(error) => (None, Some(error)),
        };
        let response = Response {
            version: 1,
            request_id: &request.request_id,
            ok: error.is_none(),
            result,
            error: error.as_deref(),
        };
        write_frame(&mut channel, &response)?;
    }
}

fn read_frame<T: serde::de::DeserializeOwned>(channel: &mut Channel<'_>) -> Result<T> {
    let mut size = [0; 4];
    channel
        .read_exact(&mut size)
        .map_err(|_| Error("safe_tools_disconnected"))?;
    let size = u32::from_be_bytes(size) as usize;
    require((1..=LIMIT).contains(&size), "invalid_safe_tools_frame")?;
    let mut bytes = Zeroizing::new(vec![0; size]);
    channel
        .read_exact(&mut bytes)
        .map_err(|_| Error("safe_tools_disconnected"))?;
    serde_json::from_slice(&bytes).map_err(|_| Error("invalid_safe_tools_request"))
}

fn write_frame(channel: &mut Channel<'_>, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error("invalid_safe_tools_response"))?;
    require(
        (1..=LIMIT).contains(&bytes.len()),
        "invalid_safe_tools_frame",
    )?;
    channel
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| channel.write_all(&bytes))
        .map_err(|_| Error("safe_tools_disconnected"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guest_cannot_supply_safe_authority_or_unknown_operations() {
        let base = serde_json::json!({ "version":1,"request_id":"00000000000000000000000000000001",
            "call":{"operation":"safe-status","offset":0} });
        let request: Request = serde_json::from_value(base.clone()).unwrap();
        assert!(request.validate().is_ok());
        let mut forged = base.clone();
        forged["safe_id"] = serde_json::json!("00000000000000000000000000000002");
        assert!(serde_json::from_value::<Request>(forged).is_err());
        let mut forged = base.clone();
        forged["call"]["parent"] = serde_json::json!("00000000000000000000000000000002");
        assert!(serde_json::from_value::<Request>(forged).is_err());
        let mut forged = base;
        forged["call"] = serde_json::json!({ "operation":"host-command","command":"id" });
        assert!(serde_json::from_value::<Request>(forged).is_err());
    }

    #[test]
    fn managed_calls_have_no_cross_safe_or_argv_authority() {
        let base=serde_json::json!({"version":1,"request_id":"a".repeat(32),"call":{"operation":"chat-create","agent":"codex","task":"explicit task","request_id":"b".repeat(32)}});
        assert!(serde_json::from_value::<Request>(base.clone()).unwrap().validate().is_ok());
        for field in ["safe_id","argv","provider","credentials"] {
            let mut forged=base.clone(); forged["call"][field]=serde_json::json!("forged");
            assert!(serde_json::from_value::<Request>(forged).is_err());
        }
        let both=serde_json::json!({"version":1,"request_id":"a".repeat(32),"call":{"operation":"chat-status","job_id":"b".repeat(32),"request_id":"c".repeat(32)}});
        assert!(serde_json::from_value::<Request>(both).unwrap().validate().is_err());
    }

    #[test]
    fn capabilities_are_acknowledged_over_the_real_private_stream() {
        let (host, guest) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || handshake(&host));
        let mut channel = Channel::new(&guest, Duration::from_secs(2));
        channel.write_all(b"tools\n").unwrap();
        let offered: Value = read_frame(&mut channel).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(
            offered["operations"],
            serde_json::json!(["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"])
        );
        assert_eq!(offered["limit"], LIMIT);
        write_frame(
            &mut channel,
            &serde_json::json!({"version":1,"kind":"ready"}),
        )
        .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(server.join().unwrap().is_ok());
    }
}
