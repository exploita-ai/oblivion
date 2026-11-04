//! Managed jobs are attached to one authenticated VM opening, never a Safe name.
use crate::safe_tools::{Call, Context, DispatchResult, Request};
use crate::storage::{Error, Result, require};
use oblivion_host::channel::Channel;
use oblivion_host::managed::{Info, Reason, State};
use oblivion_host::{agent, managed, scope};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type Release = Arc<dyn Fn(&Context, &str) -> Result<()> + Send + Sync>;
struct Record {
    info: Info,
    ready: bool,
    error: Option<&'static str>,
    stream: Option<UnixStream>,
    cancelling: Option<Instant>,
}
struct Job {
    context: Context,
    record: Mutex<Record>,
    changed: Condvar,
}
#[derive(Default)]
pub(crate) struct Registry {
    jobs: Mutex<BTreeMap<(String, String), Arc<Job>>>,
}

impl Registry {
    pub(crate) fn call(
        self: &Arc<Self>,
        context: &Context,
        request: &Request,
        release: Release,
    ) -> DispatchResult {
        let value = match &request.call {
            Call::ChatCreate {
                agent,
                task,
                request_id,
            } => self.create(context, agent, task, request_id, release),
            Call::ChatStatus { job_id, request_id } => {
                let id = job_id.clone().unwrap_or_else(|| {
                    derive_id(
                        &context.safe_id,
                        request_id.as_ref().expect("validated identifier"),
                    )
                });
                self.status(context, &id, release)
            }
            Call::ChatCancel { job_id } => self.cancel(context, job_id),
            _ => return Err("invalid_chat_job_request".into()),
        }
        .map_err(|error| error.0.to_string())?;
        serde_json::to_value(value).map_err(|_| "invalid_chat_job_response".into())
    }

    fn create(
        self: &Arc<Self>,
        context: &Context,
        agent: &str,
        task: &Zeroizing<String>,
        request_id: &str,
        release: Release,
    ) -> Result<Info> {
        current(context)?;
        let id = derive_id(&context.safe_id, request_id);
        let key = (context.safe_id.clone(), id.clone());
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| Error("chat_jobs_unavailable"))?;
        jobs.retain(|_, job| crate::safe_tools::owner_alive(&job.context.owner).unwrap_or(true));
        require(
            jobs.len() < usize::from(scope::LIMIT) * managed::RECORD_LIMIT
                || jobs.contains_key(&key),
            "chat_job_quota",
        )?;
        if let Some(job) = jobs
            .get(&key)
            .filter(|job| job.context.opening == context.opening)
            .cloned()
        {
            drop(jobs);
            return wait_admission(&job);
        }
        let same: Vec<_> = jobs
            .values()
            .filter(|job| job.context.opening == context.opening)
            .collect();
        require(same.len() < managed::RECORD_LIMIT, "chat_job_quota")?;
        for job in same {
            require(
                job.record
                    .lock()
                    .map_err(|_| Error("chat_jobs_unavailable"))?
                    .info
                    .state
                    .terminal(),
                "chat_job_busy",
            )?;
        }
        let job = Arc::new(Job {
            context: context.clone(),
            record: Mutex::new(Record {
                info: Info {
                    job_id: id.clone(),
                    request_id: request_id.into(),
                    agent: agent.into(),
                    state: State::Queued,
                    native_chat_id: None,
                    reason: None,
                },
                ready: false,
                error: None,
                stream: None,
                cancelling: None,
            }),
            changed: Condvar::new(),
        });
        jobs.insert(key, Arc::clone(&job));
        drop(jobs);
        let command = managed::Command::Start {
            job_id: id,
            request_id: request_id.into(),
            task: Zeroizing::new(task.to_string()),
        };
        let worker = Arc::clone(&job);
        let agent = agent.to_string();
        std::thread::spawn(move || {
            let result = communicate(&worker.context, &agent, command, Some(&worker), &release);
            if let Ok(mut record) = worker.record.lock() {
                match result {
                    Ok(info) => {
                        record.info = info;
                        record.ready = true;
                    }
                    Err(error) => {
                        record.info.state = State::Failed;
                        record.info.reason = Some(match error.0 {
                            "chat_job_cleanup_required" => Reason::CleanupRequired,
                            "chat_job_timeout" => Reason::Timeout,
                            _ => Reason::Interrupted,
                        });
                        if !record.ready {
                            record.error = Some(error.0);
                        }
                    }
                }
                record.stream.take();
                worker.changed.notify_all();
            }
        });
        wait_admission(&job)
    }

    fn status(&self, context: &Context, id: &str, release: Release) -> Result<Info> {
        current(context)?;
        if let Some(job) = self
            .jobs
            .lock()
            .map_err(|_| Error("chat_jobs_unavailable"))?
            .get(&(context.safe_id.clone(), id.into()))
            .filter(|job| job.context.opening == context.opening)
            .cloned()
        {
            return Ok(job
                .record
                .lock()
                .map_err(|_| Error("chat_jobs_unavailable"))?
                .info
                .clone());
        }
        communicate(
            context,
            "codex",
            managed::Command::Inspect { job_id: id.into() },
            None,
            &release,
        )
    }

    fn cancel(&self, context: &Context, id: &str) -> Result<Info> {
        current(context)?;
        let job = self
            .jobs
            .lock()
            .map_err(|_| Error("chat_jobs_unavailable"))?
            .get(&(context.safe_id.clone(), id.into()))
            .filter(|job| job.context.opening == context.opening)
            .cloned()
            .ok_or(Error("chat_job_owner_unavailable"))?;
        let mut record = job
            .record
            .lock()
            .map_err(|_| Error("chat_jobs_unavailable"))?;
        if record.info.state.terminal() {
            return Ok(record.info.clone());
        }
        let stream = record.stream.as_mut().ok_or(Error("chat_job_not_ready"))?;
        agent::write_frame(stream, 6, &libc::SIGTERM.to_be_bytes())
            .map_err(|_| Error("chat_job_cancel_failed"))?;
        record.cancelling = Some(Instant::now());
        let (record, _) = job
            .changed
            .wait_timeout_while(record, Duration::from_secs(8), |record| {
                !record.info.state.terminal()
            })
            .map_err(|_| Error("chat_jobs_unavailable"))?;
        if !record.info.state.terminal() {
            fence(context)?;
            return Err(Error("chat_job_cleanup_required"));
        }
        Ok(record.info.clone())
    }
}

fn wait_admission(job: &Job) -> Result<Info> {
    let record = job
        .record
        .lock()
        .map_err(|_| Error("chat_jobs_unavailable"))?;
    let (record, _) = job
        .changed
        .wait_timeout_while(record, Duration::from_secs(65), |record| {
            !record.ready && record.error.is_none()
        })
        .map_err(|_| Error("chat_jobs_unavailable"))?;
    if let Some(error) = record.error {
        return Err(Error(error));
    }
    require(record.ready, "chat_job_outcome_unknown")?;
    Ok(record.info.clone())
}

fn current(context: &Context) -> Result<()> {
    scope::within(context.slot, || {
        let _lock = crate::storage::recovery_lock()?;
        require(!crate::storage::recovery_required()?, "recovery_required")?;
        require(
            crate::storage::idle_opening()?.as_ref() == Some(&context.opening)
                && crate::storage::session_info()?
                    .is_some_and(|entry| entry.0 == context.safe_id && entry.1 == "agent")
                && crate::safe_tools::owner_alive(&context.owner)?,
            "session_changed",
        )?;
        crate::storage::require_safe_branch_open(&context.safe_id)
    })
}
fn fence(context: &Context) -> Result<()> {
    crate::idle_controller::latch(&crate::idle_controller::Target::Safe {
        opening: context.opening.clone(),
    })
}
fn derive_id(safe_id: &str, request_id: &str) -> String {
    let value = Sha256::digest(format!("{safe_id}{request_id}").as_bytes());
    value[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn communicate(
    context: &Context,
    selected: &str,
    command: managed::Command,
    job: Option<&Job>,
    release: &Release,
) -> Result<Info> {
    let expected = match &command {
        managed::Command::Start { job_id, .. } | managed::Command::Inspect { job_id } => {
            job_id.clone()
        }
    };
    let client = crate::storage::random_id()?;
    let stream = scope::within(context.slot, || -> Result<UnixStream> {
        let _lock = crate::storage::recovery_lock()?;
        require(
            !crate::storage::recovery_required()?
                && crate::storage::idle_opening()?.as_ref() == Some(&context.opening)
                && crate::safe_tools::owner_alive(&context.owner)?,
            "session_changed",
        )?;
        crate::storage::require_safe_branch_open(&context.safe_id)?;
        let clients = Path::new(&context.slot.runtime()).join("agent-clients");
        fs::create_dir_all(&clients).map_err(|_| Error("client_register_failed"))?;
        fs::write(clients.join(&client), b"").map_err(|_| Error("client_register_failed"))?;
        crate::vm::agent_port(&client)
    });
    let result = (|| {
        let mut stream = stream?;
        let mut ready = [0; 6];
        Channel::new(&stream, Duration::from_secs(60))
            .read_exact(&mut ready)
            .map_err(|_| Error("chat_job_not_ready"))?;
        require(&ready == b"ready\n", "invalid_chat_job_guest")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| Error("chat_job_not_ready"))?;
        agent::Launch {
            agent: selected.into(),
            argv: vec![],
            terminal: None,
            managed: Some(command),
        }
        .write(&mut stream)
        .map_err(|_| Error("chat_job_outcome_unknown"))?;
        if let Some(job) = job {
            job.record
                .lock()
                .map_err(|_| Error("chat_jobs_unavailable"))?
                .stream = Some(
                stream
                    .try_clone()
                    .map_err(|_| Error("chat_jobs_unavailable"))?,
            );
        }
        receive(&stream, context, &expected, job)
    })();
    // Always detach the hotplug client, even if admission or a frame failed.
    if release(context, &client).is_err() {
        if crate::safe_tools::owner_alive(&context.owner)? {
            fence(context)?;
            return Err(Error("chat_job_cleanup_required"));
        }
    }
    if let Some(job) = job {
        job.record
            .lock()
            .map_err(|_| Error("chat_jobs_unavailable"))?
            .stream
            .take();
    }
    if (matches!(result, Err(Error("chat_job_cleanup_required")))
        || result
            .as_ref()
            .is_ok_and(|info| info.reason == Some(Reason::CleanupRequired)))
        && crate::safe_tools::owner_alive(&context.owner)?
    {
        fence(context)?;
        return Err(Error("chat_job_cleanup_required"));
    }
    result
}

fn receive(
    stream: &UnixStream,
    context: &Context,
    expected: &str,
    job: Option<&Job>,
) -> Result<Info> {
    let mut lines = Zeroizing::new(Vec::new());
    let mut latest = None;
    let mut total = 0usize;
    let deadline = Instant::now() + Duration::from_secs(if job.is_some() { 1860 } else { 15 });
    loop {
        require(Instant::now() < deadline, "chat_job_timeout")?;
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
        let count = unsafe { libc::poll(events.as_mut_ptr(), 2, 100) };
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(count >= 0 && events[1].revents == 0, "chat_job_interrupted")?;
        if let Some(job) = job {
            require(
                !job.record
                    .lock()
                    .map_err(|_| Error("chat_jobs_unavailable"))?
                    .cancelling
                    .is_some_and(|when| when.elapsed() > Duration::from_secs(8)),
                "chat_job_cleanup_required",
            )?;
        }
        if events[0].revents == 0 {
            continue;
        }
        let mut channel = Channel::new(stream, Duration::from_secs(5));
        let (kind, payload) = private_frame(&mut channel)?;
        if kind == 4 {
            require(payload.len() == 4, "invalid_chat_job_frame")?;
            let info: Info = latest.ok_or(Error("chat_job_interrupted"))?;
            require(
                info.state.terminal() || job.is_none(),
                "chat_job_interrupted",
            )?;
            return Ok(info);
        }
        require(matches!(kind, 1 | 2), "invalid_chat_job_frame")?;
        total += payload.len();
        require(total <= 65536, "invalid_chat_job_frame")?;
        if kind == 2 {
            continue;
        }
        lines.extend_from_slice(&payload);
        require(lines.len() <= 4096, "invalid_chat_job_frame")?;
        while let Some(end) = lines.iter().position(|byte| *byte == b'\n') {
            let event: managed::Event = serde_json::from_slice(&lines[..end])
                .map_err(|_| Error("invalid_chat_job_response"))?;
            lines.drain(..=end);
            let info = match event {
                managed::Event::Status { info } => info,
                managed::Event::Rejected { error } => {
                    return Err(Error(match error {
                        managed::Rejection::NotFound => "chat_job_not_found",
                        managed::Rejection::Busy => "chat_job_busy",
                        managed::Rejection::Quota => "chat_job_quota",
                        managed::Rejection::RecoveryRequired => "chat_job_recovery_required",
                        managed::Rejection::StorageFailed => "chat_job_storage_failed",
                    }));
                }
            };
            require(
                info.valid() && info.job_id == expected,
                "invalid_chat_job_response",
            )?;
            if let Some(job) = job {
                let mut record = job
                    .record
                    .lock()
                    .map_err(|_| Error("chat_jobs_unavailable"))?;
                require(
                    info.request_id == record.info.request_id,
                    "invalid_chat_job_response",
                )?;
                // Publish terminal success only after the client/cgroup lease
                // has been released. A cleanup failure fences the opening.
                if !info.state.terminal() {
                    record.info = info.clone();
                }
                record.ready = true;
                job.changed.notify_all();
            }
            latest = Some(info);
        }
    }
}

fn private_frame(channel: &mut Channel<'_>) -> Result<(u8, Zeroizing<Vec<u8>>)> {
    let mut header = [0; 5];
    channel
        .read_exact(&mut header)
        .map_err(|_| Error("chat_job_interrupted"))?;
    let length = u32::from_be_bytes(
        header[1..]
            .try_into()
            .map_err(|_| Error("invalid_chat_job_frame"))?,
    ) as usize;
    require(length <= agent::LIMIT, "invalid_chat_job_frame")?;
    let mut payload = Zeroizing::new(vec![0; length]);
    channel
        .read_exact(&mut payload)
        .map_err(|_| Error("chat_job_interrupted"))?;
    Ok((header[0], payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::FromRawFd;

    fn context() -> Context {
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        assert!(descriptor >= 0);
        Context {
            slot: Default::default(),
            safe_id: "a".repeat(32),
            owner: Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) }),
            opening: oblivion_host::autolock::Opening {
                slot: Default::default(),
                safe_id: "a".repeat(32),
                nonce: "b".repeat(32),
            },
        }
    }
    fn info(state: State) -> Info {
        Info {
            job_id: "c".repeat(32),
            request_id: "d".repeat(32),
            agent: "codex".into(),
            state,
            native_chat_id: Some("12345678-1234-4234-8234-123456789abc".into()),
            reason: None,
        }
    }
    fn guest(stream: &mut UnixStream, info: Info) {
        let mut bytes = serde_json::to_vec(&managed::Event::Status { info }).unwrap();
        bytes.push(b'\n');
        agent::write_frame(stream, 1, &bytes).unwrap();
        agent::write_frame(stream, 4, &0i32.to_be_bytes()).unwrap();
    }
    #[test]
    fn request_identity_is_deterministic_and_scoped_to_one_safe() {
        let first = derive_id(&"a".repeat(32), &"b".repeat(32));
        assert_eq!(first, derive_id(&"a".repeat(32), &"b".repeat(32)));
        assert_ne!(first, derive_id(&"c".repeat(32), &"b".repeat(32)));
        assert!(managed::id(&first));
    }
    #[test]
    fn terminal_success_waits_for_cleanup_instead_of_becoming_visible_in_reader() {
        let context = context();
        let (host, mut peer) = UnixStream::pair().unwrap();
        let job = Job {
            context: context.clone(),
            record: Mutex::new(Record {
                info: info(State::Queued),
                ready: false,
                error: None,
                stream: None,
                cancelling: None,
            }),
            changed: Condvar::new(),
        };
        let worker = std::thread::spawn(move || guest(&mut peer, info(State::Completed)));
        let received = receive(&host, &context, &"c".repeat(32), Some(&job))
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(received.state, State::Completed);
        let record = job.record.lock().unwrap();
        assert!(record.ready);
        assert_eq!(record.info.state, State::Queued);
        worker.join().unwrap();
    }
    #[test]
    fn unrelated_job_and_oversized_frame_are_rejected_on_real_streams() {
        let context = context();
        let (host, mut peer) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || guest(&mut peer, info(State::Completed)));
        assert!(receive(&host, &context, &"e".repeat(32), None).is_err());
        worker.join().unwrap();
        let (host, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&[1]).unwrap();
        peer.write_all(&65537u32.to_be_bytes()).unwrap();
        assert!(private_frame(&mut Channel::new(&host, Duration::from_secs(1))).is_err());
    }
}
