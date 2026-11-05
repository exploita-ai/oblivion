//! Ordinary-user runtime admission. Requests identify an operation, never an
//! executable, filesystem root, user SID or HCS configuration.
#![cfg(any(windows, test))]
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const LIMIT: usize = 8192;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Describe,
    Acquire,
    Start,
    Stop,
    Recover,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    source_sha256: String,
    action: Action,
}

impl Request {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > LIMIT {
            return Err(Error("invalid_broker_request"));
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| Error("invalid_broker_request"))?;
        if request.version != 1 || !oblivion_bundle::hash(&request.source_sha256) {
            return Err(Error("invalid_broker_request"));
        }
        Ok(request)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub runtime_id: String,
    pub source_sha256: String,
    pub launcher: String,
    pub manager: String,
    pub assets: String,
}

impl Layout {
    fn validate(&self, source: &str) -> Result<()> {
        if !oblivion_wire::control::valid_id(&self.runtime_id)
            || self.runtime_id.bytes().all(|byte| byte == b'0')
            || self.source_sha256 != source
            || [&self.launcher, &self.manager, &self.assets]
                .iter()
                .any(|path| !crate::config::drive_file(path))
        {
            return Err(Error("invalid_broker_response"));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    outcome: Outcome,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Outcome {
    Control { runtime_id: String },
    Acquired { layout: Layout, generation: String },
    Done,
    Error { code: String },
}

impl Reply {
    fn decode(bytes: &[u8], action: Action, source: &str) -> Result<Self> {
        if bytes.len() > LIMIT {
            return Err(Error("invalid_broker_response"));
        }
        let reply: Self =
            serde_json::from_slice(bytes).map_err(|_| Error("invalid_broker_response"))?;
        if reply.version != 1 {
            return Err(Error("invalid_broker_response"));
        }
        let valid = match &reply.outcome {
            Outcome::Control { runtime_id } => action == Action::Describe && identifier(runtime_id),
            Outcome::Acquired { layout, generation } => {
                layout.validate(source)?;
                action == Action::Acquire && identifier(generation)
            }
            Outcome::Done => matches!(action, Action::Start | Action::Stop | Action::Recover),
            Outcome::Error { code } => {
                !code.is_empty()
                    && code.len() <= 128
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            }
        };
        if !valid {
            return Err(Error("invalid_broker_response"));
        }
        Ok(reply)
    }
}

fn identifier(value: &str) -> bool {
    oblivion_wire::control::valid_id(value) && !value.bytes().all(|byte| byte == b'0')
}

#[cfg(windows)]
mod native {
    use super::{Action, LIMIT, Layout, Outcome, Reply, Request};
    use crate::client::Channel;
    use crate::installation::{self, Installed, Root};
    use crate::private::Pipe;
    use crate::security::Identity;
    use crate::{Error, Result, broker_pipe, scm, supervisor};
    use oblivion_wire::agent;
    use std::io::{self, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    pub struct Lease {
        layout: Layout,
        _channel: Channel,
    }

    impl Lease {
        pub fn layout(&self) -> &Layout {
            &self.layout
        }
    }

    /// The SCM process is authenticated before sending even this secret-free
    /// request. The retained channel is the client's runtime ownership lease.
    pub fn acquire(source: &str, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Lease> {
        let (mut channel, outcome) = exchange(Action::Acquire, source, stop, deadline)?;
        let Outcome::Acquired { layout, .. } = outcome else {
            return Err(Error("invalid_broker_response"));
        };
        channel
            .claim_lease()
            .map_err(|_| Error("broker_lease_failed"))?;
        Ok(Lease {
            layout,
            _channel: channel,
        })
    }

    /// Status/activity discovery is bounded metadata only and never boots a VM.
    pub fn control_id(source: &str, stop: Arc<AtomicBool>, deadline: Instant) -> Result<String> {
        let (_, outcome) = exchange(Action::Describe, source, stop, deadline)?;
        match outcome {
            Outcome::Control { runtime_id } => Ok(runtime_id),
            _ => Err(Error("invalid_broker_response")),
        }
    }

    pub fn command(
        action: Action,
        source: &str,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<()> {
        if !matches!(action, Action::Start | Action::Stop | Action::Recover) {
            return Err(Error("invalid_broker_operation"));
        }
        match exchange(action, source, stop, deadline)?.1 {
            Outcome::Done => Ok(()),
            _ => Err(Error("invalid_broker_response")),
        }
    }

    fn exchange(
        action: Action,
        source: &str,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<(Channel, Outcome)> {
        let request = Request {
            version: 1,
            source_sha256: source.into(),
            action,
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| Error("invalid_broker_request"))?;
        Request::decode(&bytes)?;
        let owner = Identity::current()?;
        let server = scm::ensure_running(&owner, Arc::clone(&stop), deadline)?;
        let pipe = server.connect(Arc::clone(&stop), deadline)?;
        let mut channel = Channel::new(pipe, stop, deadline);
        agent::write_frame(&mut channel, 0, &bytes).map_err(|_| Error("broker_exchange_failed"))?;
        channel
            .flush()
            .map_err(|_| Error("broker_exchange_failed"))?;
        let (kind, bytes) =
            agent::read_frame(&mut channel).map_err(|_| Error("broker_exchange_failed"))?;
        if kind != 1 || bytes.len() > LIMIT {
            return Err(Error("invalid_broker_response"));
        }
        let reply = Reply::decode(&bytes, action, source)?;
        if let Outcome::Error { code } = &reply.outcome {
            return Err(Error(match code.as_str() {
                "runtime_busy" => "runtime_busy",
                "runtime_not_installed" => "runtime_not_installed",
                "runtime_recovery_required" => "runtime_recovery_required",
                "runtime_resources_require_recovery" => "runtime_resources_require_recovery",
                "resource_binding_changed" => "resource_binding_changed",
                "resource_network_binding_changed" => "resource_network_binding_changed",
                "runtime_file_evidence_changed" => "runtime_file_evidence_changed",
                "resource_owner_lock_timeout" => "resource_owner_lock_timeout",
                "resource_recovery_timeout" => "resource_recovery_timeout",
                "hcs_system_already_exists" => "hcs_system_already_exists",
                "windows_owned_reconciliation_required" => "windows_owned_reconciliation_required",
                "runtime_closing" => "runtime_closing",
                "installation_pending" => "installation_pending",
                "installed_runtime_source_mismatch" => "installed_runtime_source_mismatch",
                _ => "broker_operation_failed",
            }));
        }
        Ok((channel, reply.outcome))
    }

    pub fn service(owner: Identity) -> Result<()> {
        scm::dispatch(owner, serve)
    }

    fn serve(owner: Identity, stop: Arc<AtomicBool>) -> Result<()> {
        let mut endpoint = broker_pipe::bind(&owner)?;
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        let result = (|| {
            while !stop.load(Ordering::Acquire) {
                let (finished, running): (Vec<_>, Vec<_>) =
                    workers.drain(..).partition(JoinHandle::is_finished);
                workers = running;
                if !join_workers(finished) {
                    return Err(Error("broker_worker_failed"));
                }
                // Each lease is one calling terminal, including a manager.
                if workers.len() >= 64 {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                let Some(pipe) =
                    endpoint.accept(&stop, Instant::now() + Duration::from_millis(100))?
                else {
                    continue;
                };
                let owner = owner.clone();
                let stop = Arc::clone(&stop);
                workers.push(thread::spawn(move || {
                    // Invalid or abandoned callers revoke only their connection.
                    let _ = connection(pipe, &owner, stop);
                }));
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        let stopped = endpoint.stop_admission();
        let joined = join_workers(workers);
        result?;
        stopped?;
        if !joined {
            return Err(Error("broker_worker_failed"));
        }
        Ok(())
    }

    fn join_workers(workers: Vec<JoinHandle<()>>) -> bool {
        // Join every owner even if an earlier worker panicked.
        workers
            .into_iter()
            .fold(true, |joined, worker| worker.join().is_ok() && joined)
    }

    fn connection(pipe: Pipe, owner: &Identity, service_stop: Arc<AtomicBool>) -> Result<()> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut channel = Channel::new(
            pipe,
            Arc::clone(&cancelled),
            Instant::now() + Duration::from_secs(10),
        );
        let (kind, bytes) =
            agent::read_frame(&mut channel).map_err(|_| Error("invalid_broker_request"))?;
        channel.authenticate_broker(owner)?;
        if kind != 0 {
            return Err(Error("invalid_broker_request"));
        }
        let request = Request::decode(&bytes)?;
        channel
            .set_deadline(Instant::now() + Duration::from_secs(400))
            .map_err(|_| Error("broker_exchange_failed"))?;
        // The I/O owner watches EOF while startup runs. A vanished terminal must
        // cancel its pending admission, rather than leave an unowned cold boot.
        let result = thread::scope(|scope| {
            let pending = scope.spawn(|| execute(owner, request, Arc::clone(&cancelled)));
            let mut connected = true;
            let observed = (|| {
                while !pending.is_finished() {
                    if service_stop.load(Ordering::Acquire) || !connected {
                        cancelled.store(true, Ordering::Release);
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    connected = quiet(&mut channel)?;
                }
                Ok(())
            })();
            if observed.is_err() || !connected || service_stop.load(Ordering::Acquire) {
                cancelled.store(true, Ordering::Release);
            }
            let result = pending.join().map_err(|_| Error("broker_worker_failed"))?;
            observed?;
            if !connected || service_stop.load(Ordering::Acquire) {
                return Err(Error("broker_client_disconnected"));
            }
            result
        });
        let (outcome, lease) = match result {
            Ok(result) => result,
            Err(error) => (
                Outcome::Error {
                    code: error.0.into(),
                },
                None,
            ),
        };
        let reply = serde_json::to_vec(&Reply {
            version: 1,
            outcome,
        })
        .map_err(|_| Error("invalid_broker_response"))?;
        agent::write_frame(&mut channel, 1, &reply).map_err(|_| Error("broker_exchange_failed"))?;
        channel
            .flush()
            .map_err(|_| Error("broker_exchange_failed"))?;
        let Some(mut lease) = lease else {
            return Ok(());
        };
        channel
            .claim_lease()
            .map_err(|_| Error("broker_lease_failed"))?;
        while !service_stop.load(Ordering::Acquire) && quiet(&mut channel)? {}
        // Dropping the channel on any error also releases this exact supervisor
        // lease. Other terminals keep their own independent ownership.
        lease.close()
    }

    fn quiet(channel: &mut Channel) -> Result<bool> {
        match channel.try_read(&mut [0]) {
            Ok(0) => Ok(false),
            Ok(_) => Err(Error("invalid_broker_lease_data")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                channel
                    .wait_readable()
                    .map_err(|_| Error("broker_lease_failed"))?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn execute(
        owner: &Identity,
        request: Request,
        cancelled: Arc<AtomicBool>,
    ) -> Result<(Outcome, Option<supervisor::Lease>)> {
        let root = Root::for_user(owner)?;
        let (runtime_id, source) = installation::control_binding(&root)?;
        if request.source_sha256 != source || source_id()? != source {
            return Err(Error("installed_runtime_source_mismatch"));
        }
        let deadline = Instant::now() + Duration::from_secs(390);
        match request.action {
            Action::Describe => {
                installation::control_id(&root)?;
                Ok((Outcome::Control { runtime_id }, None))
            }
            Action::Acquire | Action::Start => {
                let installed = installation::discover(&root)?;
                let lease = installed.acquire(Arc::clone(&cancelled), deadline)?;
                if request.action == Action::Start {
                    lease.start_resident(cancelled, deadline)?;
                    return Ok((Outcome::Done, None));
                }
                let outcome = Outcome::Acquired {
                    layout: layout(&installed),
                    generation: lease.generation().into(),
                };
                Ok((outcome, Some(lease)))
            }
            Action::Stop => {
                supervisor::stop(&installation::owned_settings(&root)?, cancelled, deadline)?;
                Ok((Outcome::Done, None))
            }
            Action::Recover => {
                supervisor::recover(&installation::owned_settings(&root)?, cancelled, deadline)?;
                Ok((Outcome::Done, None))
            }
        }
    }

    fn layout(installed: &Installed) -> Layout {
        Layout {
            runtime_id: installed.runtime_id().into(),
            source_sha256: installed.source().into(),
            launcher: installed.launcher().into(),
            manager: installed.manager().into(),
            assets: installed.assets().into(),
        }
    }

    fn source_id() -> Result<&'static str> {
        option_env!("OBLIVION_DESKTOP_SOURCE_SHA256")
            .filter(|value| oblivion_bundle::hash(value))
            .ok_or(Error("source_bound_broker_required"))
    }
}

#[cfg(windows)]
pub use native::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_admit_only_typed_lifecycle_operations() {
        for action in [
            Action::Describe,
            Action::Acquire,
            Action::Start,
            Action::Stop,
            Action::Recover,
        ] {
            let encoded = serde_json::to_vec(&Request {
                version: 1,
                source_sha256: "a".repeat(64),
                action,
            })
            .unwrap();
            assert_eq!(Request::decode(&encoded).unwrap().action, action);
        }
        for extra in [
            "\"owner\":\"S-1-5-18\"",
            "\"helper\":\"C:\\\\untrusted.exe\"",
            "\"config\":{}",
        ] {
            let bytes = format!(
                r#"{{"version":1,"source_sha256":"{}","action":"acquire",{extra}}}"#,
                "a".repeat(64)
            );
            assert!(Request::decode(bytes.as_bytes()).is_err());
        }
        assert!(Request::decode(&vec![b' '; LIMIT + 1]).is_err());
        assert!(
            Request::decode(br#"{"version":1,"source_sha256":"a","action":"acquire"}"#).is_err()
        );
        assert!(
            Request::decode(
                format!(
                    r#"{{"version":2,"source_sha256":"{}","action":"acquire"}}"#,
                    "a".repeat(64)
                )
                .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn acquired_layout_rejects_foreign_sources_and_remote_paths() {
        let mut layout = Layout {
            runtime_id: "1".repeat(32),
            source_sha256: "a".repeat(64),
            launcher: r"C:\ProgramData\Oblivion\release\bin\oblivion.exe".into(),
            manager: r"C:\ProgramData\Oblivion\release\bin\manager.exe".into(),
            assets: r"C:\ProgramData\Oblivion\release\assets".into(),
        };
        layout.validate(&"a".repeat(64)).unwrap();
        assert!(layout.validate(&"b".repeat(64)).is_err());
        layout.manager = r"\\server\share\manager.exe".into();
        assert!(layout.validate(&"a".repeat(64)).is_err());
    }

    #[test]
    fn replies_match_the_requested_operation() {
        let control = serde_json::to_vec(&Reply {
            version: 1,
            outcome: Outcome::Control {
                runtime_id: "1".repeat(32),
            },
        })
        .unwrap();
        Reply::decode(&control, Action::Describe, &"a".repeat(64)).unwrap();
        assert!(Reply::decode(&control, Action::Acquire, &"a".repeat(64)).is_err());
        let done = br#"{"version":1,"outcome":{"kind":"done"}}"#;
        Reply::decode(done, Action::Stop, &"a".repeat(64)).unwrap();
        assert!(Reply::decode(done, Action::Acquire, &"a".repeat(64)).is_err());
        let zero = serde_json::to_vec(&Reply {
            version: 1,
            outcome: Outcome::Control {
                runtime_id: "0".repeat(32),
            },
        })
        .unwrap();
        assert!(Reply::decode(&zero, Action::Describe, &"a".repeat(64)).is_err());
    }
}
