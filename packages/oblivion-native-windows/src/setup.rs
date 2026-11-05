//! One-shot native UAC setup. The ordinary caller owns the staged software and
//! authorizes its user through the kernel pipe token, never a command-line SID.
#![cfg(any(windows, test))]
use crate::installation::AtomicReview;
use crate::prerequisites;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    Install { bytes: u64 },
    Update {},
    Gc {},
    Uninstall {},
    Atomic {},
}

impl Operation {
    fn validate(self) -> Result<()> {
        if let Self::Install { bytes } = self {
            oblivion_wire::runtime_auth::Data::NewDisk {
                runtime_id: "1".repeat(32),
                bytes,
            }
            .validate()
            .map_err(|_| Error("invalid_setup_request"))?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    source_sha256: String,
    manifest_sha256: String,
    operation: Operation,
}

impl Request {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let request: Self = decode(bytes)?;
        if request.version != 1
            || !oblivion_bundle::hash(&request.source_sha256)
            || !oblivion_bundle::hash(&request.manifest_sha256)
            || request.operation.validate().is_err()
        {
            return Err(Error("invalid_setup_request"));
        }
        Ok(request)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    enable_hyperv: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AtomicApproval {
    review_id: String,
    remove: bool,
}

impl AtomicApproval {
    fn decode(bytes: &[u8], review_id: &str) -> Result<bool> {
        let approval: Self = decode(bytes)?;
        if approval.review_id != review_id || !oblivion_bundle::hash(&approval.review_id) {
            return Err(Error("atomic_review_changed"));
        }
        Ok(approval.remove)
    }
}

fn verify_atomic_completion(
    approved: Option<&AtomicReview>,
    runtime_id: &str,
    review_id: &str,
) -> Result<()> {
    if !approved
        .is_some_and(|review| review.runtime_id == runtime_id && review.review_id == review_id)
    {
        return Err(Error("atomic_review_changed"));
    }
    Ok(())
}

fn atomic_failure(code: &str) -> Error {
    Error(match code {
        "runtime_busy" => "runtime_busy",
        "runtime_not_installed" => "runtime_not_installed",
        "runtime_recovery_required" => "runtime_recovery_required",
        "runtime_resources_require_recovery" => "runtime_resources_require_recovery",
        "installed_runtime_source_mismatch" => "installed_runtime_source_mismatch",
        "atomic_review_changed" => "atomic_review_changed",
        _ => "setup_atomic_failed",
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    manifest_sha256: String,
    operation: Operation,
    event: Event,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Requirements {
        outcome: prerequisites::Outcome,
    },
    Installed {
        runtime_id: String,
    },
    Updated {
        runtime_id: String,
    },
    Cleaned {
        runtime_id: String,
        cleanup: crate::installation::Cleanup,
    },
    AtomicReview {
        review: AtomicReview,
    },
    Atomic {
        runtime_id: String,
        review_id: String,
        cleanup: crate::installation::Cleanup,
    },
    Declined,
    Failed {
        code: String,
    },
}

impl Response {
    fn decode(bytes: &[u8], manifest: &str, operation: Operation) -> Result<Self> {
        let response: Self = decode(bytes)?;
        let valid = match &response.event {
            Event::Installed { runtime_id }
            | Event::Updated { runtime_id }
            | Event::Cleaned { runtime_id, .. } => {
                oblivion_wire::control::valid_id(runtime_id)
                    && runtime_id.bytes().any(|byte| byte != b'0')
            }
            Event::AtomicReview { review } => review.validate().is_ok(),
            Event::Atomic {
                runtime_id,
                review_id,
                ..
            } => {
                oblivion_wire::control::valid_id(runtime_id)
                    && runtime_id.bytes().any(|byte| byte != b'0')
                    && oblivion_bundle::hash(review_id)
            }
            Event::Failed { code } => {
                !code.is_empty()
                    && code.len() <= 128
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            }
            Event::Requirements {
                outcome: prerequisites::Outcome::Ready,
            } => false,
            _ => true,
        };
        let matching = matches!(
            (operation, &response.event),
            (
                Operation::Install { .. },
                Event::Installed { .. } | Event::Requirements { .. } | Event::Declined
            ) | (Operation::Update {}, Event::Updated { .. })
                | (
                    Operation::Gc {} | Operation::Uninstall {},
                    Event::Cleaned { .. }
                )
                | (
                    Operation::Atomic {},
                    Event::AtomicReview { .. } | Event::Atomic { .. } | Event::Declined
                )
                | (_, Event::Failed { .. })
        );
        if response.version != 1
            || response.manifest_sha256 != manifest
            || response.operation != operation
            || !valid
            || !matching
        {
            return Err(Error("invalid_setup_response"));
        }
        Ok(response)
    }
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(Error("invalid_setup_message"));
    }
    serde_json::from_slice(bytes).map_err(|_| Error("invalid_setup_message"))
}

pub struct Registration {
    pub runtime_id: String,
    pub bundle_id: String,
    pub source_sha256: String,
    pub launcher: String,
}

pub enum Outcome {
    Installed {
        registration: Registration,
    },
    Updated {
        registration: Registration,
    },
    Collected {
        runtime_id: String,
        cleanup: crate::installation::Cleanup,
    },
    Uninstalled {
        runtime_id: String,
        cleanup: crate::installation::Cleanup,
    },
    Atomic {
        runtime_id: String,
        cleanup: crate::installation::Cleanup,
    },
    RebootRequired,
    Declined,
    Blocked {
        reason: prerequisites::Reason,
    },
}

#[cfg(windows)]
mod native {
    use super::{
        Approval, AtomicApproval, AtomicReview, Event, LIMIT, Operation, Outcome, Registration,
        Request, Response, atomic_failure, decode, verify_atomic_completion,
    };
    use crate::bundle::VerifiedBundle;
    use crate::client::Channel;
    use crate::files::Directory;
    use crate::installation::{self, Root};
    use crate::private::{self, Endpoint, Purpose};
    use crate::security::{self, Identity};
    use crate::{Error, Result, broker, prerequisites};
    use oblivion_wire::frame;
    use serde::Serialize;
    use std::io::Write;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::ptr::null;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);

    enum Review<'a> {
        EnableHyperv,
        Atomic(&'a AtomicReview),
    }

    type Reviewer<'a> = dyn for<'review> FnMut(Review<'review>) -> Result<bool> + 'a;

    /// The original process remains unelevated. The callback is only the
    /// explicit review for enabling Hyper-V, before any VM or data creation.
    pub fn execute(
        bundle: VerifiedBundle,
        operation: Operation,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut dyn FnMut() -> Result<bool>,
    ) -> Result<Outcome> {
        if matches!(operation, Operation::Atomic {}) {
            return Err(Error("atomic_interactive_review_required"));
        }
        execute_reviewed(
            bundle,
            operation,
            stop,
            deadline,
            &mut |request| match request {
                Review::EnableHyperv => review(),
                Review::Atomic(_) => Err(Error("unexpected_setup_review")),
            },
        )
    }

    pub fn execute_atomic(
        bundle: VerifiedBundle,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut dyn FnMut(&AtomicReview) -> Result<bool>,
    ) -> Result<Outcome> {
        execute_reviewed(
            bundle,
            Operation::Atomic {},
            stop,
            deadline,
            &mut |request| match request {
                Review::EnableHyperv => Err(Error("unexpected_setup_review")),
                Review::Atomic(details) => review(details),
            },
        )
    }

    fn execute_reviewed(
        bundle: VerifiedBundle,
        operation: Operation,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut Reviewer<'_>,
    ) -> Result<Outcome> {
        let _signals = Signals::new()?;
        let finished = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let completed = Completion(&finished);
            let signal_owner = scope.spawn(|| {
                while !finished.load(Ordering::Acquire) {
                    if INTERRUPTED.load(Ordering::Acquire) {
                        stop.store(true, Ordering::Release);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            });
            let result = execute_owned(bundle, operation, Arc::clone(&stop), deadline, review);
            drop(completed);
            signal_owner
                .join()
                .map_err(|_| Error("setup_signal_worker_failed"))?;
            result
        })
    }

    fn execute_owned(
        bundle: VerifiedBundle,
        operation: Operation,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut Reviewer<'_>,
    ) -> Result<Outcome> {
        operation.validate()?;
        let owner = Identity::current()?;
        if security::elevated()? {
            return execute_here(bundle, &owner, operation, stop, deadline, review);
        }
        check(&stop, deadline)?;
        let current = Root::current()?;
        let parent = current
            .path()
            .parent()
            .and_then(Path::parent)
            .and_then(Path::to_str)
            .ok_or(Error("setup_staging_unavailable"))?;
        let mut entropy = [0; 16];
        getrandom::getrandom(&mut entropy).map_err(|_| Error("runtime_entropy_unavailable"))?;
        let nonce: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let stage = bundle.stage(&format!(r"{parent}\Oblivion-Setup-{nonce}"), &owner)?;
        let name = format!(r"\\.\pipe\oblivion.{nonce}.setup");
        let source = stage.source().to_owned();
        let bundle_id = stage.id().to_owned();
        let manifest = stage.manifest_sha256().to_owned();
        if let Err(error) = check(&stop, deadline) {
            stage.remove(&owner)?;
            return Err(error);
        }
        let Some(process) = launch(stage.helper(), stage.root(), &name)? else {
            stage.remove(&owner)?;
            return Ok(Outcome::Declined);
        };
        let result = (|| {
            let wide = wide(&name);
            let pipe = loop {
                check(&stop, deadline)?;
                if exited(&process)? {
                    return Err(Error("setup_helper_exited"));
                }
                match private::connect_control(
                    &wide,
                    &owner,
                    &stop,
                    deadline.min(Instant::now() + Duration::from_secs(1)),
                ) {
                    Ok(pipe) => break pipe,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        std::thread::sleep(Duration::from_millis(25))
                    }
                    Err(_) => return Err(Error("setup_pipe_unavailable")),
                }
            };
            pipe.verify_server_process(&process)
                .map_err(|_| Error("untrusted_setup_helper"))?;
            let mut channel = Channel::new(pipe, Arc::clone(&stop), deadline);
            send(
                &mut channel,
                &Request {
                    version: 1,
                    source_sha256: source.clone(),
                    manifest_sha256: manifest.clone(),
                    operation,
                },
            )?;
            let outcome = (|| {
                let mut reviewed = false;
                let mut authorized_atomic = None;
                loop {
                    check(&stop, deadline)?;
                    let raw = frame::read(&mut channel, 1..=LIMIT)
                        .map_err(|_| Error("setup_exchange_failed"))?;
                    let response = Response::decode(&raw, &manifest, operation)?;
                    match response.event {
                        Event::Requirements {
                            outcome: prerequisites::Outcome::EnableRequired,
                        } if !reviewed => {
                            reviewed = true;
                            let approved = review(Review::EnableHyperv)?;
                            send(
                                &mut channel,
                                &Approval {
                                    enable_hyperv: approved,
                                },
                            )?;
                        }
                        Event::AtomicReview { review: details } if !reviewed => {
                            reviewed = true;
                            require_atomic_bundle(&details, &bundle_id, &source)?;
                            let approved = review(Review::Atomic(&details))?;
                            send(
                                &mut channel,
                                &AtomicApproval {
                                    review_id: details.review_id.clone(),
                                    remove: approved,
                                },
                            )?;
                            authorized_atomic = approved.then_some(details);
                        }
                        Event::Atomic {
                            runtime_id,
                            review_id,
                            cleanup,
                        } => {
                            verify_atomic_completion(
                                authorized_atomic.as_ref(),
                                &runtime_id,
                                &review_id,
                            )?;
                            return Ok(Event::Atomic {
                                runtime_id,
                                review_id,
                                cleanup,
                            });
                        }
                        event @ (Event::Requirements { .. }
                        | Event::Installed { .. }
                        | Event::Updated { .. }
                        | Event::Cleaned { .. }
                        | Event::Declined) => return Ok(event),
                        Event::Failed { code } => {
                            return Err(match (operation, code.as_str()) {
                                (Operation::Atomic {}, code) => atomic_failure(code),
                                (Operation::Install { .. }, "atomic_path_cleanup_pending") => {
                                    Error("atomic_path_cleanup_pending")
                                }
                                _ => Error("setup_installation_failed"),
                            });
                        }
                        Event::AtomicReview { .. } => return Err(Error("invalid_setup_response")),
                    }
                }
            })();
            channel
                .close()
                .map_err(|_| Error("setup_pipe_close_failed"))?;
            outcome
        })();
        // EOF revokes the child's pending work. Never return a successful
        // result or delete its executable while the exact helper still lives.
        let observed = wait_exit(&process, Instant::now() + Duration::from_secs(120));
        if observed.is_err() {
            return Err(Error("setup_cleanup_incomplete"));
        }
        // Keep source pins until the exact helper exits. Destructive
        // maintenance must never partly remove its invoking release.
        drop(bundle);
        let cleanup = stage.remove(&owner);
        let outcome = result?;
        cleanup?;
        finish(outcome, operation, &current, source, bundle_id, stop)
    }

    fn execute_here(
        bundle: VerifiedBundle,
        owner: &Identity,
        operation: Operation,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut Reviewer<'_>,
    ) -> Result<Outcome> {
        let source = bundle.source().to_owned();
        let bundle_id = bundle.id().to_owned();
        let event = perform(
            bundle,
            owner,
            operation,
            Arc::clone(&stop),
            deadline,
            review,
        )?;
        finish(
            event,
            operation,
            &Root::for_user(owner)?,
            source,
            bundle_id,
            stop,
        )
    }

    fn perform(
        bundle: VerifiedBundle,
        owner: &Identity,
        operation: Operation,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut Reviewer<'_>,
    ) -> Result<Event> {
        operation.validate()?;
        if matches!(operation, Operation::Install { .. }) {
            match requirements(&stop, deadline, review)? {
                prerequisites::Outcome::Ready => {}
                prerequisites::Outcome::EnableRequired => return Ok(Event::Declined),
                outcome => return Ok(Event::Requirements { outcome }),
            }
        }
        let root = Root::for_user(owner)?;
        match operation {
            Operation::Install { bytes } => {
                let installed = installation::install_bundle(&root, bundle, bytes, stop, deadline)?;
                Ok(Event::Installed {
                    runtime_id: installed.runtime_id().into(),
                })
            }
            Operation::Update {} => {
                let installed = installation::update_bundle(&root, bundle, stop, deadline)?;
                Ok(Event::Updated {
                    runtime_id: installed.runtime_id().into(),
                })
            }
            Operation::Gc {} | Operation::Uninstall {} => {
                let (runtime_id, source) = installation::control_binding(&root)?;
                if source != bundle.source() {
                    return Err(Error("installed_runtime_source_mismatch"));
                }
                // Release this source view before collection; the independent
                // staging image keeps this helper outside installed releases.
                drop(bundle);
                let cleanup = if matches!(operation, Operation::Gc {}) {
                    installation::collect(&root, stop, deadline)?
                } else {
                    installation::uninstall(&root, stop, deadline)?
                };
                Ok(Event::Cleaned {
                    runtime_id,
                    cleanup,
                })
            }
            Operation::Atomic {} => {
                let details = installation::atomic_review(&root)?;
                require_atomic_bundle(&details, bundle.id(), bundle.source())?;
                if !review(Review::Atomic(&details))? {
                    return Ok(Event::Declined);
                }
                check(&stop, deadline)?;
                let cleanup = installation::atomic(&root, &details, stop, deadline)?;
                Ok(Event::Atomic {
                    runtime_id: details.runtime_id,
                    review_id: details.review_id,
                    cleanup,
                })
            }
        }
    }

    fn require_atomic_bundle(review: &AtomicReview, bundle_id: &str, source: &str) -> Result<()> {
        review.validate()?;
        if review.bundle_id != bundle_id || review.source_sha256 != source {
            return Err(Error("installed_runtime_source_mismatch"));
        }
        Ok(())
    }

    fn finish(
        event: Event,
        operation: Operation,
        current: &Root,
        source: String,
        bundle_id: String,
        stop: Arc<AtomicBool>,
    ) -> Result<Outcome> {
        match event {
            Event::Installed { runtime_id } | Event::Updated { runtime_id } => {
                let verified =
                    broker::control_id(&source, stop, Instant::now() + Duration::from_secs(30))?;
                if verified != runtime_id {
                    return Err(Error("setup_installed_identity_changed"));
                }
                let launcher = current
                    .path()
                    .join("releases")
                    .join(&bundle_id)
                    .join("bin")
                    .join("oblivion.exe")
                    .to_str()
                    .ok_or(Error("unsupported_installation_path"))?
                    .to_owned();
                let registration = Registration {
                    runtime_id,
                    bundle_id,
                    source_sha256: source,
                    launcher,
                };
                match operation {
                    Operation::Install { .. } => Ok(Outcome::Installed { registration }),
                    Operation::Update {} => Ok(Outcome::Updated { registration }),
                    _ => Err(Error("invalid_setup_response")),
                }
            }
            Event::Cleaned {
                runtime_id,
                cleanup,
            } => match operation {
                Operation::Gc {} => Ok(Outcome::Collected {
                    runtime_id,
                    cleanup,
                }),
                Operation::Uninstall {} => Ok(Outcome::Uninstalled {
                    runtime_id,
                    cleanup,
                }),
                _ => Err(Error("invalid_setup_response")),
            },
            Event::Atomic {
                runtime_id,
                cleanup,
                ..
            } if matches!(operation, Operation::Atomic {}) => Ok(Outcome::Atomic {
                runtime_id,
                cleanup,
            }),
            Event::Requirements {
                outcome: prerequisites::Outcome::RebootRequired,
            } => Ok(Outcome::RebootRequired),
            Event::Requirements {
                outcome: prerequisites::Outcome::Blocked { reason },
            } => Ok(Outcome::Blocked { reason }),
            Event::Declined => Ok(Outcome::Declined),
            _ => Err(Error("invalid_setup_response")),
        }
    }

    fn requirements(
        stop: &AtomicBool,
        deadline: Instant,
        review: &mut Reviewer<'_>,
    ) -> Result<prerequisites::Outcome> {
        let state = prerequisites::prepare(false, stop, deadline)?;
        if state == prerequisites::Outcome::EnableRequired && review(Review::EnableHyperv)? {
            return prerequisites::prepare(true, stop, deadline);
        }
        Ok(state)
    }

    pub fn service(staging: &str, name: &str) -> Result<()> {
        if !security::elevated()? {
            return Err(Error("windows_administrator_required"));
        }
        let (_stage_pin, owner) = Directory::setup_owner(staging)?;
        let source = option_env!("OBLIVION_DESKTOP_SOURCE_SHA256")
            .filter(|value| oblivion_bundle::hash(value))
            .ok_or(Error("desktop_source_identity_missing"))?;
        let bundle = VerifiedBundle::open(staging, Some(source), &owner)?;
        let executing = std::env::current_exe().map_err(|_| Error("setup_helper_unavailable"))?;
        if !executing
            .to_str()
            .is_some_and(|path| path.eq_ignore_ascii_case(bundle.helper()))
        {
            return Err(Error("setup_helper_identity_changed"));
        }
        security::expose_setup_process(&owner)?;
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(600);
        let mut endpoint = Endpoint::bind_for(name, Purpose::Setup, &owner)?;
        let pipe = endpoint
            .accept(&stop, deadline)?
            .ok_or(Error("setup_client_missing"))?;
        let mut channel = Channel::new(pipe, Arc::clone(&stop), deadline);
        let raw =
            frame::read(&mut channel, 1..=LIMIT).map_err(|_| Error("invalid_setup_request"))?;
        channel.authenticate_setup(&owner)?;
        let request = Request::decode(&raw)?;
        if request.source_sha256 != source || request.manifest_sha256 != bundle.manifest_sha256() {
            return Err(Error("setup_bundle_binding_changed"));
        }
        let manifest = request.manifest_sha256.clone();
        let operation = request.operation;
        let result = std::thread::scope(|scope| {
            let (review_request, reviews) = std::sync::mpsc::sync_channel(0);
            let (approve, approvals) = std::sync::mpsc::sync_channel(0);
            let worker_stop = Arc::clone(&stop);
            let worker_owner = owner.clone();
            let worker = scope.spawn(move || {
                let mut review = |request: Review<'_>| {
                    let event = match request {
                        Review::EnableHyperv => Event::Requirements {
                            outcome: prerequisites::Outcome::EnableRequired,
                        },
                        Review::Atomic(review) => Event::AtomicReview {
                            review: review.clone(),
                        },
                    };
                    review_request
                        .send(event)
                        .map_err(|_| Error("setup_client_disconnected"))?;
                    loop {
                        check(&worker_stop, deadline)?;
                        match approvals.recv_timeout(Duration::from_millis(25)) {
                            Ok(approved) => return Ok(approved),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(_) => return Err(Error("setup_client_disconnected")),
                        }
                    }
                };
                perform(
                    bundle,
                    &worker_owner,
                    request.operation,
                    Arc::clone(&worker_stop),
                    deadline,
                    &mut review,
                )
            });
            let mut connected = true;
            let observed = (|| {
                while !worker.is_finished() {
                    if Instant::now() >= deadline {
                        stop.store(true, Ordering::Release);
                    }
                    if let Some(event) = connected.then(|| reviews.try_recv().ok()).flatten() {
                        let review_id = match &event {
                            Event::AtomicReview { review } => Some(review.review_id.clone()),
                            _ => None,
                        };
                        response(&mut channel, &manifest, operation, event)?;
                        let raw = frame::read(&mut channel, 1..=LIMIT)
                            .map_err(|_| Error("invalid_setup_approval"))?;
                        channel.authenticate_setup(&owner)?;
                        let approved = match review_id {
                            Some(review_id) => AtomicApproval::decode(&raw, &review_id)?,
                            None => decode::<Approval>(&raw)?.enable_hyperv,
                        };
                        approve
                            .send(approved)
                            .map_err(|_| Error("setup_worker_failed"))?;
                        continue;
                    }
                    if connected {
                        match channel.try_read(&mut [0]) {
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            _ => {
                                connected = false;
                                stop.store(true, Ordering::Release);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(())
            })();
            if observed.is_err() {
                stop.store(true, Ordering::Release);
            }
            drop(approve);
            drop(reviews);
            let result = worker.join().map_err(|_| Error("setup_worker_failed"))?;
            observed?;
            if !connected {
                return Err(Error("setup_client_disconnected"));
            }
            result
        });
        match result {
            Ok(event) => response(&mut channel, &manifest, operation, event),
            Err(error) => {
                response(
                    &mut channel,
                    &manifest,
                    operation,
                    Event::Failed {
                        code: error.0.into(),
                    },
                )?;
                Err(error)
            }
        }
    }

    fn response(
        channel: &mut Channel,
        manifest: &str,
        operation: Operation,
        event: Event,
    ) -> Result<()> {
        send(
            channel,
            &Response {
                version: 1,
                manifest_sha256: manifest.into(),
                operation,
                event,
            },
        )
    }
    fn send(channel: &mut Channel, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error("invalid_setup_message"))?;
        frame::write(channel, &bytes, 1..=LIMIT).map_err(|_| Error("setup_exchange_failed"))?;
        channel.flush().map_err(|_| Error("setup_exchange_failed"))
    }
    fn launch(helper: &str, staging: &str, pipe: &str) -> Result<Option<OwnedHandle>> {
        if !crate::config::drive_file(helper) || !crate::config::drive_file(staging) {
            return Err(Error("invalid_setup_path"));
        }
        let initialized = unsafe {
            CoInitializeEx(
                null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if initialized < 0 {
            return Err(Error("setup_shell_unavailable"));
        }
        let helper = wide(helper);
        let arguments = wide(&format!("setup --staging \"{staging}\" --pipe {pipe}"));
        let verb = wide("runas");
        let mut execute = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: verb.as_ptr(),
            lpFile: helper.as_ptr(),
            lpParameters: arguments.as_ptr(),
            nShow: 0,
            ..Default::default()
        };
        let launched = unsafe { ShellExecuteExW(&mut execute) };
        let error = unsafe { GetLastError() };
        unsafe { CoUninitialize() };
        if launched == 0 {
            if error == ERROR_CANCELLED {
                return Ok(None);
            }
            return Err(Error("setup_elevation_failed"));
        }
        if execute.hProcess.is_null() {
            return Err(Error("setup_elevation_unconfirmed"));
        }
        Ok(Some(unsafe {
            OwnedHandle::from_raw_handle(execute.hProcess)
        }))
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    fn exited(process: &OwnedHandle) -> Result<bool> {
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(Error("setup_process_observation_failed")),
        }
    }
    fn wait_exit(process: &OwnedHandle, deadline: Instant) -> Result<()> {
        while !exited(process)? {
            if Instant::now() >= deadline {
                return Err(Error("setup_cleanup_incomplete"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(())
    }
    fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
        if stop.load(Ordering::Acquire) || INTERRUPTED.load(Ordering::Acquire) {
            return Err(Error("setup_cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(Error("setup_timeout"));
        }
        Ok(())
    }
    struct Signals;
    struct Completion<'a>(&'a AtomicBool);
    impl Drop for Completion<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    impl Signals {
        fn new() -> Result<Self> {
            INTERRUPTED.store(false, Ordering::Release);
            if unsafe { SetConsoleCtrlHandler(Some(signal), 1) } == 0 {
                return Err(Error("setup_signal_handler_failed"));
            }
            Ok(Self)
        }
    }
    impl Drop for Signals {
        fn drop(&mut self) {
            unsafe { SetConsoleCtrlHandler(Some(signal), 0) };
        }
    }
    unsafe extern "system" fn signal(event: u32) -> i32 {
        if !matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            return 0;
        }
        INTERRUPTED.store(true, Ordering::Release);
        1
    }

    #[cfg(test)]
    mod tests {
        use super::{LIMIT, Operation, Request, send};
        use crate::client::Channel;
        use crate::private::{Purpose, tests::connected_pair};
        use crate::security::Identity;
        use oblivion_wire::frame;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        #[test]
        fn setup_admission_authenticates_the_actual_read_message_before_interpreting_it() {
            let (_endpoint, server, client) = connected_pair(Purpose::Setup);
            let stop = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut caller = Channel::new(client, Arc::clone(&stop), deadline);
            send(
                &mut caller,
                &Request {
                    version: 1,
                    source_sha256: "a".repeat(64),
                    manifest_sha256: "b".repeat(64),
                    operation: Operation::Install { bytes: 17179869184 },
                },
            )
            .unwrap();
            let mut helper = Channel::new(server, stop, deadline);
            let bytes = frame::read(&mut helper, 1..=LIMIT).unwrap();
            helper
                .authenticate_setup(&Identity::current().unwrap())
                .unwrap();
            Request::decode(&bytes).unwrap();
            assert!(
                helper
                    .authenticate_setup(&Identity::from_sid("S-1-5-21-1-2-3-4294967294").unwrap())
                    .is_err()
            );
            assert!(
                caller
                    .authenticate_setup(&Identity::current().unwrap())
                    .is_err()
            );
        }
    }
}

#[cfg(windows)]
pub use native::{execute, execute_atomic, service};

#[cfg(test)]
mod tests {
    use super::{
        Approval, AtomicApproval, Event, LIMIT, Operation, Request, Response, atomic_failure,
        decode, verify_atomic_completion,
    };
    use serde_json::json;

    #[test]
    fn setup_request_cannot_supply_an_owner_or_a_privileged_path() {
        let value = json!({"version":1,"source_sha256":"a".repeat(64),"manifest_sha256":"b".repeat(64),"operation":{"kind":"install","bytes":17179869184_u64}});
        Request::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        for (field, invalid) in [
            ("owner", json!("S-1-5-21-1-2-3-1001")),
            ("root", json!(r"C:\Foreign")),
            ("operation", json!({"kind":"install","bytes":1})),
            ("version", json!(2)),
            ("source_sha256", json!("PRIVATE_CANARY")),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            let error = Request::decode(&serde_json::to_vec(&changed).unwrap())
                .err()
                .unwrap();
            assert!(!error.to_string().contains("PRIVATE_CANARY"));
        }
        assert!(Request::decode(&vec![b' '; LIMIT + 1]).is_err());
        assert!(decode::<Approval>(br#"{"enable_hyperv":true,"feature":"OtherFeature"}"#).is_err());
    }

    #[test]
    fn completion_is_bound_to_the_reviewed_bundle_and_exact_runtime_shape() {
        let manifest = "b".repeat(64);
        let installed = json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"installed","runtime_id":"1".repeat(32)}});
        let response = Response::decode(
            &serde_json::to_vec(&installed).unwrap(),
            &manifest,
            Operation::Install { bytes: 17179869184 },
        )
        .unwrap();
        assert!(matches!(response.event, Event::Installed { .. }));
        for invalid in [
            json!({"version":1,"manifest_sha256":"c".repeat(64),"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"installed","runtime_id":"1".repeat(32)}}),
            json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"installed","runtime_id":"0".repeat(32)}}),
            json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"requirements","outcome":{"kind":"ready"}}}),
            json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"failed","code":"PRIVATE\nCANARY"}}),
            json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"install","bytes":17179869184_u64},"event":{"kind":"installed","runtime_id":"1".repeat(32),"launcher":r"C:\Foreign\program.exe"}}),
        ] {
            assert!(
                Response::decode(
                    &serde_json::to_vec(&invalid).unwrap(),
                    &manifest,
                    Operation::Install { bytes: 17179869184 }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn maintenance_admission_and_outcomes_cannot_change_the_reviewed_operation() {
        let manifest = "b".repeat(64);
        for operation in [
            Operation::Update {},
            Operation::Gc {},
            Operation::Uninstall {},
        ] {
            let request = Request {
                version: 1,
                source_sha256: "a".repeat(64),
                manifest_sha256: manifest.clone(),
                operation,
            };
            assert_eq!(
                Request::decode(&serde_json::to_vec(&request).unwrap())
                    .unwrap()
                    .operation,
                operation
            );
        }
        let cleaned = json!({"version":1,"manifest_sha256":manifest,"operation":{"kind":"uninstall"},"event":{"kind":"cleaned","runtime_id":"1".repeat(32),"cleanup":{"releases_removed":1,"boot_files_removed":3,"retained":0,"in_use":1,"software_removed":false}}});
        let bytes = serde_json::to_vec(&cleaned).unwrap();
        let response = Response::decode(&bytes, &manifest, Operation::Uninstall {}).unwrap();
        assert!(
            matches!(response.event, Event::Cleaned { cleanup, .. } if cleanup.in_use==1 && !cleanup.software_removed)
        );
        assert!(Response::decode(&bytes, &manifest, Operation::Gc {}).is_err());
        assert!(Response::decode(&bytes, &manifest, Operation::Update {}).is_err());
        let mut changed = cleaned;
        changed["event"]["cleanup"]["destination"] = json!(r"C:\Foreign");
        assert!(
            Response::decode(
                &serde_json::to_vec(&changed).unwrap(),
                &manifest,
                Operation::Uninstall {}
            )
            .is_err()
        );
        assert!(Request::decode(br#"{"version":1,"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":{"kind":"gc","bytes":17179869184}}"#).is_err());
    }

    #[test]
    fn atomic_setup_requires_the_exact_review_before_accepting_completion() {
        let manifest = "b".repeat(64);
        let runtime_id = "1".repeat(32);
        let review_id = "c".repeat(64);
        let review = json!({
            "version": 1, "manifest_sha256": manifest, "operation": {"kind":"atomic"},
            "event": {"kind":"atomic-review", "review": {
                "runtime_id": runtime_id, "review_id": review_id,
                "archive": r"C:\ProgramData\Oblivion\test\data.vhdx", "archive_present": true,
                "data_bytes": 17179869184_u64, "bundle_id": "d".repeat(64), "source_sha256": "e".repeat(64)
            }}
        });
        let bytes = serde_json::to_vec(&review).unwrap();
        let response = Response::decode(&bytes, &manifest, Operation::Atomic {}).unwrap();
        let Event::AtomicReview { review: details } = response.event else {
            panic!("expected review")
        };
        assert!(Response::decode(&bytes, &manifest, Operation::Uninstall {}).is_err());
        let approved = serde_json::to_vec(&json!({"review_id": review_id, "remove":true})).unwrap();
        assert!(AtomicApproval::decode(&approved, &review_id).unwrap());
        assert!(AtomicApproval::decode(&approved, &"f".repeat(64)).is_err());
        assert!(AtomicApproval::decode(br#"{"enable_hyperv":true}"#, &review_id).is_err());
        let injected_path = serde_json::to_vec(
            &json!({"review_id": review_id, "remove":true, "path":r"C:\Foreign"}),
        )
        .unwrap();
        assert!(AtomicApproval::decode(&injected_path, &review_id).is_err());
        assert!(verify_atomic_completion(None, &runtime_id, &review_id).is_err());
        assert!(verify_atomic_completion(Some(&details), &runtime_id, &review_id).is_ok());
        assert!(verify_atomic_completion(Some(&details), &"2".repeat(32), &review_id).is_err());
        assert!(verify_atomic_completion(Some(&details), &runtime_id, &"f".repeat(64)).is_err());
    }

    #[test]
    fn atomic_failure_exposes_only_actionable_setup_codes() {
        assert_eq!(atomic_failure("runtime_busy").0, "runtime_busy");
        assert_eq!(
            atomic_failure("installed_runtime_source_mismatch").0,
            "installed_runtime_source_mismatch"
        );
        assert_eq!(
            atomic_failure(r"secret C:\Foreign").0,
            "setup_atomic_failed"
        );
    }
}
