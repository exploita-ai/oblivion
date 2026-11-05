//! One-shot native UAC setup. The ordinary caller owns the staged software and
//! authorizes its user through the kernel pipe token, never a command-line SID.
#![cfg(any(windows, test))]
use crate::prerequisites;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const LIMIT: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    source_sha256: String,
    manifest_sha256: String,
    bytes: u64,
}

impl Request {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let request: Self = decode(bytes)?;
        if request.version != 1
            || !oblivion_bundle::hash(&request.source_sha256)
            || !oblivion_bundle::hash(&request.manifest_sha256)
            || (oblivion_wire::runtime_auth::Data::NewDisk {
                runtime_id: "1".repeat(32),
                bytes: request.bytes,
            })
            .validate()
            .is_err()
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
struct Response {
    version: u8,
    manifest_sha256: String,
    event: Event,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Requirements { outcome: prerequisites::Outcome },
    Installed { runtime_id: String },
    Declined,
    Failed { code: String },
}

impl Response {
    fn decode(bytes: &[u8], manifest: &str) -> Result<Self> {
        let response: Self = decode(bytes)?;
        let valid = match &response.event {
            Event::Installed { runtime_id } => {
                oblivion_wire::control::valid_id(runtime_id)
                    && runtime_id.bytes().any(|byte| byte != b'0')
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
        if response.version != 1 || response.manifest_sha256 != manifest || !valid {
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

pub enum Outcome {
    Installed {
        runtime_id: String,
        launcher: String,
    },
    RebootRequired,
    Declined,
    Blocked {
        reason: prerequisites::Reason,
    },
}

#[cfg(windows)]
mod native {
    use super::{Approval, Event, LIMIT, Outcome, Request, Response, decode};
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

    /// The original process remains unelevated. The callback is only the
    /// explicit review for enabling Hyper-V, before any VM or data creation.
    pub fn install(
        bundle: VerifiedBundle,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut dyn FnMut() -> Result<bool>,
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
            let result = install_owned(bundle, bytes, Arc::clone(&stop), deadline, review);
            drop(completed);
            signal_owner
                .join()
                .map_err(|_| Error("setup_signal_worker_failed"))?;
            result
        })
    }

    fn install_owned(
        bundle: VerifiedBundle,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut dyn FnMut() -> Result<bool>,
    ) -> Result<Outcome> {
        let owner = Identity::current()?;
        if security::elevated()? {
            return install_here(bundle, &owner, bytes, stop, deadline, review);
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
                    bytes,
                },
            )?;
            let outcome = (|| {
                let mut reviewed = false;
                loop {
                    check(&stop, deadline)?;
                    let raw = frame::read(&mut channel, 1..=LIMIT)
                        .map_err(|_| Error("setup_exchange_failed"))?;
                    let response = Response::decode(&raw, &manifest)?;
                    match response.event {
                        Event::Requirements {
                            outcome: prerequisites::Outcome::EnableRequired,
                        } if !reviewed => {
                            reviewed = true;
                            let approved = review()?;
                            send(
                                &mut channel,
                                &Approval {
                                    enable_hyperv: approved,
                                },
                            )?;
                        }
                        Event::Requirements {
                            outcome: prerequisites::Outcome::RebootRequired,
                        } => return Ok(Outcome::RebootRequired),
                        Event::Requirements {
                            outcome: prerequisites::Outcome::Blocked { reason },
                        } => return Ok(Outcome::Blocked { reason }),
                        Event::Installed { runtime_id } => {
                            return Ok(Outcome::Installed {
                                runtime_id,
                                launcher: String::new(),
                            });
                        }
                        Event::Declined => return Ok(Outcome::Declined),
                        Event::Failed { .. } => return Err(Error("setup_installation_failed")),
                        _ => return Err(Error("invalid_setup_response")),
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
        let cleanup = stage.remove(&owner);
        let outcome = result?;
        cleanup?;
        match outcome {
            Outcome::Installed { runtime_id, .. } => {
                let verified = broker::control_id(
                    &source,
                    Arc::clone(&stop),
                    Instant::now() + Duration::from_secs(30),
                )?;
                if verified != runtime_id {
                    return Err(Error("setup_installed_identity_changed"));
                }
                let launcher = current
                    .path()
                    .join("releases")
                    .join(bundle_id)
                    .join("bin")
                    .join("oblivion.exe")
                    .to_str()
                    .ok_or(Error("unsupported_installation_path"))?
                    .to_owned();
                Ok(Outcome::Installed {
                    runtime_id,
                    launcher,
                })
            }
            outcome => Ok(outcome),
        }
    }

    fn install_here(
        bundle: VerifiedBundle,
        owner: &Identity,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
        review: &mut dyn FnMut() -> Result<bool>,
    ) -> Result<Outcome> {
        let source = bundle.source().to_owned();
        match requirements(&stop, deadline, review)? {
            prerequisites::Outcome::Ready => {}
            prerequisites::Outcome::RebootRequired => return Ok(Outcome::RebootRequired),
            prerequisites::Outcome::Blocked { reason } => return Ok(Outcome::Blocked { reason }),
            prerequisites::Outcome::EnableRequired => return Ok(Outcome::Declined),
        }
        let installed = installation::install_bundle(
            &Root::for_user(owner)?,
            bundle,
            bytes,
            Arc::clone(&stop),
            deadline,
        )?;
        if broker::control_id(&source, stop, Instant::now() + Duration::from_secs(30))?
            != installed.runtime_id()
        {
            return Err(Error("setup_installed_identity_changed"));
        }
        Ok(Outcome::Installed {
            runtime_id: installed.runtime_id().into(),
            launcher: installed.launcher().into(),
        })
    }

    fn requirements(
        stop: &AtomicBool,
        deadline: Instant,
        review: &mut dyn FnMut() -> Result<bool>,
    ) -> Result<prerequisites::Outcome> {
        let state = prerequisites::prepare(false, stop, deadline)?;
        if state == prerequisites::Outcome::EnableRequired && review()? {
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
        let result = std::thread::scope(|scope| {
            let (review_request, reviews) = std::sync::mpsc::sync_channel(0);
            let (approve, approvals) = std::sync::mpsc::sync_channel(0);
            let worker_stop = Arc::clone(&stop);
            let worker_owner = owner.clone();
            let worker = scope.spawn(move || {
                let mut review = || {
                    review_request
                        .send(())
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
                match requirements(&worker_stop, deadline, &mut review)? {
                    prerequisites::Outcome::Ready => {}
                    prerequisites::Outcome::EnableRequired => return Ok(Event::Declined),
                    outcome => return Ok(Event::Requirements { outcome }),
                }
                let installed = installation::install_bundle(
                    &Root::for_user(&worker_owner)?,
                    bundle,
                    request.bytes,
                    Arc::clone(&worker_stop),
                    deadline,
                )?;
                Ok(Event::Installed {
                    runtime_id: installed.runtime_id().into(),
                })
            });
            let mut connected = true;
            let observed = (|| {
                while !worker.is_finished() {
                    if Instant::now() >= deadline {
                        stop.store(true, Ordering::Release);
                    }
                    if connected && reviews.try_recv().is_ok() {
                        response(
                            &mut channel,
                            &manifest,
                            Event::Requirements {
                                outcome: prerequisites::Outcome::EnableRequired,
                            },
                        )?;
                        let raw = frame::read(&mut channel, 1..=LIMIT)
                            .map_err(|_| Error("invalid_setup_approval"))?;
                        channel.authenticate_setup(&owner)?;
                        approve
                            .send(decode::<Approval>(&raw)?.enable_hyperv)
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
            Ok(event) => response(&mut channel, &manifest, event),
            Err(error) => {
                response(
                    &mut channel,
                    &manifest,
                    Event::Failed {
                        code: error.0.into(),
                    },
                )?;
                Err(error)
            }
        }
    }

    fn response(channel: &mut Channel, manifest: &str, event: Event) -> Result<()> {
        send(
            channel,
            &Response {
                version: 1,
                manifest_sha256: manifest.into(),
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
        use super::{LIMIT, Request, send};
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
                    bytes: 17179869184,
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
pub use native::{install, service};

#[cfg(test)]
mod tests {
    use super::{Approval, Event, LIMIT, Request, Response, decode};
    use serde_json::json;

    #[test]
    fn setup_request_cannot_supply_an_owner_or_a_privileged_path() {
        let value = json!({"version":1,"source_sha256":"a".repeat(64),"manifest_sha256":"b".repeat(64),"bytes":17179869184_u64});
        Request::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        for (field, invalid) in [
            ("owner", json!("S-1-5-21-1-2-3-1001")),
            ("root", json!(r"C:\Foreign")),
            ("bytes", json!(1)),
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
        let installed = json!({"version":1,"manifest_sha256":manifest,"event":{"kind":"installed","runtime_id":"1".repeat(32)}});
        let response =
            Response::decode(&serde_json::to_vec(&installed).unwrap(), &manifest).unwrap();
        assert!(matches!(response.event, Event::Installed { .. }));
        for invalid in [
            json!({"version":1,"manifest_sha256":"c".repeat(64),"event":{"kind":"installed","runtime_id":"1".repeat(32)}}),
            json!({"version":1,"manifest_sha256":manifest,"event":{"kind":"installed","runtime_id":"0".repeat(32)}}),
            json!({"version":1,"manifest_sha256":manifest,"event":{"kind":"requirements","outcome":{"kind":"ready"}}}),
            json!({"version":1,"manifest_sha256":manifest,"event":{"kind":"failed","code":"PRIVATE\nCANARY"}}),
            json!({"version":1,"manifest_sha256":manifest,"event":{"kind":"installed","runtime_id":"1".repeat(32),"launcher":r"C:\Foreign\program.exe"}}),
        ] {
            assert!(Response::decode(&serde_json::to_vec(&invalid).unwrap(), &manifest).is_err());
        }
    }
}
