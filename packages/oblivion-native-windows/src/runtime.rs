//! HCS owns the outer controller, while the supervisor owns this helper's
//! lifetime. Only a provisioned VM receives local control connections.
use crate::config::{self, RuntimeConfig};
use crate::hcs::{Machine, State};
use crate::lifetime::Lifetime;
use crate::private::{Endpoint, Purpose};
use crate::security::Identity;
use crate::{Error, Result, auth, bridge, files, hcs, private};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::core::GUID;
use zeroize::Zeroizing;

pub fn main() -> Result<()> {
    // This process has no UI. Host-wide paging/dump policy remains an OS trust
    // boundary; suppressing error dialogs does not claim to disable host dumps.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
    if !cfg!(target_arch = "x86_64") {
        return Err(Error("windows_x86_64_required"));
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "capabilities" {
        let observation = hcs::capabilities();
        // Availability of the helper core is distinct from installed product
        // support: HNS, the Windows frontend and its installer are not wired yet.
        let document = match observation {
            Ok(capabilities) => serde_json::json!({
                "backend":"hcs-hyperv", "experimental":true, "supported":false,
                "backend_available":available(&capabilities),
                "nested_virtualization":capabilities.nested_virtualization,
                "schemas":capabilities.schemas, "reason":"windows_integration_incomplete",
            }),
            Err(error) => serde_json::json!({
                "backend":"hcs-hyperv", "experimental":true, "supported":false,
                "backend_available":false, "reason":error.0,
            }),
        };
        println!("{document}");
        return Ok(());
    }
    let [operation, option, path] = args.as_slice() else {
        return Err(Error("invalid_arguments"));
    };
    if operation != "run" || option != "--config" {
        return Err(Error("invalid_arguments"));
    }
    let lifetime = Lifetime::inherited()?;
    let identity = Identity::current()?;
    let config = files::read_config(
        path.to_str().ok_or(Error("invalid_runtime_config_path"))?,
        &identity,
    )?;
    run(config, lifetime, identity)?;
    report("runtime_stopped");
    Ok(())
}

pub fn run(config: RuntimeConfig, lifetime: Lifetime, identity: Identity) -> Result<()> {
    lifetime.check()?;
    config.validate()?;
    if !available(&hcs::capabilities()?) {
        return Err(Error("hcs_nested_virtualization_required"));
    }
    let mut leases = files::Lease::acquire(&config, &identity)?;
    let mut endpoint = Endpoint::bind(&config.control_pipe, Purpose::Control)?;
    let mut suffix = Zeroizing::new([0; 16]);
    getrandom::getrandom(suffix.as_mut_slice())
        .map_err(|_| Error("runtime_entropy_unavailable"))?;
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let bootstrap_name = format!(r"\\.\pipe\oblivion.{}.auth.{suffix}", config.runtime_id);
    // HCS connects a serial port during VM construction; its private server
    // therefore has to exist first, not after the guest has booted.
    let bootstrap = Endpoint::bind(&bootstrap_name, Purpose::Bootstrap)?;
    let configuration = config.hcs(&bootstrap_name, &identity.sddl())?;
    lifetime.check()?;
    leases.grant_vm_access(&config.vm_id())?;
    let mut stopped = false;
    let result = serve(
        &config,
        &configuration,
        lifetime,
        &mut endpoint,
        bootstrap,
        &mut stopped,
    );
    if !stopped {
        // Closing the last HCS handle requests termination, but does not prove
        // completion. Keep paths and grants pinned until this one-shot process
        // exits; explicit Windows recovery must reconcile the retained grants.
        leases.retain_until_exit();
        if let Err(error) = result {
            report(error.0);
        }
        return Err(Error("runtime_shutdown_unconfirmed"));
    }
    // A grant is scoped to this invocation's validated assets, not retained as
    // an installation-wide permission. Failure remains a cleanup error.
    let revoked = leases.revoke_vm_access();
    revoked.and(result)
}

fn serve(
    config: &RuntimeConfig,
    configuration: &str,
    lifetime: Lifetime,
    endpoint: &mut Endpoint,
    mut bootstrap: Endpoint,
    confirmed_stop: &mut bool,
) -> Result<()> {
    let token = Arc::new(auth::token()?);
    let machine = Machine::create(
        &config.vm_id(),
        configuration,
        Instant::now() + Duration::from_secs(30),
        &|| lifetime.check(),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let failed_auth = Arc::new(AtomicBool::new(false));
    let mut provisioner: Option<JoinHandle<Result<()>>> = None;
    let mut bridges: Vec<JoinHandle<()>> = Vec::new();
    let mut observed_stopped = false;
    let result = (|| {
        lifetime.check()?;
        let (sender, ready) = std::sync::mpsc::sync_channel(1);
        let cancelled = Arc::clone(&stop);
        let secret = Arc::clone(&token);
        provisioner = Some(
            std::thread::Builder::new()
                .name("runtime-bootstrap".into())
                .spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(120);
                    let result = (|| {
                        let mut stream = bootstrap
                            .accept(&cancelled, deadline)?
                            .ok_or(Error("runtime_auth_timeout"))?;
                        auth::provision(&mut stream, &secret, &cancelled, deadline)?;
                        stream
                            .close()
                            .map_err(|_| Error("private_pipe_cancellation_failed"))
                    })();
                    let _ = sender.send(result);
                    result
                })
                .map_err(|_| Error("runtime_worker_start_failed"))?,
        );
        machine.start(Instant::now() + Duration::from_secs(30), &|| {
            lifetime.check()
        })?;
        lifetime.check()?;
        let mut authenticated = false;
        let mut runtime_id: Option<GUID> = None;
        let mut next_observation = Instant::now();
        loop {
            lifetime.check()?;
            if private::drain_failed() {
                return Err(Error("private_pipe_cancellation_failed"));
            }
            if failed_auth.load(Ordering::Acquire) {
                return Err(Error("runtime_control_authentication_failed"));
            }
            if Instant::now() >= next_observation {
                let status = machine.state(Instant::now() + Duration::from_secs(2), &|| {
                    lifetime.check()
                })?;
                next_observation = Instant::now() + Duration::from_secs(1);
                match status.state {
                    State::Running => {
                        let current = status.runtime_id.ok_or(Error("hcs_runtime_id_missing"))?;
                        if runtime_id.is_some_and(|previous| {
                            previous.data1 != current.data1
                                || previous.data2 != current.data2
                                || previous.data3 != current.data3
                                || previous.data4 != current.data4
                        }) {
                            return Err(Error("hcs_runtime_identity_changed"));
                        }
                        runtime_id = Some(current);
                    }
                    State::Stopped => {
                        observed_stopped = true;
                        *confirmed_stop = true;
                        return if authenticated {
                            Ok(())
                        } else {
                            Err(Error("runtime_auth_provision_failed"))
                        };
                    }
                    _ => return Err(Error("runtime_guest_not_running")),
                }
            }
            if !authenticated {
                match ready.try_recv() {
                    Ok(Ok(())) => {
                        authenticated = true;
                        report("runtime_started");
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err(Error("runtime_auth_provision_failed"));
                    }
                }
            }
            let mut index = 0;
            while index < bridges.len() {
                if bridges[index].is_finished() {
                    bridges
                        .swap_remove(index)
                        .join()
                        .map_err(|_| Error("runtime_worker_failed"))?;
                    continue;
                }
                index += 1;
            }
            if !authenticated || bridges.len() >= 64 {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let local = match endpoint.accept(&stop, Instant::now() + Duration::from_millis(100)) {
                Ok(Some(local)) => local,
                Ok(None) | Err(Error("untrusted_private_pipe_peer")) => continue,
                Err(error) => return Err(error),
            };
            lifetime.check()?;
            let vm = runtime_id.ok_or(Error("hcs_runtime_id_missing"))?;
            let cancelled = Arc::clone(&stop);
            let secret = Arc::clone(&token);
            let failure = Arc::clone(&failed_auth);
            bridges.push(
                std::thread::Builder::new()
                    .name("runtime-control".into())
                    .spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(3);
                        if let Ok(mut guest) =
                            bridge::connect_guest(&vm, config::CONTROL_PORT, &cancelled, deadline)
                        {
                            match auth::authenticate(&mut guest, &secret, &cancelled, deadline) {
                                Ok(()) => {
                                    let _ = bridge::duplex(local, guest, cancelled);
                                }
                                Err(Error("runtime_control_authentication_failed")) => {
                                    failure.store(true, Ordering::Release)
                                }
                                Err(_) => {}
                            }
                        }
                    })
                    .map_err(|_| Error("runtime_worker_start_failed"))?,
            );
        }
    })();
    stop.store(true, Ordering::Release);
    let admission = endpoint.stop_admission();
    // S_OK from terminate is not evidence that memory or disk ownership ended.
    // Keep the owning HCS handle and leases until an actual Stopped observation.
    let stopped = if observed_stopped {
        Ok(())
    } else {
        terminate(&machine)
    };
    if stopped.is_ok() {
        *confirmed_stop = true;
    }
    let workers = finish_workers(provisioner, bridges);
    if private::drain_failed() {
        return Err(Error("private_pipe_cancellation_failed"));
    }
    stopped.and(admission).and(workers).and(result)
}

fn available(capabilities: &hcs::Capabilities) -> bool {
    capabilities.nested_virtualization
        && capabilities
            .schemas
            .iter()
            .any(|schema| schema.major == 2 && schema.minor >= 2)
}

fn terminate(machine: &Machine) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    // An AlreadyStopped response can race a normal guest shutdown. Observe the
    // actual state even if the termination request failed; never infer it.
    let requested = machine.terminate(Instant::now() + Duration::from_secs(5), &|| Ok(()));
    loop {
        if Instant::now() >= deadline {
            return requested.and(Err(Error("runtime_shutdown_unconfirmed")));
        }
        if machine.state(deadline, &|| Ok(()))?.state == State::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn finish_workers(
    provisioner: Option<JoinHandle<Result<()>>>,
    mut bridges: Vec<JoinHandle<()>>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(6);
    while provisioner
        .as_ref()
        .is_some_and(|worker| !worker.is_finished())
        || bridges.iter().any(|worker| !worker.is_finished())
    {
        if Instant::now() >= deadline {
            // Do not hang joining an unconfirmed kernel operation. Returning an
            // error exits this one-shot helper; it must never serve again.
            return Err(Error("runtime_worker_cleanup_unconfirmed"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if let Some(worker) = provisioner {
        // Cancellation after an already failed/startup VM is expected. Panic is
        // distinct: it leaves the worker's cleanup outcome unconfirmed.
        let _ = worker.join().map_err(|_| Error("runtime_worker_failed"))?;
    }
    for worker in bridges.drain(..) {
        worker.join().map_err(|_| Error("runtime_worker_failed"))?;
    }
    Ok(())
}

fn report(event: &'static str) {
    eprintln!("{}", serde_json::json!({"event":event}));
}
