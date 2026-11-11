use crate::{Result, config::RuntimeConfig, lifetime::Lifetime};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "media_sidecar.rs"]
mod media_sidecar;

pub fn run(config: RuntimeConfig, lifetime: Lifetime) -> Result<()> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux::run(config, lifetime)
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (config, lifetime);
        Err(crate::Error("linux_x86_64_or_aarch64_required"))
    }
}

pub fn report(event: &str) {
    eprintln!("{}", serde_json::json!({"event":event}));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::media_sidecar::Sidecar;
    use crate::{
        Error, Result, auth, bridge, config::RuntimeConfig, kvm, lifetime::Lifetime, media,
        private, qemu,
    };
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    static SIGNAL: AtomicI32 = AtomicI32::new(0);
    extern "C" fn signal(value: i32) {
        SIGNAL.store(value, Ordering::Relaxed);
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                unsafe {
                    libc::kill(-(self.0.id() as i32), libc::SIGKILL);
                }
                let _ = self.0.wait();
            }
        }
    }

    struct QmpPath(std::path::PathBuf);
    impl Drop for QmpPath {
        fn drop(&mut self) {
            if fs::symlink_metadata(&self.0).is_ok_and(|info| {
                info.file_type().is_socket() && info.uid() == unsafe { libc::getuid() }
            }) {
                let _ = fs::remove_file(&self.0);
            }
        }
    }

    struct Signals(Vec<(i32, libc::sighandler_t)>);
    impl Signals {
        fn install() -> Self {
            SIGNAL.store(0, Ordering::Relaxed);
            Self(
                [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGPIPE]
                    .into_iter()
                    .map(|number| {
                        let handler = if number == libc::SIGPIPE {
                            libc::SIG_IGN
                        } else {
                            signal as *const () as libc::sighandler_t
                        };
                        (number, unsafe { libc::signal(number, handler) })
                    })
                    .collect(),
            )
        }
    }
    impl Drop for Signals {
        fn drop(&mut self) {
            for (number, handler) in &self.0 {
                unsafe {
                    libc::signal(*number, *handler);
                }
            }
        }
    }

    pub fn run(config: RuntimeConfig, lifetime: Lifetime) -> Result<()> {
        lifetime.check()?;
        config.validate()?;
        let capabilities = kvm::capabilities();
        if !capabilities.supported {
            return Err(Error(
                capabilities.reason.unwrap_or("virtualization_unavailable"),
            ));
        }
        let mut endpoint = private::Endpoint::bind(&config.control_socket)?;
        let _disk = config.disk_lease()?;
        let mut media = Sidecar::bind(&config)?;
        let qmp_path = private::sidecar(&config.control_socket, ".qmp");
        let auth_path = private::sidecar(&config.control_socket, ".auth");
        for path in [&qmp_path, &auth_path] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error("runtime_socket_recovery_required")),
            }
        }
        let _qmp_path = QmpPath(qmp_path.clone());
        let _auth_path = QmpPath(auth_path.clone());
        let _signals = Signals::install();
        let mut command = Command::new(kvm::qemu().ok_or(Error("qemu_system_required"))?);
        let mut arguments = qemu::arguments(&config)?;
        if media.is_some() {
            media::reserve_port(&mut arguments);
        }
        command
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(if config.serial_stdio {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::getppid() != parent
                    || libc::setpgid(0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        lifetime.check()?;
        let mut child = ChildGuard(command.spawn().map_err(|_| Error("runtime_start_failed"))?);
        if let Some(mut destination) = child.0.stdin.take() {
            std::thread::spawn(move || {
                let mut bytes = zeroize::Zeroizing::new(vec![0; 4096]);
                loop {
                    match std::io::stdin().read(&mut bytes) {
                        Ok(0) | Err(_) => return,
                        Ok(length) if destination.write_all(&bytes[..length]).is_err() => return,
                        Ok(_) => {}
                    }
                }
            });
        }
        let mut console = child
            .0
            .stdout
            .take()
            .ok_or(Error("runtime_console_failed"))?;
        let failure = Arc::new(AtomicU8::new(0));
        let console_failure = failure.clone();
        let console_thread = std::thread::spawn(move || {
            let mut guard = qemu::SerialGuard::default();
            let mut bytes = zeroize::Zeroizing::new(vec![0; 4096]);
            loop {
                match console.read(&mut bytes) {
                    Ok(0) => return,
                    Ok(length) => {
                        if config.serial_stdio {
                            let _ = std::io::stdout().write_all(&bytes[..length]);
                        }
                        if let Some(event) = guard.observe(&bytes[..length]) {
                            console_failure.store(
                                if event == "runtime_kernel_panic" {
                                    1
                                } else {
                                    2
                                },
                                Ordering::Release,
                            );
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        console_failure.store(3, Ordering::Release);
                        return;
                    }
                }
            }
        });
        let mut qmp = qemu::Qmp::connect(&qmp_path, Instant::now() + Duration::from_secs(10))?;
        lifetime.check()?;
        let mut provisioning =
            qemu::connect_private(&auth_path, Instant::now() + Duration::from_secs(10))?;
        lifetime.check()?;
        qmp.command("cont", Instant::now() + Duration::from_secs(5))?;
        let stop = Arc::new(AtomicBool::new(false));
        let token = Arc::new(auth::token()?);
        let (sender, ready) = std::sync::mpsc::sync_channel(1);
        let provisioning_token = token.clone();
        let provisioning_cancelled = stop.clone();
        let provisioner = std::thread::spawn(move || {
            let result = auth::provision(
                &mut provisioning,
                &provisioning_token,
                &provisioning_cancelled,
                Instant::now() + Duration::from_secs(120),
            );
            let _ = sender.send(result);
        });
        let mut authenticated = false;
        let mut bridges: Vec<JoinHandle<()>> = Vec::new();
        let mut stopping = None;
        let mut qmp_closed = false;
        let result = (|| {
            loop {
                lifetime.check()?;
                let fatal = failure.load(Ordering::Acquire);
                if fatal != 0 {
                    return Err(Error(match fatal {
                        1 => "runtime_kernel_panic",
                        2 => "runtime_kernel_memory_failure",
                        4 => "runtime_control_authentication_failed",
                        _ => "runtime_console_failed",
                    }));
                }
                if let Some(status) = child
                    .0
                    .try_wait()
                    .map_err(|_| Error("runtime_wait_failed"))?
                {
                    return if status.success() && (authenticated || stopping.is_some()) {
                        Ok(())
                    } else if !authenticated {
                        Err(Error("runtime_auth_provision_failed"))
                    } else {
                        Err(Error("runtime_failed"))
                    };
                }
                if SIGNAL.swap(0, Ordering::Relaxed) != 0 && stopping.is_none() {
                    endpoint.stop_admission();
                    if let Some(media) = &mut media {
                        media.stop_admission();
                    }
                    stop.store(true, Ordering::Relaxed);
                    super::report("runtime_stopping");
                    qmp.command("system_powerdown", Instant::now() + Duration::from_secs(5))?;
                    stopping = Some(Instant::now() + Duration::from_secs(45));
                }
                if stopping.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(Error("runtime_shutdown_timeout"));
                }
                if !authenticated && stopping.is_none() {
                    match ready.try_recv() {
                        Ok(Ok(())) => {
                            authenticated = true;
                            super::report("runtime_started");
                        }
                        Ok(Err(error)) => return Err(error),
                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            return Err(Error("runtime_auth_provision_failed"));
                        }
                    }
                }
                while !qmp_closed {
                    let event = match qmp.next() {
                        Ok(Some(event)) => event,
                        Ok(None) => break,
                        Err(Error("qmp_disconnected")) if stopping.is_some() => {
                            qmp_closed = true;
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    if event.get("event").and_then(serde_json::Value::as_str) == Some("SHUTDOWN") {
                        endpoint.stop_admission();
                        if let Some(media) = &mut media {
                            media.stop_admission();
                        }
                        stop.store(true, Ordering::Relaxed);
                        stopping.get_or_insert_with(|| Instant::now() + Duration::from_secs(45));
                    }
                    if qmp.owns_media_error(&event) {
                        if let Some(media) = &media {
                            media.cancel_current();
                            continue;
                        }
                    }
                    if stopping.is_none()
                        && matches!(
                            event.get("event").and_then(serde_json::Value::as_str),
                            Some("STOP" | "BLOCK_IO_ERROR" | "GUEST_PANICKED")
                        )
                    {
                        return Err(Error("runtime_guest_failed"));
                    }
                }
                if let Some(media) = &mut media {
                    media.tick(
                        &config,
                        &token,
                        &mut qmp,
                        authenticated && stopping.is_none(),
                    )?;
                }
                let mut index = 0;
                while index < bridges.len() {
                    if bridges[index].is_finished() {
                        let _ = bridges.swap_remove(index).join();
                    } else {
                        index += 1;
                    }
                }
                while stopping.is_none() && authenticated {
                    lifetime.check()?;
                    let local = match endpoint.accept() {
                        Ok(Some(stream)) => stream,
                        Ok(None) => break,
                        Err(Error("untrusted_control_peer")) => continue,
                        Err(error) => return Err(error),
                    };
                    if bridges.len() >= 64 {
                        drop(local);
                        continue;
                    }
                    let cancelled = stop.clone();
                    let cid = config.guest_cid;
                    let port = config.control_port;
                    let secret = token.clone();
                    let authentication_failure = failure.clone();
                    bridges.push(std::thread::spawn(move || {
                        if let Ok(mut guest) = bridge::connect_guest(cid, port) {
                            match auth::authenticate(&mut guest, &secret, &cancelled) {
                                Ok(()) => {
                                    let _ = bridge::duplex(local, guest, cancelled);
                                }
                                Err(Error("runtime_control_authentication_failed")) => {
                                    authentication_failure.store(4, Ordering::Release)
                                }
                                Err(_) => {}
                            }
                        }
                    }));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        endpoint.stop_admission();
        stop.store(true, Ordering::Relaxed);
        drop(child);
        drop(qmp);
        let media_cleanup = media.map_or(Ok(()), Sidecar::finish);
        let _ = provisioner.join();
        let _ = console_thread.join();
        for bridge in bridges {
            let _ = bridge.join();
        }
        match failure.load(Ordering::Acquire) {
            1 => return Err(Error("runtime_kernel_panic")),
            2 => return Err(Error("runtime_kernel_memory_failure")),
            4 => return Err(Error("runtime_control_authentication_failed")),
            _ => {}
        }
        result.and(media_cleanup)
    }
}
