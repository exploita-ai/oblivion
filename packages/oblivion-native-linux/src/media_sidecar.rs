//! The outer Live runtime owns the controller reservation and both phases of
//! physical media cleanup. The caller only gets the transfer byte stream.
use crate::{
    Error, Result, auth, bridge, config::RuntimeConfig, live_media, media::MediaStatus, private,
    qemu::Qmp,
};
use oblivion_wire::{
    control::{HEADER_LIMIT, NATIVE_VERSION, Operation, Request, Response, valid_id},
    control_client::{self, Framing},
    frame,
    live_media::{
        DETACHED, Direction, REVOKED, Reserve, STOP, Source, detach_proof, valid_device_id,
    },
    runtime_auth::Token,
    slot::Slot,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{Receiver, Sender},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const STARTUP: Duration = Duration::from_secs(120);
const CLEANUP: Duration = Duration::from_secs(60);
const QMP_BUDGET: Duration = Duration::from_secs(8);

pub(super) struct Sidecar {
    endpoint: private::Endpoint,
    job: Option<Job>,
}

struct Job {
    requests: Receiver<QmpRequest>,
    worker: JoinHandle<()>,
    cancelled: Arc<AtomicBool>,
    ending: Arc<AtomicBool>,
}

enum QmpRequest {
    Attach {
        device: File,
        direction: Direction,
        serial: String,
        local: UnixStream,
        reserve: UnixStream,
        deadline: Instant,
        reply: Sender<Result<()>>,
    },
    Detach(Sender<Result<()>>),
}

impl Sidecar {
    pub(super) fn bind(config: &RuntimeConfig) -> Result<Option<Self>> {
        let mut live = config
            .command_line
            .split_whitespace()
            .filter(|argument| argument.starts_with("oblivion.runtime-live="));
        if live.next() != Some("oblivion.runtime-live=1") || live.next().is_some() {
            return Ok(None);
        }
        require_live_launcher()?;
        Ok(Some(Self {
            endpoint: private::Endpoint::bind(&private::sidecar(&config.control_socket, ".media"))?,
            job: None,
        }))
    }

    pub(super) fn stop_admission(&mut self) {
        self.endpoint.stop_admission();
        self.cancel_current();
    }

    pub(super) fn cancel_current(&self) {
        if let Some(job) = &self.job {
            job.cancelled.store(true, Ordering::Release);
        }
    }

    pub(super) fn tick(
        &mut self,
        config: &RuntimeConfig,
        token: &Arc<Token>,
        qmp: &mut Qmp,
        admit: bool,
    ) -> Result<()> {
        if let Some(job) = &self.job {
            if let Ok(request) = job.requests.try_recv() {
                match request {
                    QmpRequest::Attach {
                        device,
                        direction,
                        serial,
                        local,
                        reserve,
                        deadline,
                        reply,
                    } => {
                        let result = check_stop(&job.cancelled)
                            .and_then(|_| quiet(&local))
                            .and_then(|_| quiet(&reserve))
                            .and_then(|_| {
                                qmp.attach_media(
                                    device,
                                    direction,
                                    &serial,
                                    deadline.min(Instant::now() + QMP_BUDGET),
                                )
                            });
                        let _ = reply.send(result);
                    }
                    QmpRequest::Detach(reply) => {
                        let _ = reply.send(qmp.detach_media(Instant::now() + QMP_BUDGET));
                    }
                }
            }
            if !job.worker.is_finished() {
                return Ok(());
            }
            if let Some(finished) = self.job.take() {
                let _ = finished.worker.join();
            }
        }
        if !admit {
            return Ok(());
        }
        let local = match self.endpoint.accept() {
            Ok(Some(local)) => local,
            Ok(None) | Err(Error("untrusted_control_peer")) => return Ok(()),
            Err(error) => return Err(error),
        };
        let (send, requests) = std::sync::mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let ending = Arc::new(AtomicBool::new(false));
        let context = Worker {
            cid: config.guest_cid,
            port: config.control_port,
            token: token.clone(),
            cancelled: cancelled.clone(),
            ending: ending.clone(),
            qmp: send,
        };
        let available = qmp.media_status() == MediaStatus::Empty;
        let worker = thread::spawn(move || context.serve(local, available));
        self.job = Some(Job {
            requests,
            worker,
            cancelled,
            ending,
        });
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<()> {
        self.stop_admission();
        if let Some(job) = self.job.take() {
            job.ending.store(true, Ordering::Release);
            drop(job.requests);
            // The controller has already exited. A stuck host device open
            // can still delay sudo's reap, so it cannot delay runtime exit.
            let deadline = Instant::now() + Duration::from_secs(2);
            while !job.worker.is_finished() {
                if Instant::now() >= deadline {
                    return Err(Error("live_media_broker_cleanup_required"));
                }
                thread::sleep(Duration::from_millis(20));
            }
            let _ = job.worker.join();
        }
        Ok(())
    }
}

fn require_live_launcher() -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/etc/oblivion/installation.json")
        .map_err(|_| Error("live_media_unavailable"))?;
    let info = file
        .metadata()
        .map_err(|_| Error("live_media_unavailable"))?;
    if unsafe { libc::getuid() } != 1000
        || unsafe { libc::geteuid() } != 1000
        || !info.is_file()
        || info.uid() != 0
        || info.mode() & 0o022 != 0
        || info.nlink() != 1
        || info.len() > 1024
    {
        return Err(Error("live_media_unavailable"));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Profile {
        version: u8,
        mode: String,
    }
    let mut bytes = Vec::new();
    file.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("live_media_unavailable"))?;
    let profile: Profile =
        serde_json::from_slice(&bytes).map_err(|_| Error("live_media_unavailable"))?;
    if bytes.len() > 1024 || profile.version != 1 || profile.mode != "live-launcher" {
        return Err(Error("live_media_unavailable"));
    }
    Ok(())
}

struct Worker {
    cid: u32,
    port: u32,
    token: Arc<Token>,
    cancelled: Arc<AtomicBool>,
    ending: Arc<AtomicBool>,
    qmp: Sender<QmpRequest>,
}

impl Worker {
    fn serve(self, local: UnixStream, available: bool) {
        let deadline = Instant::now() + STARTUP;
        if local.set_nonblocking(true).is_err() {
            return;
        }
        let check = || check_stop(&self.cancelled);
        let result = read_selection(&mut SocketIo::new(
            &local,
            Instant::now() + Duration::from_secs(5),
            &check,
        ))
        .and_then(|selection| {
            if !available {
                return Err(Error("qmp_media_ownership_uncertain"));
            }
            self.transfer(&local, selection, deadline)
        });
        if let Err(error) = result {
            let _ = reply(&local, Err(error), &|| check_stop(&self.ending));
        }
    }

    fn transfer(
        &self,
        local: &UnixStream,
        selection: Reserve<Slot>,
        deadline: Instant,
    ) -> Result<()> {
        // This capability stays between the native runtime and its local
        // caller. The guest controls raw source bytes and cannot attest eject.
        let nonce = detach_nonce()?;
        let proof = detach_proof(&nonce).ok_or(Error("invalid_live_media_detach_nonce"))?;
        let check_local = || check_stop(&self.cancelled).and_then(|_| quiet(local));
        let (reserve, id) = self.controller(
            Operation::LiveMediaReserve,
            &selection.opening.safe_id,
            selection.opening.slot,
            &selection,
            deadline,
            &check_local,
        )?;
        let check = || check_local().and_then(|_| quiet(&reserve));
        let mut attached = false;
        let mut flush = None;
        let source = (|| {
            let device = broker(selection.direction, &selection.device_id, deadline, &check)?;
            if selection.direction == Direction::Export {
                flush = Some(
                    device
                        .try_clone()
                        .map_err(|_| Error("live_media_descriptor_unavailable"))?,
                );
            }
            check()?;
            let (send, receipt) = std::sync::mpsc::channel();
            self.qmp
                .send(QmpRequest::Attach {
                    device,
                    direction: selection.direction,
                    serial: format!("obl-{}", &id[..16]),
                    local: local
                        .try_clone()
                        .map_err(|_| Error("live_media_socket_failed"))?,
                    reserve: reserve
                        .try_clone()
                        .map_err(|_| Error("live_media_socket_failed"))?,
                    deadline,
                    reply: send,
                })
                .map_err(|_| Error("live_media_runtime_stopped"))?;
            receipt
                .recv()
                .map_err(|_| Error("live_media_runtime_stopped"))??;
            attached = true;
            let source = Source {
                lease_id: id.clone(),
                opening: selection.opening,
                device_id: selection.device_id,
                direction: selection.direction,
                purpose: selection.purpose,
            };
            let (connection, acknowledged) = self.controller(
                Operation::LiveMediaAttach,
                &source.opening.safe_id,
                source.opening.slot,
                &source,
                deadline,
                &check,
            )?;
            if acknowledged != id {
                return Err(Error("invalid_live_media_reservation"));
            }
            check()?;
            Ok(connection)
        })();

        // Once acknowledged, the caller's connection belongs to the raw source
        // protocol. Never write a control error frame into it.
        let ready = match source {
            Ok(source) => match reply(local, Ok(&nonce), &check) {
                Ok(()) => {
                    let _ = bridge::media_source(local, source, &reserve, &self.cancelled);
                    Ok(())
                }
                Err(_) => {
                    // A partly written success frame cannot be replaced.
                    let _ = local.shutdown(Shutdown::Both);
                    Ok(())
                }
            },
            Err(error) => Err(error),
        };
        let stopped = stop_controller(&reserve, &self.ending);
        let detached = if attached {
            stopped.and_then(|()| {
                // The controller has stopped its writer and removed its map.
                // Flush the same pinned block device on this worker, not QMP's
                // event loop. Failure leaves the outer attachment fenced.
                if let Some(file) = flush {
                    file.sync_all()
                        .map_err(|_| Error("live_media_flush_unconfirmed"))?;
                }
                let (send, receipt) = std::sync::mpsc::channel();
                self.qmp
                    .send(QmpRequest::Detach(send))
                    .map_err(|_| Error("live_media_runtime_stopped"))?;
                receipt
                    .recv()
                    .map_err(|_| Error("live_media_runtime_stopped"))?
            })
        } else {
            stopped
        };
        if ready.is_err() && detached.is_err() && attached {
            return detached;
        }
        if ready.is_ok() && detached.is_ok() {
            let _ = SocketIo::new(local, Instant::now() + Duration::from_secs(2), &|| {
                check_stop(&self.ending)
            })
            .write_all(&proof);
        }
        ready
    }

    fn controller(
        &self,
        operation: Operation,
        safe: &str,
        slot: Slot,
        body: &impl Serialize,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<(UnixStream, String)> {
        check()?;
        let mut peer = bridge::connect_guest(self.cid, self.port)?;
        auth::authenticate(&mut peer, &self.token, &self.cancelled)?;
        let body = Zeroizing::new(
            serde_json::to_vec(body).map_err(|_| Error("invalid_live_media_request"))?,
        );
        let mut channel = SocketIo::new(&peer, deadline, check);
        control_client::write_request(
            &mut channel,
            &Request {
                operation,
                expected_session: Some(safe.to_owned()),
                session: None,
                secret_len: body.len() as u32,
                slot,
            },
            &body,
            Framing::Native,
        )
        .map_err(|_| Error("live_media_controller_unavailable"))?;
        let id = control_client::read_response(&mut channel, Framing::Native)
            .map_err(|_| Error("live_media_controller_rejected"))?;
        if !valid_id(&id) {
            return Err(Error("invalid_live_media_reservation"));
        }
        Ok((peer, id))
    }
}

fn detach_nonce() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| Error("runtime_entropy_unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn read_selection(reader: &mut impl Read) -> Result<Reserve<Slot>> {
    #[derive(Deserialize)]
    struct Header {
        version: u8,
        #[serde(flatten)]
        request: Request<Slot>,
    }
    let header =
        frame::read(reader, 1..=HEADER_LIMIT).map_err(|_| Error("invalid_live_media_request"))?;
    let header: Header =
        serde_json::from_slice(&header).map_err(|_| Error("invalid_live_media_request"))?;
    let request = header.request;
    if header.version != NATIVE_VERSION
        || request.operation != Operation::LiveMediaReserve
        || request.session.is_some()
        || !(1..=1024).contains(&request.secret_len)
    {
        return Err(Error("invalid_live_media_request"));
    }
    let mut body = Zeroizing::new(vec![0; request.secret_len as usize]);
    reader
        .read_exact(&mut body)
        .map_err(|_| Error("invalid_live_media_request"))?;
    let selected: Reserve<Slot> =
        serde_json::from_slice(&body).map_err(|_| Error("invalid_live_media_request"))?;
    if request.slot != selected.opening.slot
        || request.expected_session.as_deref() != Some(&selected.opening.safe_id)
        || !valid_id(&selected.opening.safe_id)
        || !valid_id(&selected.opening.nonce)
        || !valid_device_id(&selected.device_id)
        || !selected.purpose.valid_for(selected.direction)
    {
        return Err(Error("invalid_live_media_request"));
    }
    Ok(selected)
}

fn reply(peer: &UnixStream, result: Result<&str>, check: &dyn Fn() -> Result<()>) -> Result<()> {
    let response = match result {
        Ok(id) => Response {
            ok: true,
            output: id,
            error: None,
        },
        Err(error) => Response {
            ok: false,
            output: "",
            error: Some(error.0),
        },
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| Error("live_media_socket_failed"))?;
    frame::write(
        &mut SocketIo::new(peer, Instant::now() + Duration::from_secs(2), check),
        &bytes,
        1..=1024,
    )
    .map_err(|_| Error("live_media_socket_failed"))
}

fn stop_controller(reserve: &UnixStream, ending: &AtomicBool) -> Result<()> {
    let check = || check_stop(ending);
    let mut io = SocketIo::new(reserve, Instant::now() + CLEANUP, &check);
    let failed = |_| Error("live_media_controller_cleanup_unconfirmed");
    io.write_all(&[STOP]).map_err(failed)?;
    let mut first = [0; 1];
    io.read_exact(&mut first).map_err(failed)?;
    if first[0] == REVOKED[0] {
        let mut revoked = [0; REVOKED.len() - 1];
        io.read_exact(&mut revoked).map_err(failed)?;
        if revoked != REVOKED[1..] {
            return Err(Error("live_media_controller_cleanup_unconfirmed"));
        }
        io.read_exact(&mut first).map_err(failed)?;
    }
    let mut rest = [0; DETACHED.len() - 1];
    io.read_exact(&mut rest).map_err(failed)?;
    if first[0] != DETACHED[0] || rest != DETACHED[1..] {
        return Err(Error("live_media_controller_cleanup_unconfirmed"));
    }
    Ok(())
}

fn check_stop(stop: &AtomicBool) -> Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(Error("live_media_cancelled"));
    }
    Ok(())
}

fn quiet(peer: &UnixStream) -> Result<()> {
    let mut byte = 0u8;
    loop {
        let count = unsafe {
            libc::recv(
                peer.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_DONTWAIT | libc::MSG_PEEK,
            )
        };
        if count < 0 {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock => return Ok(()),
                io::ErrorKind::Interrupted => continue,
                _ => {}
            }
        }
        return Err(Error("live_media_peer_lost"));
    }
}

fn broker(
    direction: Direction,
    id: &str,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<File> {
    let (socket, child_socket) =
        UnixStream::pair().map_err(|_| Error("live_media_socket_failed"))?;
    let mut command = Command::new("/usr/bin/sudo");
    let access = match direction {
        Direction::Import => "import",
        Direction::Export => "export",
    };
    command
        .args([
            "-n",
            "--",
            "/usr/lib/oblivion/live-media.py",
            "lease",
            access,
            id,
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(child_socket)))
        .stderr(Stdio::null());
    // No controlling TTY for sudo's use_pty policy. The broker's stdout
    // must remain the connected Unix socket used for SCM_RIGHTS.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    check()?;
    let mut broker = Broker {
        child: command
            .spawn()
            .map_err(|_| Error("live_media_broker_failed"))?,
        socket,
    };
    drop(command);
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    let channel = SocketIo::new(&broker.socket, deadline, check);
    channel
        .wait(libc::POLLIN)
        .map_err(|_| Error("live_media_broker_failed"))?;
    let file = live_media::receive(&broker.socket, direction, deadline)?;
    loop {
        check()?;
        match broker
            .child
            .try_wait()
            .map_err(|_| Error("live_media_broker_failed"))?
        {
            Some(status) if status.success() => return Ok(file),
            Some(_) => return Err(Error("live_media_broker_failed")),
            None if Instant::now() >= deadline => return Err(Error("live_media_broker_timeout")),
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
}

struct Broker {
    child: Child,
    socket: UnixStream,
}
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if matches!(self.child.try_wait(), Ok(None)) {
            // This is the child we spawned. sudo can forward TERM to the
            // privileged command and wait for it, unlike SIGKILL.
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
            }
            let _ = self.child.wait();
        }
    }
}

struct SocketIo<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
    check: &'a dyn Fn() -> Result<()>,
}

impl<'a> SocketIo<'a> {
    fn new(stream: &'a UnixStream, deadline: Instant, check: &'a dyn Fn() -> Result<()>) -> Self {
        Self {
            stream,
            deadline,
            check,
        }
    }

    fn wait(&self, events: i16) -> io::Result<()> {
        loop {
            (self.check)().map_err(io::Error::other)?;
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut fd = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            let status =
                unsafe { libc::poll(&mut fd, 1, remaining.as_millis().clamp(1, 100) as i32) };
            if status > 0 {
                return (self.check)().map_err(io::Error::other);
            }
            if status < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }

    fn perform<T>(
        &self,
        events: i16,
        mut operation: impl FnMut() -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            self.wait(events)?;
            match operation() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl Read for SocketIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream;
        self.perform(libc::POLLIN, || stream.read(bytes))
    }
}

impl Write for SocketIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut stream = self.stream;
        self.perform(libc::POLLOUT, || stream.write(bytes))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DETACHED, REVOKED, STOP, SocketIo, detach_proof, read_selection, stop_controller};
    use crate::bridge;
    use oblivion_wire::{
        control::{Operation, Request},
        control_client::{self, Framing},
        idle::Opening,
        live_media::{Direction, Purpose, Reserve},
        slot::Slot,
    };
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn sidecar_binds_native_request_to_the_exact_opening() {
        let mut selection = Reserve {
            opening: Opening {
                slot: Slot::try_from(3).unwrap(),
                safe_id: "a".repeat(32),
                nonce: "b".repeat(32),
            },
            device_id: "c".repeat(64),
            direction: Direction::Import,
            purpose: Purpose::Copy,
        };
        let read_request = |selection: &Reserve<Slot>, expected, slot| {
            let body = serde_json::to_vec(selection).unwrap();
            let request = Request {
                operation: Operation::LiveMediaReserve,
                session: None,
                secret_len: body.len() as u32,
                expected_session: Some(expected),
                slot,
            };
            let mut bytes = Vec::new();
            control_client::write_request(&mut bytes, &request, &body, Framing::Native).unwrap();
            read_selection(&mut bytes.as_slice())
        };
        for (expected, slot, success) in [
            (
                selection.opening.safe_id.clone(),
                selection.opening.slot,
                true,
            ),
            ("d".repeat(32), selection.opening.slot, false),
            (selection.opening.safe_id.clone(), Slot::ZERO, false),
        ] {
            assert_eq!(read_request(&selection, expected, slot).is_ok(), success);
        }
        for (purpose, direction, allowed) in [
            (Purpose::Copy, Direction::Import, true),
            (Purpose::Copy, Direction::Export, true),
            (Purpose::Inspect, Direction::Import, true),
            (Purpose::Inspect, Direction::Export, false),
            (Purpose::Recover, Direction::Import, false),
            (Purpose::Recover, Direction::Export, true),
            (Purpose::Discard, Direction::Import, false),
            (Purpose::Discard, Direction::Export, true),
        ] {
            selection.direction = direction;
            selection.purpose = purpose;
            let admitted = read_request(
                &selection,
                selection.opening.safe_id.clone(),
                selection.opening.slot,
            );
            assert_eq!(admitted.is_ok(), allowed);
            if let Ok(admitted) = admitted {
                assert_eq!((admitted.purpose, admitted.direction), (purpose, direction));
            }
        }
    }

    #[test]
    fn only_the_controller_stop_receipt_allows_outer_eject() {
        for (messages, success) in [
            (vec![DETACHED.as_slice()], true),
            (vec![REVOKED.as_slice(), DETACHED.as_slice()], true),
            (vec![REVOKED.as_slice()], false),
            (vec![b"copied\n".as_slice()], false),
            (vec![], false),
        ] {
            let (reserve, mut controller) = UnixStream::pair().unwrap();
            reserve.set_nonblocking(true).unwrap();
            controller
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let worker = thread::spawn(move || {
                let mut command = [0; 1];
                controller.read_exact(&mut command).unwrap();
                assert_eq!(command, [STOP]);
                for message in messages {
                    controller.write_all(message).unwrap();
                }
            });
            assert_eq!(
                stop_controller(&reserve, &AtomicBool::new(false)).is_ok(),
                success
            );
            worker.join().unwrap();
        }
    }

    #[test]
    fn caller_write_eof_closes_source_and_keeps_teardown_reply() {
        let (mut caller, local) = UnixStream::pair().unwrap();
        let (mut guest, source) = UnixStream::pair().unwrap();
        let (_controller, reserve) = UnixStream::pair().unwrap();
        for peer in [&caller, &guest] {
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        }
        let proof = detach_proof(&"a".repeat(32)).unwrap();
        let worker = thread::spawn(move || {
            let stop = AtomicBool::new(false);
            bridge::media_source(&local, source, &reserve, &stop).unwrap();
            let mut io = SocketIo::new(&local, Instant::now() + Duration::from_secs(1), &|| Ok(()));
            io.write_all(&proof).unwrap();
        });
        caller.write_all(b"request").unwrap();
        let mut request = [0; 7];
        guest.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        guest.write_all(b"copied\n").unwrap();
        let mut copied = [0; 7];
        caller.read_exact(&mut copied).unwrap();
        assert_eq!(&copied, b"copied\n");
        // Raw guest data can imitate the marker shape, but lacks the local
        // ACK's nonce. The actual runtime proof follows source shutdown.
        let forged = detach_proof(&"b".repeat(32)).unwrap();
        guest.write_all(&forged).unwrap();
        let mut detached = [0; 42];
        caller.read_exact(&mut detached).unwrap();
        assert_eq!(detached, forged);
        assert_ne!(detached, proof);
        caller.shutdown(Shutdown::Write).unwrap();
        assert_eq!(guest.read(&mut [0; 1]).unwrap(), 0);
        caller.read_exact(&mut detached).unwrap();
        assert_eq!(detached, proof);
        worker.join().unwrap();
    }
}
