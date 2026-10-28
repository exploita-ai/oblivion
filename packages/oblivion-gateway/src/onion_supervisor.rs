use crate::tor::{ClientAuth, OnionController, OnionService, Tor};
use oblivion_tor_state::State;
use serde::Deserialize;
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const FRAME_LIMIT: usize = 512 * 1024;
const HEARTBEAT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Initialize {
        state: Option<String>,
    },
    Enable {},
    Publish {
        client_auth: ClientAuth,
        ttl_seconds: u16,
    },
    Observe {},
    Snapshot {},
    Shutdown {},
}

struct Runtime {
    tor: Option<Tor>,
    prepared: Option<OnionController>,
    published: Option<OnionService>,
    enabled: bool,
    expected: Vec<u8>,
    expires: Option<Instant>,
}

pub fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1
        || unsafe { libc::geteuid() } != 0
        || std::fs::read_to_string("/proc/swaps")?.lines().count() != 1
    {
        return Err(io::Error::other("isolation_required"));
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::umask(0o077) };
    let mut channel = Channel::open()?;
    let mut runtime = Runtime {
        tor: None,
        prepared: None,
        published: None,
        enabled: false,
        expected: crate::onion_network::configure(false, false)?,
        expires: None,
    };
    channel.write(&json!({"ready":true,"version":1,"role":"onion-gateway"}))?;
    let result = runtime.serve(&mut channel);
    let expired = runtime.expires.is_some_and(|end| Instant::now() >= end);
    // Run every cleanup step even if one fails. The owner socket's closure
    // independently terminates Tor, including on SIGKILL of this process.
    let cleanup = runtime.stop();
    if result.is_err() {
        let _ = channel.write(&json!({
            "ok":false,
            "error":if cleanup.is_err() { "cleanup_failed" } else if expired { "expired" } else { "control_failed" },
            "state":cleanup.as_ref().ok().and_then(|state| state.as_ref()).map(State::as_str),
        }));
    }
    result?;
    cleanup?;
    Ok(())
}

impl Runtime {
    fn serve(&mut self, channel: &mut Channel) -> io::Result<()> {
        loop {
            let request: Request = serde_json::from_slice(&channel.read(self.expires)?)
                .map_err(|_| io::Error::other("invalid_request"))?;
            match request {
                Request::Initialize { state } => {
                    if self.tor.is_some() {
                        return Err(io::Error::other("already_initialized"));
                    }
                    let state = state
                        .as_deref()
                        .map(State::parse)
                        .transpose()
                        .map_err(|_| io::Error::other("invalid_tor_state"))?;
                    self.tor = Some(Tor::initialize(state)?);
                    self.prepared = Some(OnionController::new()?);
                }
                Request::Enable {} => {
                    let tor = self
                        .tor
                        .as_ref()
                        .ok_or_else(|| io::Error::other("not_initialized"))?;
                    if !self.enabled {
                        self.expected = crate::onion_network::configure(true, false)?;
                        tor.enable()?;
                        self.enabled = true;
                    }
                }
                Request::Publish {
                    client_auth,
                    ttl_seconds,
                } => {
                    if !(1..=3600).contains(&ttl_seconds) || self.published.is_some() {
                        return Err(io::Error::other("invalid_publication"));
                    }
                    if !crate::network::isolated(&self.expected)? {
                        return Err(io::Error::other("isolation_lost"));
                    }
                    let tor = self
                        .tor
                        .as_ref()
                        .ok_or_else(|| io::Error::other("not_initialized"))?;
                    if !self.enabled || !tor.bootstrapped()? {
                        channel.write(&json!({"ok":false,"error":"tor_not_ready"}))?;
                        continue;
                    }
                    self.expected = crate::onion_network::configure(true, true)?;
                    self.expires =
                        Some(Instant::now() + Duration::from_secs(u64::from(ttl_seconds)));
                    let owner = self
                        .prepared
                        .take()
                        .ok_or_else(|| io::Error::other("invalid_publication"))?;
                    self.published = Some(owner.publish(&client_auth)?);
                    channel.write(&json!({"ok":true,"service_id":self.published.as_ref().map(OnionService::id)}))?;
                    continue;
                }
                Request::Observe {} => {
                    let isolated = crate::network::isolated(&self.expected)?;
                    if !isolated {
                        return Err(io::Error::other("isolation_lost"));
                    }
                    let progress = self.tor.as_ref().map(Tor::progress).transpose()?;
                    channel.write(&json!({"ok":true,"isolated":true,"tor_progress":progress,
                        "tor_ready":self.enabled && progress == Some(100),"active":self.published.is_some()}))?;
                    continue;
                }
                Request::Snapshot {} => {
                    let state = self
                        .tor
                        .as_ref()
                        .ok_or_else(|| io::Error::other("not_initialized"))?
                        .snapshot(false)?;
                    channel.write(&json!({"ok":true,"state":state.as_str()}))?;
                    continue;
                }
                Request::Shutdown {} => {
                    let state = self.stop()?;
                    channel.write(
                        &json!({"ok":true,"closed":true,"state":state.as_ref().map(State::as_str)}),
                    )?;
                    return Ok(());
                }
            }
            channel.write(&json!({"ok":true,"initialized":self.tor.is_some(),"active":self.published.is_some()}))?;
        }
    }

    fn stop(&mut self) -> io::Result<Option<State>> {
        let revoked = self.published.take().map(OnionService::revoke).transpose();
        drop(self.prepared.take());
        let state = self.tor.take().map(|tor| tor.snapshot(true)).transpose();
        let reset = crate::onion_network::configure(false, false);
        self.enabled = false;
        self.expires = None;
        revoked?;
        self.expected = reset?;
        state
    }
}

struct Channel {
    file: File,
    signals: OwnedFd,
}

impl Channel {
    fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/virtio-ports/oblivion.onion-gateway")?;
        let meta = file.metadata()?;
        if !meta.file_type().is_char_device() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other("invalid_control_device"));
        }
        let mut mask = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGTERM);
            libc::sigaddset(&mut mask, libc::SIGINT);
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            signals: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn wait(&self, events: i16, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            let mut fds = [
                libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.signals.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis.max(1)) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if fds[1].revents != 0 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            if fds[0].revents & events != 0 {
                return Ok(());
            }
        }
    }

    fn read_bytes(&mut self, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            self.wait(libc::POLLIN, deadline)?;
            match self.file.read(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(size) => bytes = &mut bytes[size..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read(&mut self, expires: Option<Instant>) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut header = [0; 4];
        let deadline =
            (Instant::now() + HEARTBEAT).min(expires.unwrap_or_else(|| Instant::now() + HEARTBEAT));
        self.read_bytes(&mut header[..1], deadline)?;
        let deadline = (Instant::now() + Duration::from_secs(5)).min(deadline);
        self.read_bytes(&mut header[1..], deadline)?;
        let length = u32::from_be_bytes(header) as usize;
        if !(1..=FRAME_LIMIT).contains(&length) {
            return Err(io::Error::other("invalid_frame_length"));
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        self.read_bytes(&mut bytes, deadline)?;
        Ok(bytes)
    }

    fn write(&mut self, value: &serde_json::Value) -> io::Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        if bytes.len() > FRAME_LIMIT {
            return Err(io::Error::other("invalid_frame_length"));
        }
        let header = (bytes.len() as u32).to_be_bytes();
        let deadline = Instant::now() + Duration::from_secs(5);
        for mut chunk in [header.as_slice(), bytes.as_slice()] {
            while !chunk.is_empty() {
                self.wait(libc::POLLOUT, deadline)?;
                match self.file.write(chunk) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                    Ok(size) => chunk = &chunk[size..],
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Request;

    #[test]
    fn private_commands_do_not_accept_credentials_targets_or_arbitrary_tor_control() {
        for text in [
            r#"{"operation":"configure","api_key":"synthetic-key"}"#,
            r#"{"operation":"publish","client_auth":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ttl_seconds":30,"target":"127.0.0.1:22"}"#,
            r#"{"operation":"observe","command":"SETCONF DisableNetwork=0"}"#,
            r#"{"operation":"shutdown","detach":true}"#,
        ] {
            assert!(serde_json::from_str::<Request>(text).is_err());
        }
        for text in [
            r#"{"operation":"initialize","state":null}"#,
            r#"{"operation":"enable"}"#,
            r#"{"operation":"observe"}"#,
            r#"{"operation":"snapshot"}"#,
            r#"{"operation":"shutdown"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(text).is_ok());
        }
    }
}
