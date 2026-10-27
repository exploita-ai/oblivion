use oblivion_gateway::egress::Tools;
use oblivion_transport::Transport;
use oblivion_transport::provider::Provider;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const FRAME_LIMIT: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Configure {
        provider: Provider,
        api_key: Zeroizing<String>,
        #[serde(default)]
        transport: Transport,
    },
    Grant {
        token: Zeroizing<String>,
        #[serde(default)]
        tools: Option<Tools>,
    },
    Revoke {},
    Status {},
    Observe {},
    Shutdown {},
    TorInitialize {
        state: Option<String>,
    },
    TorEnable {},
    TorSnapshot {
        stop: bool,
    },
}

#[derive(Serialize)]
struct Reply {
    ok: bool,
    configured: bool,
    active: bool,
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
    let mut api = None;
    // This handshake contains no operational secrets and precedes configuration.
    channel.write(b"{\"ready\":true,\"version\":1}", &mut api)?;
    let result = serve(&mut channel, &mut api);
    if let Some(mut api) = api.take() {
        api.stop()?;
    }
    if result.is_err() {
        // Failures close the current grant before reporting anything. A broken
        // control channel cannot be reattached to reuse this VM's credential.
        let _ = channel.write(b"{\"ok\":false,\"error\":\"control_failed\"}", &mut api);
    }
    result
}

fn serve(channel: &mut Channel, api: &mut Option<Grant>) -> io::Result<()> {
    let mut key = None;
    let mut provider = None;
    let mut transport = None;
    let mut tor = None;
    let mut firewall = None;
    loop {
        let bytes = channel.read(api)?;
        let request: Request =
            serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid_request"))?;
        drop(bytes);
        let shutdown = matches!(request, Request::Shutdown {});
        match request {
            Request::TorInitialize { state } => {
                if tor.is_some()
                    || api.is_some()
                    || key.is_none()
                    || !matches!(transport, Some(Transport::Tor {}))
                {
                    return Err(io::Error::other("invalid_tor_initialization"));
                }
                let state = state
                    .as_deref()
                    .map(oblivion_tor_state::State::parse)
                    .transpose()
                    .map_err(|_| io::Error::other("invalid_tor_state"))?;
                tor = Some(crate::tor::Tor::initialize(state)?);
            }
            Request::TorEnable {} => {
                tor.as_ref()
                    .ok_or_else(|| io::Error::other("tor_not_initialized"))?
                    .enable()?;
            }
            Request::TorSnapshot { stop } => {
                if stop {
                    if let Some(mut current) = api.take() {
                        current.stop()?;
                    }
                }
                let state = tor
                    .as_ref()
                    .ok_or_else(|| io::Error::other("tor_not_initialized"))?
                    .snapshot(stop)?;
                #[derive(Serialize)]
                struct Snapshot<'a> {
                    ok: bool,
                    state: &'a str,
                    bootstrapped: bool,
                }
                channel.write(
                    &serde_json::to_vec(&Snapshot {
                        ok: true,
                        state: state.as_str(),
                        bootstrapped: !stop
                            && tor
                                .as_ref()
                                .ok_or_else(|| io::Error::other("tor_not_initialized"))?
                                .bootstrapped()?,
                    })?,
                    api,
                )?;
                continue;
            }
            Request::Configure {
                provider: selected_provider,
                api_key,
                transport: selected,
            } => {
                if key.is_some()
                    || !(16..=4096).contains(&api_key.len())
                    || !api_key.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(io::Error::other("invalid_configuration"));
                }
                crate::network::configure(&selected)?;
                firewall = Some(crate::network::snapshot()?);
                transport = Some(selected);
                provider = Some(selected_provider);
                key = Some(api_key);
            }
            Request::Grant { token, tools } => {
                if api.is_some()
                    || token.len() != 64
                    || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(io::Error::other("invalid_grant"));
                }
                let key = key
                    .as_ref()
                    .ok_or_else(|| io::Error::other("not_configured"))?;
                let transport = transport
                    .as_ref()
                    .ok_or_else(|| io::Error::other("not_configured"))?;
                let provider = provider.ok_or_else(|| io::Error::other("not_configured"))?;
                if matches!(transport, Transport::Tor {}) && tor.is_none() {
                    return Err(io::Error::other("tor_not_initialized"));
                }
                *api = Some(Grant::start(
                    provider,
                    key,
                    &token,
                    transport,
                    tools.as_ref(),
                )?);
            }
            Request::Revoke {} | Request::Shutdown {} => {
                if let Some(mut current) = api.take() {
                    current.stop()?;
                }
            }
            Request::Status {} => {}
            Request::Observe {} => {
                let isolated = firewall
                    .as_ref()
                    .is_some_and(|expected| crate::network::isolated(expected).unwrap_or(false));
                if !isolated {
                    return Err(io::Error::other("isolation_lost"));
                }
                let transport = transport
                    .as_ref()
                    .ok_or_else(|| io::Error::other("not_configured"))?;
                let progress = tor.as_ref().and_then(|tor| tor.progress().ok());
                let ready = match transport {
                    Transport::Tor {} => progress == Some(100),
                    Transport::Socks5 { .. } => Process::start(
                        Role::Probe,
                        Zeroizing::new(serde_json::to_vec(
                            &serde_json::json!({"probe": transport}),
                        )?),
                    )
                    .is_ok(),
                };
                channel.write(
                    &serde_json::to_vec(
                        &serde_json::json!({"ready": ready, "isolated": isolated, "tor_progress": progress}),
                    )?,
                    api,
                )?;
                continue;
            }
        }
        channel.write(
            &serde_json::to_vec(&Reply {
                ok: true,
                configured: key.is_some() && provider.is_some(),
                active: api.is_some(),
            })?,
            api,
        )?;
        if shutdown {
            return Ok(());
        }
    }
}

struct Grant {
    api: Process,
    egress: Process,
    tools: Option<Process>,
}

impl Grant {
    fn start(
        provider: Provider,
        key: &str,
        token: &str,
        transport: &Transport,
        tools: Option<&Tools>,
    ) -> io::Result<Self> {
        #[derive(Serialize)]
        struct EgressCredentials<'a> {
            provider: Provider,
            transport: &'a Transport,
            session_token: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            tools: Option<&'a Tools>,
        }
        let egress = Process::start(
            Role::Egress,
            Zeroizing::new(serde_json::to_vec(&EgressCredentials {
                provider,
                transport,
                session_token: token,
                tools,
            })?),
        )?;
        #[derive(Serialize)]
        struct ApiCredentials<'a> {
            provider: Provider,
            api_key: &'a str,
            session_token: &'a str,
            socks: &'static str,
        }
        let api = Process::start(
            Role::Api,
            Zeroizing::new(serde_json::to_vec(&ApiCredentials {
                provider,
                api_key: key,
                session_token: token,
                socks: "127.0.0.1:9051",
            })?),
        )?;
        #[derive(Serialize)]
        struct ToolsCredentials<'a> {
            session_token: &'a str,
            socks: &'static str,
        }
        let tools = tools
            .map(|_| {
                Process::start(
                    Role::Tools,
                    Zeroizing::new(serde_json::to_vec(&ToolsCredentials {
                        session_token: token,
                        socks: "127.0.0.1:9051",
                    })?),
                )
            })
            .transpose()?;
        Ok(Self { api, egress, tools })
    }

    fn stop(&mut self) -> io::Result<()> {
        // Try every closure even if one fails. Process::drop also prevents a
        // startup error from leaving the other service or its sockets alive.
        let tools = self.tools.as_mut().map(Process::stop).transpose();
        let api = self.api.stop();
        let egress = self.egress.stop();
        tools?;
        api?;
        egress
    }
}

enum Role {
    Api,
    Egress,
    Tools,
    Probe,
}

struct Process {
    child: Child,
    control: Option<UnixStream>,
}

impl Process {
    fn start(role: Role, mut bytes: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let (program, uid, ip, port) = match role {
            Role::Api => ("/usr/bin/oblivion-api", 1300, [10, 88, 0, 1], 8111u16),
            Role::Egress => ("/usr/bin/oblivion-egress", 1201, [127, 0, 0, 1], 9051u16),
            Role::Tools => ("/usr/bin/oblivion-tools", 1301, [10, 88, 0, 1], 8112u16),
            Role::Probe => ("/usr/bin/oblivion-egress", 1201, [127, 0, 0, 1], 0u16),
        };
        let (control, inherited) = UnixStream::pair()?;
        control.set_read_timeout(Some(Duration::from_secs(5)))?;
        control.set_write_timeout(Some(Duration::from_secs(5)))?;
        // SO_REUSEADDR permits a new grant after TIME_WAIT without allowing two
        // live listeners. No path, command, address or port comes from the host.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = unsafe { TcpListener::from_raw_fd(raw) };
        let enabled: libc::c_int = 1;
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip),
            },
            sin_zero: [0; 8],
        };
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            ) != 0
                || libc::bind(
                    raw,
                    (&address as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as _,
                ) != 0
                || libc::listen(raw, 64) != 0
        } {
            return Err(io::Error::last_os_error());
        }
        // Normalize donors above 4 so dup2 cannot overwrite either source.
        let channel = duplicate(inherited.as_raw_fd())?;
        let incoming = duplicate(listener.as_raw_fd())?;
        let parent = std::process::id() as libc::pid_t;
        let mut command = Command::new(program);
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let mut empty = std::mem::zeroed();
                libc::sigemptyset(&mut empty);
                if libc::dup2(channel.as_raw_fd(), 3) < 0 || libc::dup2(incoming.as_raw_fd(), 4) < 0
                    || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(uid) != 0 || libc::setuid(uid) != 0
                    // Credential changes clear PDEATHSIG: arm it afterwards and
                    // verify the supervisor did not die in the intervening gap.
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
                { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
        let mut api = Self {
            child: command.spawn()?,
            control: Some(control),
        };
        drop(inherited);
        drop(listener);
        bytes.push(b'\n');
        let channel = api
            .control
            .as_mut()
            .ok_or_else(|| io::Error::other("missing_control"))?;
        channel.write_all(&bytes)?;
        let mut ready = [0; 15];
        channel.read_exact(&mut ready)?;
        if &ready != b"{\"ready\":true}\n" {
            return Err(io::Error::other("invalid_ready"));
        }
        Ok(api)
    }

    fn stop(&mut self) -> io::Result<()> {
        self.control.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.child.kill()?;
                self.child.wait()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Startup and protocol errors cannot strand a listener. Abrupt parent
        // death is covered independently by PDEATHSIG and the systemd cgroup.
        self.control.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            if self.child.kill().is_ok() {
                let _ = self.child.wait();
            }
        }
    }
}

fn duplicate(fd: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

struct Channel {
    file: File,
    signals: OwnedFd,
}

impl Channel {
    fn open() -> io::Result<Self> {
        // udev owns this fixed private virtio port. It is not a session NIC,
        // serial console, command socket, or filesystem chosen by the caller.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/virtio-ports/oblivion.gateway")?;
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

    fn wait(
        &self,
        events: i16,
        deadline: Option<Instant>,
        api: &mut Option<Grant>,
    ) -> io::Result<()> {
        loop {
            if let Some(api) = api {
                let tools_exited = api
                    .tools
                    .as_mut()
                    .map(|tools| tools.child.try_wait())
                    .transpose()?
                    .flatten()
                    .is_some();
                if tools_exited
                    || api.api.child.try_wait()?.is_some()
                    || api.egress.child.try_wait()?.is_some()
                {
                    return Err(io::Error::other("grant_process_exited"));
                }
            }
            if deadline.is_some_and(|end| Instant::now() >= end) {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
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
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) } < 0 {
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

    fn read_bytes(
        &mut self,
        mut bytes: &mut [u8],
        deadline: Option<Instant>,
        api: &mut Option<Grant>,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            self.wait(libc::POLLIN, deadline, api)?;
            match self.file.read(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(size) => bytes = &mut bytes[size..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read(&mut self, api: &mut Option<Grant>) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut header = [0; 4];
        self.read_bytes(&mut header[..1], None, api)?;
        let deadline = Some(Instant::now() + Duration::from_secs(5));
        self.read_bytes(&mut header[1..], deadline, api)?;
        let length = u32::from_be_bytes(header) as usize;
        if !(1..=FRAME_LIMIT).contains(&length) {
            return Err(io::Error::other("invalid_frame_length"));
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        self.read_bytes(&mut bytes, deadline, api)?;
        Ok(bytes)
    }

    fn write(&mut self, bytes: &[u8], api: &mut Option<Grant>) -> io::Result<()> {
        let header = (bytes.len() as u32).to_be_bytes();
        let deadline = Some(Instant::now() + Duration::from_secs(5));
        for mut chunk in [header.as_slice(), bytes] {
            while !chunk.is_empty() {
                self.wait(libc::POLLOUT, deadline, api)?;
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
