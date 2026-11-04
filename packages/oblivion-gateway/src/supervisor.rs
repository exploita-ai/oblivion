use oblivion_gateway::egress::Tools;
use oblivion_transport::Transport;
use oblivion_transport::policy::Access;
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
    ConfigureTools {
        #[serde(default)]
        transport: Transport,
    },
    TransportChange {
        transport: Transport,
        state: Option<String>,
    },
    Grant {
        token: Zeroizing<String>,
        #[serde(default)]
        tools: Option<Tools>,
        #[serde(default)]
        rotation_allowed: bool,
    },
    RotationAllowed { allowed: bool },
    Revoke {},
    Policy {
        tools: Tools,
    },
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
    let mut grant = None;
    // This handshake contains no operational secrets and precedes configuration.
    channel.write(b"{\"ready\":true,\"version\":1}", &mut grant)?;
    let result = serve(&mut channel, &mut grant);
    if let Some(mut grant) = grant.take() {
        grant.stop()?;
    }
    if result.is_err() {
        // Failures close the current grant before reporting anything. A broken
        // control channel cannot be reattached to reuse this VM's credential.
        let _ = channel.write(b"{\"ok\":false,\"error\":\"control_failed\"}", &mut grant);
    }
    result
}

fn serve(channel: &mut Channel, grant: &mut Option<Grant>) -> io::Result<()> {
    let mut transport = None;
    let mut tor = None;
    let mut firewall = None;
    let mut access = Access::Strict;
    let mut transport_blocked = false;
    loop {
        if let Some(grant) = grant.as_mut() {
            if !transport_blocked && grant.poll_rotation(transport.as_ref(), tor.as_ref())? {
                firewall = Some(crate::network::snapshot()?);
            }
        }
        let bytes = channel.read(grant)?;
        let request: Request =
            serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid_request"))?;
        drop(bytes);
        let shutdown = matches!(request, Request::Shutdown {});
        match request {
            Request::TorInitialize { state } => {
                if tor.is_some()
                    || grant.is_some()
                    || transport.is_none()
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
                    if let Some(mut current) = grant.take() {
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
                        )?;
                continue;
            }
            Request::ConfigureTools { transport: selected } => {
                if transport.is_some() {
                    return Err(io::Error::other("invalid_configuration"));
                }
                crate::network::configure(&selected)?;
                firewall = Some(crate::network::snapshot()?);
                transport = Some(selected);
            }
            Request::TransportChange { transport: selected, state } => {
                if transport.is_none() {
                    return Err(io::Error::other("not_configured"));
                }
                transport_blocked = true;
                let result = change_transport(grant, &mut tor, &selected, access, state.as_deref());
                if result.is_err() {
                    // A failed route is an explicit latched state. The same
                    // private control channel can retry without replacing the
                    // VM or its point-to-point NIC socket.
                    crate::network::rotation_block()?;
                    if let Some(grant) = grant.as_mut() {
                        grant.blocked = true;
                        if let Some(mut plane) = grant.plane.take() { plane.stop()?; }
                    }
                    if let Some(tor) = &tor { let _ = tor.disable(); }
                } else {
                    transport_blocked = false;
                }
                transport = Some(selected);
                firewall = Some(crate::network::snapshot()?);
                channel.write(&serde_json::to_vec(&Reply {
                    ok: result.is_ok(), configured: true, active: grant.is_some(),
                })?, grant)?;
                continue;
            }
            Request::Grant { token, tools, rotation_allowed } => {
                if transport_blocked || grant.is_some()
                    || token.len() != 64
                    || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(io::Error::other("invalid_grant"));
                }
                let transport = transport
                    .as_ref()
                    .ok_or_else(|| io::Error::other("not_configured"))?;
                if matches!(transport, Transport::Tor {}) && tor.is_none() {
                    return Err(io::Error::other("tor_not_initialized"));
                }
                access = tools.as_ref().map_or(Access::Strict, |tools| tools.access);
                if access == Access::Offline {
                    return Err(io::Error::other("offline_grant_denied"));
                }
                *grant = Some(Grant::start(
                    &token,
                    transport,
                    tools,
                )?);
                grant.as_mut().unwrap().rotation_allowed = rotation_allowed;
            }
            Request::RotationAllowed { allowed } => {
                let grant = grant.as_mut().ok_or_else(|| io::Error::other("grant_required"))?;
                if grant.blocked { return Err(io::Error::other("rotation_recovery_required")); }
                grant.rotation_allowed = allowed;
            }
            Request::Policy { tools } => {
                // An explicit failed rotation stays latched; a mode change must
                // not replace its firewall with a permissive transport policy.
                if transport_blocked || grant.as_ref().is_some_and(|grant| grant.blocked) {
                    return Err(io::Error::other("rotation_recovery_required"));
                }
                let mut previous = grant
                    .take()
                    .ok_or_else(|| io::Error::other("grant_required"))?;
                previous.stop()?;
                let transport = transport
                    .as_ref()
                    .ok_or_else(|| io::Error::other("not_configured"))?;
                if tools.access == Access::Offline {
                    crate::network::offline()?;
                    if let Some(tor) = &tor {
                        tor.disable()?;
                    }
                } else if access == Access::Offline {
                    crate::network::configure(transport)?;
                    if let Some(tor) = &tor {
                        tor.enable()?;
                    }
                }
                firewall = Some(crate::network::snapshot()?);
                access = tools.access;
                *grant = Some(Grant::start(
                    &previous.token,
                    transport,
                    Some(tools),
                )?);
                grant.as_mut().unwrap().rotation_allowed = previous.rotation_allowed;
            }
            Request::Revoke {} | Request::Shutdown {} => {
                if let Some(mut current) = grant.take() {
                    current.stop()?;
                    // Destroy a latched gateway instead of allowing a later
                    // grant to mistake its blocked ruleset for a ready route.
                    if current.blocked {
                        return Err(io::Error::other("rotation_recovery_required"));
                    }
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
                let ready = !transport_blocked && access != Access::Offline && !grant.as_ref().is_some_and(|grant| grant.blocked)
                    && match transport {
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
                        )?;
                continue;
            }
        }
        channel.write(
            &serde_json::to_vec(&Reply {
                ok: true,
                configured: transport.is_some(),
                active: grant.is_some(),
            })?,
        )?;
        if shutdown {
            return Ok(());
        }
    }
}

fn change_transport(
    grant: &mut Option<Grant>,
    tor: &mut Option<crate::tor::Tor>,
    selected: &Transport,
    access: Access,
    state: Option<&str>,
) -> io::Result<()> {
    // This table precedes established connections. It stays installed across
    // process teardown, base-policy replacement and transport verification.
    crate::network::rotation_block()?;
    if let Some(grant) = grant.as_mut() {
        grant.blocked = true;
        if grant.pending.take().is_some() {
            grant.rotation.control.as_mut().ok_or_else(|| io::Error::other("rotation_control_missing"))?.write_all(b"U")?;
        }
        if let Some(mut plane) = grant.plane.take() { plane.stop()?; }
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    if let Some(tor) = tor.as_ref() {
        tor.disable()?;
        while !tor.drained()? {
            if Instant::now() >= deadline { return Err(io::Error::other("transport_drain_timeout")); }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    crate::network::change_transport(selected, access == Access::Offline)?;
    if matches!(selected, Transport::Tor {}) && tor.is_none() {
        let state = state.map(oblivion_tor_state::State::parse).transpose()
            .map_err(|_| io::Error::other("invalid_tor_state"))?;
        *tor = Some(crate::tor::Tor::initialize(state)?);
    }
    if access != Access::Offline {
        crate::network::transport_probe()?;
        match selected {
            Transport::Tor {} => {
                let tor = tor.as_ref().ok_or_else(|| io::Error::other("tor_not_initialized"))?;
                tor.enable()?;
                let mut circuit = None;
                loop {
                    if Instant::now() >= deadline { return Err(io::Error::other("transport_bootstrap_timeout")); }
                    if tor.bootstrapped()? {
                        if let Some(id) = circuit {
                            if tor.circuit_ready(id, &Default::default())? { break; }
                        } else {
                            circuit = Some(tor.build_circuit()?);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            Transport::Socks5 { .. } => {
                Process::start(Role::Probe, Zeroizing::new(serde_json::to_vec(
                    &serde_json::json!({"probe": selected}),
                )?))?;
            }
        }
    }
    let barrier = crate::network::snapshot()?;
    if let Some(grant) = grant.as_mut() {
        grant.plane = Some(Plane::start(&grant.token, selected, grant.policy.as_ref())?);
    }
    if !crate::network::isolated(&barrier)? { return Err(io::Error::other("isolation_lost")); }
    let baseline = crate::network::transport_baseline()?;
    crate::network::rotation_release()?;
    // All verification precedes the atomic release. Only in-memory assignments
    // follow it, so a later diagnostic failure cannot turn a completed change
    // into a reported failed transition with an open data plane.
    if let Some(grant) = grant.as_mut() {
        grant.normal_firewall = baseline;
        grant.blocked = false;
    }
    Ok(())
}

struct Grant {
    token: Zeroizing<String>,
    plane: Option<Plane>,
    rotation: Process,
    policy: Option<Tools>,
    blocked: bool,
    pending: Option<PendingRotation>,
    previous_exits: std::collections::BTreeSet<String>,
    normal_firewall: Vec<u8>,
    rotation_firewall: Vec<u8>,
    last_rotation: Option<Instant>,
    rotation_allowed: bool,
}

struct PendingRotation {
    deadline: Instant,
    circuit: Option<u32>,
    draining: bool,
}

struct Plane {
    egress: Process,
    tools: Option<Process>,
    web: Process,
}

impl Grant {
    fn start(
        token: &str,
        transport: &Transport,
        tools: Option<Tools>,
    ) -> io::Result<Self> {
        let plane = Plane::start(token, transport, tools.as_ref())?;
        let rotation = Process::start(Role::Rotation, Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({"session_token": token}),
        )?))?;
        Ok(Self {
            token: Zeroizing::new(token.to_owned()), plane: Some(plane), rotation,
            policy: tools, blocked: false, pending: None, rotation_allowed: false,
            previous_exits: Default::default(), normal_firewall: crate::network::snapshot()?, rotation_firewall: Vec::new(), last_rotation: None,
        })
    }

    fn poll_rotation(&mut self, transport: Option<&Transport>, tor: Option<&crate::tor::Tor>) -> io::Result<bool> {
        let control = self.rotation.control.as_mut().ok_or_else(|| io::Error::other("rotation_control_missing"))?;
        let mut request = [0u8];
        let received = unsafe { libc::recv(control.as_raw_fd(), request.as_mut_ptr().cast(), 1, libc::MSG_DONTWAIT) };
        if received == 0 || (received < 0 && io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock) {
            return Err(io::Error::other("rotation_control_lost"));
        }
        if received == 1 {
            if request != *b"R" || self.pending.is_some() { return Err(io::Error::other("invalid_rotation_request")); }
            if !self.rotation_allowed {
                control.write_all(b"T")?;
                return Ok(false);
            }
            if !matches!(transport, Some(Transport::Tor {})) || tor.is_none() || self.policy.as_ref().is_some_and(|policy| policy.access == Access::Offline) {
                control.write_all(b"U")?;
                return Ok(false);
            }
            if self.last_rotation.is_some_and(|time| time.elapsed() < Duration::from_secs(30)) {
                control.write_all(b"C")?;
                return Ok(false);
            }
            self.last_rotation = Some(Instant::now());
            // Set the latch before touching children or Tor. Any failure below
            // leaves it installed; supervisor death also kills the whole cgroup.
            crate::network::rotation_block()?;
            self.blocked = true;
            self.pending = Some(PendingRotation { deadline: Instant::now() + Duration::from_secs(90), circuit: None, draining: true });
            let prepare = (|| {
                if let Some(mut plane) = self.plane.take() { plane.stop()?; }
                let tor = tor.unwrap();
                let exits = tor.exits()?;
                if !exits.is_empty() { self.previous_exits = exits; }
                tor.prepare_rotation(&self.previous_exits)
            })();
            if prepare.is_err() { self.fail_rotation(tor, b'P')?; }
            return Ok(true);
        }
        let Some(pending) = self.pending.as_mut() else { return Ok(false) };
        if pending.draining {
            // DisableNetwork closes asynchronously. Keep the full barrier while
            // Tor retires old streams; do not mistake that transition for failure.
            let result = (|| {
                if Instant::now() >= pending.deadline { return Err(io::Error::other("rotation_timed_out")); }
                let tor = tor.ok_or_else(|| io::Error::other("tor_required"))?;
                if !tor.drained()? { return Ok(false); }
                crate::network::rotation_tor_only()?;
                self.rotation_firewall = crate::network::snapshot()?;
                tor.enable()?;
                Ok(true)
            })();
            return match result {
                Ok(false) => Ok(false),
                Ok(true) => { pending.draining = false; Ok(true) }
                Err(_) => { self.fail_rotation(tor, b'D')?; Ok(true) }
            };
        }
        let result = (|| {
            if Instant::now() >= pending.deadline { return Err(io::Error::other("rotation_timed_out")); }
            let tor = tor.ok_or_else(|| io::Error::other("tor_required"))?;
            if !tor.bootstrapped()? { return Ok(false); }
            if pending.circuit.is_none() {
                pending.circuit = Some(tor.build_circuit()?);
                return Ok(false);
            }
            if !tor.circuit_ready(pending.circuit.unwrap(), &self.previous_exits)? { return Ok(false); }
            if !crate::network::isolated(&self.rotation_firewall)? { return Err(io::Error::other("isolation_lost")); }
            self.plane = Some(Plane::start(
                &self.token,
                transport.ok_or_else(|| io::Error::other("not_configured"))?, self.policy.as_ref(),
            )?);
            if !crate::network::isolated(&self.rotation_firewall)? { return Err(io::Error::other("isolation_lost")); }
            // The baseline is verified with the barrier still installed. Only
            // its known table is removed in the final atomic release.
            crate::network::rotation_release()?;
            if !crate::network::isolated(&self.normal_firewall)? { return Err(io::Error::other("isolation_lost")); }
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(false),
            Ok(true) => {
                self.pending = None;
                self.blocked = false;
                self.rotation.control.as_mut().unwrap().write_all(if self.previous_exits.is_empty() { b"N" } else { b"S" })?;
                Ok(true)
            }
            Err(error) => {
                let phase = match error.to_string().as_str() {
                    "circuit_build_failed" => b'B',
                    "previous_exit_reused" => b'X',
                    "rotation_timed_out" => b'O',
                    "isolation_lost" => b'I',
                    "invalid_exit_identity" | "invalid_circuit_status" => b'E',
                    "invalid_tor_information" | "invalid_tor_line" => b'H',
                    "unexpected_tor_reply" => b'R',
                    _ if error.kind() == io::ErrorKind::AddrInUse => b'L',
                    _ => b'V',
                };
                self.fail_rotation(tor, phase)?; Ok(true)
            }
        }
    }

    fn fail_rotation(&mut self, tor: Option<&crate::tor::Tor>, phase: u8) -> io::Result<()> {
        crate::network::rotation_block()?;
        if let Some(mut plane) = self.plane.take() { plane.stop()?; }
        if let Some(tor) = tor { let _ = tor.disable(); }
        self.pending = None;
        self.blocked = true;
        self.rotation.control.as_mut().unwrap().write_all(&[phase])
    }

    fn stop(&mut self) -> io::Result<()> {
        let plane = self.plane.as_mut().map(Plane::stop).transpose();
        let rotation = self.rotation.stop();
        plane?;
        rotation
    }

    fn exited(&mut self) -> io::Result<bool> {
        Ok(self.rotation.child.try_wait()?.is_some() || self.plane.as_mut().map(Plane::exited).transpose()?.unwrap_or(false))
    }
}

impl Plane {
    fn start(token: &str, transport: &Transport, tools: Option<&Tools>) -> io::Result<Self> {
        #[derive(Serialize)]
        struct EgressCredentials<'a> {
            transport: &'a Transport,
            session_token: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            tools: Option<&'a Tools>,
        }
        let egress = Process::start(
            Role::Egress,
            Zeroizing::new(serde_json::to_vec(&EgressCredentials {
                transport,
                session_token: token,
                tools,
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
        let web = Process::start(
            Role::Web,
            Zeroizing::new(serde_json::to_vec(&ToolsCredentials {
                session_token: token,
                socks: "127.0.0.1:9051",
            })?),
        )?;
        Ok(Self {
            egress,
            tools,
            web,
        })
    }

    fn stop(&mut self) -> io::Result<()> {
        // Try every closure even if one fails. Process::drop also prevents a
        // startup error from leaving the other service or its sockets alive.
        self.egress.control.take();
        self.web.control.take();
        if let Some(tools) = &mut self.tools { tools.control.take(); }
        let deadline = Instant::now() + Duration::from_secs(5);
        let egress = self.egress.stop_until(deadline);
        let tools = self.tools.as_mut().map(|tools| tools.stop_until(deadline)).transpose();
        let web = self.web.stop_until(deadline);
        tools?;
        web?;
        egress
    }

    fn exited(&mut self) -> io::Result<bool> {
        Ok(self.tools.as_mut().map(|tools| tools.child.try_wait()).transpose()?.flatten().is_some()
            || self.web.child.try_wait()?.is_some() || self.egress.child.try_wait()?.is_some())
    }
}

enum Role {
    Egress,
    Tools,
    Web,
    Probe,
    Rotation,
}

struct Process {
    child: Child,
    control: Option<UnixStream>,
}

impl Process {
    fn start(role: Role, mut bytes: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let (program, uid, ip, port) = match role {
            Role::Egress => ("/usr/bin/oblivion-egress", 1201, [127, 0, 0, 1], 9051u16),
            Role::Tools => ("/usr/bin/oblivion-tools", 1301, [10, 88, 0, 1], 8112u16),
            Role::Web => ("/usr/bin/oblivion-web", 1302, [10, 88, 0, 1], 8113u16),
            Role::Probe => ("/usr/bin/oblivion-egress", 1201, [127, 0, 0, 1], 0u16),
            Role::Rotation => ("/usr/bin/oblivion-rotation", 1303, [10, 88, 0, 1], 8114u16),
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
        let mut grant = Self {
            child: command.spawn()?,
            control: Some(control),
        };
        drop(inherited);
        drop(listener);
        bytes.push(b'\n');
        let channel = grant
            .control
            .as_mut()
            .ok_or_else(|| io::Error::other("missing_control"))?;
        channel.write_all(&bytes)?;
        let mut ready = [0; 15];
        channel.read_exact(&mut ready)?;
        if &ready != b"{\"ready\":true}\n" {
            return Err(io::Error::other("invalid_ready"));
        }
        Ok(grant)
    }

    fn stop(&mut self) -> io::Result<()> {
        self.stop_until(Instant::now() + Duration::from_secs(5))
    }

    fn stop_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.control.take();
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
        grant: &mut Option<Grant>,
    ) -> io::Result<()> {
        loop {
            if let Some(grant) = grant {
                if grant.exited()? {
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
        grant: &mut Option<Grant>,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            self.wait(libc::POLLIN, deadline, grant)?;
            match self.file.read(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(size) => bytes = &mut bytes[size..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read(&mut self, grant: &mut Option<Grant>) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut header = [0; 4];
        self.read_bytes(&mut header[..1], None, grant)?;
        let deadline = Some(Instant::now() + Duration::from_secs(5));
        self.read_bytes(&mut header[1..], deadline, grant)?;
        let length = u32::from_be_bytes(header) as usize;
        if !(1..=FRAME_LIMIT).contains(&length) {
            return Err(io::Error::other("invalid_frame_length"));
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        self.read_bytes(&mut bytes, deadline, grant)?;
        Ok(bytes)
    }

    fn write(&mut self, bytes: &[u8], grant: &mut Option<Grant>) -> io::Result<()> {
        let header = (bytes.len() as u32).to_be_bytes();
        let deadline = Some(Instant::now() + Duration::from_secs(5));
        for mut chunk in [header.as_slice(), bytes] {
            while !chunk.is_empty() {
                self.wait(libc::POLLOUT, deadline, grant)?;
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
