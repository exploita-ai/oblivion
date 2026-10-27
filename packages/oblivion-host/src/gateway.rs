use crate::storage::{Error, Result, lock_named, require};
use crate::vm::{self, Role};
use oblivion_host::channel::Channel;
use oblivion_transport::Transport;
use oblivion_transport::policy::Tools;
use oblivion_transport::provider::Provider;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const UNIT: &str = "oblivion-gateway-host.service";
const SOCKET: &str = "/run/oblivion/gateway-control.sock";

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Request<'a> {
    Grant {
        token: &'a str,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tools: Option<Tools>,
    },
    Revoke {},
    Check {},
    Observe {},
    Stop {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    ready: bool,
    version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    ok: bool,
    configured: bool,
    active: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub ready: bool,
    pub isolated: bool,
    pub tor: bool,
    pub age_ms: u64,
    pub tor_progress: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    ready: bool,
    isolated: bool,
    #[serde(default)]
    tor_progress: Option<u8>,
}

pub fn observation() -> Result<Observation> {
    let stream = UnixStream::connect(SOCKET).map_err(|_| Error("gateway_unavailable"))?;
    peer(&stream, 0)?;
    let mut channel = Channel::new(&stream, Duration::from_secs(4));
    send(&mut channel, b"{\"operation\":\"observe\"}")?;
    serde_json::from_slice(&receive(&mut channel)?)
        .map_err(|_| Error("invalid_gateway_observation"))
}

fn observe(stream: &UnixStream) -> Result<Observed> {
    let mut channel = Channel::new(stream, Duration::from_secs(4));
    send(&mut channel, b"{\"operation\":\"observe\"}")?;
    serde_json::from_slice(&receive(&mut channel)?)
        .map_err(|_| Error("invalid_gateway_observation"))
}

pub fn state() -> Result<String> {
    vm::unit_state(UNIT)
}

pub fn start(wait: bool) -> Result<()> {
    require(
        matches!(state()?.as_str(), "inactive" | "failed"),
        "gateway_already_running",
    )?;
    let arguments = if wait { vec!["start".to_owned(), UNIT.to_owned()] }
        else { vec!["start".to_owned(), "--no-block".to_owned(), UNIT.to_owned()] };
    vm::execute("/usr/bin/systemctl", &arguments).map_err(|_| Error("gateway_start_failed"))?;
    require(!wait || state()? == "active", "gateway_start_failed")
}

pub fn stop() -> Result<()> {
    require(shutdown()?, "gateway_shutdown_unconfirmed")
}

/// The checkpoint result is advisory only after both gateway units are stopped.
/// Global locking must still close the session and vault if checkpointing fails.
pub fn shutdown() -> Result<bool> {
    let checkpoint = if state()? == "active" {
        request(&Request::Stop {}, false)
    } else {
        Ok(())
    };
    destroy()?;
    Ok(checkpoint.is_ok())
}

fn destroy() -> Result<()> {
    // Always inspect both units: the host process may have died before its
    // ExecStopPost, or a previous cleanup may have been interrupted.
    if !matches!(state()?.as_str(), "inactive" | "failed") {
        vm::execute("/usr/bin/systemctl", &["stop".to_owned(), UNIT.to_owned()])?;
    }
    vm::stop_role(Role::Gateway, true)?;
    require(
        matches!(state()?.as_str(), "inactive" | "failed"),
        "gateway_still_running",
    )
}

pub fn prepare() -> Result<Zeroizing<String>> {
    require(state()? == "active", "gateway_unavailable")?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes.as_mut()))
        .map_err(|_| Error("random_failed"))?;
    let token = Zeroizing::new(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    // Only the point-to-point Ethernet socket is accessible to the session VM.
    // Its parent remains private to UID 1101; systemd binds this one socket.
    let path = c"/run/oblivion-gateway-vm/inside.sock";
    require(
        unsafe { libc::chown(path.as_ptr(), vm::GATEWAY_UID, vm::VM_UID) } == 0,
        "gateway_network_unavailable",
    )?;
    fs::set_permissions(
        Path::new("/run/oblivion-gateway-vm/inside.sock"),
        fs::Permissions::from_mode(0o660),
    )
    .map_err(|_| Error("gateway_network_unavailable"))?;
    Ok(token)
}

pub fn grant(token: &str, tools: Option<Tools>) -> Result<()> {
    request(&Request::Grant { token, tools }, true)
}

pub fn revoke() -> Result<()> {
    if state()? == "active" && request(&Request::Revoke {}, false).is_ok() {
        return Ok(());
    }
    // A missing acknowledgement is not a successful revocation. Destroy the
    // entire gateway before allowing storage closure or another session.
    destroy()
}

pub fn ready() -> Result<()> {
    require(state()? == "active", "gateway_unavailable")?;
    request(&Request::Check {}, false)
}

fn request(request: &Request<'_>, active: bool) -> Result<()> {
    let stream = UnixStream::connect(SOCKET).map_err(|_| Error("gateway_unavailable"))?;
    peer(&stream, 0)?;
    let mut channel = Channel::new(
        &stream,
        Duration::from_secs(if matches!(request, Request::Stop {}) {
            30
        } else {
            10
        }),
    );
    let bytes =
        Zeroizing::new(serde_json::to_vec(request).map_err(|_| Error("gateway_encode_failed"))?);
    send(&mut channel, &bytes)?;
    configured(&mut channel, active)
}

pub fn serve(
    config: &vm::Config,
    key: crate::storage::ApiKey,
    transport: Transport,
    network: bool,
) -> Result<()> {
    require(
        network || matches!(transport, Transport::Tor {}),
        "external_proxy_requires_network",
    )?;
    let _lock = lock_named("gateway.lock")?;
    config.validate()?;
    config.start_role(Role::Gateway)?;
    let result = connected(key, transport, network);
    let stopped = vm::stop_role(Role::Gateway, true);
    result?;
    stopped
}

fn connected(key: crate::storage::ApiKey, transport: Transport, network: bool) -> Result<()> {
    let tor = matches!(transport, Transport::Tor {});
    let stream = UnixStream::connect(format!("{}/control.sock", Role::Gateway.runtime()))
        .map_err(|_| Error("gateway_channel_unavailable"))?;
    peer(&stream, vm::GATEWAY_UID)?;
    let mut channel = Channel::new(&stream, Duration::from_secs(60));
    vm::resume_gateway()?;
    let ready: Ready = serde_json::from_slice(&receive(&mut channel)?)
        .map_err(|_| Error("invalid_gateway_ready"))?;
    require(ready.ready && ready.version == 1, "invalid_gateway_ready")?;
    #[derive(Serialize)]
    struct Configure<'a> {
        operation: &'static str,
        provider: Provider,
        api_key: &'a str,
        transport: &'a Transport,
    }
    let request = Zeroizing::new(
        serde_json::to_vec(&Configure {
            operation: "configure",
            provider: key.provider,
            transport: &transport,
            api_key: std::str::from_utf8(&key.secret).map_err(|_| Error("invalid_api_key"))?,
        })
        .map_err(|_| Error("gateway_encode_failed"))?,
    );
    let mut channel = Channel::new(&stream, Duration::from_secs(30));
    send(&mut channel, &request)?;
    drop(request);
    drop(key);
    drop(transport);
    configured(&mut channel, false)?;
    // SOCKS does not read, import, checkpoint or mutate Tor's saved guards.
    let mut saved = if tor {
        crate::storage::tor_state()?
    } else {
        None
    };
    let writable = tor && crate::storage::tor_state_writable()?;
    let bootstrapped = if tor {
        #[derive(Serialize)]
        struct Initialize<'a> {
            operation: &'static str,
            state: Option<&'a str>,
        }
        let initial = serde_json::to_vec(&Initialize {
            operation: "tor-initialize",
            state: saved.as_ref().map(oblivion_tor_state::State::as_str),
        })
        .map_err(|_| Error("gateway_encode_failed"))?;
        exchange(&stream, &initial, false)?;
        checkpoint(&stream, &mut saved, writable, false)?
    } else {
        true
    };
    let mut network_ready = !network || bootstrapped;
    if network && tor {
        exchange(&stream, b"{\"operation\":\"tor-enable\"}", false)?;
    }
    let mut observed = observe(&stream)?;
    let mut observed_at = Instant::now();
    network_ready = network_ready && observed.isolated && (!network || observed.ready);
    if let Ok(meta) = fs::symlink_metadata(SOCKET) {
        require(meta.file_type().is_socket(), "invalid_gateway_socket")?;
        fs::remove_file(SOCKET).map_err(|_| Error("gateway_socket_failed"))?;
    }
    let listener = UnixListener::bind(SOCKET).map_err(|_| Error("gateway_socket_failed"))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Error("gateway_socket_failed"))?;
    crate::ipc::notify_ready()?;
    let mut active = false;
    let mut session = None;
    let mut checked = Instant::now();
    // Only privileged storage workers can request a grant or revocation.
    loop {
        if let Some(process) = &session {
            if session_exited(process)? {
                exchange(&stream, b"{\"operation\":\"revoke\"}", false)?;
                active = false;
                session = None;
            }
        }
        match listener.accept() {
            Ok((client, _)) => {
                peer(&client, 0)?;
                let bytes = receive(&mut Channel::new(&client, Duration::from_secs(5)))?;
                let request: Request<'_> =
                    serde_json::from_slice(&bytes).map_err(|_| Error("invalid_gateway_request"))?;
                if matches!(request, Request::Observe {}) {
                    let observation = Observation {
                        ready: network_ready && network,
                        isolated: observed.isolated,
                        tor,
                        age_ms: observed_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        tor_progress: observed.tor_progress.filter(|value| *value <= 100),
                    };
                    send(
                        &mut Channel::new(&client, Duration::from_secs(2)),
                        &serde_json::to_vec(&observation)
                            .map_err(|_| Error("gateway_encode_failed"))?,
                    )?;
                    continue;
                }
                if matches!(request, Request::Check {} | Request::Grant { .. })
                    && (!network_ready || observed_at.elapsed() > Duration::from_secs(10))
                {
                    send(
                        &mut Channel::new(&client, Duration::from_secs(5)),
                        b"{\"ok\":false,\"configured\":true,\"active\":false}",
                    )?;
                    continue;
                }
                if matches!(request, Request::Stop {}) {
                    if tor {
                        checkpoint(&stream, &mut saved, writable, true)?;
                    } else {
                        exchange(&stream, b"{\"operation\":\"shutdown\"}", false)?;
                    }
                    send(
                        &mut Channel::new(&client, Duration::from_secs(5)),
                        b"{\"ok\":true,\"configured\":true,\"active\":false}",
                    )?;
                    return Ok(());
                }
                let next = match request {
                    Request::Grant { token, .. } => {
                        require(
                            !active
                                && token.len() == 64
                                && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
                            "invalid_gateway_grant",
                        )?;
                        // QEMU is already running with its vCPUs paused. Bind
                        // this grant to that process before it can use the API.
                        session = Some(watch_session()?);
                        true
                    }
                    Request::Revoke {} => false,
                    Request::Check {} => active,
                    Request::Stop {} | Request::Observe {} => unreachable!(),
                };
                exchange(
                    &stream,
                    if matches!(request, Request::Check {}) {
                        b"{\"operation\":\"status\"}"
                    } else {
                        &bytes
                    },
                    next,
                )?;
                active = next;
                if !active {
                    session = None;
                }
                send(
                    &mut Channel::new(&client, Duration::from_secs(5)),
                    if active {
                        b"{\"ok\":true,\"configured\":true,\"active\":true}"
                    } else {
                        b"{\"ok\":true,\"configured\":true,\"active\":false}"
                    },
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(Error("gateway_socket_failed")),
        }
        std::thread::sleep(Duration::from_millis(250));
        exchange(&stream, b"{\"operation\":\"status\"}", active)?;
        if checked.elapsed() >= Duration::from_secs(4) {
            checked = Instant::now();
            let bootstrapped = if tor {
                checkpoint(&stream, &mut saved, writable, false)?
            } else {
                true
            };
            observed = observe(&stream)?;
            observed_at = Instant::now();
            network_ready = observed.isolated && (!network || (bootstrapped && observed.ready));
        }
    }
}

fn watch_session() -> Result<OwnedFd> {
    // Connect only while the guest is paused, then release the console before
    // the manager attaches. No guest output or extra virtual device is needed.
    let console = UnixStream::connect("/run/oblivion-session/console.sock")
        .map_err(|_| Error("session_watch_unavailable"))?;
    peer(&console, vm::VM_UID)?;
    let mut fd = -1;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    // SO_PEERPIDFD is Linux 6.5+; 77 is its x86_64/aarch64 ABI value, not yet
    // exported by the pinned libc crate. This avoids reopening a recycled PID.
    require(
        unsafe {
            libc::getsockopt(
                console.as_raw_fd(),
                libc::SOL_SOCKET,
                77,
                (&mut fd as *mut libc::c_int).cast(),
                &mut size,
            )
        } == 0,
        "session_watch_unavailable",
    )?;
    let process = unsafe { OwnedFd::from_raw_fd(fd) };
    require(!session_exited(&process)?, "session_already_exited")?;
    Ok(process)
}

fn session_exited(process: &OwnedFd) -> Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: process.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    require(
        unsafe { libc::poll(&mut descriptor, 1, 0) } >= 0,
        "session_watch_failed",
    )?;
    Ok(descriptor.revents != 0)
}

pub fn peer(stream: &UnixStream, uid: u32) -> Result<()> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            ) == 0
        } && peer.uid == uid,
        "invalid_gateway_peer",
    )
}

fn exchange(stream: &UnixStream, bytes: &[u8], active: bool) -> Result<()> {
    let mut channel = Channel::new(stream, Duration::from_secs(30));
    send(&mut channel, bytes)?;
    configured(&mut channel, active)
}

fn configured(stream: &mut Channel<'_>, active: bool) -> Result<()> {
    let status: Status =
        serde_json::from_slice(&receive(stream)?).map_err(|_| Error("invalid_gateway_status"))?;
    require(status.ok, "gateway_not_ready")?;
    require(
        status.configured && status.active == active,
        "gateway_state_mismatch",
    )
}

fn checkpoint(
    stream: &UnixStream,
    saved: &mut Option<oblivion_tor_state::State>,
    writable: bool,
    stop: bool,
) -> Result<bool> {
    let mut channel = Channel::new(stream, Duration::from_secs(30));
    send(
        &mut channel,
        if stop {
            b"{\"operation\":\"tor-snapshot\",\"stop\":true}"
        } else {
            b"{\"operation\":\"tor-snapshot\",\"stop\":false}"
        },
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Snapshot {
        ok: bool,
        state: String,
        bootstrapped: bool,
    }
    let snapshot: Snapshot = serde_json::from_slice(&receive(&mut channel)?)
        .map_err(|_| Error("invalid_tor_snapshot"))?;
    require(snapshot.ok, "tor_snapshot_failed")?;
    let state = oblivion_tor_state::State::parse(&snapshot.state)
        .map_err(|_| Error("invalid_tor_state"))?;
    if saved
        .as_ref()
        .is_none_or(|previous| !previous.same_guards(&state))
    {
        if writable {
            crate::storage::save_tor_state(&state)?;
        }
        *saved = Some(state);
    }
    Ok(snapshot.bootstrapped
        && saved
            .as_ref()
            .is_some_and(oblivion_tor_state::State::has_guards))
}

fn send(stream: &mut Channel<'_>, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .map_err(|_| Error("gateway_channel_failed"))
}

fn receive(stream: &mut Channel<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let mut size = [0; 4];
    stream
        .read_exact(&mut size)
        .map_err(|_| Error("gateway_channel_failed"))?;
    let size = u32::from_be_bytes(size) as usize;
    require((1..=512 * 1024).contains(&size), "invalid_gateway_frame")?;
    let mut bytes = Zeroizing::new(vec![0; size]);
    stream
        .read_exact(&mut bytes)
        .map_err(|_| Error("gateway_channel_failed"))?;
    Ok(bytes)
}
