use crate::storage::{Error, Result, lock_named, require};
use oblivion_host::channel::Channel;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

pub const SOCKET: &str = "/run/oblivion-control.sock";

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    InitGeneral,
    PrepareUsb,
    SaveNetwork,
    Settings,
    SettingsCatalog,
    ClaimIntro,
    OpenDocuments,
    OpenDocumentsEphemeral,
    StartChat,
    ChatReady,
    ChatRecover,
    Browse,
    NetworkMenu,
    Connections,
    DiscardGeneralPending,
    DiscardSessionPending,
    Unlock,
    UnlockEphemeral,
    Create,
    RenameSession,
    Open,
    OpenEphemeral,
    Close,
    ForceClose,
    Lock,
    Status,
    Debug,
    Console,
    SetApiKey,
    ClearApiKey,
    ApiKeys,
    Egress,
    NetworkPolicy,
    Transfers,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: Operation,
    session: Option<String>,
    secret_len: u16,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    output: String,
    error: Option<String>,
    #[serde(skip)]
    console: Option<UnixStream>,
}

pub fn serve(config: &Path, uid: u32) -> Result<()> {
    let _lock = lock_named("daemon.lock")?;
    // /run is root-owned. The lock prevents unlinking the socket of a live daemon.
    // A manager can connect but cannot replace its inode or choose another path.
    if Path::new(SOCKET).exists() {
        fs::remove_file(SOCKET).map_err(|_| Error("socket_cleanup_failed"))?;
    }
    let listener = UnixListener::bind(SOCKET).map_err(|_| Error("socket_bind_failed"))?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("socket_permissions_failed"))?;
    unsafe {
        require(
            libc::chown(c"/run/oblivion-control.sock".as_ptr(), uid, !0) == 0,
            "socket_owner_failed",
        )?;
    }
    notify_ready()?;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let response = match handle(&mut stream, config, uid) {
            Ok(response) => response,
            Err(error) => Response {
                ok: false,
                output: String::new(),
                error: Some(error.0.to_owned()),
                console: None,
            },
        };
        // Only a connected serial console descriptor is delegated, never QMP or
        // permission to traverse the hypervisor's private runtime directory.
        let mut channel = Channel::new(&stream, Duration::from_secs(10));
        if let Some(console) = &response.console {
            if channel.prepare_write().is_err() || send_console(&stream, console).is_err() {
                continue;
            }
        }
        // One request per connection; neither payloads nor errors are logged.
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = channel.write_all(&bytes);
        }
    }
    Err(Error("listener_stopped"))
}

fn handle(stream: &mut UnixStream, config: &Path, uid: u32) -> Result<Response> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    unsafe {
        require(
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut length,
            ) == 0,
            "peer_check_failed",
        )?;
        require(peer.assume_init().uid == uid, "unauthorized_peer")?;
    }
    let mut channel = Channel::new(stream, Duration::from_secs(10));
    let mut size = [0; 4];
    channel
        .read_exact(&mut size)
        .map_err(|_| Error("invalid_frame"))?;
    let size = u32::from_be_bytes(size) as usize;
    require((1..=1024).contains(&size), "invalid_frame_length")?;
    let mut header = vec![0; size];
    channel
        .read_exact(&mut header)
        .map_err(|_| Error("invalid_frame"))?;
    let request: Request = serde_json::from_slice(&header).map_err(|_| Error("invalid_request"))?;
    require(
        request.secret_len
            <= if matches!(
                request.operation,
                Operation::ApiKeys
                    | Operation::Browse
                    | Operation::PrepareUsb
                    | Operation::Settings
                    | Operation::Egress
                    | Operation::NetworkPolicy
                    | Operation::Transfers
                    | Operation::Connections
            ) {
                4096
            } else {
                1024
            },
        "invalid_secret_length",
    )?;
    require(
        matches!(
            request.operation,
            Operation::Open | Operation::OpenDocuments | Operation::DiscardSessionPending
        ) == request.session.is_some(),
        "invalid_session_argument",
    )?;
    if let Some(id) = &request.session {
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid_session_id",
        )?;
    }
    let needs_secret = matches!(
        request.operation,
        Operation::InitGeneral
            | Operation::PrepareUsb
            | Operation::Unlock
            | Operation::UnlockEphemeral
            | Operation::Create
            | Operation::RenameSession
            | Operation::Open
            | Operation::OpenDocuments
            | Operation::SetApiKey
            | Operation::ApiKeys
            | Operation::Egress
            | Operation::NetworkPolicy
            | Operation::Transfers
            | Operation::Settings
            | Operation::Browse
            | Operation::Connections
            | Operation::Debug
    );
    require(
        needs_secret == (request.secret_len > 0),
        "unexpected_secret",
    )?;
    let mut secret = Zeroizing::new(vec![0; request.secret_len as usize]);
    channel
        .read_exact(&mut secret)
        .map_err(|_| Error("incomplete_secret"))?;
    if matches!(request.operation, Operation::Console) {
        let _lock = lock_named("storage.lock")?;
        require(!crate::vm::stopped()?, "vm_not_running")?;
        let console = UnixStream::connect("/run/oblivion-session/console.sock")
            .map_err(|_| Error("console_unavailable"))?;
        return Ok(Response {
            ok: true,
            output: String::new(),
            error: None,
            console: Some(console),
        });
    }
    let operation = match request.operation {
        Operation::InitGeneral => "init-general",
        Operation::PrepareUsb => "prepare-usb",
        Operation::SaveNetwork => "save-network",
        Operation::Settings => "settings",
        Operation::SettingsCatalog => "settings-catalog",
        Operation::ClaimIntro => "claim-intro",
        Operation::OpenDocuments => "enter-documents",
        Operation::OpenDocumentsEphemeral => "enter-documents-ephemeral",
        Operation::StartChat => "start-chat",
        Operation::ChatReady => "chat-ready",
        Operation::ChatRecover => "chat-recover",
        Operation::Browse => "browse",
        Operation::NetworkMenu => "network-menu",
        Operation::Connections => "connections",
        Operation::DiscardGeneralPending => "discard-general-pending",
        Operation::DiscardSessionPending => "discard-session-pending",
        Operation::Unlock => "unlock",
        Operation::UnlockEphemeral => "unlock-ephemeral",
        Operation::Create => "create",
        Operation::RenameSession => "rename-session",
        Operation::Open => "enter",
        Operation::OpenEphemeral => "enter-ephemeral",
        Operation::Close => "leave",
        Operation::ForceClose => "force-leave",
        Operation::Lock => "lock",
        Operation::Status => "status",
        Operation::Debug => "debug",
        Operation::SetApiKey => "set-api-key",
        Operation::ClearApiKey => "clear-api-key",
        Operation::ApiKeys => "api-keys",
        Operation::Egress => "egress",
        Operation::NetworkPolicy => "network-policy",
        Operation::Transfers => "transfers",
        Operation::Console => unreachable!(),
    };
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| Error("executable_unavailable"))?);
    command
        .args(["--config"])
        .arg(config)
        .arg(operation)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(id) = request.session {
        command.arg(id);
    }
    let mut child = command
        .spawn()
        .map_err(|_| Error("operation_start_failed"))?;
    let input = child
        .stdin
        .take()
        .ok_or(Error("secret_pipe_failed"))?
        .write_all(&secret);
    let output = child
        .wait_with_output()
        .map_err(|_| Error("operation_wait_failed"))?;
    input.map_err(|_| Error("secret_pipe_failed"))?;
    Ok(Response {
        console: None,
        ok: output.status.success(),
        output: String::from_utf8(output.stdout).map_err(|_| Error("invalid_response"))?,
        error: if output.status.success() {
            None
        } else {
            Some(
                String::from_utf8(output.stderr)
                    .map_err(|_| Error("invalid_response"))?
                    .trim()
                    .to_owned(),
            )
        },
    })
}

fn send_console(stream: &UnixStream, console: &UnixStream) -> Result<()> {
    // usize storage gives cmsghdr its required alignment on both target architectures.
    let mut control = [0usize; 8];
    let mut byte = b'F';
    let mut data = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize };
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), console.as_raw_fd());
        require(
            libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) == 1,
            "console_transfer_failed",
        )
    }
}

pub fn notify_ready() -> Result<()> {
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        let address = if let Some(name) = path.as_bytes().strip_prefix(b"@") {
            SocketAddr::from_abstract_name(name)
        } else {
            SocketAddr::from_pathname(path)
        }
        .map_err(|_| Error("notify_address_failed"))?;
        UnixDatagram::unbound()
            .and_then(|socket| socket.send_to_addr(b"READY=1", &address))
            .map_err(|_| Error("notify_failed"))?;
    }
    Ok(())
}
