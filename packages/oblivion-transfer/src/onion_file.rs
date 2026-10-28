//! Privileged file-VM lifecycle. HTTP runs in a different, unprivileged unit.
use crate::channel::Channel;
use crate::directory::Directory;
use crate::endpoint::{read_message, write_message};
use crate::{Entry, Limits, Receipt, Selection, invalid, require, validate_id};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ROOT: &str = "/run/oblivion-onion";
const STAGE: &str = "/run/oblivion-onion-stage";
const STATE: &str = "/run/oblivion-onion-state";
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 1024;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Backup {
        ttl_seconds: u16,
    },
    PrepareShare {},
    Share {
        receipt: Receipt,
        paths: Vec<String>,
        ttl_seconds: u16,
    },
    Receive {
        ttl_seconds: u16,
    },
    Observe {},
    Freeze {},
    Source {},
    Shutdown {},
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Fresh,
    Staging,
    Sharing,
    Receiving,
    Review,
    Copying,
    Closed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerStatus {
    state: String,
    mode: String,
    files: usize,
    bytes: u64,
    transferred_bytes: u64,
    rejected: u64,
    // Names from the HTTP process are not a filesystem authority. The copy
    // endpoint discovers actual frozen files through its existing browser.
    #[serde(default, skip_serializing)]
    received: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReply {
    ok: bool,
    status: Option<WorkerStatus>,
    error: Option<serde::de::IgnoredAny>,
}

struct Runtime {
    phase: Phase,
    worker: Option<UnixStream>,
    deadline: Option<Instant>,
}

pub fn run() -> io::Result<()> {
    require(
        std::env::args_os().len() == 1 && unsafe { libc::geteuid() } == 0,
        "isolation_required",
    )?;
    require(
        fs::read_to_string("/proc/swaps")?.lines().count() == 1,
        "swap_enabled",
    )?;
    for (root, uid) in [(ROOT, 1000), (STAGE, 1002), (STATE, 0)] {
        let directory = Directory::open(Path::new(root))?;
        let metadata = directory.metadata()?;
        require(
            metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "unsafe_runtime",
        )?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let file = File::open(root)?;
        if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        require(
            unsafe { filesystem.assume_init() }.f_type == libc::TMPFS_MAGIC,
            "runtime_not_volatile",
        )?;
    }
    fs::create_dir(format!("{ROOT}/share"))?;
    fs::set_permissions(format!("{ROOT}/share"), fs::Permissions::from_mode(0o700))?;
    owner(Path::new(&format!("{ROOT}/share")), 1000, 1000)?;
    fs::create_dir(format!("{STATE}/empty"))?;
    owner(Path::new(&format!("{STATE}/empty")), 0, 1000)?;
    fs::set_permissions(format!("{STATE}/empty"), fs::Permissions::from_mode(0o550))?;
    std::os::unix::fs::symlink(format!("{STATE}/empty"), format!("{STATE}/share"))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/dev/virtio-ports/oblivion.onion.file")?;
    let metadata = file.metadata()?;
    require(
        metadata.file_type().is_char_device()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "unsafe_control",
    )?;
    let mut mask = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        libc::sigaddset(&mut mask, libc::SIGINT);
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let signal = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if signal < 0 {
        return Err(io::Error::last_os_error());
    }
    let signal = unsafe { OwnedFd::from_raw_fd(signal) };
    let mut runtime = Runtime {
        phase: Phase::Fresh,
        worker: None,
        deadline: None,
    };
    let result = serve(&file, &signal, &mut runtime);
    let cleaned = runtime.stop();
    if result.is_err() {
        if let Ok(mut channel) = Channel::new(file.try_clone()?, Duration::from_secs(2)) {
            let _ = write_message(
                &mut channel,
                &json!({"ok":false,"error":if cleaned.is_ok() {"operation_failed"} else {"cleanup_failed"}}),
            );
        }
    }
    result?;
    cleaned
}

fn serve(file: &File, signal: &OwnedFd, runtime: &mut Runtime) -> io::Result<()> {
    write_message(
        &mut Channel::new(file.try_clone()?, Duration::from_secs(5))?,
        &json!({"ready":true,"version":1,"role":"onion-file"}),
    )?;
    loop {
        let end = (Instant::now() + Duration::from_secs(15)).min(
            runtime
                .deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(15)),
        );
        let mut channel = Channel::until(file.try_clone()?, end)?;
        channel.watch(signal.try_clone()?);
        let request: Request = read_message(&mut channel, 128 * 1024)?;
        // The idle heartbeat only bounds admission. Hashing and preparing a
        // snapshot can take longer, without granting another idle interval.
        let mut channel = Channel::new(file.try_clone()?, Duration::from_secs(120))?;
        channel.watch(signal.try_clone()?);
        match request {
            Request::Backup { ttl_seconds } => {
                require(runtime.phase == Phase::Fresh, "invalid_phase")?;
                runtime.start_worker("backup", ttl_seconds)?;
                runtime.phase = Phase::Sharing;
            }
            Request::PrepareShare {} => {
                require(runtime.phase == Phase::Fresh, "invalid_phase")?;
                service("start", &["oblivion-onion-stage.service"])?;
                runtime.phase = Phase::Staging;
            }
            Request::Share {
                receipt,
                paths,
                ttl_seconds,
            } => {
                require(runtime.phase == Phase::Staging, "invalid_phase")?;
                validate_id(&receipt.id)?;
                require(
                    receipt.entries > 0
                        && receipt.entries <= MAX_FILES
                        && receipt.bytes <= MAX_BYTES,
                    "invalid_receipt",
                )?;
                completed("oblivion-onion-stage.service")?;
                let transaction = Directory::open(Path::new(STAGE))?.directory(&receipt.id)?;
                let saved: Receipt =
                    serde_json::from_reader(transaction.source("receipt.json")?.take(4096))
                        .map_err(|_| invalid("invalid_receipt"))?;
                require(saved == receipt, "invalid_receipt")?;
                let root = Path::new(STAGE).join(&receipt.id).join("files");
                let whole = approved_snapshot(&root, &paths, &receipt)?;
                seal(&root, whole.manifest().entries(), 0, 1000, 0o550, 0o440)?;
                fs::remove_file(format!("{STATE}/share"))?;
                std::os::unix::fs::symlink(&root, format!("{STATE}/share"))?;
                runtime.start_worker("share", ttl_seconds)?;
                runtime.phase = Phase::Sharing;
            }
            Request::Receive { ttl_seconds } => {
                require(runtime.phase == Phase::Fresh, "invalid_phase")?;
                runtime.start_worker("receive", ttl_seconds)?;
                runtime.phase = Phase::Receiving;
            }
            Request::Observe {} => {
                let status = if runtime.worker.is_some() {
                    Some(runtime.worker_command("status")?)
                } else {
                    None
                };
                require(
                    runtime.phase != Phase::Sharing && runtime.phase != Phase::Receiving
                        || service_active("oblivion-onion-relay.service")?,
                    "relay_failed",
                )?;
                write_message(
                    &mut channel,
                    &json!({"ok":true,"phase":runtime.phase,"worker":status}),
                )?;
                continue;
            }
            Request::Freeze {} => {
                require(runtime.phase == Phase::Receiving, "invalid_phase")?;
                service("stop", &["oblivion-onion-relay.service"])?;
                require(
                    !service_active("oblivion-onion-relay.service")?,
                    "relay_not_stopped",
                )?;
                runtime.worker_command("handoff")?;
                runtime.worker.take();
                service(
                    "stop",
                    &[
                        "oblivion-onion-worker.socket",
                        "oblivion-onion-worker@*.service",
                    ],
                )?;
                let root = Path::new(ROOT).join("receive");
                let names = Directory::open(&root)?.names(4096)?;
                if !names.is_empty() {
                    let files = Selection::prepare(
                        &root,
                        &names,
                        Limits {
                            entries: 4096,
                            bytes: MAX_BYTES,
                        },
                    )?;
                    seal(&root, files.manifest().entries(), 1002, 1002, 0o500, 0o400)?;
                } else {
                    owner(&root, 1002, 1002)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o500))?;
                }
                runtime.phase = Phase::Review;
            }
            Request::Source {} => {
                require(runtime.phase == Phase::Review, "invalid_phase")?;
                service("start", &["oblivion-onion-source.service"])?;
                runtime.phase = Phase::Copying;
            }
            Request::Shutdown {} => {
                runtime.stop()?;
                write_message(&mut channel, &json!({"ok":true,"phase":Phase::Closed}))?;
                return Ok(());
            }
        }
        write_message(&mut channel, &json!({"ok":true,"phase":runtime.phase}))?;
    }
}

fn approved_snapshot(root: &Path, paths: &[String], receipt: &Receipt) -> io::Result<Selection> {
    // Selection order belongs to the approved manifest. Sorting the supplied
    // paths here would reject a valid receipt for a differently ordered offer.
    let selected = Selection::prepare(
        root,
        paths,
        Limits {
            entries: MAX_FILES,
            bytes: MAX_BYTES,
        },
    )?;
    require(
        selected.manifest().sha256() == receipt.manifest_sha256,
        "snapshot_changed",
    )?;
    let whole = Selection::prepare(
        root,
        &Directory::open(root)?.names(MAX_FILES)?,
        Limits {
            entries: MAX_FILES,
            bytes: MAX_BYTES,
        },
    )?;
    require(
        whole.manifest().entries().len() == receipt.entries
            && whole.manifest().bytes() == receipt.bytes,
        "unexpected_snapshot_files",
    )?;
    Ok(whole)
}

impl Runtime {
    fn start_worker(&mut self, mode: &str, ttl: u16) -> io::Result<()> {
        require((1..=3600).contains(&ttl), "invalid_deadline")?;
        service("start", &["oblivion-onion-worker.socket"])?;
        let mut socket = UnixStream::connect(format!("{STATE}/worker.sock"))?;
        socket.set_read_timeout(Some(Duration::from_secs(120)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let command = json!({"op":"start","mode":mode,"max_bytes":if mode == "backup" { crate::MAX_ENCRYPTED_VOLUME_BYTES } else { MAX_BYTES },"max_files":if mode == "backup" { 1 } else { MAX_FILES },"ttl_seconds":ttl});
        serde_json::to_writer(&mut socket, &command)?;
        socket.write_all(b"\n")?;
        let status = worker_reply(&socket)?;
        require(
            status.state == "serving" && status.mode == mode,
            "worker_not_ready",
        )?;
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        self.worker = Some(socket);
        self.deadline = Some(Instant::now() + Duration::from_secs(u64::from(ttl)));
        service("start", &["oblivion-onion-relay.service"])?;
        Ok(())
    }

    fn worker_command(&mut self, operation: &str) -> io::Result<WorkerStatus> {
        let socket = self
            .worker
            .as_mut()
            .ok_or_else(|| invalid("worker_not_started"))?;
        serde_json::to_writer(&mut *socket, &json!({"op":operation}))?;
        socket.write_all(b"\n")?;
        worker_reply(socket)
    }

    fn stop(&mut self) -> io::Result<()> {
        // Socket closure revokes the worker independently; systemd then reaps
        // its entire cgroup, the TCP relay and both copy endpoints before RAM
        // staging is removed. A failed stop is never reported as a clean close.
        self.worker.take();
        service(
            "stop",
            &[
                "oblivion-onion-relay.service",
                "oblivion-onion-worker.socket",
                "oblivion-onion-worker@*.service",
                "oblivion-onion-source.service",
                "oblivion-onion-stage.service",
            ],
        )?;
        for root in [ROOT, STAGE] {
            for entry in fs::read_dir(root)? {
                let path = entry?.path();
                if fs::symlink_metadata(&path)?.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
                }
            }
        }
        self.phase = Phase::Closed;
        self.deadline = None;
        Ok(())
    }
}

fn worker_reply(socket: &UnixStream) -> io::Result<WorkerStatus> {
    let mut bytes = Vec::new();
    BufReader::new(socket)
        .take(512 * 1024 + 1)
        .read_until(b'\n', &mut bytes)?;
    require(
        bytes.len() <= 512 * 1024 && bytes.last() == Some(&b'\n'),
        "invalid_worker_reply",
    )?;
    let reply: WorkerReply =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid_worker_reply"))?;
    require(reply.ok && reply.error.is_none(), "worker_failed")?;
    let status = reply
        .status
        .ok_or_else(|| invalid("invalid_worker_reply"))?;
    require(
        matches!(status.state.as_str(), "serving" | "frozen" | "stopped")
            && matches!(status.mode.as_str(), "share" | "receive" | "backup")
            && status.files <= MAX_FILES
            && status.bytes
                <= if status.mode == "backup" {
                    crate::MAX_ENCRYPTED_VOLUME_BYTES
                } else {
                    MAX_BYTES + 16 * 1024 * 1024
                }
            && status.transferred_bytes
                <= if status.mode == "backup" {
                    status.bytes
                } else {
                    MAX_BYTES + 16 * 1024 * 1024
                },
        "invalid_worker_reply",
    )?;
    Ok(status)
}

fn owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let path =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| invalid("invalid_path"))?;
    if unsafe { libc::lchown(path.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn seal(
    root: &Path,
    entries: &[Entry],
    uid: u32,
    gid: u32,
    directory_mode: u32,
    file_mode: u32,
) -> io::Result<()> {
    for entry in entries {
        let path = root.join(entry.path());
        owner(&path, uid, gid)?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if matches!(entry, Entry::Directory { .. }) {
                directory_mode
            } else {
                file_mode
            }),
        )?;
    }
    owner(root, uid, gid)?;
    fs::set_permissions(root, fs::Permissions::from_mode(directory_mode))
}

fn service(operation: &str, units: &[&str]) -> io::Result<()> {
    let status = Command::new("/usr/bin/systemctl")
        .arg(operation)
        .args(units)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    require(status.success(), "unit_failed")
}

fn service_active(unit: &str) -> io::Result<bool> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property=ActiveState", "--value"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    require(output.status.success(), "unit_failed")?;
    Ok(!matches!(
        output.stdout.as_slice(),
        b"inactive\n" | b"failed\n"
    ))
}

fn completed(unit: &str) -> io::Result<()> {
    require(!service_active(unit)?, "copy_not_completed")?;
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property=Result", "--value"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    require(
        output.status.success() && output.stdout == b"success\n",
        "copy_failed",
    )?;
    service("stop", &[unit])
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    use super::*;
    use support::Tree;

    #[test]
    fn snapshot_keeps_approved_order_and_rejects_changed_or_unlisted_content() {
        let tree = Tree::new();
        fs::write(tree.0.join("z.txt"), b"last").unwrap();
        fs::write(tree.0.join("a.txt"), b"first").unwrap();
        let paths = vec!["z.txt".to_string(), "a.txt".to_string()];
        let selection = Selection::prepare(
            &tree.0,
            &paths,
            Limits {
                entries: 2,
                bytes: 9,
            },
        )
        .unwrap();
        let receipt = Receipt {
            id: "0123456789abcdef0123456789abcdef".into(),
            manifest_sha256: selection.manifest().sha256(),
            entries: 2,
            bytes: 9,
        };
        assert!(approved_snapshot(&tree.0, &paths, &receipt).is_ok());
        assert!(approved_snapshot(&tree.0, &["a.txt".into(), "z.txt".into()], &receipt).is_err());
        fs::write(tree.0.join("extra.txt"), b"").unwrap();
        assert!(approved_snapshot(&tree.0, &paths, &receipt).is_err());
        fs::remove_file(tree.0.join("extra.txt")).unwrap();
        fs::write(tree.0.join("z.txt"), b"edit").unwrap();
        assert!(approved_snapshot(&tree.0, &paths, &receipt).is_err());
    }

    #[test]
    fn private_requests_cannot_choose_paths_listeners_or_commands() {
        for request in [
            json!({"operation":"receive", "ttl_seconds":30, "root":"/vault"}),
            json!({"operation":"receive", "ttl_seconds":30, "listen":"0.0.0.0"}),
            json!({"operation":"observe", "command":"sh"}),
            json!({"operation":"source", "path":"/"}),
            json!({"operation":"unknown"}),
        ] {
            assert!(serde_json::from_value::<Request>(request).is_err());
        }
    }

    #[test]
    fn worker_metadata_never_grants_a_filesystem_path() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"{\"ok\":true,\"status\":{\"state\":\"frozen\",\"mode\":\"receive\",\"files\":1,\"bytes\":3,\"transferred_bytes\":3,\"rejected\":0,\"received\":[{\"path\":\"../../vault\"}]}}\n").unwrap();
        let status = worker_reply(&receiver).unwrap();
        assert!(
            serde_json::to_value(status)
                .unwrap()
                .get("received")
                .is_none()
        );
        sender.write_all(b"{\"ok\":true,\"status\":{\"state\":\"frozen\",\"mode\":\"receive\",\"files\":1025,\"bytes\":3,\"transferred_bytes\":3,\"rejected\":0}}\n").unwrap();
        assert!(worker_reply(&receiver).is_err());
    }
}
