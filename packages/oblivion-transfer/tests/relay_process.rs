#![cfg(target_os = "linux")]
mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{self, Approval, OfferRequest, read_message, write_message};
use oblivion_transfer::{Limits, Manifest, Receipt, relay};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const LIMITS: Limits = Limits {
    entries: 64,
    bytes: 1024 * 1024,
};

fn file(stream: UnixStream) -> File {
    OwnedFd::from(stream).into()
}
fn channel(stream: UnixStream) -> Channel {
    Channel::new(file(stream), Duration::from_secs(10)).unwrap()
}
fn request() -> OfferRequest {
    OfferRequest {
        id: ID.into(),
        limits: LIMITS,
        paths: vec!["document.txt".into()],
    }
}

struct Worker(Child);

impl Worker {
    fn relay(source: File, destination: File, control: File) -> Self {
        // Pin all inherited descriptors above the destination range before dup2.
        // This prevents FD3/4/5 remapping from clobbering another input.
        let inputs: Vec<OwnedFd> = [source, destination, control]
            .iter()
            .map(|file| {
                let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
                assert!(fd >= 10);
                unsafe { OwnedFd::from_raw_fd(fd) }
            })
            .collect();
        let fds = [
            inputs[0].as_raw_fd(),
            inputs[1].as_raw_fd(),
            inputs[2].as_raw_fd(),
        ];
        let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-copy-relay"));
        command
            .arg("30000")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                for (index, fd) in fds.iter().enumerate() {
                    if libc::dup2(*fd, index as i32 + 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Self(command.spawn().unwrap())
    }

    fn finish(&mut self, success: bool) {
        let status = self.0.wait().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            if success {
                b"".as_slice()
            } else {
                b"transfer_failed\n".as_slice()
            }
        );
        assert_eq!(status.success(), success);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket_owner(path: &Path) -> (Worker, UnixStream) {
    let listener = UnixListener::bind(path).unwrap();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_encoded_bytes();
    assert!(bytes.len() < address.sun_path.len());
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let mut command = Command::new("/bin/sleep");
    command
        .arg("30")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Only async-signal-safe syscalls in the forked child. The connection is
    // established by this child, so SO_PEERPIDFD refers to its real identity.
    unsafe {
        command.pre_exec(move || {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            if fd < 0
                || libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_un).cast(),
                    size_of::<libc::sockaddr_un>() as _,
                ) < 0
                || libc::dup2(fd, 3) < 0
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if fd != 3 {
                libc::close(fd);
            }
            Ok(())
        });
    }
    let worker = Worker(command.spawn().unwrap());
    (worker, listener.accept().unwrap().0)
}

#[test]
fn compiled_relay_uses_inherited_ports_and_verifies_the_full_copy() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("document.txt"), b"PRIVATE_RELAY_COMPILED_39").unwrap();
    let (sender, from) = UnixStream::pair().unwrap();
    let (receiver, to) = UnixStream::pair().unwrap();
    let (control, controller) = UnixStream::pair().unwrap();
    let mut worker = Worker::relay(file(from), file(to), file(controller));
    let from = source.0.clone();
    let to = target.0.clone();
    let sender = std::thread::spawn(move || endpoint::send(&mut channel(sender), &from));
    let receiver = std::thread::spawn(move || endpoint::accept(&mut channel(receiver), &to));
    let mut control = channel(control);
    write_message(&mut control, &request()).unwrap();
    let manifest = Manifest::read(&mut control, LIMITS).unwrap();
    let status = fs::read_to_string(format!("/proc/{}/status", worker.0.id())).unwrap();
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    write_message(
        &mut control,
        &Approval {
            id: ID.into(),
            manifest_sha256: manifest.sha256(),
        },
    )
    .unwrap();
    let receipt: Receipt = read_message(&mut control, 1024).unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.manifest_sha256, manifest.sha256());
    sender.join().unwrap().unwrap();
    receiver.join().unwrap().unwrap();
    worker.finish(true);
    assert_eq!(
        fs::read(target.0.join(ID).join("files/document.txt")).unwrap(),
        b"PRIVATE_RELAY_COMPILED_39"
    );
}

#[test]
fn real_peer_process_death_revokes_the_other_blocked_channel() {
    let tree = Tree::new();
    let (mut owner, destination) = socket_owner(&tree.0.join("owner.sock"));
    let (source, from) = UnixStream::pair().unwrap();
    let (control, controller) = UnixStream::pair().unwrap();
    let mut worker = Worker::relay(file(from), file(destination), file(controller));
    let mut source = channel(source);
    let mut control = channel(control);
    write_message(&mut control, &request()).unwrap();
    let _: OfferRequest = read_message(&mut source, 64 * 1024).unwrap();
    // The relay is waiting for the source offer, not reading the destination.
    // Reaping its owner must therefore wake it through the pinned process FD.
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert_eq!(control.read(&mut [0]).unwrap(), 0);
    assert_eq!(source.read(&mut [0]).unwrap(), 0);
    worker.finish(false);
}

#[test]
fn owner_handle_is_a_kernel_pidfd_and_survives_path_removal() {
    let tree = Tree::new();
    let (mut owner, socket) = socket_owner(&tree.0.join("owner.sock"));
    let descriptor = relay::peer_process(&file(socket)).unwrap();
    assert_eq!(
        fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd())).unwrap(),
        Path::new("anon_inode:[pidfd]")
    );
    fs::remove_file(tree.0.join("owner.sock")).unwrap();
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let mut reader = channel(reader);
    reader.watch(descriptor);
    writer.write_all(b"still live").unwrap();
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert_eq!(
        reader.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
}
