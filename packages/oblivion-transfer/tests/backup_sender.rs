mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{
    Approval, OfferRequest, ReceiveRequest, read_message, write_message,
};
use oblivion_transfer::{ENCRYPTED_VOLUME_NAME, Entry, Limits, Manifest, Receipt, Selection};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const MIB: u64 = 1024 * 1024;

struct Endpoint {
    child: Child,
    channel: Channel,
    socket: UnixStream,
}

impl Endpoint {
    fn start(role: &str, source: File, maximum: u64) -> Self {
        let (stream, peer) = UnixStream::pair().unwrap();
        // Reserve both sources above the destinations before dup2: otherwise
        // mapping the channel to fd 3 could replace the source file itself.
        let descriptor = |file: libc::c_int| {
            let fd = unsafe { libc::fcntl(file, libc::F_DUPFD_CLOEXEC, 10) };
            assert!(fd >= 10);
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let channel = descriptor(peer.as_raw_fd());
        let source = descriptor(source.as_raw_fd());
        let channel_fd = channel.as_raw_fd();
        let source_fd = source.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-copy"));
        command
            .args([role, &maximum.to_string(), "60000"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(channel_fd, 3) < 0 || libc::dup2(source_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        Self {
            child,
            channel: Channel::new(
                File::from(OwnedFd::from(stream.try_clone().unwrap())),
                Duration::from_secs(60),
            )
            .unwrap(),
            socket: stream,
        }
    }

    fn finish(&mut self, success: bool) {
        if success {
            self.channel.write_all(b"released\n").unwrap();
        }
        assert_eq!(self.child.wait().unwrap().success(), success);
        let mut output = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        assert!(output.is_empty());
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        assert_eq!(
            output,
            if success {
                b"".as_slice()
            } else {
                b"transfer_failed\n".as_slice()
            }
        );
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn default_sized_volume_streams_from_only_the_delegated_descriptor() {
    let source = Tree::new();
    let destination = Tree::new();
    let path = source.0.join("private-session-id.luks");
    let mut fixture = File::create(&path).unwrap();
    // Synthetic transport fixture: a signature is not a valid encrypted disk.
    fixture
        .write_all(b"LUKS\xba\xbe\x00\x02PINNED_DESCRIPTOR")
        .unwrap();
    fixture.set_len(512 * MIB).unwrap();
    drop(fixture);
    let mut sender = Endpoint::start("send-open-file", File::open(&path).unwrap(), 512 * MIB);
    let pending = destination.0.join("new-archive.pending");
    let target = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .unwrap();
    let mut receiver = Endpoint::start("receive-open-file", target, 512 * MIB);
    fs::rename(&pending, destination.0.join("pinned-destination.pending")).unwrap();
    fs::write(&pending, b"UNSELECTED_DESTINATION_MUST_NOT_CHANGE").unwrap();
    fs::rename(&path, source.0.join("selected-original.luks")).unwrap();
    fs::write(&path, b"UNSELECTED_REPLACEMENT_MUST_NOT_BE_COPIED").unwrap();
    let limits = Limits {
        entries: 1,
        bytes: 512 * MIB,
    };
    write_message(
        &mut sender.channel,
        &OfferRequest {
            id: ID.into(),
            limits,
            paths: vec![ENCRYPTED_VOLUME_NAME.into()],
        },
    )
    .unwrap();
    let manifest = Manifest::read(&mut sender.channel, limits).unwrap();
    assert_eq!(manifest.bytes(), 512 * MIB);
    assert_eq!(manifest.entries().len(), 1);
    assert_eq!(manifest.entries()[0].path(), ENCRYPTED_VOLUME_NAME);
    write_message(
        &mut receiver.channel,
        &ReceiveRequest {
            approval: Approval {
                id: ID.into(),
                manifest_sha256: manifest.sha256(),
            },
            limits,
        },
    )
    .unwrap();
    manifest.write(&mut receiver.channel).unwrap();
    let mut ready = [0; 8];
    receiver.channel.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"receive\n");
    write_message(
        &mut sender.channel,
        &Approval {
            id: ID.into(),
            manifest_sha256: manifest.sha256(),
        },
    )
    .unwrap();
    assert_eq!(
        std::io::copy(
            &mut (&mut sender.channel).take(512 * MIB + 8),
            &mut receiver.channel
        )
        .unwrap(),
        512 * MIB + 8
    );
    let receipt: Receipt = read_message(&mut receiver.channel, 1024).unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.manifest_sha256, manifest.sha256());
    assert_eq!(receipt.bytes, 512 * MIB);
    write_message(&mut sender.channel, &receipt).unwrap();
    let mut done = [0; 7];
    sender.channel.read_exact(&mut done).unwrap();
    assert_eq!(&done, b"copied\n");
    sender.finish(true);
    receiver.finish(true);
    let mut restored = File::open(destination.0.join("pinned-destination.pending")).unwrap();
    assert_eq!(restored.metadata().unwrap().len(), 512 * MIB);
    let mut prefix = [0; 25];
    restored.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"LUKS\xba\xbe\x00\x02PINNED_DESCRIPTOR");
    assert_eq!(
        fs::read(&path).unwrap(),
        b"UNSELECTED_REPLACEMENT_MUST_NOT_BE_COPIED"
    );
    assert_eq!(
        fs::read(pending).unwrap(),
        b"UNSELECTED_DESTINATION_MUST_NOT_CHANGE"
    );
}

#[test]
fn invalid_authority_limits_and_approval_never_release_file_bytes() {
    let source = Tree::new();
    let path = source.0.join("private-name.luks");
    let mut fixture = File::create(&path).unwrap();
    fixture.write_all(b"LUKS\xba\xbe\x00\x02").unwrap();
    fixture.set_len(32 * MIB).unwrap();
    drop(fixture);
    for case in 0..6 {
        let file = if case == 2 {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        } else {
            File::open(&path).unwrap()
        };
        let mut sender = Endpoint::start("send-open-file", file, 32 * MIB);
        write_message(
            &mut sender.channel,
            &OfferRequest {
                id: ID.into(),
                paths: vec![
                    if case == 0 {
                        "../private-name.luks"
                    } else {
                        ENCRYPTED_VOLUME_NAME
                    }
                    .into(),
                ],
                limits: Limits {
                    entries: if case == 3 { 2 } else { 1 },
                    bytes: if case == 1 { 64 * MIB } else { 32 * MIB },
                },
            },
        )
        .unwrap();
        if case >= 4 {
            let manifest = Manifest::read(
                &mut sender.channel,
                Limits {
                    entries: 1,
                    bytes: 32 * MIB,
                },
            )
            .unwrap();
            write_message(
                &mut sender.channel,
                &Approval {
                    id: if case == 4 { "f".repeat(32) } else { ID.into() },
                    manifest_sha256: if case == 5 {
                        "0".repeat(64)
                    } else {
                        manifest.sha256()
                    },
                },
            )
            .unwrap();
        }
        let mut leaked = Vec::new();
        sender.channel.read_to_end(&mut leaked).unwrap();
        assert!(leaked.is_empty());
        sender.finish(false);
    }
    let mut plain = File::create(&path).unwrap();
    plain
        .write_all(b"PLAINTEXT_MUST_NOT_BE_TREATED_AS_A_BACKUP")
        .unwrap();
    plain.set_len(32 * MIB).unwrap();
    drop(plain);
    let mut sender = Endpoint::start("send-open-file", File::open(&path).unwrap(), 32 * MIB);
    write_message(
        &mut sender.channel,
        &OfferRequest {
            id: ID.into(),
            limits: Limits {
                entries: 1,
                bytes: 32 * MIB,
            },
            paths: vec![ENCRYPTED_VOLUME_NAME.into()],
        },
    )
    .unwrap();
    let mut leaked = Vec::new();
    sender.channel.read_to_end(&mut leaked).unwrap();
    assert!(leaked.is_empty());
    sender.finish(false);
}

#[test]
fn receiver_refuses_unsafe_files_authority_corruption_and_truncation() {
    let tree = Tree::new();
    let source = tree.0.join("source.luks");
    let mut fixture = File::create(&source).unwrap();
    fixture.write_all(b"LUKS\xba\xbe\x00\x02FIXTURE").unwrap();
    fixture.set_len(32 * MIB).unwrap();
    drop(fixture);
    let selection = Selection::encrypted_volume(File::open(&source).unwrap(), 32 * MIB).unwrap();
    let digest = match &selection.manifest().entries()[0] {
        Entry::File { sha256, .. } => sha256.clone(),
        _ => unreachable!(),
    };
    for case in 0..11 {
        let path = tree.0.join(format!("target-{case}.pending"));
        fs::write(
            &path,
            if case == 1 {
                b"existing".as_slice()
            } else {
                b"".as_slice()
            },
        )
        .unwrap();
        if case == 2 {
            fs::hard_link(&path, tree.0.join("hardlink")).unwrap();
        }
        let file = OpenOptions::new()
            .read(true)
            .write(case != 0)
            .append(case == 3)
            .open(&path)
            .unwrap();
        let mut receiver = Endpoint::start("receive-open-file", file, 32 * MIB);
        if case >= 4 {
            let limits = Limits {
                entries: if case == 4 { 2 } else { 1 },
                bytes: if case == 5 { 64 * MIB } else { 32 * MIB },
            };
            let manifest = Manifest::new(
                vec![Entry::File {
                    path: if case == 6 {
                        "unselected.luks"
                    } else {
                        ENCRYPTED_VOLUME_NAME
                    }
                    .into(),
                    size: 32 * MIB,
                    sha256: if case == 9 {
                        "0".repeat(64)
                    } else {
                        digest.clone()
                    },
                }],
                limits,
            )
            .unwrap();
            let _ = write_message(
                &mut receiver.channel,
                &ReceiveRequest {
                    approval: Approval {
                        id: ID.into(),
                        manifest_sha256: if case == 7 {
                            "0".repeat(64)
                        } else {
                            manifest.sha256()
                        },
                    },
                    limits,
                },
            );
            let _ = manifest.write(&mut receiver.channel);
            if case >= 8 {
                let mut ready = [0; 8];
                receiver.channel.read_exact(&mut ready).unwrap();
                assert_eq!(&ready, b"receive\n");
                if case == 8 {
                    receiver.channel.write_all(b"PLAINTEXT").unwrap();
                } else if case == 10 {
                    receiver
                        .channel
                        .write_all(b"LUKS\xba\xbe\x00\x02partial")
                        .unwrap();
                } else {
                    let mut file = File::open(&source).unwrap();
                    let _ = std::io::copy(&mut file, &mut receiver.channel);
                    let _ = receiver.channel.write_all(b"OBLVEND1");
                }
            }
        }
        receiver.socket.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        let closed = receiver.channel.read_to_end(&mut response);
        assert!(
            closed.is_ok()
                || closed
                    .as_ref()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        assert!(response.is_empty(), "no receipt on failure");
        receiver.finish(false);
        if case == 1 {
            assert_eq!(fs::read(&path).unwrap(), b"existing");
        }
        if case <= 8 && case != 1 {
            assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        }
        assert!(!tree.0.join("session.oblivion").exists());
    }
}

#[test]
fn media_backup_selection_is_one_pinned_file_without_parent_directory_entries() {
    let tree = Tree::new();
    fs::create_dir_all(tree.0.join("exports/archive")).unwrap();
    let path = tree.0.join("exports/archive/session.oblivion");
    let mut file = File::create(&path).unwrap();
    file.write_all(b"LUKS\xba\xbe\x00\x02").unwrap();
    file.set_len(32 * MIB).unwrap();
    drop(file);
    let selected =
        Selection::encrypted_path(&tree.0, "exports/archive/session.oblivion", 32 * MIB).unwrap();
    assert_eq!(selected.manifest().entries().len(), 1);
    assert_eq!(
        selected.manifest().entries()[0].path(),
        ENCRYPTED_VOLUME_NAME
    );
    for path in [
        "../source",
        "/etc/passwd",
        "exports/archive",
        "exports/../../escape",
    ] {
        assert!(Selection::encrypted_path(&tree.0, path, 32 * MIB).is_err());
    }
    std::os::unix::fs::symlink("archive", tree.0.join("exports/link")).unwrap();
    assert!(Selection::encrypted_path(&tree.0, "exports/link/session.oblivion", 32 * MIB).is_err());
}
