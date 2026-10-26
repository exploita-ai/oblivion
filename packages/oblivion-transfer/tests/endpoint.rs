mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{
    Approval, OfferRequest, ReceiveRequest, read_message, write_message,
};
use oblivion_transfer::{Limits, Manifest, Receipt, Selection};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const NAME: &str = "selected-secret-document.txt";
const CONTENT: &[u8] = b"OBLIVION_COPY_CANARY_f81d";
const LIMITS: Limits = Limits {
    entries: 64,
    bytes: 1024 * 1024,
};

#[test]
fn unavailable_directory_replies_and_keeps_the_document_channel_usable() {
    use oblivion_transfer::browser::{Request, Response};
    use oblivion_transfer::endpoint::SourceRequest;
    let source = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::write(source.0.join("workspace/note.txt"), CONTENT).unwrap();
    let mut sender = Endpoint::start("documents", &source, 5000);
    for path in ["workspace/missing", "workspace"] {
        write_message(
            &mut sender.channel,
            &SourceRequest::Browse {
                browse: Request {
                    path: path.into(),
                    after: None,
                    limit: 100,
                },
            },
        )
        .unwrap();
        let response: Response = read_message(&mut sender.channel, 65536).unwrap();
        if path.ends_with("missing") {
            assert!(matches!(response, Response::Unavailable { .. }));
            continue;
        }
        let Response::Page(page) = response else {
            panic!("directory unavailable")
        };
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].name, "note.txt");
    }
}

#[test]
fn document_sender_refuses_session_state_and_only_exports_approved_document_roots() {
    let source = Tree::new();
    fs::create_dir(source.0.join("state")).unwrap();
    fs::write(source.0.join("state/chat.db"), b"private session state").unwrap();
    for path in [
        "state/chat.db",
        "workspace/../state/chat.db",
        "/workspace/document.txt",
    ] {
        let mut sender = Endpoint::start("documents", &source, 5000);
        write_message(
            &mut sender.channel,
            &OfferRequest {
                paths: vec![path.into()],
                ..request()
            },
        )
        .unwrap();
        let mut output = Vec::new();
        sender.channel.read_to_end(&mut output).unwrap();
        assert!(output.is_empty());
        sender.finish(false);
    }
    for role in ["export", "export-portable"] {
        let source = Tree::new();
        fs::create_dir(source.0.join("workspace")).unwrap();
        fs::write(source.0.join("workspace/document.txt"), CONTENT).unwrap();
        let target = Tree::new();
        let mut sender = Endpoint::start("documents", &source, 5000);
        let mut receiver = Endpoint::start(role, &target, 5000);
        write_message(
            &mut sender.channel,
            &OfferRequest {
                paths: vec!["workspace/document.txt".into()],
                ..request()
            },
        )
        .unwrap();
        let manifest = Manifest::read(&mut sender.channel, LIMITS).unwrap();
        write_message(
            &mut receiver.channel,
            &ReceiveRequest {
                approval: approval(&manifest),
                limits: LIMITS,
            },
        )
        .unwrap();
        manifest.write(&mut receiver.channel).unwrap();
        let mut ready = [0; 8];
        receiver.channel.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"receive\n");
        write_message(&mut sender.channel, &approval(&manifest)).unwrap();
        let mut data = vec![0; CONTENT.len() + 8];
        sender.channel.read_exact(&mut data).unwrap();
        receiver.channel.write_all(&data).unwrap();
        let receipt: Receipt = read_message(&mut receiver.channel, 1024).unwrap();
        write_message(&mut sender.channel, &receipt).unwrap();
        let mut done = [0; 7];
        sender.channel.read_exact(&mut done).unwrap();
        assert_eq!(&done, b"copied\n");
        sender.finish(true);
        receiver.finish(true);
        assert_eq!(
            fs::read(
                target
                    .0
                    .join(format!("Oblivion-{ID}/files/workspace/document.txt"))
            )
            .unwrap(),
            CONTENT
        );
    }
}

struct Endpoint {
    child: Child,
    channel: Channel,
}

impl Endpoint {
    fn start(role: &str, root: &Tree, budget: u64) -> Self {
        Self::spawn(role, root, None, budget)
    }

    fn spawn(role: &str, root: &Tree, published: Option<&Tree>, budget: u64) -> Self {
        let (stream, peer) = UnixStream::pair().unwrap();
        let fd = peer.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-copy"));
        command
            .args([role, root.0.to_str().unwrap()])
            .args(published.map(|tree| &tree.0))
            .arg(budget.to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        drop(peer);
        Self {
            child,
            channel: Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5))
                .unwrap(),
        }
    }

    fn finish(&mut self, success: bool) {
        assert_eq!(self.child.wait().unwrap().success(), success);
        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        let mut stderr = Vec::new();
        self.child
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
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request() -> OfferRequest {
    OfferRequest {
        id: ID.into(),
        limits: LIMITS,
        paths: vec![NAME.into()],
    }
}

fn approval(manifest: &Manifest) -> Approval {
    Approval {
        id: ID.into(),
        manifest_sha256: manifest.sha256(),
    }
}

#[test]
fn compiled_endpoints_copy_only_after_approval_and_verify_the_receipt() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    fs::write(source.0.join("unselected"), b"do not copy").unwrap();
    let mut sender = Endpoint::start("send", &source, 5000);
    let mut receiver = Endpoint::start("receive", &target, 5000);
    write_message(&mut sender.channel, &request()).unwrap();
    let manifest = Manifest::read(&mut sender.channel, LIMITS).unwrap();
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());

    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string(format!("/proc/{}/status", sender.child.id())).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        let cmdline = fs::read(format!("/proc/{}/cmdline", sender.child.id())).unwrap();
        assert!(!String::from_utf8_lossy(&cmdline).contains(NAME));
        assert!(!String::from_utf8_lossy(&cmdline).contains(std::str::from_utf8(CONTENT).unwrap()));
    }

    write_message(
        &mut receiver.channel,
        &ReceiveRequest {
            approval: approval(&manifest),
            limits: LIMITS,
        },
    )
    .unwrap();
    manifest.write(&mut receiver.channel).unwrap();
    let mut ready = [0; 8];
    receiver.channel.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"receive\n");
    write_message(&mut sender.channel, &approval(&manifest)).unwrap();
    let count = std::io::copy(
        &mut Read::by_ref(&mut sender.channel).take(manifest.bytes() + 8),
        &mut receiver.channel,
    )
    .unwrap();
    assert_eq!(count, manifest.bytes() + 8);
    let receipt: Receipt = read_message(&mut receiver.channel, 1024).unwrap();
    assert_eq!(receipt.manifest_sha256, manifest.sha256());
    assert_eq!(receipt.bytes, CONTENT.len() as u64);
    write_message(&mut sender.channel, &receipt).unwrap();
    let mut done = [0; 7];
    sender.channel.read_exact(&mut done).unwrap();
    assert_eq!(&done, b"copied\n");
    sender.finish(true);
    receiver.finish(true);
    assert_eq!(
        fs::read(target.0.join(ID).join("files").join(NAME)).unwrap(),
        CONTENT
    );
    assert!(!target.0.join(ID).join("files/unselected").exists());
}

#[test]
fn sender_does_not_release_file_bytes_for_a_different_approval() {
    let source = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    for wrong_id in [true, false] {
        let mut sender = Endpoint::start("send", &source, 5000);
        write_message(&mut sender.channel, &request()).unwrap();
        let manifest = Manifest::read(&mut sender.channel, LIMITS).unwrap();
        let mut selected = approval(&manifest);
        if wrong_id {
            selected.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        }
        if !wrong_id {
            selected.manifest_sha256 = "0".repeat(64);
        }
        write_message(&mut sender.channel, &selected).unwrap();
        let mut bytes = Vec::new();
        sender.channel.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        sender.finish(false);
    }
}

#[test]
fn receiver_rejects_unapproved_offer_and_quota_before_creating_files() {
    let source = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &[NAME.into()], LIMITS).unwrap();
    for wrong_hash in [true, false] {
        let target = Tree::new();
        let mut receiver = Endpoint::start("receive", &target, 5000);
        let mut selected = approval(selection.manifest());
        if wrong_hash {
            selected.manifest_sha256 = "0".repeat(64);
        }
        write_message(
            &mut receiver.channel,
            &ReceiveRequest {
                approval: selected,
                limits: if wrong_hash {
                    LIMITS
                } else {
                    Limits {
                        entries: 64,
                        bytes: 1,
                    }
                },
            },
        )
        .unwrap();
        selection.manifest().write(&mut receiver.channel).unwrap();
        let mut bytes = Vec::new();
        receiver.channel.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        receiver.finish(false);
        assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
    }
}

#[test]
fn forged_receipt_never_reports_success_to_the_sender() {
    let source = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    let mut sender = Endpoint::start("send", &source, 5000);
    write_message(&mut sender.channel, &request()).unwrap();
    let manifest = Manifest::read(&mut sender.channel, LIMITS).unwrap();
    write_message(&mut sender.channel, &approval(&manifest)).unwrap();
    let mut payload = vec![0; manifest.bytes() as usize + 8];
    sender.channel.read_exact(&mut payload).unwrap();
    assert_eq!(&payload[..CONTENT.len()], CONTENT);
    write_message(
        &mut sender.channel,
        &Receipt {
            id: ID.into(),
            manifest_sha256: manifest.sha256(),
            entries: 1,
            bytes: 0,
        },
    )
    .unwrap();
    let mut done = Vec::new();
    sender.channel.read_to_end(&mut done).unwrap();
    assert!(done.is_empty());
    sender.finish(false);
}

#[test]
fn receiver_deadline_removes_partial_data_even_when_peer_stays_connected() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &[NAME.into()], LIMITS).unwrap();
    let mut receiver = Endpoint::start("receive", &target, 500);
    write_message(
        &mut receiver.channel,
        &ReceiveRequest {
            approval: approval(selection.manifest()),
            limits: LIMITS,
        },
    )
    .unwrap();
    selection.manifest().write(&mut receiver.channel).unwrap();
    let mut ready = [0; 8];
    receiver.channel.read_exact(&mut ready).unwrap();
    receiver.channel.write_all(&CONTENT[..1]).unwrap();
    let mut result = Vec::new();
    receiver.channel.read_to_end(&mut result).unwrap();
    assert!(result.is_empty());
    receiver.finish(false);
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
}

#[test]
fn oversized_control_frames_and_unknown_fields_fail_without_path_disclosure() {
    let target = Tree::new();
    let mut receiver = Endpoint::start("receive", &target, 5000);
    receiver.channel.write_all(&u32::MAX.to_be_bytes()).unwrap();
    let mut bytes = Vec::new();
    receiver.channel.read_to_end(&mut bytes).unwrap();
    receiver.finish(false);
    let mut sender = Endpoint::start("send", &target, 5000);
    let mut invalid = serde_json::to_value(request()).unwrap();
    invalid["root"] = serde_json::json!("/unapproved");
    write_message(&mut sender.channel, &invalid).unwrap();
    sender.channel.read_to_end(&mut bytes).unwrap();
    sender.finish(false);
    assert!(bytes.is_empty());
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
}

#[test]
fn compiled_import_endpoint_publishes_only_complete_verified_files() {
    let source = Tree::new();
    fs::write(source.0.join(NAME), CONTENT).unwrap();
    for (corrupt, lose_receipt) in [(false, false), (true, false), (false, true)] {
        let inbox = Tree::new();
        let published = Tree::new();
        let mut selection = Selection::prepare(&source.0, &[NAME.into()], LIMITS).unwrap();
        let mut receiver = Endpoint::spawn("import", &inbox, Some(&published), 5000);
        write_message(
            &mut receiver.channel,
            &ReceiveRequest {
                approval: approval(selection.manifest()),
                limits: LIMITS,
            },
        )
        .unwrap();
        selection.manifest().write(&mut receiver.channel).unwrap();
        let mut ready = [0; 8];
        receiver.channel.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"receive\n");
        assert_eq!(fs::read_dir(&published.0).unwrap().count(), 0);
        let mut data = Vec::new();
        selection.send_data(&mut data).unwrap();
        if corrupt {
            data[0] ^= 1;
        }
        receiver.channel.write_all(&data).unwrap();
        if corrupt {
            let mut bytes = Vec::new();
            // Linux resets a Unix socket closed with the unread END marker;
            // both reset and EOF mean refusal, with no success receipt.
            if let Err(error) = receiver.channel.read_to_end(&mut bytes) {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
            assert!(bytes.is_empty());
            assert_eq!(fs::read_dir(&published.0).unwrap().count(), 0);
        } else {
            if !lose_receipt {
                let receipt: Receipt = read_message(&mut receiver.channel, 1024).unwrap();
                assert_eq!(receipt.manifest_sha256, selection.manifest().sha256());
            }
            if lose_receipt {
                assert!(receiver.child.wait().unwrap().success());
            }
            assert_eq!(
                fs::read(published.0.join(ID).join("files").join(NAME)).unwrap(),
                CONTENT
            );
            assert!(inbox.0.join(ID).join("published").is_file());
            assert!(!inbox.0.join(ID).join("files").exists());
        }
        receiver.finish(!corrupt);
        // The lost-receipt case closes without ever consuming the final
        // response. A fresh endpoint must still identify the completed import.
        drop(receiver);
        if !corrupt {
            use oblivion_transfer::recovery::{Request, Response, State};
            fs::write(
                published.0.join(ID).join("files").join(NAME),
                b"edited after import",
            )
            .unwrap();
            let mut recovered = Endpoint::spawn("recover", &inbox, Some(&published), 5000);
            write_message(&mut recovered.channel, &Request::List { after: None }).unwrap();
            let response: Response = read_message(&mut recovered.channel, 64 * 1024).unwrap();
            let Response::Inventory { records, next } = response else {
                panic!("inventory")
            };
            assert!(next.is_none());
            assert_eq!(records[0].state, State::Published);
            assert_eq!(
                records[0].receipt.as_ref().unwrap().manifest_sha256,
                selection.manifest().sha256()
            );
            assert_eq!(
                records[0].receipt.as_ref().unwrap().bytes,
                CONTENT.len() as u64
            );
            recovered.finish(true);
        }
    }
}

#[test]
fn killed_receiver_leaves_a_private_copy_recoverable_by_a_fresh_endpoint() {
    use oblivion_transfer::recovery::{Request, Response, State};
    let source = Tree::new();
    let inbox = Tree::new();
    let published = Tree::new();
    fs::write(source.0.join(NAME), vec![42; 128 * 1024]).unwrap();
    let selection = Selection::prepare(&source.0, &[NAME.into()], LIMITS).unwrap();
    let mut receiver = Endpoint::spawn("import", &inbox, Some(&published), 5000);
    write_message(
        &mut receiver.channel,
        &ReceiveRequest {
            approval: approval(selection.manifest()),
            limits: LIMITS,
        },
    )
    .unwrap();
    selection.manifest().write(&mut receiver.channel).unwrap();
    let mut ready = [0; 8];
    receiver.channel.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"receive\n");
    // A second endpoint cannot inspect/discard while the receiver owns the
    // inbox. This lock is released by the kernel when that process dies.
    let mut busy = Endpoint::spawn("recover", &inbox, Some(&published), 5000);
    write_message(&mut busy.channel, &Request::List { after: None }).unwrap();
    busy.finish(false);
    receiver.channel.write_all(&vec![42; 64 * 1024]).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !fs::metadata(inbox.0.join(ID).join("pending").join(NAME))
        .is_ok_and(|m| m.len() == 64 * 1024)
    {
        assert!(
            std::time::Instant::now() < deadline,
            "receiver did not write partial data"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    receiver.child.kill().unwrap();
    receiver.child.wait().unwrap();
    let mut recovered = Endpoint::spawn("recover", &inbox, Some(&published), 5000);
    write_message(&mut recovered.channel, &Request::List { after: None }).unwrap();
    let response: Response = read_message(&mut recovered.channel, 64 * 1024).unwrap();
    let Response::Inventory { records, next } = response else {
        panic!("inventory")
    };
    assert!(next.is_none());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, State::Private);
    assert!(records[0].receipt.is_none());
    recovered.finish(true);
    let mut discard = Endpoint::spawn("recover", &inbox, Some(&published), 5000);
    write_message(&mut discard.channel, &Request::Discard { id: ID.into() }).unwrap();
    let response: Response = read_message(&mut discard.channel, 1024).unwrap();
    assert!(matches!(response, Response::Discarded { id } if id == ID));
    discard.finish(true);
    assert!(!inbox.0.join(ID).exists());
    assert!(fs::read_dir(&published.0).unwrap().next().is_none());
}
