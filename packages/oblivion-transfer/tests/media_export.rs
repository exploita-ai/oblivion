#![cfg(unix)]

mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{self, Approval, ReceiveRequest, read_message, write_message};
use oblivion_transfer::native_files::{Context, Direction};
use oblivion_transfer::stream::PreparedMediaExport;
use oblivion_transfer::{
    Entry, ExportMode, Limits, Manifest, Receipt, Selection, receive_external,
};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";
const CONTENT: &[u8] = b"the reviewed USB payload";
const LIMITS: Limits = Limits {
    entries: 16,
    bytes: 1024,
};

fn context() -> Context {
    Context {
        id: ID.into(),
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction: Direction::Export,
        name: format!("Oblivion-{ID}"),
    }
}

fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}

#[test]
fn documents_are_reviewed_before_opening_the_usb_writer() {
    let source = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::write(source.0.join("workspace/note"), CONTENT).unwrap();
    fs::write(source.0.join("private"), b"excluded").unwrap();
    let (sender, client) = UnixStream::pair().unwrap();
    let source = thread::spawn(move || endpoint::documents(&mut channel(sender), &source.0));
    let prepared =
        PreparedMediaExport::prepare(channel(client), &["workspace/note".into()], context())
            .unwrap();
    let summary = prepared.summary().unwrap();
    assert_eq!(prepared.plan().selected, "note");
    assert_eq!(summary.bytes, CONTENT.len() as u64);

    let target = Tree::new();
    let path = target.0.clone();
    let (client, receiver) = UnixStream::pair().unwrap();
    let writer = thread::spawn(move || {
        endpoint::export_live_media(&mut channel(receiver), &path, ExportMode::Portable)
    });
    let receipt = prepared
        .send(
            &mut channel(client),
            &summary.manifest_sha256,
            &mut |_, _| Ok(()),
        )
        .unwrap();
    source.join().unwrap().unwrap();
    writer.join().unwrap().unwrap();
    let exported = target.0.join(context().name);
    assert_eq!(fs::read(exported.join("files/note")).unwrap(), CONTENT);
    assert_eq!(fs::read_dir(exported.join("files")).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 1);
    let durable: Receipt =
        serde_json::from_reader(File::open(exported.join("receipt.json")).unwrap()).unwrap();
    let manifest = Manifest::read(
        &mut File::open(exported.join("manifest.bin")).unwrap(),
        LIMITS,
    )
    .unwrap();
    assert_eq!(durable, receipt);
    assert_eq!(manifest.sha256(), summary.manifest_sha256);
}

#[test]
fn portable_names_and_fat32_sizes_are_rejected_before_staging() {
    let target = Tree::new();
    for (names, reason) in [
        (
            vec!["Résumé", "RE\u{301}SUME\u{301}"],
            "export_name_collision",
        ),
        (vec!["NUL.txt"], "unsupported_export_name"),
    ] {
        let manifest = Manifest::new(
            names
                .into_iter()
                .map(|path| Entry::Directory { path: path.into() })
                .collect(),
            LIMITS,
        )
        .unwrap();
        let error = receive_external(
            &mut io::empty(),
            &manifest,
            &target.0,
            ID,
            ExportMode::Portable,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), reason);
        assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    }
    let size = u64::from(u32::MAX) + 1;
    let manifest = Manifest::new(
        vec![Entry::File {
            path: "large".into(),
            size,
            sha256: "0".repeat(64),
        }],
        Limits {
            entries: 1,
            bytes: size,
        },
    )
    .unwrap();
    let error = receive_external(
        &mut io::empty(),
        &manifest,
        &target.0,
        ID,
        ExportMode::Fat32,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "fat32_file_too_large");
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
}

fn offer(channel: &mut Channel, manifest: &Manifest) {
    write_message(
        channel,
        &ReceiveRequest {
            approval: Approval {
                id: ID.into(),
                manifest_sha256: manifest.sha256(),
            },
            limits: LIMITS,
        },
    )
    .unwrap();
    manifest.write(channel).unwrap();
    let mut ready = [0; 8];
    channel.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"receive\n");
}

fn fixture_file() -> (Tree, Selection) {
    let tree = Tree::new();
    fs::write(tree.0.join("note"), CONTENT).unwrap();
    let selection = Selection::prepare(&tree.0, &["note".into()], LIMITS).unwrap();
    (tree, selection)
}

#[test]
fn a_concurrent_final_name_is_preserved_without_a_receipt() {
    let target = Tree::new();
    let path = target.0.clone();
    let (client, receiver) = UnixStream::pair().unwrap();
    let writer = thread::spawn(move || {
        endpoint::export_live_media(&mut channel(receiver), &path, ExportMode::Posix)
    });
    let (_source, mut selection) = fixture_file();
    let mut client = channel(client);
    offer(&mut client, selection.manifest());
    let existing = target.0.join(context().name);
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), b"unchanged").unwrap();
    selection.send_data(&mut client).unwrap();
    assert!(read_message::<Receipt>(&mut client, 1024).is_err());
    assert_eq!(
        writer.join().unwrap().unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(existing.join("keep")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 1);
}

#[test]
fn the_writer_binary_revokes_partial_copy_on_the_independent_proof_fd() {
    let target = Tree::new();
    let (client, receiver) = UnixStream::pair().unwrap();
    let (mut stop, proof) = UnixStream::pair().unwrap();
    let inherited = |socket: UnixStream| {
        let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        assert!(fd >= 5);
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let receiver = inherited(receiver);
    let proof = inherited(proof);
    let (data_fd, proof_fd) = (receiver.as_raw_fd(), proof.as_raw_fd());
    let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-copy"));
    command
        .arg("live-media-export")
        .arg(&target.0)
        .args(["5000", "posix"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(data_fd, 3) < 0 || libc::dup2(proof_fd, 4) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop((receiver, proof));
    let (_source, selection) = fixture_file();
    let mut client = channel(client);
    offer(&mut client, selection.manifest());
    client.write_all(&CONTENT[..4]).unwrap();
    stop.write_all(b"X").unwrap();
    assert!(read_message::<Receipt>(&mut client, 1024).is_err());
    assert!(!child.wait().unwrap().success());
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
}
