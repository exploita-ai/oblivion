#![cfg(unix)]

mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{
    self, Approval, OfferRequest, ReceiveRequest, SelectionOffer, read_message, write_message,
};
use oblivion_transfer::native_file_events::Phase;
use oblivion_transfer::native_files::{Action, Context, Direction, Request, State};
use oblivion_transfer::selection::{Mapping, Plan};
use oblivion_transfer::stream::{self, PreparedMediaImport};
use oblivion_transfer::{Entry, Limits, Manifest, Receipt, Selection};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";

fn context() -> Context {
    Context {
        id: ID.into(),
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction: Direction::Import,
        name: "usb-copy".into(),
    }
}

fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(4)).unwrap()
}

fn destination(inbox: &Tree, target: &Tree) -> (Channel, JoinHandle<io::Result<()>>) {
    let (caller, guest) = UnixStream::pair().unwrap();
    let inbox = inbox.0.clone();
    let target = target.0.clone();
    let receiver = thread::spawn(move || {
        let mut guest = channel(guest);
        let request = read_message(&mut guest, 1024)?;
        stream::operations::serve(&mut guest, &inbox, &target, request)
    });
    let mut caller = channel(caller);
    write_message(
        &mut caller,
        &Request::Import {
            id: ID.into(),
            safe_id: SAFE.into(),
            opening: OPENING.into(),
            name: context().name,
        },
    )
    .unwrap();
    (caller, receiver)
}

#[test]
fn reviews_the_exact_media_selection_and_publishes_through_native_files() {
    let media = Tree::new();
    fs::create_dir(media.0.join("photos")).unwrap();
    fs::write(media.0.join("photos/frame"), vec![42; 150_000]).unwrap();
    fs::write(media.0.join("invoice"), b"tax").unwrap();
    fs::write(media.0.join("other"), b"excluded").unwrap();
    let (peer, caller) = UnixStream::pair().unwrap();
    let source = thread::spawn(move || endpoint::media_source(&mut channel(peer), &media.0));
    let inbox = Tree::new();
    let target = Tree::new();

    let prepared = PreparedMediaImport::prepare(
        channel(caller),
        &["photos/frame".into(), "invoice".into()],
        context(),
    )
    .unwrap();
    let summary = prepared.summary().unwrap();
    assert_eq!((summary.files, summary.bytes), (2, 150_003));
    assert_eq!(prepared.plan().selected, "selection");
    assert!(fs::read_dir(&inbox.0).unwrap().next().is_none());
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());

    let (mut safe, receiver) = destination(&inbox, &target);
    let mut events = Vec::new();
    let receipt = prepared
        .send(&mut safe, &summary.manifest_sha256, &mut |phase, bytes| {
            events.push((phase, bytes));
            Ok(())
        })
        .unwrap();
    source.join().unwrap().unwrap();
    receiver.join().unwrap().unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.manifest_sha256, summary.manifest_sha256);
    assert_eq!(events.first(), Some(&(Phase::Copying, 0)));
    assert_eq!(events.last(), Some(&(Phase::Finalizing, summary.bytes)));
    assert!(events.windows(2).all(|pair| pair[0].1 <= pair[1].1));
    assert_eq!(
        fs::read(target.0.join("usb-copy/frame")).unwrap(),
        vec![42; 150_000]
    );
    assert_eq!(fs::read(target.0.join("usb-copy/invoice")).unwrap(), b"tax");
    assert_eq!(fs::read_dir(target.0.join("usb-copy")).unwrap().count(), 2);
    let status = stream::operations::manage(
        &inbox.0,
        &target.0,
        ID,
        SAFE,
        OPENING,
        Direction::Import,
        Action::Status,
    )
    .unwrap();
    assert_eq!(status.state, State::Published);
}

#[test]
fn rejects_absolute_or_traversing_media_paths_before_sending_an_offer() {
    for path in ["/etc/passwd", "../secret", "folder/../secret"] {
        let (peer, caller) = UnixStream::pair().unwrap();
        let prepared = PreparedMediaImport::prepare(channel(caller), &[path.into()], context());
        assert_eq!(prepared.err().unwrap().to_string(), "invalid_path");
        assert_eq!(channel(peer).read(&mut [0]).unwrap(), 0);
    }
}

fn note_offer(alias: &str, directory: bool) -> SelectionOffer {
    SelectionOffer {
        directories: vec![directory],
        plan: Plan {
            selected: alias.into(),
            mappings: vec![Mapping {
                input_index: 0,
                alias: Some(alias.into()),
                covered_by: None,
            }],
        },
    }
}

#[test]
fn rejects_a_substituted_mapping_and_a_manifest_expanded_beyond_the_selection() {
    for (alias, reason) in [
        ("other", "selection_changed"),
        ("note", "selection_expanded"),
    ] {
        let (peer, caller) = UnixStream::pair().unwrap();
        let source = thread::spawn(move || {
            let mut peer = channel(peer);
            let request: OfferRequest = read_message(&mut peer, 64 * 1024).unwrap();
            assert_eq!(request.paths, ["note"]);
            write_message(&mut peer, &note_offer(alias, true)).unwrap();
            if alias == "note" {
                Manifest::new(
                    vec![
                        Entry::Directory {
                            path: "note".into(),
                        },
                        Entry::Directory {
                            path: "other".into(),
                        },
                    ],
                    request.limits,
                )
                .unwrap()
                .write(&mut peer)
                .unwrap();
            }
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        });
        let prepared = PreparedMediaImport::prepare(channel(caller), &["note".into()], context());
        assert_eq!(prepared.err().unwrap().to_string(), reason);
        source.join().unwrap();
    }
}

#[test]
fn withholds_the_terminator_when_media_bytes_disagree_with_the_approved_hash() {
    let (peer, caller) = UnixStream::pair().unwrap();
    let source = thread::spawn(move || {
        let media = Tree::new();
        fs::write(media.0.join("note"), b"good").unwrap();
        let selection = Selection::prepare(
            &media.0,
            &["note".into()],
            Limits {
                entries: 1,
                bytes: 4,
            },
        )
        .unwrap();
        let mut peer = channel(peer);
        let request: OfferRequest = read_message(&mut peer, 64 * 1024).unwrap();
        assert_eq!(request.paths, ["note"]);
        write_message(&mut peer, &note_offer("note", false)).unwrap();
        selection.manifest().write(&mut peer).unwrap();
        let approval: Approval = read_message(&mut peer, 1024).unwrap();
        assert_eq!(approval.manifest_sha256, selection.manifest().sha256());
        peer.write_all(b"evilOBLVEND1").unwrap();
    });
    let prepared =
        PreparedMediaImport::prepare(channel(caller), &["note".into()], context()).unwrap();
    let summary = prepared.summary().unwrap();
    let (safe, receiver) = UnixStream::pair().unwrap();
    let receiver = thread::spawn(move || {
        let mut receiver = channel(receiver);
        let request: ReceiveRequest = read_message(&mut receiver, 1024).unwrap();
        Manifest::read(&mut receiver, request.limits).unwrap();
        receiver.write_all(b"receive\n").unwrap();
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"evil");
    });
    let mut safe = channel(safe);
    let error = prepared
        .send(&mut safe, &summary.manifest_sha256, &mut |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(error.to_string(), "content_changed");
    drop(safe);
    source.join().unwrap();
    receiver.join().unwrap();
}

#[test]
fn missing_source_completion_keeps_a_published_receiver_outcome() {
    let (peer, caller) = UnixStream::pair().unwrap();
    let source = thread::spawn(move || {
        let media = Tree::new();
        fs::write(media.0.join("note"), b"copy").unwrap();
        let mut selection = Selection::prepare(
            &media.0,
            &["note".into()],
            Limits {
                entries: 1,
                bytes: 4,
            },
        )
        .unwrap();
        let mut peer = channel(peer);
        let request: OfferRequest = read_message(&mut peer, 64 * 1024).unwrap();
        assert_eq!(request.paths, ["note"]);
        write_message(&mut peer, &note_offer("note", false)).unwrap();
        selection.manifest().write(&mut peer).unwrap();
        let approval: Approval = read_message(&mut peer, 1024).unwrap();
        assert_eq!(approval.manifest_sha256, selection.manifest().sha256());
        selection.send_data(&mut peer).unwrap();
        let receipt: Receipt = read_message(&mut peer, 1024).unwrap();
        assert_eq!(receipt.manifest_sha256, approval.manifest_sha256);
        peer.write_all(b"failed\n").unwrap();
    });
    let prepared =
        PreparedMediaImport::prepare(channel(caller), &["note".into()], context()).unwrap();
    let summary = prepared.summary().unwrap();
    let inbox = Tree::new();
    let target = Tree::new();
    let (mut safe, receiver) = destination(&inbox, &target);
    let error = prepared
        .send(&mut safe, &summary.manifest_sha256, &mut |_, _| Ok(()))
        .unwrap_err();
    assert_eq!(error.to_string(), "source_not_completed");
    source.join().unwrap();
    receiver.join().unwrap().unwrap();
    assert_eq!(fs::read(target.0.join("usb-copy")).unwrap(), b"copy");
    assert_eq!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Import,
            Action::Status
        )
        .unwrap()
        .state,
        State::Published
    );
}
