mod support;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{
    Approval, OfferRequest, ReceiveRequest, read_message, write_message,
};
use oblivion_transfer::native_files::{Action, Context, Direction, State};
use oblivion_transfer::{Limits, Selection, stream};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use support::Tree;
const ID: &str = "0123456789abcdef0123456789abcdef";
const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";
const LIMITS: Limits = Limits {
    entries: 64,
    bytes: 1024 * 1024,
};
fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}
fn context(direction: Direction) -> Context {
    Context {
        id: ID.into(),
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction,
        name: "project".into(),
    }
}
fn source() -> Tree {
    let tree = Tree::new();
    fs::create_dir(tree.0.join("project")).unwrap();
    fs::write(tree.0.join("project/note.txt"), b"original").unwrap();
    tree
}
fn status(
    inbox: &Tree,
    target: &Tree,
    direction: Direction,
) -> oblivion_transfer::native_files::Status {
    stream::operations::manage(
        &inbox.0,
        &target.0,
        ID,
        SAFE,
        OPENING,
        direction,
        Action::Status,
    )
    .unwrap()
}
fn ready() -> (Tree, Tree) {
    let source = source();
    let inbox = Tree::new();
    let target = Tree::new();
    fs::create_dir(target.0.join("project")).unwrap();
    fs::write(target.0.join("project/keep.txt"), b"existing output").unwrap();
    let context = context(Direction::Import);
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        stream::send_path(&mut channel(sender), &source.0.join("project"), LIMITS, ID)
    });
    let mut receiver = channel(receiver);
    assert!(stream::receive_directory(&mut receiver, &inbox.0, &target.0, &context).is_err());
    drop(receiver);
    assert!(sender.join().unwrap().is_err());
    let outcome = status(&inbox, &target, Direction::Import);
    assert_eq!(outcome.state, State::Ready);
    assert!(outcome.can_recover && outcome.can_discard);
    (inbox, target)
}
#[test]
fn import_ack_loss_after_publication_reconciles_without_recopy_or_deleting_edits() {
    let source = source();
    let inbox = Tree::new();
    let target = Tree::new();
    let context = context(Direction::Import);
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        let mut selection = Selection::prepare(&source.0, &["project".into()], LIMITS).unwrap();
        let mut channel = channel(sender);
        write_message(
            &mut channel,
            &ReceiveRequest {
                approval: Approval {
                    id: ID.into(),
                    manifest_sha256: selection.manifest().sha256(),
                },
                limits: LIMITS,
            },
        )
        .unwrap();
        selection.manifest().write(&mut channel).unwrap();
        let mut accepted = [0; 8];
        channel.read_exact(&mut accepted).unwrap();
        assert_eq!(&accepted, b"receive\n");
        selection.send_data(&mut channel).unwrap();
        drop(channel); // Actual loss before receipt.
    });
    let mut receiver = channel(receiver);
    assert!(stream::receive_directory(&mut receiver, &inbox.0, &target.0, &context).is_err());
    sender.join().unwrap();
    drop(receiver);
    let outcome = status(&inbox, &target, Direction::Import);
    outcome.validate(ID, SAFE, OPENING).unwrap();
    assert_eq!(outcome.state, State::Published);
    assert_eq!(outcome.receipt.as_ref().unwrap().bytes, 8);
    assert!(!outcome.can_recover && !outcome.can_discard);
    fs::write(target.0.join("project/note.txt"), b"edited by agent").unwrap();
    assert_eq!(
        status(&inbox, &target, Direction::Import).state,
        State::Published
    );
    assert!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Import,
            Action::Discard
        )
        .is_err()
    );
    assert_eq!(
        fs::read(target.0.join("project/note.txt")).unwrap(),
        b"edited by agent"
    );
}
#[test]
fn export_ack_loss_after_publication_is_published_from_the_durable_receipt() {
    let source = source();
    let inbox = Tree::new();
    let target = Tree::new();
    let context = context(Direction::Export);
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        let mut channel = channel(sender);
        let request: OfferRequest = read_message(&mut channel, 4096).unwrap();
        let mut selection = Selection::prepare(&source.0, &request.paths, LIMITS).unwrap();
        selection.manifest().write(&mut channel).unwrap();
        let _: Approval = read_message(&mut channel, 1024).unwrap();
        selection.send_data(&mut channel).unwrap();
        drop(channel);
    });
    assert!(
        stream::download(
            &mut channel(receiver),
            "project",
            &inbox.0,
            &target.0,
            &context
        )
        .is_err()
    );
    sender.join().unwrap();
    assert_eq!(
        status(&inbox, &target, Direction::Export).state,
        State::Published
    );
    assert_eq!(
        fs::read(target.0.join("project/note.txt")).unwrap(),
        b"original"
    );
}
#[test]
fn unknown_and_incomplete_never_claim_success_or_authorize_deleting_outputs() {
    let inbox = Tree::new();
    let target = Tree::new();
    fs::write(target.0.join("project"), b"preexisting unrelated file").unwrap();
    assert_eq!(
        status(&inbox, &target, Direction::Import).state,
        State::Unknown
    );
    let context = context(Direction::Import);
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let source = source();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        let selection = Selection::prepare(&source.0, &["project".into()], LIMITS).unwrap();
        let mut channel = channel(sender);
        write_message(
            &mut channel,
            &ReceiveRequest {
                approval: Approval {
                    id: ID.into(),
                    manifest_sha256: selection.manifest().sha256(),
                },
                limits: LIMITS,
            },
        )
        .unwrap();
        selection.manifest().write(&mut channel).unwrap();
        let mut accepted = [0; 8];
        channel.read_exact(&mut accepted).unwrap();
        channel.write_all(b"part").unwrap();
        drop(channel);
    });
    assert!(
        stream::receive_directory(&mut channel(receiver), &inbox.0, &target.0, &context).is_err()
    );
    sender.join().unwrap();
    let outcome = status(&inbox, &target, Direction::Import);
    assert_eq!(outcome.state, State::Incomplete);
    assert!(outcome.can_discard);
    assert!(outcome.receipt.is_none());
    assert!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Import,
            Action::Recover
        )
        .is_err()
    );
    assert_eq!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Import,
            Action::Discard
        )
        .unwrap()
        .state,
        State::Discarded
    );
    assert!(!inbox.0.join(ID).exists());
    assert_eq!(
        fs::read(target.0.join("project")).unwrap(),
        b"preexisting unrelated file"
    );
    assert!(stream::operations::begin(&inbox.0, &target.0, &context).is_err());
}
#[test]
fn recover_after_conflict_removed_accepts_fresh_opening_but_not_wrong_authority() {
    let (inbox, target) = ready();
    assert!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Import,
            Action::Recover
        )
        .is_err()
    );
    assert_eq!(
        fs::read(target.0.join("project/keep.txt")).unwrap(),
        b"existing output"
    );
    fs::remove_dir_all(target.0.join("project")).unwrap();
    let reopened = "33333333333333333333333333333333";
    let outcome = stream::operations::manage(
        &inbox.0,
        &target.0,
        ID,
        SAFE,
        reopened,
        Direction::Import,
        Action::Recover,
    )
    .unwrap();
    outcome.validate(ID, SAFE, reopened).unwrap();
    assert_eq!(outcome.state, State::Published);
    assert_eq!(outcome.source_opening.as_deref(), Some(OPENING));
    assert_eq!(
        fs::read(target.0.join("project/note.txt")).unwrap(),
        b"original"
    );
    assert!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            &"4".repeat(32),
            reopened,
            Direction::Import,
            Action::Status
        )
        .is_err()
    );
    let other = Tree::new();
    assert!(
        stream::operations::manage(
            &inbox.0,
            &other.0,
            ID,
            SAFE,
            reopened,
            Direction::Import,
            Action::Status
        )
        .is_err()
    );
    assert!(
        stream::operations::manage(
            &inbox.0,
            &target.0,
            ID,
            SAFE,
            reopened,
            Direction::Export,
            Action::Status
        )
        .is_err()
    );
}
#[test]
fn private_recovery_rehashes_bytes_and_rejects_extra_unapproved_children() {
    for extra in [false, true] {
        let (inbox, target) = ready();
        fs::remove_dir_all(target.0.join("project")).unwrap();
        let staged = inbox.0.join(ID).join("files/project");
        if extra {
            fs::write(staged.join("unapproved.txt"), b"not in receipt").unwrap();
        } else {
            fs::write(staged.join("note.txt"), b"altered!").unwrap();
        }
        assert!(
            stream::operations::manage(
                &inbox.0,
                &target.0,
                ID,
                SAFE,
                OPENING,
                Direction::Import,
                Action::Recover
            )
            .is_err()
        );
        assert!(!target.0.join("project").exists());
        assert!(status(&inbox, &target, Direction::Import).can_discard);
    }
}
#[test]
fn tracked_copy_keeps_both_reviewed_receiver_roots_when_paths_are_replaced() {
    use std::os::unix::fs::DirBuilderExt;
    for replace_inbox in [false, true] {
        let source = source();
        let inbox = Tree::new();
        let target = Tree::new();
        let context = context(Direction::Export);
        stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (reached, waiting) = std::sync::mpsc::channel();
        let (resume, proceed) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let mut channel = channel(sender);
            let request: OfferRequest = read_message(&mut channel, 4096).unwrap();
            let mut selection = Selection::prepare(&source.0, &request.paths, LIMITS).unwrap();
            selection.manifest().write(&mut channel).unwrap();
            let _: Approval = read_message(&mut channel, 1024).unwrap();
            reached.send(()).unwrap();
            proceed.recv().unwrap();
            selection.send_data(&mut channel).unwrap();
            let receipt: oblivion_transfer::Receipt = read_message(&mut channel, 1024).unwrap();
            channel.write_all(b"copied\n").unwrap();
            receipt
        });
        let inbox_path = inbox.0.clone();
        let target_path = target.0.clone();
        let receiver = std::thread::spawn(move || {
            stream::download(
                &mut channel(receiver),
                "project",
                &inbox_path,
                &target_path,
                &context,
            )
        });
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
        let replaced = if replace_inbox { &inbox.0 } else { &target.0 };
        let moved = replaced.with_extension("reviewed");
        fs::rename(replaced, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(replaced).unwrap();
        resume.send(()).unwrap();
        assert_eq!(receiver.join().unwrap().unwrap(), sender.join().unwrap());
        assert!(fs::read_dir(replaced).unwrap().next().is_none());
        if replace_inbox {
            assert_eq!(
                fs::read(target.0.join("project/note.txt")).unwrap(),
                b"original"
            );
            assert_eq!(
                stream::operations::manage(
                    &moved,
                    &target.0,
                    ID,
                    SAFE,
                    OPENING,
                    Direction::Export,
                    Action::Status
                )
                .unwrap()
                .state,
                State::Published
            );
        } else {
            assert_eq!(
                fs::read(moved.join("project/note.txt")).unwrap(),
                b"original"
            );
            assert!(
                stream::operations::manage(
                    &inbox.0,
                    &target.0,
                    ID,
                    SAFE,
                    OPENING,
                    Direction::Export,
                    Action::Status
                )
                .is_err()
            );
        }
        fs::remove_dir_all(moved).unwrap();
    }
}
