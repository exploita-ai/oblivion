mod support;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::native_file_events::Phase;
use oblivion_transfer::native_files::{Action, Context, Direction, State};
use oblivion_transfer::{endpoint, stream};
use std::fs::{self, File};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use support::Tree;
const ID: &str = "0123456789abcdef0123456789abcdef";
const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";
const BYTES: usize = 160_000;
fn context(direction: Direction) -> Context {
    Context {
        id: ID.into(),
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction,
        name: "reviewed".into(),
    }
}
fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}
fn progress(events: &[(Phase, u64)]) {
    assert_eq!(events.first(), Some(&(Phase::Copying, 0)));
    assert_eq!(events.last(), Some(&(Phase::Finalizing, BYTES as u64)));
    assert!(events.windows(2).all(|pair| pair[0].1 <= pair[1].1));
    assert!(events.iter().all(|(_, count)| *count <= BYTES as u64));
    assert!(
        events
            .iter()
            .any(|(phase, count)| *phase == Phase::Copying && *count > 0 && *count < BYTES as u64)
    );
}
fn export(
    watch: Option<OwnedFd>,
) -> (
    stream::PreparedDownload,
    Tree,
    std::thread::JoinHandle<io::Result<()>>,
) {
    let source = Tree::new();
    fs::create_dir_all(source.0.join("workspace/project")).unwrap();
    fs::write(source.0.join("workspace/project/note"), vec![b'a'; BYTES]).unwrap();
    fs::write(source.0.join("workspace/project/other"), b"unselected").unwrap();
    let target = Tree::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let source = std::thread::spawn(move || endpoint::documents(&mut channel(sender), &source.0));
    let mut receiver = channel(receiver);
    if let Some(watch) = watch {
        receiver.watch(watch);
    }
    let prepared = stream::PreparedDownload::prepare(
        receiver,
        "workspace/project/note",
        &target.0,
        context(Direction::Export),
    )
    .unwrap();
    (prepared, target, source)
}
#[test]
fn prepared_upload_retains_the_reviewed_selection_and_counts_only_document_bytes() {
    let source = Tree::new();
    fs::write(source.0.join("note"), vec![b'a'; BYTES]).unwrap();
    let context = context(Direction::Import);
    let prepared =
        stream::PreparedUpload::prepare(&source.0.join("note"), context.clone(), &mut || Ok(()))
            .unwrap();
    let summary = prepared.summary().unwrap();
    assert_eq!(
        (
            summary.entries,
            summary.files,
            summary.directories,
            summary.bytes
        ),
        (1, 1, 0, BYTES as u64)
    );
    let inbox = Tree::new();
    let target = Tree::new();
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let destination = target.0.clone();
    let staging = inbox.0.clone();
    let receiver = std::thread::spawn(move || {
        stream::receive_directory(&mut channel(receiver), &staging, &destination, &context)
    });
    let mut events = Vec::new();
    let receipt = prepared
        .send(
            &mut channel(sender),
            &summary.manifest_sha256,
            &mut |phase, bytes| {
                events.push((phase, bytes));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(receiver.join().unwrap().unwrap(), receipt);
    assert_eq!(receipt.manifest_sha256, summary.manifest_sha256);
    progress(&events);
    assert_eq!(
        fs::metadata(target.0.join("reviewed")).unwrap().len(),
        BYTES as u64
    );
}
#[test]
fn upload_preparation_checks_real_cancellation_during_hash_reads() {
    let source = Tree::new();
    fs::write(source.0.join("large"), vec![b'a'; 4 * 1024 * 1024]).unwrap();
    let mut checks = 0;
    let prepared = stream::PreparedUpload::prepare(
        &source.0.join("large"),
        context(Direction::Import),
        &mut || {
            checks += 1;
            if checks >= 7 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            Ok(())
        },
    );
    assert_eq!(prepared.err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(checks, 7);
    assert_eq!(fs::read_dir(&source.0).unwrap().count(), 1);
}
#[test]
fn changed_upload_after_review_never_finishes_or_publishes_under_the_old_digest() {
    let source = Tree::new();
    fs::write(source.0.join("note"), vec![b'a'; BYTES]).unwrap();
    let context = context(Direction::Import);
    let prepared =
        stream::PreparedUpload::prepare(&source.0.join("note"), context.clone(), &mut || Ok(()))
            .unwrap();
    let summary = prepared.summary().unwrap();
    fs::write(source.0.join("note"), vec![b'b'; BYTES]).unwrap();
    let inbox = Tree::new();
    let target = Tree::new();
    stream::operations::begin(&inbox.0, &target.0, &context).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let destination = target.0.clone();
    let staging = inbox.0.clone();
    let receiver = std::thread::spawn(move || {
        stream::receive_directory(&mut channel(receiver), &staging, &destination, &context)
    });
    let mut events = Vec::new();
    assert!(
        prepared
            .send(
                &mut channel(sender),
                &summary.manifest_sha256,
                &mut |phase, bytes| {
                    events.push((phase, bytes));
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(receiver.join().unwrap().is_err());
    assert!(!target.0.join("reviewed").exists());
    assert!(events.iter().all(|(phase, _)| *phase == Phase::Copying));
}
#[test]
fn export_review_has_no_destination_writes_or_payload_approval_and_counts_no_ancestors() {
    let (prepared, target, source) = export(None);
    let summary = prepared.summary().unwrap();
    assert_eq!(
        (
            summary.entries,
            summary.files,
            summary.directories,
            summary.bytes
        ),
        (3, 1, 0, BYTES as u64)
    );
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    assert!(!source.is_finished());
    assert!(
        prepared
            .receive(&"0".repeat(64), &mut |_, _| Ok(()))
            .is_err()
    );
    assert!(source.join().unwrap().is_err());
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
}
#[test]
fn prepared_export_reports_real_bytes_and_finalizes_only_after_payload_verification() {
    let (prepared, target, source) = export(None);
    let summary = prepared.summary().unwrap();
    let mut events = Vec::new();
    let receipt = prepared
        .receive(&summary.manifest_sha256, &mut |phase, bytes| {
            events.push((phase, bytes));
            Ok(())
        })
        .unwrap();
    source.join().unwrap().unwrap();
    progress(&events);
    assert_eq!(receipt.bytes, BYTES as u64);
    assert_eq!(
        fs::metadata(target.0.join("reviewed")).unwrap().len(),
        BYTES as u64
    );
}
#[test]
fn cancel_watch_before_approval_does_not_create_receiver_state() {
    let (owner, watch) = UnixStream::pair().unwrap();
    let (prepared, target, source) = export(Some(watch.into()));
    let summary = prepared.summary().unwrap();
    drop(owner);
    assert!(
        prepared
            .receive(&summary.manifest_sha256, &mut |_, _| Ok(()))
            .is_err()
    );
    assert!(source.join().unwrap().is_err());
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
}
#[test]
fn cancellation_while_copying_or_before_publication_never_reports_success() {
    for finalizing in [false, true] {
        let (prepared, target, source) = export(None);
        let summary = prepared.summary().unwrap();
        assert!(
            prepared
                .receive(&summary.manifest_sha256, &mut |phase, bytes| {
                    if if finalizing {
                        phase == Phase::Finalizing
                    } else {
                        phase == Phase::Copying && bytes > 0
                    } {
                        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                    }
                    Ok(())
                })
                .is_err()
        );
        assert!(source.join().unwrap().is_err());
        assert!(!target.0.join("reviewed").exists());
        let outcome = stream::operations::manage(
            &target.0.join(".oblivion-transfers"),
            &target.0,
            ID,
            SAFE,
            OPENING,
            Direction::Export,
            Action::Status,
        )
        .unwrap();
        assert_ne!(outcome.state, State::Published);
        assert!(outcome.can_discard);
    }
}

#[test]
fn upload_requires_the_reviewed_digest_before_any_offer_or_payload() {
    use std::io::Read;
    let source = Tree::new();
    fs::write(source.0.join("note"), b"original").unwrap();
    let prepared = stream::PreparedUpload::prepare(
        &source.0.join("note"),
        context(Direction::Import),
        &mut || Ok(()),
    )
    .unwrap();
    let (sender, mut peer) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut sender = channel(sender);
    let mut progress = Vec::new();
    assert!(
        prepared
            .send(&mut sender, &"0".repeat(64), &mut |phase, bytes| {
                progress.push((phase, bytes));
                Ok(())
            })
            .is_err()
    );
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(progress.is_empty());
}

#[test]
fn export_keeps_the_reviewed_destination_descriptor_across_the_review_pause() {
    use std::os::unix::fs::DirBuilderExt;
    let (prepared, target, source) = export(None);
    let summary = prepared.summary().unwrap();
    let moved = target.0.with_extension("reviewed");
    fs::rename(&target.0, &moved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&target.0).unwrap();
    prepared
        .receive(&summary.manifest_sha256, &mut |_, _| Ok(()))
        .unwrap();
    source.join().unwrap().unwrap();
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    assert_eq!(
        fs::metadata(moved.join("reviewed")).unwrap().len(),
        BYTES as u64
    );
    assert_eq!(
        stream::operations::manage(
            &moved.join(".oblivion-transfers"),
            &moved,
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
    fs::remove_dir_all(moved).unwrap();
}
