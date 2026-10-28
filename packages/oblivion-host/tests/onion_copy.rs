use oblivion_host::onion_copy;
use oblivion_host::transfers;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{self, Approval, OfferRequest, read_message, write_message};
use oblivion_transfer::{Manifest, Receipt};
use std::fs::{self, DirBuilder, File};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ID: &str = "0123456789abcdef0123456789abcdef";
const CONTENT: &[u8] = b"OBLIVION_ONION_APPROVED_COPY_4be";

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "oblivion-onion-copy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        for name in ["source", "inbox", "imports"] {
            DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))
                .unwrap();
        }
        fs::write(root.join("source/document.txt"), CONTENT).unwrap();
        fs::write(root.join("source/unselected.txt"), b"not selected").unwrap();
        Self(root)
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn file(socket: UnixStream) -> File {
    OwnedFd::from(socket).into()
}
fn channel(socket: UnixStream) -> Channel {
    Channel::new(file(socket), Duration::from_secs(5)).unwrap()
}

#[test]
fn sealed_intake_uses_real_browser_approval_and_import_endpoints_before_cleanup_ack() {
    for approve in [false, true] {
        let tree = Tree::new();
        let (source, sender) = UnixStream::pair().unwrap();
        let (destination, receiver) = UnixStream::pair().unwrap();
        let (control, manager) = UnixStream::pair().unwrap();
        let monitor = manager.try_clone().unwrap();
        let (owner_a, alive_a) = UnixStream::pair().unwrap();
        let (owner_b, alive_b) = UnixStream::pair().unwrap();
        let source_root = tree.0.join("source");
        let sender = std::thread::spawn(move || {
            let mut channel = channel(sender);
            channel.write_all(b"ready\n").unwrap();
            endpoint::send(&mut channel, &source_root)
        });
        let inbox = tree.0.join("inbox");
        let imports = tree.0.join("imports");
        let receiver = std::thread::spawn(move || {
            let mut channel = channel(receiver);
            channel.write_all(b"ready\n").unwrap();
            let mut gate = [0];
            channel.read_exact(&mut gate)?;
            assert_eq!(&gate, b"G");
            endpoint::import(&mut channel, &inbox, &imports)
        });
        let bridge = std::thread::spawn(move || {
            let source = file(source);
            let destination = file(destination);
            let owners = vec![owner_a.into(), owner_b.into()];
            let deadline = Instant::now() + Duration::from_secs(5);
            onion_copy::ready(&source, &destination, &owners, deadline)?;
            onion_copy::stage(
                source,
                destination,
                file(control),
                owners,
                deadline,
                ID.into(),
            )
        });
        let mut manager = channel(manager);
        write_message(
            &mut manager,
            &serde_json::json!({"browse":{"path":"","after":null,"limit":100}}),
        )
        .unwrap();
        let page: oblivion_transfer::browser::Response = read_message(&mut manager, 65536).unwrap();
        assert!(
            matches!(page, oblivion_transfer::browser::Response::Page(page) if page.entries.len() == 2)
        );
        write_message(
            &mut manager,
            &OfferRequest {
                id: ID.into(),
                paths: vec!["document.txt".into()],
                limits: transfers::limits(),
            },
        )
        .unwrap();
        let manifest = Manifest::read(&mut manager, transfers::limits()).unwrap();
        assert_eq!(manifest.entries().len(), 1);
        assert_eq!(manifest.entries()[0].path(), "document.txt");
        assert_eq!(fs::read_dir(tree.0.join("inbox")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(tree.0.join("imports")).unwrap().count(), 0);
        if !approve {
            monitor.shutdown(Shutdown::Both).unwrap();
            assert!(bridge.join().unwrap().is_err());
            assert!(sender.join().unwrap().is_err());
            assert!(receiver.join().unwrap().is_err());
            assert_eq!(fs::read_dir(tree.0.join("imports")).unwrap().count(), 0);
            drop((alive_a, alive_b));
            continue;
        }
        write_message(
            &mut manager,
            &Approval {
                id: ID.into(),
                manifest_sha256: manifest.sha256(),
            },
        )
        .unwrap();
        let completed = bridge.join().unwrap().unwrap();
        sender.join().unwrap().unwrap();
        receiver.join().unwrap().unwrap();
        assert_eq!(
            fs::read(tree.0.join("imports").join(ID).join("files/document.txt")).unwrap(),
            CONTENT
        );
        assert!(
            !tree
                .0
                .join("imports")
                .join(ID)
                .join("files/unselected.txt")
                .exists()
        );
        let mut descriptor = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 0);
        let receipt = completed.acknowledge().unwrap();
        assert_eq!(
            read_message::<Receipt>(&mut manager, 1024).unwrap(),
            receipt
        );
        assert_eq!(receipt.id, ID);
        assert_eq!(receipt.bytes, CONTENT.len() as u64);
        drop((alive_a, alive_b));
    }
}

#[test]
fn endpoint_readiness_is_revoked_by_owner_death_without_waiting_for_data() {
    let (source, _sender) = UnixStream::pair().unwrap();
    let (destination, _receiver) = UnixStream::pair().unwrap();
    let (owner, alive) = UnixStream::pair().unwrap();
    drop(alive);
    let error = onion_copy::ready(
        &file(source),
        &file(destination),
        &[owner.into()],
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[test]
fn sharing_stages_only_the_approved_documents_and_retains_the_original_selection() {
    let tree = Tree::new();
    fs::create_dir(tree.0.join("source/workspace")).unwrap();
    fs::write(tree.0.join("source/workspace/document.txt"), CONTENT).unwrap();
    fs::write(
        tree.0.join("source/workspace/unselected.txt"),
        b"not shared",
    )
    .unwrap();
    let (source, sender) = UnixStream::pair().unwrap();
    let (destination, receiver) = UnixStream::pair().unwrap();
    let (control, manager) = UnixStream::pair().unwrap();
    let (owner_a, alive_a) = UnixStream::pair().unwrap();
    let (owner_b, alive_b) = UnixStream::pair().unwrap();
    let root = tree.0.join("source");
    let sender = std::thread::spawn(move || {
        let mut channel = channel(sender);
        channel.write_all(b"ready\n")?;
        let mut gate = [0];
        channel.read_exact(&mut gate)?;
        assert_eq!(&gate, b"G");
        endpoint::documents(&mut channel, &root)
    });
    let inbox = tree.0.join("inbox");
    let staging = tree.0.join("imports");
    let receiver = std::thread::spawn(move || {
        let mut channel = channel(receiver);
        channel.write_all(b"ready\n")?;
        endpoint::import(&mut channel, &inbox, &staging)
    });
    let bridge = std::thread::spawn(move || {
        let source = file(source);
        let destination = file(destination);
        let owners = vec![owner_a.into(), owner_b.into()];
        let deadline = Instant::now() + Duration::from_secs(5);
        onion_copy::ready(&source, &destination, &owners, deadline)?;
        onion_copy::share(
            source,
            destination,
            file(control),
            owners,
            deadline,
            ID.into(),
        )
    });
    let mut manager = channel(manager);
    write_message(
        &mut manager,
        &OfferRequest {
            id: ID.into(),
            paths: vec!["workspace/document.txt".into()],
            limits: transfers::limits(),
        },
    )
    .unwrap();
    let manifest = Manifest::read(&mut manager, transfers::limits()).unwrap();
    assert_eq!(fs::read_dir(tree.0.join("imports")).unwrap().count(), 0);
    write_message(
        &mut manager,
        &Approval {
            id: ID.into(),
            manifest_sha256: manifest.sha256(),
        },
    )
    .unwrap();
    let completed = bridge.join().unwrap().unwrap();
    sender.join().unwrap().unwrap();
    receiver.join().unwrap().unwrap();
    assert_eq!(completed.paths(), ["workspace/document.txt"]);
    assert_eq!(
        fs::read(
            tree.0
                .join("imports")
                .join(ID)
                .join("files/workspace/document.txt")
        )
        .unwrap(),
        CONTENT
    );
    assert!(
        !tree
            .0
            .join("imports")
            .join(ID)
            .join("files/workspace/unselected.txt")
            .exists()
    );
    let receipt = completed.acknowledge().unwrap();
    assert_eq!(
        read_message::<Receipt>(&mut manager, 1024).unwrap(),
        receipt
    );
    drop((alive_a, alive_b));
}

#[test]
fn readiness_cannot_be_replaced_by_another_guest_protocol() {
    let (source, mut sender) = UnixStream::pair().unwrap();
    let (destination, _receiver) = UnixStream::pair().unwrap();
    sender.write_all(b"other\n").unwrap();
    assert!(
        onion_copy::ready(
            &file(source),
            &file(destination),
            &[],
            Instant::now() + Duration::from_secs(5)
        )
        .is_err()
    );
}
