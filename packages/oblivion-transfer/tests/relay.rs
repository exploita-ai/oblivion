mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{
    self, Approval, OfferRequest, ReceiveRequest, read_message, write_message,
};
use oblivion_transfer::{Limits, Manifest, Receipt, Selection, relay};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const LIMITS: Limits = Limits {
    entries: 64,
    bytes: 1024 * 1024,
};
const CONTENT: &[u8] = b"OBLIVION_RELAY_CANARY_91e";

#[test]
fn export_receipt_is_withheld_until_detach_and_disconnect_is_not_eject_success() {
    use std::os::fd::AsRawFd;
    for detached in [true, false] {
        let source = Tree::new();
        let target = Tree::new();
        fs::write(source.0.join("document.txt"), CONTENT).unwrap();
        let (from, sender) = UnixStream::pair().unwrap();
        let (to, receiver) = UnixStream::pair().unwrap();
        let (controller, manager) = UnixStream::pair().unwrap();
        let monitor = manager.try_clone().unwrap();
        let (owner_a, alive_a) = UnixStream::pair().unwrap();
        let (owner_b, alive_b) = UnixStream::pair().unwrap();
        let relay = std::thread::spawn(move || {
            relay::export(
                file(from),
                file(to),
                file(controller),
                vec![owner_a.into(), owner_b.into()],
                Duration::from_secs(5),
                relay::Permit {
                    id: ID.into(),
                    limits: LIMITS,
                },
            )
        });
        let from = source.0.clone();
        let sender = std::thread::spawn(move || endpoint::send(&mut channel(sender), &from));
        let to = target.0.clone();
        let (ready, published) = std::sync::mpsc::sync_channel(0);
        let (release, released) = std::sync::mpsc::sync_channel(0);
        let receiver = std::thread::spawn(move || {
            let mut receiver = channel(receiver);
            endpoint::export(&mut receiver, &to, oblivion_transfer::ExportMode::Posix).unwrap();
            ready.send(()).unwrap();
            released.recv().unwrap();
            if detached {
                receiver.write_all(b"detached\n").unwrap();
            }
        });
        let mut manager = channel(manager);
        write_message(&mut manager, &request()).unwrap();
        let manifest = Manifest::read(&mut manager, LIMITS).unwrap();
        write_message(&mut manager, &approval(&manifest)).unwrap();
        published.recv().unwrap();
        sender.join().unwrap().unwrap();
        let mut poll = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 0);
        release.send(()).unwrap();
        if detached {
            let receipt: Receipt = read_message(&mut manager, 1024).unwrap();
            assert_eq!(receipt.manifest_sha256, manifest.sha256());
            relay.join().unwrap().unwrap();
        } else {
            let mut output = Vec::new();
            manager.read_to_end(&mut output).unwrap();
            assert!(output.is_empty());
            assert!(relay.join().unwrap().is_err());
        }
        receiver.join().unwrap();
        drop((alive_a, alive_b));
    }
}

#[test]
fn recovery_relay_validates_the_inventory_and_revokes_it_with_the_guest_or_manager() {
    use oblivion_transfer::recovery::{Request, Response};
    for case in ["complete", "owner", "manager", "invalid"] {
        let (destination, guest) = UnixStream::pair().unwrap();
        let (control, manager) = UnixStream::pair().unwrap();
        let (owner, alive) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            relay::recover(
                file(destination),
                file(control),
                owner.into(),
                Duration::from_secs(5),
            )
        });
        let mut manager = channel(manager);
        let mut guest = channel(guest);
        write_message(&mut manager, &Request::List { after: None }).unwrap();
        let _: Request = read_message(&mut guest, 1024).unwrap();
        match case {
            "owner" => {
                drop(alive);
            }
            "manager" => {
                drop(manager);
                assert!(worker.join().unwrap().is_err());
                continue;
            }
            "invalid" => {
                write_message(&mut guest, &Response::Discarded { id: ID.into() }).unwrap();
            }
            _ => {
                write_message(
                    &mut guest,
                    &Response::Inventory {
                        records: vec![],
                        next: None,
                    },
                )
                .unwrap();
                let response: Response = read_message(&mut manager, 64 * 1024).unwrap();
                response.validate(&Request::List { after: None }).unwrap();
                assert!(worker.join().unwrap().is_ok());
                continue;
            }
        }
        let mut output = Vec::new();
        manager.read_to_end(&mut output).unwrap();
        assert!(output.is_empty());
        assert!(worker.join().unwrap().is_err());
    }
}

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
fn approval(manifest: &Manifest) -> Approval {
    Approval {
        id: ID.into(),
        manifest_sha256: manifest.sha256(),
    }
}

struct Relay {
    source: Channel,
    destination: Channel,
    control: Channel,
    cancel: UnixStream,
    owners: Vec<UnixStream>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Relay {
    fn start() -> Self {
        Self::permitted(None)
    }

    fn permitted(permit: Option<relay::Permit>) -> Self {
        let (source, from) = UnixStream::pair().unwrap();
        let (destination, to) = UnixStream::pair().unwrap();
        let (control, controller) = UnixStream::pair().unwrap();
        let (source_owner, from_owner) = UnixStream::pair().unwrap();
        let (destination_owner, to_owner) = UnixStream::pair().unwrap();
        Self {
            source: channel(source),
            destination: channel(destination),
            cancel: control.try_clone().unwrap(),
            control: channel(control),
            owners: vec![source_owner, destination_owner],
            worker: Some(std::thread::spawn(move || {
                relay::run_permitted(
                    file(from),
                    file(to),
                    file(controller),
                    vec![from_owner.into(), to_owner.into()],
                    Duration::from_secs(5),
                    permit,
                )
            })),
        }
    }

    fn offer(&mut self, manifest: &Manifest) {
        write_message(&mut self.control, &request()).unwrap();
        let request: OfferRequest = read_message(&mut self.source, 64 * 1024).unwrap();
        assert_eq!(request.id, ID);
        manifest.write(&mut self.source).unwrap();
        assert_eq!(
            Manifest::read(&mut self.control, LIMITS).unwrap().sha256(),
            manifest.sha256()
        );
    }

    fn approve(&mut self, manifest: &Manifest) {
        write_message(&mut self.control, &approval(manifest)).unwrap();
        let grant: ReceiveRequest = read_message(&mut self.destination, 1024).unwrap();
        assert_eq!(grant.approval.manifest_sha256, manifest.sha256());
        assert_eq!(
            Manifest::read(&mut self.destination, LIMITS)
                .unwrap()
                .sha256(),
            manifest.sha256()
        );
        self.destination.write_all(b"receive\n").unwrap();
        let approved: Approval = read_message(&mut self.source, 1024).unwrap();
        assert_eq!(approved.id, ID);
    }

    fn finish(&mut self) -> io::Result<()> {
        self.worker.take().unwrap().join().unwrap()
    }
}

#[test]
fn actual_endpoints_complete_through_the_relay_without_payload_on_control() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let relay = Relay::start();
    let from = source.0.clone();
    let to = target.0.clone();
    let sender = std::thread::spawn(move || endpoint::send(&mut { relay.source }, &from));
    let receiver = std::thread::spawn(move || endpoint::accept(&mut { relay.destination }, &to));
    let mut control = relay.control;
    write_message(&mut control, &request()).unwrap();
    let manifest = Manifest::read(&mut control, LIMITS).unwrap();
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    write_message(&mut control, &approval(&manifest)).unwrap();
    let receipt: Receipt = read_message(&mut control, 1024).unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.bytes, CONTENT.len() as u64);
    assert_eq!(receipt.manifest_sha256, manifest.sha256());
    relay.worker.unwrap().join().unwrap().unwrap();
    sender.join().unwrap().unwrap();
    receiver.join().unwrap().unwrap();
    assert_eq!(
        fs::read(target.0.join(ID).join("files/document.txt")).unwrap(),
        CONTENT
    );
    assert_eq!(control.read(&mut [0]).unwrap(), 0);
    drop(relay.owners);
}

#[test]
fn mismatched_approval_closes_both_ports_without_authorizing_either_endpoint() {
    let source = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &request().paths, LIMITS).unwrap();
    for different_id in [false, true] {
        let mut relay = Relay::start();
        relay.offer(selection.manifest());
        let mut wrong = approval(selection.manifest());
        if different_id {
            wrong.id = "f".repeat(32);
        }
        if !different_id {
            wrong.manifest_sha256 = "0".repeat(64);
        }
        write_message(&mut relay.control, &wrong).unwrap();
        assert_eq!(
            relay.finish().unwrap_err().to_string(),
            "offer_not_approved"
        );
        assert_eq!(relay.source.read(&mut [0]).unwrap(), 0);
        assert_eq!(relay.destination.read(&mut [0]).unwrap(), 0);
        assert_eq!(relay.control.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn either_owner_death_revokes_a_pending_approval_with_data_ports_still_open() {
    let source = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &request().paths, LIMITS).unwrap();
    for owner in [0, 1] {
        let mut relay = Relay::start();
        relay.offer(selection.manifest());
        drop(relay.owners.remove(owner));
        assert_eq!(
            relay.finish().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(relay.source.read(&mut [0]).unwrap(), 0);
        assert_eq!(relay.destination.read(&mut [0]).unwrap(), 0);
        assert_eq!(relay.control.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn manager_cancel_or_disconnect_aborts_a_partial_copy_and_cleans_the_receiver() {
    let source = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &request().paths, LIMITS).unwrap();
    for disconnect in [false, true] {
        let target = Tree::new();
        let mut relay = Relay::start();
        relay.offer(selection.manifest());
        let path = target.0.clone();
        let receiver =
            std::thread::spawn(move || endpoint::accept(&mut { relay.destination }, &path));
        write_message(&mut relay.control, &approval(selection.manifest())).unwrap();
        let _: Approval = read_message(&mut relay.source, 1024).unwrap();
        relay.source.write_all(&CONTENT[..1]).unwrap();
        if disconnect {
            relay.cancel.shutdown(Shutdown::Write).unwrap();
        }
        if !disconnect {
            relay.cancel.write_all(b"cancel").unwrap();
        }
        assert_eq!(
            relay
                .worker
                .take()
                .unwrap()
                .join()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(receiver.join().unwrap().is_err());
        assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    }
}

#[test]
fn corrupt_payload_never_forwards_the_commit_marker() {
    let source = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let selection = Selection::prepare(&source.0, &request().paths, LIMITS).unwrap();
    let mut relay = Relay::start();
    relay.offer(selection.manifest());
    relay.approve(selection.manifest());
    relay.source.write_all(&vec![b'x'; CONTENT.len()]).unwrap();
    assert_eq!(relay.finish().unwrap_err().to_string(), "content_changed");
    let mut received = Vec::new();
    relay.destination.read_to_end(&mut received).unwrap();
    assert_eq!(received, vec![b'x'; CONTENT.len()]);
    assert_eq!(relay.control.read(&mut [0]).unwrap(), 0);
}

#[test]
fn forged_receipt_is_not_forwarded_to_source_or_controller() {
    let source = Tree::new();
    fs::write(source.0.join("document.txt"), CONTENT).unwrap();
    let mut selection = Selection::prepare(&source.0, &request().paths, LIMITS).unwrap();
    let mut relay = Relay::start();
    relay.offer(selection.manifest());
    relay.approve(selection.manifest());
    selection.send_data(&mut relay.source).unwrap();
    let mut bytes = vec![0; CONTENT.len() + 8];
    relay.destination.read_exact(&mut bytes).unwrap();
    write_message(
        &mut relay.destination,
        &Receipt {
            id: ID.into(),
            manifest_sha256: selection.manifest().sha256(),
            entries: 1,
            bytes: 0,
        },
    )
    .unwrap();
    assert_eq!(relay.finish().unwrap_err().to_string(), "invalid_receipt");
    assert_eq!(relay.source.read(&mut [0]).unwrap(), 0);
    assert_eq!(relay.control.read(&mut [0]).unwrap(), 0);
}

#[test]
fn root_permit_rejects_changed_id_and_increased_limits_before_forwarding() {
    for change in 0..3 {
        let mut relay = Relay::permitted(Some(relay::Permit {
            id: ID.into(),
            limits: LIMITS,
        }));
        let mut offer = request();
        match change {
            0 => offer.id = "a".repeat(32),
            1 => offer.limits.bytes += 1,
            _ => offer.limits.entries += 1,
        }
        write_message(&mut relay.control, &offer).unwrap();
        assert!(relay.worker.take().unwrap().join().unwrap().is_err());
        let mut bytes = Vec::new();
        relay.source.read_to_end(&mut bytes).unwrap();
        relay.destination.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }
}
