use oblivion_host::onion_task::{Command, Task};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{read_message, write_message};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn channel(socket: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(socket)), Duration::from_secs(5)).unwrap()
}

#[test]
fn a_waiting_file_rpc_leaves_the_ownership_thread_available() {
    let (client, peer) = UnixStream::pair().unwrap();
    let task = Task::start(channel(client), Command::Receive { ttl_seconds: 60 }).unwrap();
    let mut peer = channel(peer);
    assert!(matches!(
        read_message::<Command>(&mut peer, 4096).unwrap(),
        Command::Receive { ttl_seconds: 60 }
    ));
    // The request is already in flight, but the owner can inspect/cancel it
    // without waiting for startup, hashing or the HTTP worker's response.
    assert!(!task.is_finished());
    write_message(
        &mut peer,
        &serde_json::json!({"ok":true,"phase":"receiving"}),
    )
    .unwrap();
    task.join().unwrap();
}

#[test]
fn cancellation_interrupts_an_inflight_file_rpc_before_any_reply() {
    let (client, peer) = UnixStream::pair().unwrap();
    let (watch, mut cancel) = UnixStream::pair().unwrap();
    let mut client = channel(client);
    client.watch(OwnedFd::from(watch));
    let task = Task::start(client, Command::Freeze {}).unwrap();
    let mut peer = channel(peer);
    assert!(matches!(
        read_message::<Command>(&mut peer, 4096).unwrap(),
        Command::Freeze {}
    ));
    cancel.write_all(b"cancel").unwrap();
    assert_eq!(
        task.join().unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
}

#[test]
fn file_acknowledgements_require_the_exact_completed_phase_and_bounded_metadata() {
    for reply in [
        serde_json::json!({"ok":false,"phase":"review"}),
        serde_json::json!({"ok":true,"phase":"receiving"}),
        serde_json::json!({"ok":true,"phase":"copying"}),
        serde_json::json!({"ok":true,"phase":"closed"}),
        serde_json::json!({"ok":true,"phase":"review","path":"/vault"}),
        serde_json::json!({"ok":true,"phase":"review","secret":"x".repeat(4096)}),
    ] {
        let (client, peer) = UnixStream::pair().unwrap();
        let task = Task::start(channel(client), Command::Freeze {}).unwrap();
        let mut peer = channel(peer);
        read_message::<Command>(&mut peer, 4096).unwrap();
        let encoded = serde_json::to_vec(&reply).unwrap();
        if encoded.len() > 4096 {
            // The production reader rejects the length before reading a body.
            // Sending a body after that rejection races the expected close.
            peer.write_all(&(encoded.len() as u32).to_be_bytes())
                .unwrap();
        } else {
            write_message(&mut peer, &reply).unwrap();
        }
        assert!(task.join().is_err());
    }
    for (command, phase) in [
        (Command::Freeze {}, "review"),
        (Command::Source {}, "copying"),
        (Command::PrepareShare {}, "staging"),
        (Command::Backup { ttl_seconds: 300 }, "sharing"),
        (
            Command::Share {
                receipt: oblivion_transfer::Receipt {
                    id: "a".repeat(32),
                    manifest_sha256: "b".repeat(64),
                    entries: 1,
                    bytes: 3,
                },
                paths: vec!["workspace/note.txt".into()],
                ttl_seconds: 60,
            },
            "sharing",
        ),
    ] {
        let (client, peer) = UnixStream::pair().unwrap();
        let task = Task::start(channel(client), command).unwrap();
        let mut peer = channel(peer);
        read_message::<Command>(&mut peer, 4096).unwrap();
        write_message(&mut peer, &serde_json::json!({"ok":true,"phase":phase})).unwrap();
        task.join().unwrap();
    }
}
