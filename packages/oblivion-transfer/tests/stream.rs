mod support;

use oblivion_transfer::channel::Channel;
use oblivion_transfer::{Limits, endpoint, stream};
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const LIMITS: Limits = Limits { entries: 64, bytes: 1024 * 1024 };

fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}

#[test]
fn desktop_upload_publishes_one_working_tree_and_recovers_the_same_receipt() {
    let source = Tree::new();
    fs::create_dir(source.0.join("project")).unwrap();
    fs::write(source.0.join("project/note.txt"), b"editable document").unwrap();
    let inbox = Tree::new();
    let workspace = Tree::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        stream::send_path(&mut channel(sender), &source.0.join("project"), LIMITS, ID).unwrap()
    });
    let receipt = stream::receive_directory(&mut channel(receiver), &inbox.0, &workspace.0, "gbsoftware", LIMITS).unwrap();
    assert_eq!(sender.join().unwrap(), receipt);
    assert_eq!(fs::read(workspace.0.join("gbsoftware/note.txt")).unwrap(), b"editable document");
    assert!(!inbox.0.join(ID).join("files/project").exists());
    assert_eq!(stream::recover_directory(&inbox.0, &workspace.0, ID).unwrap(), receipt);
    fs::write(workspace.0.join("gbsoftware/note.txt"), b"agent changed this").unwrap();
    assert_eq!(stream::recover_directory(&inbox.0, &workspace.0, ID).unwrap(), receipt);
    assert_eq!(fs::read(workspace.0.join("gbsoftware/note.txt")).unwrap(), b"agent changed this");
}

#[test]
fn publication_preserves_even_an_existing_empty_destination_directory() {
    let source = Tree::new();
    fs::create_dir(source.0.join("project")).unwrap();
    fs::write(source.0.join("project/note.txt"), b"new document").unwrap();
    let inbox = Tree::new();
    let workspace = Tree::new();
    fs::create_dir(workspace.0.join("occupied")).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || stream::send_path(&mut channel(sender), &source.0.join("project"), LIMITS, ID));
    let mut receiver = channel(receiver);
    assert!(stream::receive_directory(&mut receiver, &inbox.0, &workspace.0, "occupied", LIMITS).is_err());
    drop(receiver);
    assert!(sender.join().unwrap().is_err());
    assert!(fs::read_dir(workspace.0.join("occupied")).unwrap().next().is_none());
    assert_eq!(fs::read(inbox.0.join(ID).join("files/project/note.txt")).unwrap(), b"new document");
    assert!(stream::recover_directory(&inbox.0, &workspace.0, ID).is_err());
}

#[test]
fn desktop_download_uses_existing_document_sender_and_copies_only_the_selected_entry() {
    let source = Tree::new();
    fs::create_dir_all(source.0.join("workspace/project")).unwrap();
    fs::write(source.0.join("workspace/project/note.txt"), b"selected").unwrap();
    fs::write(source.0.join("workspace/project/other.txt"), b"excluded").unwrap();
    let inbox = Tree::new();
    let target = Tree::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || endpoint::documents(&mut channel(sender), &source.0));
    let receipt = stream::download(&mut channel(receiver), "workspace/project/note.txt", &inbox.0, &target.0, "exported.txt", LIMITS, ID).unwrap();
    sender.join().unwrap().unwrap();
    assert_eq!(fs::read(target.0.join("exported.txt")).unwrap(), b"selected");
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 1);
    assert_eq!(receipt.bytes, 8);
}
