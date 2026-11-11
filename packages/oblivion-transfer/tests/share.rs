mod support;

use oblivion_transfer::{Limits, Selection};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::write_message;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const LIMITS: Limits = Limits { entries: 32, bytes: 1024 * 1024 };

#[test]
fn approved_share_stream_uses_existing_manifest_hash_and_verified_receipt() {
    let source = Tree::new();
    let target = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::write(source.0.join("workspace/code"), b"shared code").unwrap();
    let selected = Selection::prepare(&source.0, &["workspace".into()], LIMITS).unwrap();
    let public = source.0.join("approved.json");
    fs::write(&public, serde_json::to_vec(&serde_json::json!({
        "version":1, "request_id":ID,"manifest_sha256":selected.manifest().sha256(),
        "entries":selected.manifest().entries(),"aliases":["workspace/code"]
    })).unwrap()).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o600)).unwrap();
    let (send, receive) = UnixStream::pair().unwrap();
    let root = source.0.clone();
    let sender = std::thread::spawn(move || {
        let mut channel = Channel::new(File::from(OwnedFd::from(send)), Duration::from_secs(3)).unwrap();
        let receipt = oblivion_transfer::share::send(&mut channel, &root, File::open(public).unwrap()).unwrap();
        channel.write_all(b"copied\n").unwrap();
        receipt
    });
    let mut channel = Channel::new(File::from(OwnedFd::from(receive)), Duration::from_secs(3)).unwrap();
    let receipt = oblivion_transfer::share::receive(&mut channel, &target.0, ID).unwrap();
    write_message(&mut channel, &receipt).unwrap();
    let mut copied = [0; 7];
    channel.read_exact(&mut copied).unwrap();
    assert_eq!(&copied, b"copied\n");
    assert_eq!(sender.join().unwrap(), receipt);
    assert_eq!(fs::read(target.0.join(format!("{ID}/files/workspace/code"))).unwrap(), b"shared code");
}

#[test]
fn a_valid_manifest_cannot_alias_a_home_credential_or_a_different_catalog() {
    let source = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::write(source.0.join("workspace/code"), b"selected").unwrap();
    let selected = Selection::prepare(&source.0, &["workspace".into()], LIMITS).unwrap();
    let file = source.0.join("plan");
    fs::write(&file, serde_json::to_vec(&serde_json::json!({
        "version":1,"request_id":ID,"manifest_sha256":selected.manifest().sha256(),
        "entries":selected.manifest().entries(),"aliases":["home/.codex/auth.json"]
    })).unwrap()).unwrap();
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut channel = Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(1)).unwrap();
    assert!(oblivion_transfer::share::send(&mut channel, &source.0, File::open(file).unwrap()).is_err());
}
