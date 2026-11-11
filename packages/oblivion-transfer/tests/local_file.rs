#![cfg(unix)]
mod support;
use oblivion_transfer::local_file::Input;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::symlink;
use support::Tree;

#[test]
fn format_agnostic_input_is_readonly_regular_and_never_follows_links() {
    let tree = Tree::new();
    let path = tree.0.join("encrypted share");
    let bytes = b"age-encryption.org/v1\nopaque Share ciphertext";
    fs::write(&path, bytes).unwrap();
    let mut input = Input::open(&path).unwrap();
    assert_eq!(input.size().unwrap(), bytes.len() as u64);
    let mut read = Vec::new();
    input.read_to_end(&mut read).unwrap();
    assert_eq!(read, bytes);
    input.verify().unwrap();
    assert!(
        Input::from_file(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        )
        .is_err()
    );
    symlink(&path, tree.0.join("symbolic link")).unwrap();
    assert!(Input::open(&tree.0.join("symbolic link")).is_err());
    fs::hard_link(&path, tree.0.join("hard link")).unwrap();
    assert!(input.verify().is_err());
    assert!(Input::open(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn selected_input_retains_the_open_file_when_its_local_name_is_replaced() {
    let tree = Tree::new();
    let path = tree.0.join("selected share");
    fs::write(&path, b"the explicitly selected encrypted file").unwrap();
    let mut input = Input::open(&path).unwrap();
    fs::rename(&path, tree.0.join("moved selected file")).unwrap();
    fs::write(&path, b"unrelated replacement").unwrap();
    input.verify().unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"the explicitly selected encrypted file");
    assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");
}
