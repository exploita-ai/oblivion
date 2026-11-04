mod support;

use oblivion_transfer::{Entry, Limits, Manifest, Selection, receive};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::symlink;
use support::Tree;

const LIMITS: Limits = Limits { entries: 64, bytes: 1024 * 1024 };

fn manifest() -> Manifest {
    Manifest::new(vec![
        Entry::Directory { path: "workspace".into() },
        Entry::File { path: "workspace/selected".into(), size: 4, sha256: format!("{:x}", Sha256::digest(b"code")) },
        Entry::Directory { path: "history".into() },
        Entry::File { path: "history/chats.jsonl".into(), size: 7, sha256: format!("{:x}", Sha256::digest(b"catalog")) },
    ], LIMITS).unwrap()
}

#[test]
fn approved_aliases_copy_only_reviewed_files_without_staging_the_workspace() {
    let source = Tree::new();
    let target = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::create_dir(source.0.join("private-stage")).unwrap();
    fs::write(source.0.join("workspace/selected"), b"code").unwrap();
    fs::write(source.0.join("workspace/excluded"), b"never share").unwrap();
    fs::write(source.0.join("private-stage/export"), b"catalog").unwrap();
    let mut selection = Selection::approved(&source.0, manifest(), &["workspace/selected".into(), "private-stage/export".into()]).unwrap();
    let mut bytes = Vec::new();
    selection.send_data(&mut bytes).unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    receive(&mut Cursor::new(bytes), selection.manifest(), &target.0, id).unwrap();
    assert_eq!(fs::read(target.0.join(format!("{id}/files/workspace/selected"))).unwrap(), b"code");
    assert_eq!(fs::read(target.0.join(format!("{id}/files/history/chats.jsonl"))).unwrap(), b"catalog");
    assert!(!target.0.join(format!("{id}/files/workspace/excluded")).exists());
    assert!(!target.0.join(format!("{id}/files/private-stage")).exists());
}

#[test]
fn changed_or_escaping_aliases_never_complete_a_transfer() {
    let source = Tree::new();
    fs::create_dir(source.0.join("workspace")).unwrap();
    fs::create_dir(source.0.join("private-stage")).unwrap();
    fs::write(source.0.join("workspace/selected"), b"code").unwrap();
    fs::write(source.0.join("private-stage/export"), b"catalog").unwrap();
    assert!(Selection::approved(&source.0, manifest(), &["../selected".into(), "private-stage/export".into()]).is_err());
    symlink("private-stage", source.0.join("escape")).unwrap();
    assert!(Selection::approved(&source.0, manifest(), &["workspace/selected".into(), "escape/export".into()]).is_err());
    let mut selection = Selection::approved(&source.0, manifest(), &["workspace/selected".into(), "private-stage/export".into()]).unwrap();
    fs::write(source.0.join("workspace/selected"), b"edit").unwrap();
    let mut bytes = Vec::new();
    assert!(selection.send_data(&mut bytes).is_err());
    assert!(!bytes.ends_with(b"OBLVEND1"));
}
