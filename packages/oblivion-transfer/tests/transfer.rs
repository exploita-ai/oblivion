mod support;

use oblivion_transfer::{Entry, ExportMode, Limits, Manifest, Selection, publish, receive};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LIMITS: Limits = Limits {
    entries: 64,
    bytes: 1024 * 1024,
};

#[test]
fn external_export_preserves_existing_data_and_never_reuses_a_destination() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("note"), b"selected").unwrap();
    fs::write(target.0.join("existing"), b"keep this document").unwrap();
    let (manifest, bytes) = encode(&source, &["note"]);
    let receipt = oblivion_transfer::receive_external(
        &mut Cursor::new(bytes.clone()),
        &manifest,
        &target.0,
        ID,
        ExportMode::Posix,
    )
    .unwrap();
    assert_eq!(receipt.manifest_sha256, manifest.sha256());
    let exported = target.0.join(format!("Oblivion-{ID}/files/note"));
    assert_eq!(fs::read(&exported).unwrap(), b"selected");
    assert_eq!(fs::metadata(&exported).unwrap().mode() & 0o777, 0o644);
    fs::write(&exported, b"external edit").unwrap();
    assert!(
        oblivion_transfer::receive_external(
            &mut Cursor::new(bytes),
            &manifest,
            &target.0,
            ID,
            ExportMode::Posix
        )
        .is_err()
    );
    assert_eq!(fs::read(&exported).unwrap(), b"external edit");
    assert_eq!(
        fs::read(target.0.join("existing")).unwrap(),
        b"keep this document"
    );
}

#[test]
fn portable_export_rejects_names_that_could_be_rewritten_by_the_filesystem() {
    let target = Tree::new();
    for name in [
        "note.", "note ", "a:b", "a?b", "a*b", "a\"b", "a<b", "a>b", "a|b",
    ] {
        // The common manifest accepts these POSIX filenames. The external
        // portable writer must reject them before creating a transaction.
        let manifest = Manifest::new(vec![empty(name)], LIMITS).unwrap();
        assert!(
            oblivion_transfer::receive_external(
                &mut Cursor::new(b"OBLVEND1"),
                &manifest,
                &target.0,
                ID,
                ExportMode::Portable,
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
    }
}

#[test]
fn truncated_external_export_removes_only_its_new_partial_copy() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("note"), b"selected").unwrap();
    fs::write(target.0.join("existing"), b"keep").unwrap();
    let (manifest, bytes) = encode(&source, &["note"]);
    assert!(
        oblivion_transfer::receive_external(
            &mut Cursor::new(&bytes[..bytes.len() - 1]),
            &manifest,
            &target.0,
            ID,
            ExportMode::Posix,
        )
        .is_err()
    );
    assert!(!target.0.join(format!("Oblivion-{ID}")).exists());
    assert_eq!(fs::read(target.0.join("existing")).unwrap(), b"keep");
}

fn empty(path: &str) -> Entry {
    Entry::File {
        path: path.into(),
        size: 0,
        sha256: EMPTY.into(),
    }
}

fn encode(source: &Tree, paths: &[&str]) -> (Manifest, Vec<u8>) {
    let mut selection = Selection::prepare(
        &source.0,
        &paths.iter().map(|p| (*p).into()).collect::<Vec<_>>(),
        LIMITS,
    )
    .unwrap();
    let mut bytes = Vec::new();
    selection.manifest().write(&mut bytes).unwrap();
    selection.send_data(&mut bytes).unwrap();
    let mut reader = Cursor::new(bytes);
    let manifest = Manifest::read(&mut reader, LIMITS).unwrap();
    let offset = reader.position() as usize;
    (manifest, reader.into_inner()[offset..].to_vec())
}

#[test]
fn real_stream_copies_selected_tree_with_hash_receipt_and_private_permissions() {
    let source = Tree::new();
    let target = Tree::new();
    fs::create_dir(source.0.join("documenti")).unwrap();
    fs::create_dir(source.0.join("documenti/vuota")).unwrap();
    let content: Vec<_> = (0..300_000).map(|n| (n % 251) as u8).collect();
    fs::write(source.0.join("documenti/città.pdf"), &content).unwrap();
    fs::write(source.0.join("documenti/empty"), []).unwrap();
    fs::write(source.0.join("non-selezionato"), b"private source").unwrap();
    let mut selection = Selection::prepare(&source.0, &["documenti".into()], LIMITS).unwrap();
    let digest = selection.manifest().sha256();
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    sender
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let worker = std::thread::spawn(move || {
        selection.manifest().write(&mut sender).unwrap();
        selection.send_data(&mut sender).unwrap();
        let mut receipt = String::new();
        sender.read_to_string(&mut receipt).unwrap();
        serde_json::from_str::<oblivion_transfer::Receipt>(&receipt).unwrap()
    });
    let manifest = Manifest::read(&mut receiver, LIMITS).unwrap();
    assert_eq!(manifest.sha256(), digest);
    // This is the caller's approval boundary; receive does not choose the offer.
    let receipt = receive(&mut receiver, &manifest, &target.0, ID).unwrap();
    receiver
        .write_all(&serde_json::to_vec(&receipt).unwrap())
        .unwrap();
    drop(receiver);
    assert_eq!(worker.join().unwrap(), receipt);
    assert_eq!(receipt.bytes, 300_000);
    assert_eq!(receipt.entries, 4);
    assert_eq!(receipt.manifest_sha256, digest);
    let copied = target.0.join(ID).join("files/documenti/città.pdf");
    assert_eq!(fs::read(&copied).unwrap(), content);
    assert_eq!(fs::metadata(copied).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(target.0.join(ID).join("files/documenti"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert!(target.0.join(ID).join("files/documenti/vuota").is_dir());
    assert!(!target.0.join(ID).join("pending").exists());
    assert!(!target.0.join(ID).join("files/non-selezionato").exists());
    assert!(source.0.join("documenti/città.pdf").is_file());
}

#[test]
fn hostile_paths_and_tree_conflicts_are_rejected_before_receiving() {
    for path in [
        "",
        "/absolute",
        "../outside",
        "a/../b",
        "./a",
        "a//b",
        "a/",
        "a\\b",
        "a\0b",
        "a\nb",
        "\x1b[2J",
        "a\u{202e}b",
    ] {
        assert!(
            Manifest::new(vec![empty(path)], LIMITS).is_err(),
            "{path:?}"
        );
    }
    for entries in [
        vec![empty("a"), empty("a")],
        vec![empty("a/b")],
        vec![empty("a"), empty("a/b")],
        vec![empty("a"), Entry::Directory { path: "a".into() }],
    ] {
        assert!(Manifest::new(entries, LIMITS).is_err());
    }
    assert!(Manifest::new(vec![empty(&"x".repeat(256))], LIMITS).is_err());
    assert!(Manifest::new(vec![empty(&vec!["a"; 33].join("/"))], LIMITS).is_err());
}

#[test]
fn manifest_limits_and_numeric_overflow_cannot_allocate_a_destination() {
    assert!(Manifest::new(vec![], LIMITS).is_err());
    assert!(
        Manifest::new(
            vec![empty("a"), empty("b")],
            Limits {
                entries: 1,
                bytes: 0
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![Entry::File {
                path: "a".into(),
                size: 2,
                sha256: EMPTY.into()
            }],
            Limits {
                entries: 1,
                bytes: 1
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![
                Entry::File {
                    path: "a".into(),
                    size: u64::MAX,
                    sha256: EMPTY.into()
                },
                Entry::File {
                    path: "b".into(),
                    size: 1,
                    sha256: EMPTY.into()
                }
            ],
            Limits {
                entries: 2,
                bytes: u64::MAX
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![Entry::File {
                path: "a".into(),
                size: 0,
                sha256: "not-a-hash".into()
            }],
            LIMITS
        )
        .is_err()
    );
    let mut oversize = b"OBLVCP01".to_vec();
    oversize.extend(u32::MAX.to_be_bytes());
    assert_eq!(
        Manifest::read(&mut Cursor::new(oversize), LIMITS)
            .err()
            .unwrap()
            .to_string(),
        "header_limit"
    );
}

#[test]
fn protocol_rejects_unknown_fields_version_truncated_or_malformed_headers() {
    for json in [
        r#"[{"kind":"directory","path":"a","mode":511}]"#,
        r#"[{"kind":"symlink","path":"a","target":"/etc"}]"#,
        r#"{}"#,
        "[",
    ] {
        let mut wire = b"OBLVCP01".to_vec();
        wire.extend((json.len() as u32).to_be_bytes());
        wire.extend(json.as_bytes());
        assert!(Manifest::read(&mut Cursor::new(wire), LIMITS).is_err());
    }
    for wire in [
        b"OBLVCP02".to_vec(),
        b"OBLV".to_vec(),
        b"OBLVCP01\0\0\0\x10[]".to_vec(),
    ] {
        assert!(Manifest::read(&mut Cursor::new(wire), LIMITS).is_err());
    }
}

#[test]
fn corruption_truncation_and_missing_commit_never_publish_partial_files() {
    let source = Tree::new();
    fs::write(source.0.join("a"), b"synthetic-document").unwrap();
    let (manifest, wire) = encode(&source, &["a"]);
    let mut corrupt = wire.clone();
    corrupt[0] ^= 1;
    let mut wrong_end = wire.clone();
    *wrong_end.last_mut().unwrap() ^= 1;
    for bytes in [
        vec![],
        wire[..4].to_vec(),
        wire[..wire.len() - 1].to_vec(),
        corrupt,
        wrong_end,
    ] {
        let target = Tree::new();
        fs::write(target.0.join("existing"), b"preserve").unwrap();
        assert!(receive(&mut Cursor::new(bytes), &manifest, &target.0, ID).is_err());
        assert!(!target.0.join(ID).exists());
        assert_eq!(fs::read(target.0.join("existing")).unwrap(), b"preserve");
    }
}

#[test]
fn existing_transaction_is_never_reused_or_overwritten() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("a"), b"first").unwrap();
    let (manifest, wire) = encode(&source, &["a"]);
    receive(&mut Cursor::new(&wire), &manifest, &target.0, ID).unwrap();
    assert!(receive(&mut Cursor::new(&wire), &manifest, &target.0, ID).is_err());
    assert_eq!(
        fs::read(target.0.join(ID).join("files/a")).unwrap(),
        b"first"
    );
    let link_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    symlink(&source.0, target.0.join(link_id)).unwrap();
    assert!(receive(&mut Cursor::new(&wire), &manifest, &target.0, link_id).is_err());
    assert_eq!(fs::read(source.0.join("a")).unwrap(), b"first");
}

#[test]
fn source_links_fifo_socket_and_unselected_paths_are_rejected() {
    let source = Tree::new();
    let outside = Tree::new();
    fs::write(outside.0.join("secret"), b"outside selection").unwrap();
    symlink(outside.0.join("secret"), source.0.join("link")).unwrap();
    symlink(&outside.0, source.0.join("directory-link")).unwrap();
    fs::hard_link(outside.0.join("secret"), source.0.join("hardlink")).unwrap();
    let fifo =
        std::ffi::CString::new(source.0.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let _socket = UnixListener::bind(source.0.join("socket")).unwrap();
    for path in [
        "link",
        "directory-link",
        "directory-link/secret",
        "hardlink",
        "fifo",
        "socket",
        "../secret",
    ] {
        assert!(
            Selection::prepare(&source.0, &[path.into()], LIMITS).is_err(),
            "{path}"
        );
    }
    assert!(
        Selection::prepare(&source.0.join("directory-link"), &["secret".into()], LIMITS).is_err()
    );
}

#[test]
fn pinned_source_descriptors_survive_path_replacement_without_following_new_links() {
    let source = Tree::new();
    let outside = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("selected"), b"approved").unwrap();
    fs::write(outside.0.join("secret"), b"unapproved").unwrap();
    let mut selection = Selection::prepare(&source.0, &["selected".into()], LIMITS).unwrap();
    fs::rename(source.0.join("selected"), source.0.join("old")).unwrap();
    symlink(outside.0.join("secret"), source.0.join("selected")).unwrap();
    let mut data = Vec::new();
    selection.send_data(&mut data).unwrap();
    receive(&mut Cursor::new(data), selection.manifest(), &target.0, ID).unwrap();
    assert_eq!(
        fs::read(target.0.join(ID).join("files/selected")).unwrap(),
        b"approved"
    );
}

#[test]
fn changed_source_aborts_without_a_success_trailer_or_publication() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("a"), b"before").unwrap();
    let mut selection = Selection::prepare(&source.0, &["a".into()], LIMITS).unwrap();
    fs::write(source.0.join("a"), b"after!").unwrap();
    let mut data = Vec::new();
    assert_eq!(
        selection.send_data(&mut data).unwrap_err().to_string(),
        "source_changed"
    );
    assert!(!data.ends_with(b"OBLVEND1"));
    assert!(receive(&mut Cursor::new(data), selection.manifest(), &target.0, ID).is_err());
    assert!(!target.0.join(ID).exists());
}

#[test]
fn connection_cancellation_removes_the_private_partial_transaction() {
    let source = Tree::new();
    let target = Tree::new();
    fs::write(source.0.join("a"), b"cancel-this-transfer").unwrap();
    let (manifest, bytes) = encode(&source, &["a"]);
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    sender.write_all(&bytes[..3]).unwrap();
    drop(sender);
    assert!(receive(&mut receiver, &manifest, &target.0, ID).is_err());
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
}

#[test]
fn receiver_requires_private_directory_and_local_opaque_transaction_id() {
    let target = Tree::new();
    let parent = Tree::new();
    let manifest = Manifest::new(vec![empty("a")], LIMITS).unwrap();
    for id in [
        "",
        "../escape",
        "/absolute",
        "123",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(receive(&mut Cursor::new(b"OBLVEND1"), &manifest, &target.0, id).is_err());
    }
    fs::set_permissions(&target.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        receive(&mut Cursor::new(b"OBLVEND1"), &manifest, &target.0, ID)
            .unwrap_err()
            .to_string(),
        "unsafe_receive_root"
    );
    fs::set_permissions(&target.0, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target.0, parent.0.join("alias")).unwrap();
    assert!(
        receive(
            &mut Cursor::new(b"OBLVEND1"),
            &manifest,
            &parent.0.join("alias"),
            ID
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
}

#[test]
fn recursive_source_limits_apply_before_reading_large_files() {
    let source = Tree::new();
    fs::create_dir(source.0.join("dir")).unwrap();
    fs::write(source.0.join("dir/a"), b"too large").unwrap();
    fs::write(source.0.join("dir/b"), []).unwrap();
    assert!(
        Selection::prepare(
            &source.0,
            &["dir".into()],
            Limits {
                entries: 2,
                bytes: 100
            }
        )
        .is_err()
    );
    assert!(
        Selection::prepare(
            &source.0,
            &["dir".into()],
            Limits {
                entries: 4,
                bytes: 2
            }
        )
        .is_err()
    );
    let selection = Selection::prepare(&source.0, &["dir/a".into()], LIMITS).unwrap();
    assert_eq!(selection.manifest().entries().len(), 2);
    assert_eq!(selection.manifest().bytes(), 9);
}

#[test]
fn verified_copy_is_published_once_with_chat_group_access() {
    let source = Tree::new();
    let inbox = Tree::new();
    let published = Tree::new();
    fs::create_dir(source.0.join("docs")).unwrap();
    fs::write(source.0.join("docs/note.txt"), b"document").unwrap();
    let (manifest, bytes) = encode(&source, &["docs"]);
    receive(&mut Cursor::new(bytes), &manifest, &inbox.0, ID).unwrap();
    assert_eq!(fs::read_dir(&published.0).unwrap().count(), 0);
    publish(&inbox.0, &published.0, ID, &manifest).unwrap();
    assert!(inbox.0.join(ID).join("receipt.json").is_file());
    assert!(inbox.0.join(ID).join("published").is_file());
    let path = published.0.join(ID).join("files/docs/note.txt");
    assert_eq!(fs::read(&path).unwrap(), b"document");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o660);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
        0o770
    );
    assert_eq!(
        fs::metadata(published.0.join(ID)).unwrap().mode() & 0o777,
        0o750
    );
    let (_, bytes) = encode(&source, &["docs"]);
    assert!(receive(&mut Cursor::new(bytes), &manifest, &inbox.0, ID).is_err());
    fs::write(&path, b"chat edit").unwrap();
    assert!(publish(&inbox.0, &published.0, ID, &manifest).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"chat edit");
}

#[test]
fn publication_rejects_chat_writable_parent_and_symlink_substitution() {
    let source = Tree::new();
    let inbox = Tree::new();
    let published = Tree::new();
    fs::write(source.0.join("note"), b"document").unwrap();
    let (manifest, bytes) = encode(&source, &["note"]);
    receive(&mut Cursor::new(bytes), &manifest, &inbox.0, ID).unwrap();
    fs::set_permissions(&published.0, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(publish(&inbox.0, &published.0, ID, &manifest).is_err());
    assert!(!published.0.join(ID).exists());
    fs::set_permissions(&published.0, fs::Permissions::from_mode(0o750)).unwrap();
    let path = inbox.0.join(ID).join("files/note");
    fs::remove_file(&path).unwrap();
    symlink(source.0.join("note"), &path).unwrap();
    assert!(publish(&inbox.0, &published.0, ID, &manifest).is_err());
    assert_eq!(
        fs::metadata(published.0.join(ID)).unwrap().mode() & 0o777,
        0o700
    );
    assert!(!published.0.join(ID).join("files").exists());
    assert_eq!(fs::read(source.0.join("note")).unwrap(), b"document");
}
