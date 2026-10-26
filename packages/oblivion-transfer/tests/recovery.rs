mod support;

use oblivion_transfer::recovery::{self, Request, Response, State};
use oblivion_transfer::{Limits, Selection, publish, receive};
use std::fs::{self, DirBuilder};
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn received(inbox: &Tree) -> oblivion_transfer::Manifest {
    let source = Tree::new();
    fs::write(source.0.join("note"), b"original").unwrap();
    let mut selection = Selection::prepare(
        &source.0,
        &["note".into()],
        Limits {
            entries: 64,
            bytes: 1024,
        },
    )
    .unwrap();
    let mut bytes = Vec::new();
    selection.manifest().write(&mut bytes).unwrap();
    let manifest = oblivion_transfer::Manifest::read(
        &mut Cursor::new(bytes),
        Limits {
            entries: 64,
            bytes: 1024,
        },
    )
    .unwrap();
    let mut data = Vec::new();
    selection.send_data(&mut data).unwrap();
    receive(&mut Cursor::new(data), &manifest, &inbox.0, ID).unwrap();
    manifest
}

fn inventory(inbox: &Tree, published: &Tree) -> Vec<recovery::Record> {
    let request = Request::List { after: None };
    let response = recovery::execute(&inbox.0, &published.0, request).unwrap();
    response.validate(&Request::List { after: None }).unwrap();
    let Response::Inventory { records, next } = response else {
        panic!("inventory expected")
    };
    assert!(next.is_none());
    records
}

#[test]
fn durable_receipt_describes_original_import_and_never_authorizes_deleting_chat_edits() {
    let inbox = Tree::new();
    let published = Tree::new();
    let manifest = received(&inbox);
    publish(&inbox.0, &published.0, ID, &manifest).unwrap();
    fs::write(published.0.join(ID).join("files/note"), b"later chat edit").unwrap();
    let records = inventory(&inbox, &published);
    assert_eq!(records[0].state, State::Published);
    assert_eq!(records[0].receipt.as_ref().unwrap().bytes, 8);
    assert_eq!(
        records[0].receipt.as_ref().unwrap().manifest_sha256,
        manifest.sha256()
    );
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
    assert_eq!(
        fs::read(published.0.join(ID).join("files/note")).unwrap(),
        b"later chat edit"
    );
    // A published tree is untrusted, mutable chat content. Status never follows
    // its entries, even if the agent replaces a document with a symlink.
    fs::remove_file(published.0.join(ID).join("files/note")).unwrap();
    symlink("/etc/passwd", published.0.join(ID).join("files/note")).unwrap();
    assert_eq!(inventory(&inbox, &published)[0].state, State::Published);
}

#[test]
fn private_copy_and_interrupted_private_publication_can_be_discarded_explicitly() {
    for moved in [false, true] {
        let inbox = Tree::new();
        let published = Tree::new();
        received(&inbox);
        if moved {
            DirBuilder::new()
                .mode(0o700)
                .create(published.0.join(ID))
                .unwrap();
            fs::rename(
                inbox.0.join(ID).join("files"),
                published.0.join(ID).join("files"),
            )
            .unwrap();
        }
        assert_eq!(inventory(&inbox, &published)[0].state, State::Private);
        recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).unwrap();
        assert!(!inbox.0.join(ID).exists());
        assert!(!published.0.join(ID).exists());
        assert!(inventory(&inbox, &published).is_empty());
    }
}

#[test]
fn exposure_without_final_marker_and_missing_publication_are_preserved() {
    let inbox = Tree::new();
    let published = Tree::new();
    let manifest = received(&inbox);
    publish(&inbox.0, &published.0, ID, &manifest).unwrap();
    fs::remove_file(inbox.0.join(ID).join("published")).unwrap();
    assert_eq!(inventory(&inbox, &published)[0].state, State::Available);
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
    fs::write(inbox.0.join(ID).join("published"), []).unwrap();
    fs::set_permissions(
        inbox.0.join(ID).join("published"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::remove_dir_all(published.0.join(ID)).unwrap();
    assert_eq!(inventory(&inbox, &published)[0].state, State::Missing);
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
    assert!(inbox.0.join(ID).join("receipt.json").exists());
}

#[test]
fn legacy_publication_without_a_ledger_is_never_treated_as_private() {
    let inbox = Tree::new();
    let published = Tree::new();
    DirBuilder::new()
        .mode(0o750)
        .create(published.0.join(ID))
        .unwrap();
    assert_eq!(inventory(&inbox, &published)[0].state, State::Available);
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
}

#[test]
fn pagination_visits_every_record_without_silently_truncating() {
    let inbox = Tree::new();
    let published = Tree::new();
    for i in 0..65 {
        DirBuilder::new()
            .mode(0o700)
            .create(inbox.0.join(format!("{i:032x}")))
            .unwrap();
    }
    let response =
        recovery::execute(&inbox.0, &published.0, Request::List { after: None }).unwrap();
    response.validate(&Request::List { after: None }).unwrap();
    let Response::Inventory { records, next } = response else {
        panic!("inventory")
    };
    assert_eq!(records.len(), 64);
    assert_eq!(next, Some(format!("{:032x}", 63)));
    let response = recovery::execute(
        &inbox.0,
        &published.0,
        Request::List {
            after: next.clone(),
        },
    )
    .unwrap();
    response.validate(&Request::List { after: next }).unwrap();
    let Response::Inventory { records, next } = response else {
        panic!("inventory")
    };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, format!("{:032x}", 64));
    assert!(next.is_none());
}

#[test]
fn corrupt_receipts_symlinks_and_path_requests_fail_without_removal() {
    let inbox = Tree::new();
    let published = Tree::new();
    received(&inbox);
    fs::write(inbox.0.join(ID).join("receipt.json"), b"{").unwrap();
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
    assert!(inbox.0.join(ID).join("files/note").exists());
    assert!(
        recovery::execute(
            &inbox.0,
            &published.0,
            Request::Discard {
                id: "../outside".into()
            }
        )
        .is_err()
    );
    fs::remove_dir_all(inbox.0.join(ID)).unwrap();
    symlink(&published.0, inbox.0.join(ID)).unwrap();
    assert!(recovery::execute(&inbox.0, &published.0, Request::Discard { id: ID.into() }).is_err());
    assert!(published.0.is_dir());
}
