#![cfg(windows)]
//! Actual Windows receiver filesystem operations with a bounded source reply
//! transcript. Only transport delivery/ACK loss is controlled by the fixture.
use oblivion_native_windows::security::Identity;
use oblivion_transfer::copy_protocol::Transport;
use oblivion_transfer::endpoint::{SelectionOffer, write_message};
use oblivion_transfer::native_files::{Action, Context, Direction, State, TransfersQuery};
use oblivion_transfer::selection::{Input, Plan};
use oblivion_transfer::stream::{PreparedDownload, operations};
use oblivion_transfer::{Entry, Limits, Manifest};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

struct Area(PathBuf);
impl Area {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oblivion-windows-destination-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let identity = Identity::current().unwrap();
        let descriptor = identity.file_descriptor().unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let wide = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        assert_ne!(unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) }, 0);
        Self(path)
    }
    fn inbox(&self) -> PathBuf {
        self.0.join(".oblivion-transfers")
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Reply {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Reply {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}
impl Write for Reply {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.write(input)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Transport for Reply {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn context() -> Context {
    Context {
        id: "a".repeat(32),
        safe_id: "b".repeat(32),
        opening: "c".repeat(32),
        direction: Direction::Export,
        name: "result".into(),
    }
}
fn manifest(bytes: &[u8]) -> Manifest {
    Manifest::new(
        vec![Entry::File {
            path: "item".into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }],
        Limits {
            entries: 100,
            bytes: 1024,
        },
    )
    .unwrap()
}
fn prepared(
    target: &Path,
    context: Context,
    manifest: &Manifest,
    bytes: &[u8],
    completed: bool,
) -> io::Result<PreparedDownload<Reply>> {
    let directory = matches!(manifest.entries()[0], Entry::Directory { .. });
    let selected = vec!["workspace/item".to_owned()];
    let plan = Plan::new(&[Input {
        path: selected[0].clone(),
        directory,
    }])?;
    let mut input = Vec::new();
    write_message(
        &mut input,
        &SelectionOffer {
            directories: vec![directory],
            plan,
        },
    )?;
    manifest.write(&mut input)?;
    input.extend_from_slice(bytes);
    input.extend_from_slice(b"OBLVEND1");
    if completed {
        input.extend_from_slice(b"copied\n");
    }
    PreparedDownload::prepare(
        Reply {
            input: Cursor::new(input),
            output: Vec::new(),
        },
        &selected,
        target,
        context,
    )
}
fn status(
    area: &Area,
    context: &Context,
    opening: &str,
    action: Action,
) -> oblivion_transfer::native_files::Status {
    operations::manage(
        &area.inbox(),
        &area.0,
        &context.id,
        &context.safe_id,
        opening,
        Direction::Export,
        action,
    )
    .unwrap()
}

#[test]
fn lost_final_ack_is_published_and_discovered_after_every_handle_was_closed() {
    let area = Area::new();
    let context = context();
    let manifest = manifest(b"verified data");
    let prepared = prepared(&area.0, context.clone(), &manifest, b"verified data", false).unwrap();
    assert!(
        !area.inbox().exists(),
        "review must not create receiver staging"
    );
    assert!(
        fs::rename(&area.0, area.0.with_extension("moved")).is_err(),
        "review must pin its actual target object"
    );
    let digest = prepared.summary().unwrap().manifest_sha256;
    assert!(prepared.receive(&digest, &mut |_, _| Ok(())).is_err());
    assert_eq!(fs::read(area.0.join("result")).unwrap(), b"verified data");
    let fresh_opening = "d".repeat(32);
    let published = status(&area, &context, &fresh_opening, Action::Status);
    assert_eq!(published.state, State::Published);
    published
        .validate(&context.id, &context.safe_id, &fresh_opening)
        .unwrap();
    assert_eq!(
        published.source_opening.as_deref(),
        Some(context.opening.as_str())
    );
    let query = TransfersQuery {
        safe_id: context.safe_id.clone(),
        opening: fresh_opening,
        direction: Direction::Export,
        after: None,
        limit: 8,
    };
    let page = operations::inventory(&area.inbox(), &area.0, &query).unwrap();
    page.validate(&query).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].operation_id, context.id);
}

#[test]
fn moved_before_marker_recovery_keeps_the_now_edited_output_and_refuses_discard() {
    let area = Area::new();
    let context = context();
    let manifest = manifest(b"original");
    let prepared = prepared(&area.0, context.clone(), &manifest, b"original", true).unwrap();
    let digest = prepared.summary().unwrap().manifest_sha256;
    prepared.receive(&digest, &mut |_, _| Ok(())).unwrap();
    // Durable rename observed, completion-marker durability was interrupted.
    fs::remove_file(area.inbox().join(&context.id).join("published")).unwrap();
    fs::write(area.0.join("result"), b"user edits after publication").unwrap();
    let ready = status(&area, &context, &"d".repeat(32), Action::Status);
    assert_eq!(ready.state, State::Ready);
    assert!(ready.can_recover && !ready.can_discard);
    assert!(
        operations::manage(
            &area.inbox(),
            &area.0,
            &context.id,
            &context.safe_id,
            &context.opening,
            Direction::Export,
            Action::Discard
        )
        .is_err()
    );
    assert_eq!(
        status(&area, &context, &"d".repeat(32), Action::Recover).state,
        State::Published
    );
    assert_eq!(
        fs::read(area.0.join("result")).unwrap(),
        b"user edits after publication"
    );
}

#[test]
fn existing_empty_directory_is_never_replaced_and_only_private_receive_is_discarded() {
    let area = Area::new();
    fs::create_dir(area.0.join("result")).unwrap();
    let context = context();
    let manifest = Manifest::new(
        vec![Entry::Directory {
            path: "item".into(),
        }],
        Limits {
            entries: 1,
            bytes: 1,
        },
    )
    .unwrap();
    let prepared = prepared(&area.0, context.clone(), &manifest, b"", true).unwrap();
    let digest = prepared.summary().unwrap().manifest_sha256;
    assert!(prepared.receive(&digest, &mut |_, _| Ok(())).is_err());
    assert!(area.0.join("result").is_dir());
    let ready = status(&area, &context, &context.opening, Action::Status);
    assert_eq!(ready.state, State::Ready);
    assert!(ready.can_discard);
    assert_eq!(
        status(&area, &context, &context.opening, Action::Discard).state,
        State::Discarded
    );
    assert!(area.0.join("result").is_dir());
    assert_eq!(fs::read_dir(area.0.join("result")).unwrap().count(), 0);
}

#[test]
fn invalid_windows_names_and_case_collision_are_rejected_before_staging() {
    for name in ["CON", "document.", "file:stream", "LPT¹.txt"] {
        let area = Area::new();
        let mut context = context();
        context.name = name.into();
        assert!(prepared(&area.0, context, &manifest(b"data"), b"data", true).is_err());
        assert!(!area.inbox().exists());
    }
    let area = Area::new();
    let manifest = Manifest::new(
        vec![
            Entry::Directory {
                path: "item".into(),
            },
            Entry::Directory {
                path: "item/Name".into(),
            },
            Entry::Directory {
                path: "item/name".into(),
            },
        ],
        Limits {
            entries: 3,
            bytes: 1,
        },
    )
    .unwrap();
    assert!(prepared(&area.0, context(), &manifest, b"", true).is_err());
    assert!(!area.inbox().exists());
}

#[test]
fn missing_lock_cannot_be_recreated_by_status_or_inventory() {
    let area = Area::new();
    let context = context();
    let manifest = manifest(b"data");
    let prepared = prepared(&area.0, context.clone(), &manifest, b"data", true).unwrap();
    let digest = prepared.summary().unwrap().manifest_sha256;
    prepared.receive(&digest, &mut |_, _| Ok(())).unwrap();
    fs::remove_file(area.inbox().join(".lock")).unwrap();
    assert!(
        operations::manage(
            &area.inbox(),
            &area.0,
            &context.id,
            &context.safe_id,
            &context.opening,
            Direction::Export,
            Action::Status
        )
        .is_err()
    );
    let query = TransfersQuery {
        safe_id: context.safe_id,
        opening: context.opening,
        direction: Direction::Export,
        after: None,
        limit: 8,
    };
    assert!(operations::inventory(&area.inbox(), &area.0, &query).is_err());
    assert!(!area.inbox().join(".lock").exists());
}

#[test]
fn modified_private_bytes_cannot_be_published_by_recovery() {
    let area = Area::new();
    fs::create_dir(area.0.join("result")).unwrap();
    let context = context();
    let manifest = manifest(b"original");
    let prepared = prepared(&area.0, context.clone(), &manifest, b"original", true).unwrap();
    let digest = prepared.summary().unwrap().manifest_sha256;
    assert!(prepared.receive(&digest, &mut |_, _| Ok(())).is_err());
    fs::remove_dir(area.0.join("result")).unwrap();
    fs::write(
        area.inbox().join(&context.id).join("files/item"),
        b"tampered",
    )
    .unwrap();
    assert!(
        operations::manage(
            &area.inbox(),
            &area.0,
            &context.id,
            &context.safe_id,
            &context.opening,
            Direction::Export,
            Action::Recover
        )
        .is_err()
    );
    assert!(!area.0.join("result").exists());
}

#[test]
fn changed_target_file_id_record_never_authorizes_recovery_or_inventory() {
    let area = Area::new();
    let context = context();
    let manifest = manifest(b"data");
    let prepared = prepared(&area.0, context.clone(), &manifest, b"data", true).unwrap();
    let digest = prepared.summary().unwrap().manifest_sha256;
    prepared.receive(&digest, &mut |_, _| Ok(())).unwrap();
    let record = area
        .inbox()
        .join("operations")
        .join(&context.id)
        .join("context.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    value["target"]["file_id"] = serde_json::json!(vec![0u8; 16]);
    fs::write(record, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        operations::manage(
            &area.inbox(),
            &area.0,
            &context.id,
            &context.safe_id,
            &context.opening,
            Direction::Export,
            Action::Status
        )
        .is_err()
    );
    let query = TransfersQuery {
        safe_id: context.safe_id,
        opening: context.opening,
        direction: Direction::Export,
        after: None,
        limit: 8,
    };
    let page = operations::inventory(&area.inbox(), &area.0, &query).unwrap();
    assert!(page.entries.is_empty());
    assert_eq!(page.skipped, 1);
    assert_eq!(fs::read(area.0.join("result")).unwrap(), b"data");
}
