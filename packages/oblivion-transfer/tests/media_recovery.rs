#![cfg(unix)]

mod support;

use oblivion_transfer::media_export::{
    Authority, Rejection, Request, Response, State, Status, execute,
};
use oblivion_transfer::{ExportMode, Limits, Selection, receive_external};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const LIMITS: Limits = Limits {
    entries: 16,
    bytes: 1024,
};

fn export(target: &Path, id: &str) -> PathBuf {
    let source = Tree::new();
    fs::write(source.0.join("z"), b"reviewed").unwrap();
    fs::write(source.0.join("a"), b"selected").unwrap();
    // Source manifests need not have the same order as directory enumeration.
    let mut selection = Selection::prepare(&source.0, &["z".into(), "a".into()], LIMITS).unwrap();
    let mut payload = Vec::new();
    selection.send_data(&mut payload).unwrap();
    receive_external(
        &mut Cursor::new(payload),
        selection.manifest(),
        target,
        id,
        ExportMode::Posix,
    )
    .unwrap();
    target.join(format!("Oblivion-{id}"))
}

fn stage(target: &Path, id: &str) -> PathBuf {
    let final_path = export(target, id);
    let pending = target.join(format!(".Oblivion-{id}.pending"));
    fs::rename(final_path, &pending).unwrap();
    pending
}

fn status(target: &Path, id: &str) -> Status {
    let request = Request::Status { id: id.into() };
    let Response::Status { status } =
        execute(target, &request, Authority::Inspect, || Ok(())).unwrap()
    else {
        panic!("not a status response")
    };
    status
}

#[test]
fn missing_receipt_recovers_a_verified_stage_without_recopying_data() {
    use std::os::unix::fs::MetadataExt;
    let target = Tree::new();
    let pending = stage(&target.0, ID);
    fs::remove_file(pending.join("receipt.json")).unwrap();
    fs::write(pending.join("receipt.pending"), b"partial prior receipt").unwrap();
    fs::set_permissions(
        pending.join("receipt.pending"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(pending.join("files/z"), fs::Permissions::from_mode(0o600)).unwrap();
    let source_inode = fs::metadata(pending.join("files/z")).unwrap().ino();
    let observed = status(&target.0, ID);
    assert_eq!(observed.state, State::Ready);
    assert!(!pending.join("receipt.json").exists());
    let request = Request::Recover {
        id: ID.into(),
        review_sha256: observed.review_sha256.unwrap(),
    };
    let Response::Status { status: published } = execute(
        &target.0,
        &request,
        Authority::Recover(ExportMode::Posix),
        || Ok(()),
    )
    .unwrap() else {
        panic!("not a status response")
    };
    assert_eq!(published.state, State::Published);
    assert_eq!(published.receipt, observed.receipt);
    let final_path = target.0.join(format!("Oblivion-{ID}"));
    assert_eq!(fs::read(final_path.join("files/z")).unwrap(), b"reviewed");
    let final_meta = fs::metadata(final_path.join("files/z")).unwrap();
    assert_eq!(final_meta.ino(), source_inode);
    assert_eq!(final_meta.permissions().mode() & 0o777, 0o644);
    assert!(final_path.join("receipt.json").is_file());
    assert!(!final_path.join("receipt.pending").exists());
    assert!(!pending.exists());
    assert_eq!(status(&target.0, ID).state, State::Published);
}

#[test]
fn changed_review_and_wrong_guest_role_cannot_discard_a_stage() {
    let target = Tree::new();
    let pending = stage(&target.0, ID);
    fs::remove_file(pending.join("receipt.json")).unwrap();
    fs::rename(pending.join("files"), pending.join("pending")).unwrap();
    fs::write(pending.join("pending/z"), b"part").unwrap();
    let observed = status(&target.0, ID);
    assert_eq!(observed.state, State::Incomplete);
    let digest = observed.review_sha256.unwrap();
    assert!(
        execute(
            &target.0,
            &Request::Recover {
                id: ID.into(),
                review_sha256: digest.clone()
            },
            Authority::Recover(ExportMode::Posix),
            || Ok(())
        )
        .is_err()
    );
    let stale = Request::Discard {
        id: ID.into(),
        review_sha256: digest,
    };
    assert!(execute(&target.0, &stale, Authority::Inspect, || Ok(())).is_err());
    assert!(
        execute(
            &target.0,
            &stale,
            Authority::Recover(ExportMode::Posix),
            || Ok(())
        )
        .is_err()
    );
    fs::write(pending.join("pending/z"), b"edit").unwrap();
    assert_eq!(
        execute(&target.0, &stale, Authority::Discard, || Ok(()))
            .unwrap_err()
            .to_string(),
        "usb_review_changed"
    );
    assert_eq!(fs::read(pending.join("pending/z")).unwrap(), b"edit");
    fs::write(target.0.join("other"), b"unrelated").unwrap();
    let fresh = Request::Discard {
        id: ID.into(),
        review_sha256: status(&target.0, ID).review_sha256.unwrap(),
    };
    let Response::Status { status: discarded } =
        execute(&target.0, &fresh, Authority::Discard, || Ok(())).unwrap()
    else {
        panic!("not a status response")
    };
    assert_eq!(discarded.state, State::Discarded);
    assert!(!pending.exists());
    assert_eq!(fs::read(target.0.join("other")).unwrap(), b"unrelated");
}

#[test]
fn foreign_entries_and_edited_publications_never_authorize_removal() {
    let target = Tree::new();
    let pending = stage(&target.0, ID);
    let request = Request::Discard {
        id: ID.into(),
        review_sha256: status(&target.0, ID).review_sha256.unwrap(),
    };
    let extra = pending.join("files/extra");
    fs::write(&extra, b"foreign").unwrap();
    assert_eq!(status(&target.0, ID).state, State::Unknown);
    assert!(execute(&target.0, &request, Authority::Discard, || Ok(())).is_err());
    assert_eq!(fs::read(&extra).unwrap(), b"foreign");
    fs::remove_file(&extra).unwrap();
    fs::remove_file(pending.join("files/z")).unwrap();
    fs::hard_link(pending.join("files/a"), pending.join("files/z")).unwrap();
    assert_eq!(status(&target.0, ID).state, State::Unknown);
    assert!(execute(&target.0, &request, Authority::Discard, || Ok(())).is_err());
    fs::remove_file(pending.join("files/z")).unwrap();
    symlink("a", pending.join("files/z")).unwrap();
    assert_eq!(status(&target.0, ID).state, State::Unknown);
    assert!(execute(&target.0, &request, Authority::Discard, || Ok(())).is_err());

    let final_id = "11111111111111111111111111111111";
    let final_path = export(&target.0, final_id);
    fs::write(final_path.join("files/z"), b"new edit").unwrap();
    assert_eq!(status(&target.0, final_id).state, State::Unknown);
    let request = Request::Discard {
        id: final_id.into(),
        review_sha256: "0".repeat(64),
    };
    assert!(execute(&target.0, &request, Authority::Discard, || Ok(())).is_err());
    assert_eq!(fs::read(final_path.join("files/z")).unwrap(), b"new edit");
}

#[test]
fn inventory_is_sorted_bounded_and_never_grants_operation_authority() {
    let target = Tree::new();
    for index in (0..12).rev() {
        fs::create_dir(target.0.join(format!("Oblivion-{index:032x}"))).unwrap();
    }
    fs::create_dir(target.0.join("Oblivion-unrelated")).unwrap();
    let mut after = None;
    let mut found = Vec::new();
    loop {
        let request = Request::Inventory { after, limit: 8 };
        let response = execute(&target.0, &request, Authority::Inspect, || Ok(())).unwrap();
        let Response::Inventory {
            operations,
            next_cursor,
        } = response
        else {
            panic!("not an inventory")
        };
        assert!(operations.len() <= 8);
        found.extend(operations);
        if next_cursor.is_none() {
            break;
        }
        after = next_cursor;
    }
    assert_eq!(
        found,
        (0..12)
            .map(|index| format!("{index:032x}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(status(&target.0, &found[0]).state, State::Unknown);
}

#[test]
fn final_and_staged_collision_preserves_both_trees() {
    let target = Tree::new();
    let pending = stage(&target.0, ID);
    let digest = status(&target.0, ID).review_sha256.unwrap();
    let published = target.0.join(format!("Oblivion-{ID}"));
    fs::create_dir(&published).unwrap();
    fs::write(published.join("keep"), b"preserved").unwrap();
    assert_eq!(status(&target.0, ID).state, State::Unknown);
    let recover = Request::Recover {
        id: ID.into(),
        review_sha256: digest.clone(),
    };
    let discard = Request::Discard {
        id: ID.into(),
        review_sha256: digest,
    };
    assert!(
        execute(
            &target.0,
            &recover,
            Authority::Recover(ExportMode::Posix),
            || Ok(())
        )
        .is_err()
    );
    assert!(execute(&target.0, &discard, Authority::Discard, || Ok(())).is_err());
    assert_eq!(fs::read(published.join("keep")).unwrap(), b"preserved");
    assert_eq!(fs::read(pending.join("files/z")).unwrap(), b"reviewed");
}

#[test]
fn interrupted_discard_keeps_manifest_until_payload_cleanup_is_complete() {
    use std::io::ErrorKind;
    let target = Tree::new();
    let pending = stage(&target.0, ID);
    fs::remove_file(pending.join("receipt.json")).unwrap();
    fs::rename(pending.join("files"), pending.join("pending")).unwrap();
    let request = Request::Discard {
        id: ID.into(),
        review_sha256: status(&target.0, ID).review_sha256.unwrap(),
    };
    let result = execute(&target.0, &request, Authority::Discard, || {
        if pending.join("pending").exists() {
            return Ok(());
        }
        Err(ErrorKind::Interrupted.into())
    });
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Interrupted);
    assert!(pending.join("manifest.bin").is_file());
    assert!(pending.join("operation.json").is_file());
    let observed = status(&target.0, ID);
    assert_eq!(observed.state, State::Incomplete);
    let request = Request::Discard {
        id: ID.into(),
        review_sha256: observed.review_sha256.unwrap(),
    };
    execute(&target.0, &request, Authority::Discard, || Ok(())).unwrap();
    assert!(!pending.exists());
}

#[test]
fn compiled_inspection_endpoint_rejects_mutation_with_a_bounded_reply() {
    use oblivion_transfer::channel::Channel;
    use oblivion_transfer::endpoint::{read_message, write_message};
    use std::fs::File;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let target = Tree::new();
    let pending = stage(&target.0, ID);
    let request = Request::Discard {
        id: ID.into(),
        review_sha256: status(&target.0, ID).review_sha256.unwrap(),
    };
    let (local, peer) = UnixStream::pair().unwrap();
    let fd = peer.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-copy"));
    command
        .arg("live-media-inspect")
        .arg(&target.0)
        .arg("5000")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(peer);
    let mut local = Channel::new(File::from(OwnedFd::from(local)), Duration::from_secs(4)).unwrap();
    write_message(&mut local, &request).unwrap();
    let response: Response = read_message(&mut local, 1024).unwrap();
    assert!(matches!(
        response,
        Response::Rejected {
            reason: Rejection::NotAuthorized
        }
    ));
    assert!(response.validate(&request).is_err());
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read(pending.join("files/z")).unwrap(), b"reviewed");
}
