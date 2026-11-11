mod support;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::native_files::{Context, Direction};
use oblivion_transfer::{endpoint, stream};
use std::fs::{self, File};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use support::Tree;
const ID: &str = "0123456789abcdef0123456789abcdef";
fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}
fn context(direction: Direction) -> Context {
    Context {
        id: ID.into(),
        safe_id: "a".repeat(32),
        opening: "b".repeat(32),
        direction,
        name: "Reviewed collection".into(),
    }
}
fn upload(
    prepared: stream::PreparedUpload,
    target: &Path,
) -> io::Result<oblivion_transfer::Receipt> {
    let inbox = Tree::new();
    let context = context(Direction::Import);
    stream::operations::begin(&inbox.0, target, &context)?;
    let destination = target.to_owned();
    let (sender, receiver) = UnixStream::pair()?;
    let received = std::thread::spawn(move || {
        stream::receive_directory(&mut channel(receiver), &inbox.0, &destination, &context)
    });
    let summary = prepared.summary()?;
    let result = prepared.send(
        &mut channel(sender),
        &summary.manifest_sha256,
        &mut |_, _| Ok(()),
    );
    let receipt = received.join().unwrap();
    assert_eq!(result.as_ref().ok(), receipt.as_ref().ok());
    result
}
#[test]
fn mixed_parent_import_uses_one_reviewed_collection_and_only_selected_bytes() {
    let first = Tree::new();
    let second = Tree::new();
    fs::create_dir(first.0.join("folder")).unwrap();
    fs::create_dir(first.0.join("folder/empty")).unwrap();
    fs::write(first.0.join("report.txt"), b"first").unwrap();
    fs::write(second.0.join("report.txt"), b"second").unwrap();
    fs::write(first.0.join("folder/inside"), b"included").unwrap();
    fs::write(first.0.join("raw\\name.txt"), b"literal backslash").unwrap();
    fs::write(second.0.join("not selected"), b"private").unwrap();
    let sources = vec![
        first.0.join("report.txt"),
        second.0.join("report.txt"),
        first.0.join("folder/inside"),
        first.0.join("folder"),
        first.0.join("report.txt"),
        first.0.join("raw\\name.txt"),
    ];
    let prepared =
        stream::PreparedUpload::prepare(&sources, context(Direction::Import), &mut || Ok(()))
            .unwrap();
    let plan = prepared.plan().clone();
    assert_eq!(plan.mappings[2].covered_by, Some(3));
    assert_eq!(plan.mappings[4].covered_by, Some(0));
    assert_ne!(plan.mappings[0].alias, plan.mappings[1].alias);
    assert!(!plan.mappings[5].alias.as_ref().unwrap().contains('\\'));
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains(first.0.to_str().unwrap())
    );
    let summary = prepared.summary().unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (4, 2, 36)
    );
    let target = Tree::new();
    let receipt = upload(prepared, &target.0).unwrap();
    assert_eq!(receipt.manifest_sha256, summary.manifest_sha256);
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 1);
    let collection = target.0.join("Reviewed collection");
    assert_eq!(
        fs::read(collection.join(plan.mappings[0].alias.as_ref().unwrap())).unwrap(),
        b"first"
    );
    assert_eq!(
        fs::read(collection.join(plan.mappings[1].alias.as_ref().unwrap())).unwrap(),
        b"second"
    );
    assert_eq!(
        fs::read(
            collection
                .join(plan.mappings[3].alias.as_ref().unwrap())
                .join("inside")
        )
        .unwrap(),
        b"included"
    );
    assert!(
        collection
            .join(plan.mappings[3].alias.as_ref().unwrap())
            .join("empty")
            .is_dir()
    );
    assert_eq!(
        fs::read(collection.join(plan.mappings[5].alias.as_ref().unwrap())).unwrap(),
        b"literal backslash"
    );
    assert!(!collection.join("not selected").exists());
}
#[test]
fn export_combines_both_documents_roots_without_exposing_other_vault_content() {
    let source = Tree::new();
    fs::create_dir_all(source.0.join("workspace/folder")).unwrap();
    fs::create_dir(source.0.join("imports")).unwrap();
    fs::create_dir(source.0.join("state")).unwrap();
    fs::write(source.0.join("workspace/readme"), b"workspace").unwrap();
    fs::write(source.0.join("imports/readme"), b"imports").unwrap();
    fs::write(source.0.join("workspace/folder/code"), b"code").unwrap();
    fs::write(source.0.join("state/secret"), b"credential").unwrap();
    fs::write(source.0.join("workspace/unselected"), b"private").unwrap();
    let target = Tree::new();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let sent = std::thread::spawn(move || endpoint::documents(&mut channel(sender), &source.0));
    let prepared = stream::PreparedDownload::prepare(
        channel(receiver),
        &[
            "workspace/readme".into(),
            "imports/readme".into(),
            "workspace/folder/code".into(),
            "workspace/folder".into(),
        ],
        &target.0,
        context(Direction::Export),
    )
    .unwrap();
    let plan = prepared.plan().clone();
    assert_eq!(plan.mappings[2].covered_by, Some(3));
    let summary = prepared.summary().unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (3, 1, 20)
    );
    assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    let receipt = prepared
        .receive(&summary.manifest_sha256, &mut |_, _| Ok(()))
        .unwrap();
    sent.join().unwrap().unwrap();
    assert_eq!(receipt.bytes, 20);
    let collection = target.0.join("Reviewed collection");
    assert_eq!(
        fs::read(collection.join(plan.mappings[0].alias.as_ref().unwrap())).unwrap(),
        b"workspace"
    );
    assert_eq!(
        fs::read(collection.join(plan.mappings[1].alias.as_ref().unwrap())).unwrap(),
        b"imports"
    );
    assert_eq!(
        fs::read(
            collection
                .join(plan.mappings[3].alias.as_ref().unwrap())
                .join("code")
        )
        .unwrap(),
        b"code"
    );
    assert_eq!(fs::read_dir(&collection).unwrap().count(), 3);
    assert!(!collection.join("state").exists());
}
#[test]
fn pinned_source_parents_survive_path_replacement_during_review() {
    let source = Tree::new();
    fs::create_dir(source.0.join("chosen")).unwrap();
    fs::write(source.0.join("chosen/file"), b"reviewed").unwrap();
    fs::write(source.0.join("other"), b"other").unwrap();
    let prepared = stream::PreparedUpload::prepare(
        &[source.0.join("chosen/file"), source.0.join("other")],
        context(Direction::Import),
        &mut || Ok(()),
    )
    .unwrap();
    let plan = prepared.plan().clone();
    fs::rename(source.0.join("chosen"), source.0.join("retained")).unwrap();
    fs::create_dir(source.0.join("chosen")).unwrap();
    fs::write(source.0.join("chosen/file"), b"replacement").unwrap();
    let target = Tree::new();
    upload(prepared, &target.0).unwrap();
    assert_eq!(
        fs::read(
            target
                .0
                .join("Reviewed collection")
                .join(plan.mappings[0].alias.as_ref().unwrap())
        )
        .unwrap(),
        b"reviewed"
    );
}
#[test]
fn invalid_nested_names_and_symlink_selections_fail_before_destination_mutation() {
    let source = Tree::new();
    fs::create_dir(source.0.join("folder")).unwrap();
    fs::write(source.0.join("other"), b"other").unwrap();
    for name in [
        "not\\portable",
        "bad\u{061c}name",
        "bad\u{2028}name",
        "bad\u{2029}name",
    ] {
        fs::write(source.0.join("folder").join(name), b"private").unwrap();
        assert!(
            stream::PreparedUpload::prepare(
                &[source.0.join("folder"), source.0.join("other")],
                context(Direction::Import),
                &mut || Ok(())
            )
            .is_err()
        );
        fs::remove_file(source.0.join("folder").join(name)).unwrap();
    }
    std::os::unix::fs::symlink("other", source.0.join("link")).unwrap();
    assert!(
        stream::PreparedUpload::prepare(
            &[source.0.join("link"), source.0.join("other")],
            context(Direction::Import),
            &mut || Ok(())
        )
        .is_err()
    );
}
#[test]
fn descriptor_budget_is_checked_in_the_real_preparation_process() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "low_descriptor_fixture"])
        .env("OBLIVION_SELECTION_FD_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore]
fn low_descriptor_fixture() {
    if std::env::var_os("OBLIVION_SELECTION_FD_FIXTURE").is_none() {
        return;
    }
    let source = Tree::new();
    fs::create_dir(source.0.join("a")).unwrap();
    fs::create_dir(source.0.join("b")).unwrap();
    fs::write(source.0.join("a/file"), b"a").unwrap();
    fs::write(source.0.join("b/file"), b"b").unwrap();
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
        0
    );
    let mut limit = unsafe { limit.assume_init() };
    limit.rlim_cur = 41;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let result = stream::PreparedUpload::prepare(
        &[source.0.join("a/file"), source.0.join("b/file")],
        context(Direction::Import),
        &mut || Ok(()),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "selection_descriptor_limit"
    );
    let paths = (0..128)
        .map(|index| {
            let path = source.0.join("a").join(format!("file-{index}"));
            fs::write(&path, b"x").unwrap();
            path
        })
        .collect::<Vec<_>>();
    let prepared =
        stream::PreparedUpload::prepare(&paths, context(Direction::Import), &mut || Ok(()))
            .unwrap();
    assert_eq!(prepared.summary().unwrap().files, 128);
}

#[test]
fn documents_source_refuses_unauthorized_and_symlinked_selections_before_offering() {
    for selected in [
        "state/secret",
        "workspace/../state/secret",
        "workspace/link",
    ] {
        let source = Tree::new();
        fs::create_dir(source.0.join("workspace")).unwrap();
        fs::create_dir(source.0.join("state")).unwrap();
        fs::write(source.0.join("state/secret"), b"credential").unwrap();
        std::os::unix::fs::symlink("../state/secret", source.0.join("workspace/link")).unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sent = std::thread::spawn(move || endpoint::documents(&mut channel(sender), &source.0));
        let mut receiver = channel(receiver);
        endpoint::write_message(
            &mut receiver,
            &endpoint::OfferRequest {
                id: ID.into(),
                limits: oblivion_transfer::Limits {
                    entries: 100,
                    bytes: 1024,
                },
                paths: vec![selected.into()],
            },
        )
        .unwrap();
        assert!(sent.join().unwrap().is_err());
        let mut offered = [0; 1];
        assert_eq!(std::io::Read::read(&mut receiver, &mut offered).unwrap(), 0);
    }
}

#[test]
fn an_expanded_source_manifest_or_changed_mapping_is_rejected_before_review() {
    for changed_mapping in [false, true] {
        let source = Tree::new();
        fs::create_dir(source.0.join("selection")).unwrap();
        for name in ["a", "b", "unselected"] {
            fs::write(source.0.join("selection").join(name), b"data").unwrap();
        }
        let target = Tree::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sent = std::thread::spawn(move || {
            let mut channel = channel(sender);
            let request: endpoint::OfferRequest =
                endpoint::read_message(&mut channel, 65536).unwrap();
            let mut plan = oblivion_transfer::selection::Plan::new(
                &request
                    .paths
                    .iter()
                    .map(|path| oblivion_transfer::selection::Input {
                        path: path.clone(),
                        directory: false,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            if changed_mapping {
                plan.mappings[0].alias = Some("different".into());
            }
            endpoint::write_message(
                &mut channel,
                &endpoint::SelectionOffer {
                    directories: vec![false, false],
                    plan,
                },
            )
            .unwrap();
            if !changed_mapping {
                let selection = oblivion_transfer::Selection::prepare(
                    &source.0,
                    &["selection".into()],
                    oblivion_transfer::Limits {
                        entries: 100,
                        bytes: 1024,
                    },
                )
                .unwrap();
                selection.manifest().write(&mut channel).unwrap();
            }
        });
        let result = stream::PreparedDownload::prepare(
            channel(receiver),
            &["workspace/a".into(), "imports/b".into()],
            &target.0,
            context(Direction::Export),
        );
        assert_eq!(
            result.err().unwrap().to_string(),
            if changed_mapping {
                "selection_changed"
            } else {
                "selection_expanded"
            }
        );
        sent.join().unwrap();
        assert!(fs::read_dir(&target.0).unwrap().next().is_none());
    }
}
