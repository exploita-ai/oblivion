#![cfg(windows)]
use oblivion_transfer::copy_protocol::{self, Transport};
use oblivion_transfer::endpoint::{ReceiveRequest, read_message, write_message};
use oblivion_transfer::native_file_events::Summary;
use oblivion_transfer::windows_source::SourceSelection;
use oblivion_transfer::{Entry, Limits, Manifest, Receipt, relay_payload};
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Wdk::Storage::FileSystem::{REPARSE_DATA_BUFFER, REPARSE_DATA_BUFFER_0_1};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oblivion-windows-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap()
    }
}
fn limits() -> Limits {
    Limits {
        entries: 100,
        bytes: 4 * 1024 * 1024,
    }
}

fn junction(path: &Path, target: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    let directory = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let target = fs::canonicalize(target)?;
    let print = target.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
    let substitute = format!(r"\??\{print}").encode_utf16().collect::<Vec<_>>();
    let printed = print.encode_utf16().collect::<Vec<_>>();
    let strings = substitute
        .iter()
        .copied()
        .chain([0])
        .chain(printed.iter().copied())
        .chain([0])
        .collect::<Vec<_>>();
    // Use the SDK layout for the Microsoft mount-point reparse buffer.
    let data_bytes = std::mem::offset_of!(REPARSE_DATA_BUFFER_0_1, PathBuffer) + strings.len() * 2;
    let bytes = std::mem::offset_of!(REPARSE_DATA_BUFFER, Anonymous) + data_bytes;
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let record = buffer.as_mut_ptr().cast::<REPARSE_DATA_BUFFER>();
    unsafe {
        (*record).ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        (*record).ReparseDataLength = data_bytes.try_into().unwrap();
        let mount = &mut (*record).Anonymous.MountPointReparseBuffer;
        mount.SubstituteNameOffset = 0;
        mount.SubstituteNameLength = (substitute.len() * 2).try_into().unwrap();
        mount.PrintNameOffset = ((substitute.len() + 1) * 2).try_into().unwrap();
        mount.PrintNameLength = (printed.len() * 2).try_into().unwrap();
        copy_nonoverlapping(
            strings.as_ptr(),
            mount.PathBuffer.as_mut_ptr(),
            strings.len(),
        );
    }
    let mut returned = 0;
    if unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            record.cast(),
            bytes as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Exchange {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Exchange {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}
impl Write for Exchange {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Transport for Exchange {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn native_source_collection_uses_common_plan_manifest_and_verified_payload() {
    let first = Tree::new();
    let second = Tree::new();
    fs::create_dir_all(first.0.join("folder/empty")).unwrap();
    fs::write(first.0.join("folder/inside.txt"), b"inside").unwrap();
    fs::write(first.0.join("report.txt"), b"first").unwrap();
    fs::write(second.0.join("report.txt"), b"second").unwrap();
    fs::write(second.0.join("not selected"), b"private").unwrap();
    fs::write(first.0.join("é.txt"), b"unicode").unwrap();
    let mut selected = SourceSelection::prepare(
        &[
            first.0.join("report.txt"),
            second.0.join("report.txt"),
            first.0.join("folder/inside.txt"),
            first.0.join("folder"),
            first.0.join("report.txt"),
            first.0.join("é.txt"),
        ],
        limits(),
        &mut || Ok(()),
    )
    .unwrap();
    let plan = selected.plan();
    assert_eq!(plan.mappings[2].covered_by, Some(3));
    assert_eq!(plan.mappings[4].covered_by, Some(0));
    assert_ne!(plan.mappings[0].alias, plan.mappings[1].alias);
    let encoded = serde_json::to_string(plan).unwrap();
    assert!(!encoded.contains("oblivion-windows-source"));
    assert!(!encoded.contains(":/"));
    let summary = Summary::from_manifest(selected.manifest(), plan).unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (4, 2, 24)
    );
    let mut manifest = Vec::new();
    selected.manifest().write(&mut manifest).unwrap();
    let decoded = Manifest::read(&mut Cursor::new(manifest), limits()).unwrap();
    let mut payload = Vec::new();
    selected.send_data(&mut payload).unwrap();
    let mut relayed = Vec::new();
    relay_payload(&mut Cursor::new(&payload), &mut relayed, &decoded).unwrap();
    assert_eq!(relayed, payload);
    assert_eq!(&payload[..payload.len() - 8], b"firstsecondinsideunicode");
    assert!(
        !decoded
            .entries()
            .iter()
            .any(|entry| entry.path().contains("not selected"))
    );
    let expected = Receipt {
        id: "a".repeat(32),
        manifest_sha256: summary.manifest_sha256.clone(),
        entries: summary.entries,
        bytes: summary.bytes,
    };
    let mut replies = b"receive\n".to_vec();
    write_message(&mut replies, &expected).unwrap();
    let mut channel = Exchange {
        input: Cursor::new(replies),
        output: Vec::new(),
    };
    let mut progress = Vec::new();
    let receipt = copy_protocol::send(
        &mut channel,
        &mut selected,
        &expected.id,
        &summary.manifest_sha256,
        &mut |phase, bytes| {
            progress.push((phase, bytes));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(receipt, expected);
    assert!(progress.windows(2).all(|pair| pair[0].1 <= pair[1].1));
    assert_eq!(progress.last().unwrap().1, 24);
    let mut sent = Cursor::new(channel.output);
    let request: ReceiveRequest = read_message(&mut sent, 4096).unwrap();
    assert_eq!(request.approval.manifest_sha256, summary.manifest_sha256);
    let offered = Manifest::read(&mut sent, limits()).unwrap();
    let mut sent_payload = Vec::new();
    relay_payload(&mut sent, &mut sent_payload, &offered).unwrap();
    assert_eq!(sent_payload, payload);
}

#[test]
fn source_handles_prevent_write_and_replacement_through_review_until_dropped() {
    let tree = Tree::new();
    let path = tree.0.join("chosen.txt");
    fs::write(&path, b"reviewed").unwrap();
    let mut selected = SourceSelection::prepare(&[path.clone()], limits(), &mut || Ok(())).unwrap();
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::rename(&path, tree.0.join("moved.txt")).is_err());
    let mut payload = Vec::new();
    selected.send_data(&mut payload).unwrap();
    assert_eq!(&payload[..payload.len() - 8], b"reviewed");
    drop(selected);
    fs::write(&path, b"new contents").unwrap();
    assert_eq!(fs::read(path).unwrap(), b"new contents");
}

#[test]
fn existing_writer_and_hardlink_are_rejected_before_review_without_modifying_sources() {
    let tree = Tree::new();
    let path = tree.0.join("chosen.txt");
    fs::write(&path, b"unchanged").unwrap();
    let writer = OpenOptions::new().write(true).open(&path).unwrap();
    assert!(SourceSelection::prepare(&[path.clone()], limits(), &mut || Ok(())).is_err());
    drop(writer);
    fs::hard_link(&path, tree.0.join("second.txt")).unwrap();
    assert!(SourceSelection::prepare(&[path.clone()], limits(), &mut || Ok(())).is_err());
    assert_eq!(fs::read(path).unwrap(), b"unchanged");
}

#[test]
fn actual_junction_roots_children_and_intermediate_parents_are_never_traversed() {
    let source = Tree::new();
    let target = Tree::new();
    let folder = source.0.join("selected");
    fs::create_dir(&folder).unwrap();
    fs::write(target.0.join("secret.txt"), b"not selected").unwrap();
    let link = folder.join("linked");
    junction(&link, &target.0).unwrap();
    for path in [folder, link.clone(), link.join("secret.txt")] {
        assert!(SourceSelection::prepare(&[path], limits(), &mut || Ok(())).is_err());
    }
    fs::remove_dir(link).unwrap();
    assert_eq!(
        fs::read(target.0.join("secret.txt")).unwrap(),
        b"not selected"
    );
}

#[test]
fn case_aliases_resolve_to_one_actual_source_and_ordinary_document_acl_is_accepted() {
    let tree = Tree::new();
    let path = tree.0.join("Case Test.txt");
    fs::write(&path, b"one file").unwrap();
    let alias = PathBuf::from(path.to_str().unwrap().to_uppercase());
    let selected = SourceSelection::prepare(&[path, alias], limits(), &mut || Ok(())).unwrap();
    assert_eq!(selected.plan().mappings[1].covered_by, Some(0));
    assert_eq!(
        selected
            .manifest()
            .entries()
            .iter()
            .filter(|entry| matches!(entry, Entry::File { .. }))
            .count(),
        1
    );
}

#[test]
fn invalid_native_paths_and_preparation_cancel_never_produce_a_selection() {
    for path in [
        r"relative\file",
        r"C:relative",
        r"\\server\share\file",
        r"\\?\C:\file",
        r"C:\file:stream",
        r"C:\a\..\b",
        r"C:\a\.\b",
    ] {
        assert!(
            SourceSelection::prepare(&[PathBuf::from(path)], limits(), &mut || Ok(())).is_err()
        );
    }
    let tree = Tree::new();
    let path = tree.0.join("large");
    fs::write(&path, vec![b'a'; 2 * 1024 * 1024]).unwrap();
    let mut checks = 0;
    let result = SourceSelection::prepare(&[path.clone()], limits(), &mut || {
        checks += 1;
        assert!(checks <= 5, "cancelled preparation must not retry");
        if checks >= 5 {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        Ok(())
    });
    let error = result.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(error.to_string(), "cancelled");
    assert_eq!(checks, 5);
    assert_eq!(fs::metadata(path).unwrap().len(), 2 * 1024 * 1024);
    let folder = tree.0.join("folder");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("hidden\u{202e}.txt"), b"unchanged").unwrap();
    assert!(SourceSelection::prepare(&[folder.clone()], limits(), &mut || Ok(())).is_err());
    assert_eq!(
        fs::read(folder.join("hidden\u{202e}.txt")).unwrap(),
        b"unchanged"
    );
}
