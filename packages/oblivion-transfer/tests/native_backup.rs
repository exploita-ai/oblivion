#![cfg(unix)]
mod support;
use oblivion_transfer::backup::{OutputTarget, Source};
use oblivion_transfer::copy_protocol;
use oblivion_transfer::{ENCRYPTED_VOLUME_NAME, Entry};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
use support::Tree;

const BYTES: u64 = 32 * 1024 * 1024;
const ID: &str = "aabbccddeeff00112233445566778899";

#[test]
fn ciphertext_source_has_one_fixed_alias_and_changed_bytes_never_emit_end() {
    let tree = Tree::new();
    let path = tree.0.join("private source filename.luks");
    let mut file = File::create(&path).unwrap();
    file.set_len(BYTES).unwrap();
    file.write_all(b"LUKS\xba\xbe\x00\x02").unwrap();
    drop(file);
    assert!(
        Source::from_file(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            BYTES
        )
        .is_err()
    );
    let mut source = Source::open(&path, BYTES).unwrap();
    assert_eq!(source.bytes(), BYTES);
    assert!(
        matches!(source.manifest().entries(), [Entry::File { path, size, .. }] if path == ENCRYPTED_VOLUME_NAME && *size == BYTES)
    );
    let mut encoded = Vec::new();
    source.manifest().write(&mut encoded).unwrap();
    assert!(!String::from_utf8_lossy(&encoded).contains("private source filename"));
    let mut changed = OpenOptions::new().write(true).open(&path).unwrap();
    changed.seek(SeekFrom::Start(4096)).unwrap();
    changed.write_all(b"changed after review").unwrap();
    changed.sync_all().unwrap();
    let mut bytes = Vec::new();
    assert!(copy_protocol::Source::write_payload(&mut source, &mut bytes).is_err());
    assert_eq!(bytes.len() as u64, BYTES);
    assert!(!bytes.ends_with(b"OBLVEND1"));
}

#[test]
fn private_output_never_replaces_a_late_target_or_deletes_foreign_temporary_data() {
    let tree = Tree::new();
    let path = tree.0.join("personal.luks");
    let temporary = tree.0.join(format!(".oblivion-backup-{ID}.partial"));
    let mut output = OutputTarget::new(&path).unwrap().create(ID).unwrap();
    output
        .copy_file()
        .unwrap()
        .write_all(b"private ciphertext")
        .unwrap();
    fs::write(&path, b"unrelated destination").unwrap();
    assert!(output.publish().is_err());
    drop(output);
    assert_eq!(fs::read(&path).unwrap(), b"unrelated destination");
    assert!(!temporary.exists());
    fs::remove_file(&path).unwrap();
    let mut output = OutputTarget::new(&path).unwrap().create(ID).unwrap();
    output
        .copy_file()
        .unwrap()
        .write_all(b"complete ciphertext")
        .unwrap();
    output.publish().unwrap();
    assert_eq!(output.path(), path);
    drop(output);
    assert_eq!(fs::read(&path).unwrap(), b"complete ciphertext");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
    fs::remove_file(&path).unwrap();
    let mut output = OutputTarget::new(&path).unwrap().create(ID).unwrap();
    output
        .copy_file()
        .unwrap()
        .write_all(b"owned partial")
        .unwrap();
    fs::rename(&temporary, tree.0.join("moved original")).unwrap();
    fs::write(&temporary, b"foreign replacement").unwrap();
    assert!(output.publish().is_err());
    drop(output);
    assert!(!path.exists());
    assert_eq!(fs::read(&temporary).unwrap(), b"foreign replacement");
    assert_eq!(
        fs::read(tree.0.join("moved original")).unwrap(),
        b"owned partial"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn process_owned_backup_publication_supports_tmpfs_without_a_filesystem_uuid() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::path::PathBuf::from("/dev/shm").join(format!(
        "oblivion-native-backup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let mut output = OutputTarget::new(&path.join("backup.luks"))
        .unwrap()
        .create(ID)
        .unwrap();
    output
        .copy_file()
        .unwrap()
        .write_all(b"owned ciphertext")
        .unwrap();
    output.publish().unwrap();
    drop(output);
    assert_eq!(
        fs::read(path.join("backup.luks")).unwrap(),
        b"owned ciphertext"
    );
    fs::remove_dir_all(path).unwrap();
}
