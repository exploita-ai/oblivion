use oblivion_transfer::channel::Channel;
use oblivion_transfer::{ENCRYPTED_VOLUME_NAME, Entry, Limits, Manifest, Receipt, Selection, endpoint, stream};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const ID: &str = "0123456789abcdef0123456789abcdef";
const BYTES: u64 = 32 * 1024 * 1024;
const BUDGET: Duration = Duration::from_secs(60);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from("/tmp").join(format!("oblivion-personal-copy-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

fn private_file(path: &Path) -> File {
    let file = OpenOptions::new().create_new(true).read(true).write(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::getuid() });
    file
}

fn volume(root: &Path) -> (PathBuf, String) {
    let path = root.join("selected.luks");
    let mut file = private_file(&path);
    let mut hash = Sha256::new();
    let mut chunk = [0; 64 * 1024];
    // A synthetic transport fixture: the LUKS2 signature does not authenticate
    // or make this patterned payload into a mountable encrypted filesystem.
    for index in 0..BYTES / chunk.len() as u64 {
        chunk.fill((index % 251) as u8);
        if index == 0 { chunk[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x02"); }
        file.write_all(&chunk).unwrap();
        hash.update(chunk);
    }
    file.sync_all().unwrap();
    let manifest = Manifest::new(vec![Entry::File { path: ENCRYPTED_VOLUME_NAME.into(), size: BYTES,
        sha256: format!("{:x}", hash.finalize()) }], Limits { entries: 1, bytes: BYTES }).unwrap();
    (path, manifest.sha256())
}

fn channel(socket: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(socket)), BUDGET).unwrap()
}

fn same_bytes(source: &Path, destination: &Path) {
    let mut source = File::open(source).unwrap();
    let mut destination = File::open(destination).unwrap();
    assert_eq!(source.metadata().unwrap().len(), BYTES);
    assert_eq!(destination.metadata().unwrap().len(), BYTES);
    let mut left = [0; 32 * 1024];
    let mut right = [0; 32 * 1024];
    for _ in 0..BYTES / left.len() as u64 {
        source.read_exact(&mut left).unwrap();
        destination.read_exact(&mut right).unwrap();
        assert_eq!(left, right);
    }
    assert_eq!(source.read(&mut left[..1]).unwrap(), 0);
    assert_eq!(destination.read(&mut right[..1]).unwrap(), 0);
}

fn hold_completion(receipt: &Receipt, observed: mpsc::SyncSender<Vec<u8>>, release: mpsc::Receiver<()>) -> io::Result<()> {
    observed.send(serde_json::to_vec(receipt)?).map_err(|_| io::ErrorKind::BrokenPipe)?;
    release.recv_timeout(Duration::from_secs(10)).map_err(|_| io::ErrorKind::TimedOut)?;
    Ok(())
}

fn receipt(bytes: &[u8], expected_sha: &str) -> Receipt {
    let receipt: Receipt = serde_json::from_slice(bytes).unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.manifest_sha256, expected_sha);
    assert_eq!(receipt.entries, 1);
    assert_eq!(receipt.bytes, BYTES);
    receipt
}

#[test]
fn personal_export_records_completion_before_final_ack_and_copies_exact_ciphertext() {
    let fixture = Fixture::new();
    let (source, expected_sha) = volume(&fixture.0);
    let target = fixture.0.join("desktop.partial");
    let destination = private_file(&target);
    let input = File::open(&source).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (observed, callback) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(0);
    let (done, client) = mpsc::sync_channel(1);
    let sender = std::thread::spawn(move || endpoint::send_open_file_completed(&mut channel(sender), input, BYTES,
        |receipt| hold_completion(receipt, observed, held)));
    let receiver = std::thread::spawn(move || {
        done.send(stream::download_open_file(&mut channel(receiver), destination, BYTES, ID)).unwrap();
    });
    let completed = receipt(&callback.recv_timeout(BUDGET).unwrap(), &expected_sha);
    // The receiver has verified SHA, END and fsync and is waiting for copied.
    // Holding the real persistence callback must withhold that last success.
    assert!(matches!(client.recv_timeout(Duration::from_millis(150)), Err(mpsc::RecvTimeoutError::Timeout)));
    release.send(()).unwrap();
    assert_eq!(client.recv_timeout(BUDGET).unwrap().unwrap(), completed);
    assert_eq!(sender.join().unwrap().unwrap(), completed);
    receiver.join().unwrap();
    same_bytes(&source, &target);
    assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn personal_import_records_completion_before_receipt_and_keeps_the_approved_identity() {
    let fixture = Fixture::new();
    let (source, expected_sha) = volume(&fixture.0);
    let target = fixture.0.join("new-safe.pending");
    let destination = private_file(&target);
    let mut selection = Selection::encrypted_volume(File::open(&source).unwrap(), BYTES).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (observed, callback) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(0);
    let (done, client) = mpsc::sync_channel(1);
    let receiver = std::thread::spawn(move || endpoint::receive_open_file_completed(&mut channel(receiver), destination, BYTES,
        |receipt| hold_completion(receipt, observed, held)));
    let sender = std::thread::spawn(move || {
        done.send(stream::send(&mut channel(sender), &mut selection, ID)).unwrap();
    });
    let completed = receipt(&callback.recv_timeout(BUDGET).unwrap(), &expected_sha);
    assert!(matches!(client.recv_timeout(Duration::from_millis(150)), Err(mpsc::RecvTimeoutError::Timeout)));
    release.send(()).unwrap();
    assert_eq!(client.recv_timeout(BUDGET).unwrap().unwrap(), completed);
    assert_eq!(receiver.join().unwrap().unwrap(), completed);
    sender.join().unwrap();
    same_bytes(&source, &target);
    assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn failed_completion_record_never_acknowledges_or_replaces_an_existing_destination() {
    let fixture = Fixture::new();
    let (source, _) = volume(&fixture.0);
    let original = fixture.0.join("existing-safe.luks");
    private_file(&original).write_all(b"ORIGINAL_SAFE_MUST_REMAIN").unwrap();
    let pending = fixture.0.join("new-safe.pending");
    let destination = private_file(&pending);
    let completion = fixture.0.join("completion.json");
    private_file(&completion).write_all(b"ORIGINAL_RECEIPT_MUST_REMAIN").unwrap();
    let attempted = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&attempted);
    let (sender, receiver) = UnixStream::pair().unwrap();
    let receiver = std::thread::spawn(move || endpoint::receive_open_file_completed(&mut channel(receiver), destination, BYTES, |_| {
        observed.store(true, Ordering::Release);
        // A real create_new conflict, equally effective for root and nonroot.
        OpenOptions::new().create_new(true).write(true).mode(0o600).open(completion)?;
        Ok(())
    }));
    let mut selection = Selection::encrypted_volume(File::open(&source).unwrap(), BYTES).unwrap();
    assert!(stream::send(&mut channel(sender), &mut selection, ID).is_err());
    assert_eq!(receiver.join().unwrap().unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert!(attempted.load(Ordering::Acquire));
    assert_eq!(fs::read(original).unwrap(), b"ORIGINAL_SAFE_MUST_REMAIN");
    assert_eq!(fs::read(fixture.0.join("completion.json")).unwrap(), b"ORIGINAL_RECEIPT_MUST_REMAIN");
    same_bytes(&source, &pending);
}
