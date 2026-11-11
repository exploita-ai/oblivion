#![cfg(target_os = "linux")]
mod support;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::native_files::{Action, Context, Direction, State, TransfersQuery};
use oblivion_transfer::stream;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use support::Tree;

const ID: &str = "0123456789abcdef0123456789abcdef";
const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";
const REOPENED: &str = "33333333333333333333333333333333";

struct Volume {
    tree: Tree,
    devices: Vec<PathBuf>,
    mounted: bool,
}
impl Volume {
    fn new() -> Self {
        let tree = Tree::new();
        fs::create_dir(tree.0.join("mounted")).unwrap();
        File::create(tree.0.join("volume.ext4"))
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        assert!(
            Command::new("mkfs.ext4")
                .args(["-q", "-F"])
                .arg(tree.0.join("volume.ext4"))
                .status()
                .unwrap()
                .success()
        );
        let control = CString::new(tree.0.join("loop-control").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mknod(
                    control.as_ptr(),
                    libc::S_IFCHR | 0o600,
                    libc::makedev(10, 237),
                )
            },
            0
        );
        let mut volume = Self {
            tree,
            devices: Vec::new(),
            mounted: false,
        };
        volume.attach();
        volume.mount(0);
        volume
    }
    fn path(&self) -> PathBuf {
        self.tree.0.join("mounted")
    }
    fn attach(&mut self) {
        let control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.tree.0.join("loop-control"))
            .unwrap();
        let minor = unsafe { libc::ioctl(control.as_raw_fd(), 0x4c82) };
        assert!(minor >= 0, "{}", std::io::Error::last_os_error());
        let node = self.tree.0.join(format!("loop{minor}"));
        let name = CString::new(node.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mknod(
                    name.as_ptr(),
                    libc::S_IFBLK | 0o600,
                    libc::makedev(7, minor as u32),
                )
            },
            0
        );
        assert!(
            Command::new("losetup")
                .arg(&node)
                .arg(self.tree.0.join("volume.ext4"))
                .status()
                .unwrap()
                .success()
        );
        self.devices.push(node);
    }
    fn mount(&mut self, index: usize) {
        let source = CString::new(self.devices[index].as_os_str().as_bytes()).unwrap();
        let target = CString::new(self.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    c"ext4".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        self.mounted = true;
    }
    fn unmount(&mut self) {
        let target = CString::new(self.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::umount(target.as_ptr()) },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        self.mounted = false;
    }
    fn mount_tmpfs(&mut self) {
        let target = CString::new(self.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    c"size=1m,mode=0700".as_ptr().cast(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        self.mounted = true;
    }
}
impl Drop for Volume {
    fn drop(&mut self) {
        if self.mounted {
            self.unmount();
        }
        for device in &self.devices {
            assert!(
                Command::new("losetup")
                    .arg("-d")
                    .arg(device)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}

fn channel(stream: UnixStream) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), Duration::from_secs(5)).unwrap()
}
fn manage(base: &Path, action: Action) -> std::io::Result<oblivion_transfer::native_files::Status> {
    stream::operations::manage(
        &base.join("inbox"),
        &base.join("target"),
        ID,
        SAFE,
        REOPENED,
        Direction::Import,
        action,
    )
}

/// Uses only a private temporary ext4 file and loop associations owned here.
/// No user devices, privileged VM or image build is involved.
#[test]
#[ignore = "requires CAP_SYS_ADMIN, mknod and loop device access in an isolated Linux container"]
fn verified_transfer_recovers_after_the_same_filesystem_gets_a_different_device_number() {
    let mut volume = Volume::new();
    let source = Tree::new();
    fs::create_dir(source.0.join("project")).unwrap();
    fs::write(source.0.join("project/note.txt"), b"original").unwrap();
    for name in ["inbox", "target"] {
        fs::create_dir(volume.path().join(name)).unwrap();
        fs::set_permissions(volume.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir(volume.path().join("target/project")).unwrap();
    fs::write(volume.path().join("target/project/keep.txt"), b"existing").unwrap();
    let context = Context {
        id: ID.into(),
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction: Direction::Import,
        name: "project".into(),
    };
    let unsupported = Tree::new();
    assert_eq!(
        stream::operations::begin(&unsupported.0, Path::new("/proc"), &context)
            .unwrap_err()
            .to_string(),
        "filesystem_identity_unavailable"
    );
    assert!(!unsupported.0.join("operations").exists());
    let (request, mut peer) = UnixStream::pair().unwrap();
    let mut exported = context.clone();
    exported.direction = Direction::Export;
    match stream::PreparedDownload::prepare(
        channel(request),
        &["workspace/project".into()],
        Path::new("/proc"),
        exported,
    ) {
        Err(error) => assert_eq!(error.to_string(), "filesystem_identity_unavailable"),
        Ok(_) => panic!("filesystem without an identifier accepted for export"),
    }
    assert_eq!(
        peer.read(&mut [0u8; 1]).unwrap(),
        0,
        "unsupported destination must not receive an offer"
    );
    stream::operations::begin(
        &volume.path().join("inbox"),
        &volume.path().join("target"),
        &context,
    )
    .unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let send_context = context.clone();
    let sender = std::thread::spawn(move || {
        let prepared = stream::PreparedUpload::prepare(
            &[source.0.join("project")],
            send_context,
            &mut || Ok(()),
        )?;
        let summary = prepared.summary()?;
        prepared.send(
            &mut channel(sender),
            &summary.manifest_sha256,
            &mut |_, _| Ok(()),
        )
    });
    let mut receiver = channel(receiver);
    assert!(
        stream::receive_directory(
            &mut receiver,
            &volume.path().join("inbox"),
            &volume.path().join("target"),
            &context
        )
        .is_err()
    );
    drop(receiver);
    assert!(sender.join().unwrap().is_err());
    assert_eq!(
        manage(&volume.path(), Action::Status).unwrap().state,
        State::Ready
    );
    let original = fs::metadata(volume.path().join("target")).unwrap();
    volume.unmount();
    // Both loop mappings reference this fixture's file, but only one is mounted.
    volume.attach();
    volume.mount(1);
    let remounted = fs::metadata(volume.path().join("target")).unwrap();
    assert_ne!(original.dev(), remounted.dev());
    assert_eq!(original.ino(), remounted.ino());
    assert_eq!(
        manage(&volume.path(), Action::Status).unwrap().state,
        State::Ready
    );
    let page = stream::operations::inventory(
        &volume.path().join("inbox"),
        &volume.path().join("target"),
        &TransfersQuery {
            safe_id: SAFE.into(),
            opening: REOPENED.into(),
            direction: Direction::Import,
            after: None,
            limit: 8,
        },
    )
    .unwrap();
    assert_eq!(page.entries[0].operation_id, ID);
    fs::remove_dir_all(volume.path().join("target/project")).unwrap();
    assert_eq!(
        manage(&volume.path(), Action::Recover).unwrap().state,
        State::Published
    );
    assert_eq!(
        fs::read(volume.path().join("target/project/note.txt")).unwrap(),
        b"original"
    );
    fs::write(
        volume.path().join("target/project/note.txt"),
        b"edited by agent",
    )
    .unwrap();
    volume.unmount();
    volume.mount(0);
    assert_eq!(
        manage(&volume.path(), Action::Status).unwrap().state,
        State::Published
    );
    assert!(manage(&volume.path(), Action::Discard).is_err());
    assert_eq!(
        fs::read(volume.path().join("target/project/note.txt")).unwrap(),
        b"edited by agent"
    );
    eprintln!(
        "verified remount: dev {} -> {}, inode {}; recovery and historical receipt preserved",
        original.dev(),
        remounted.dev(),
        original.ino()
    );
    // An ephemeral filesystem can reuse its device number and root inode after
    // destruction. Its new UUID must never adopt the old receiver record.
    volume.unmount();
    volume.mount_tmpfs();
    let ephemeral_inbox = Tree::new();
    stream::operations::begin(&ephemeral_inbox.0, &volume.path(), &context).unwrap();
    let previous = fs::metadata(volume.path()).unwrap();
    volume.unmount();
    volume.mount_tmpfs();
    let fresh = fs::metadata(volume.path()).unwrap();
    assert_eq!(previous.ino(), fresh.ino());
    assert_eq!(
        stream::operations::manage(
            &ephemeral_inbox.0,
            &volume.path(),
            ID,
            SAFE,
            REOPENED,
            Direction::Import,
            Action::Status
        )
        .unwrap_err()
        .to_string(),
        "file_operation_changed"
    );
    eprintln!(
        "new tmpfs rejects previous identity: dev {} -> {}, inode {}",
        previous.dev(),
        fresh.dev(),
        fresh.ino()
    );
}
