use crate::{Error, Result};
use std::fs;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::RawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) const KVM: &str = "/dev/kvm";
pub(crate) const VHOST_VSOCK: &str = "/dev/vhost-vsock";

pub(crate) fn required(device: &str) -> Option<&'static str> {
    let uid = unsafe { libc::getuid() };
    if uid != unsafe { libc::geteuid() } {
        return None;
    }
    let account = Account::local(uid)?;
    let group = Group::local()?;
    if !group.controls(device) {
        return None;
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 || unsafe { libc::getegid() } == group.gid {
        return None;
    }
    let mut groups = vec![0; count as usize];
    if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count
        || groups.contains(&group.gid)
    {
        return None;
    }
    Some(if group.includes(&account) {
        "kvm_login_required"
    } else {
        "kvm_access_enrollment_required"
    })
}

pub fn enroll() -> Result<()> {
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(Error("kvm_enrollment_requires_administrator"));
    }
    let parent = unsafe { libc::getppid() };
    let uid = parent_uid(libc::STDIN_FILENO, parent)?;
    let account = Account::local(uid).ok_or(Error("kvm_local_account_required"))?;
    let group = Group::local().ok_or(Error("kvm_group_unavailable"))?;
    if !group.controls(KVM) && !group.controls(VHOST_VSOCK) {
        return Err(Error("kvm_group_device_unavailable"));
    }
    if group.includes(&account) {
        return Ok(());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(Error("kvm_enrollment_parent_required"));
    }
    let result = Command::new("/usr/sbin/adduser")
        .arg(&account.name)
        .arg("kvm")
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !result.is_ok_and(|status| status.success())
        || !Group::local()
            .is_some_and(|current| current.gid == group.gid && current.includes(&account))
    {
        return Err(Error("kvm_enrollment_failed"));
    }
    Ok(())
}

// pkexec preserves stdio and execs the requested helper in its own process.
// The socketpair created by its direct parent binds the destination to that
// process's kernel credentials even when a different administrator approves.
fn parent_uid(fd: RawFd, parent: libc::pid_t) -> Result<libc::uid_t> {
    let peer = peer_credentials(fd)?;
    if parent <= 1 || peer.pid != parent || peer.uid == 0 || peer.uid == libc::uid_t::MAX {
        return Err(Error("kvm_enrollment_parent_required"));
    }
    Ok(peer.uid)
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred> {
    let mut peer = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
    {
        return Err(Error("kvm_enrollment_parent_required"));
    }
    Ok(unsafe { peer.assume_init() })
}

struct Account {
    name: String,
    gid: libc::gid_t,
}

impl Account {
    fn local(uid: libc::uid_t) -> Option<Self> {
        if uid == 0 || uid == libc::uid_t::MAX {
            return None;
        }
        let database = fs::read("/etc/passwd").ok()?;
        let mut accounts = database.split(|byte| *byte == b'\n').filter_map(|line| {
            let mut fields = line.split(|byte| *byte == b':');
            let name = std::str::from_utf8(fields.next()?).ok()?;
            fields.next()?;
            if number(fields.next()?)? != uid {
                return None;
            }
            let gid = number(fields.next()?)?;
            fields.next()?; // GECOS
            fields.next()?; // home
            let shell = fields.next()?;
            Some((name, gid, shell))
        });
        let (name, gid, shell) = accounts.next()?;
        if accounts.next().is_some()
            || !name
                .as_bytes()
                .first()
                .is_some_and(|first| first.is_ascii_alphanumeric() || *first == b'_')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-$".contains(&byte))
            || shell.ends_with(b"/nologin")
            || shell.ends_with(b"/false")
        {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            gid,
        })
    }
}

struct Group {
    gid: libc::gid_t,
    members: Vec<u8>,
}

impl Group {
    fn local() -> Option<Self> {
        let database = fs::read("/etc/group").ok()?;
        let mut groups = database.split(|byte| *byte == b'\n').filter_map(|line| {
            let mut fields = line.strip_prefix(b"kvm:")?.split(|byte| *byte == b':');
            fields.next()?;
            Some((number(fields.next()?)?, fields.next()?))
        });
        let (gid, members) = groups.next()?;
        if gid == 0 || gid == libc::gid_t::MAX || groups.next().is_some() {
            return None;
        }
        Some(Self {
            gid,
            members: members.to_vec(),
        })
    }

    fn includes(&self, account: &Account) -> bool {
        account.gid == self.gid
            || self
                .members
                .split(|byte| *byte == b',')
                .any(|member| member == account.name.as_bytes())
    }

    fn controls(&self, device: &str) -> bool {
        fs::symlink_metadata(Path::new(device)).is_ok_and(|info| {
            info.file_type().is_char_device()
                && info.uid() == 0
                && info.gid() == self.gid
                && info.mode() & 0o066 == 0o060
        })
    }
}

fn number(field: &[u8]) -> Option<u32> {
    std::str::from_utf8(field).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{parent_uid, peer_credentials};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn socketpair_uses_kernel_identity_and_rejects_wrong_parent() {
        let (_parent, child) = UnixStream::pair().unwrap();
        let fd = child.as_raw_fd();
        let pid = unsafe { libc::getpid() };
        let uid = unsafe { libc::geteuid() };
        let peer = peer_credentials(fd).unwrap();
        assert_eq!((peer.pid, peer.uid), (pid, uid));
        assert!(parent_uid(fd, 1).is_err());
        assert!(parent_uid(fd, pid + 1).is_err());
        if uid == 0 {
            assert!(parent_uid(fd, pid).is_err());
        } else {
            assert_eq!(parent_uid(fd, pid).unwrap(), uid);
        }
    }

    #[test]
    fn inherited_file_is_not_an_enrollment_channel() {
        let input = File::open("/dev/null").unwrap();
        assert!(parent_uid(input.as_raw_fd(), unsafe { libc::getpid() }).is_err());
    }
}
