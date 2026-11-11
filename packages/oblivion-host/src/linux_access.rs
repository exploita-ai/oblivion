use crate::control::Result;
use std::fs::{OpenOptions, symlink_metadata};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::{fs::MetadataExt, net::UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};

const HELPER: &str = "/usr/lib/oblivion-desktop/bin/oblivion-vm";
const PKEXEC: &str = "/usr/bin/pkexec";

pub fn diagnostic(reason: &str) -> Option<&'static str> {
    match reason {
        "kvm_access_enrollment_required" => {
            Some("This account needs access to the kvm group to start Oblivion.")
        }
        "kvm_login_required" => {
            Some("Log out and back in, then rerun Oblivion. For SSH, disconnect and reconnect.")
        }
        "kvm_device_missing" => {
            Some("The KVM device is unavailable. Check the host kernel and virtualization support.")
        }
        "vhost_vsock_device_missing" => Some(
            "The vhost-vsock device is unavailable. Check that the host kernel provides vhost_vsock and the module is loaded.",
        ),
        "kvm_device_access_denied" => {
            Some("This process cannot open the KVM device. Check the host device access policy.")
        }
        "vhost_vsock_device_access_denied" => Some(
            "This process cannot open the vhost-vsock device. Check the host device access policy.",
        ),
        _ => None,
    }
}

/// The packaged first-run path may call this after checking its fixed helper.
/// Success requests one new unprivileged capability probe.
pub fn prepare(reason: &str) -> Result<bool> {
    if reason != "kvm_access_enrollment_required" {
        return match diagnostic(reason) {
            Some(message) => Err(message.into()),
            None => Ok(false),
        };
    }
    if !trusted_executable(HELPER) || !trusted_executable(PKEXEC) {
        return Err("The packaged KVM access setup is unavailable.".into());
    }
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "KVM access setup requires an interactive terminal.")?;
    writeln!(
        tty,
        "Oblivion needs access to KVM and vhost-vsock. Setup adds your account to the kvm group and requires administrator approval."
    )?;
    write!(tty, "Type ENABLE to continue, or press Enter to cancel: ")?;
    tty.flush()?;
    let mut answer = Vec::new();
    BufReader::new(tty.take(32)).read_until(b'\n', &mut answer)?;
    if !matches!(answer.as_slice(), b"ENABLE\n" | b"ENABLE\r\n") {
        return Err("KVM access setup was cancelled.".into());
    }
    // pkexec 126 preserves stdin and keeps its TTY authentication separate.
    // Keep the parent socket alive while the direct child performs setup.
    let (_parent, child) = UnixStream::pair()?;
    let status = Command::new(PKEXEC)
        .args([HELPER, "enroll"])
        .stdin(Stdio::from(OwnedFd::from(child)))
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(126) => Err("KVM access setup was cancelled.".into()),
        _ => Err("KVM access setup did not finish. Administrator authorization and a local account are required.".into()),
    }
}

fn trusted_executable(path: &str) -> bool {
    Path::new(path)
        .ancestors()
        .enumerate()
        .all(|(index, component)| {
            symlink_metadata(component).is_ok_and(|metadata| {
                metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && if index == 0 {
                        metadata.is_file() && metadata.mode() & 0o111 != 0
                    } else {
                        metadata.is_dir()
                    }
            })
        })
}
