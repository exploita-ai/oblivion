use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
pub struct Capabilities {
    pub version: u8,
    pub backend: &'static str,
    pub architecture: &'static str,
    pub virtualization: bool,
    pub nested: bool,
    pub vsock: bool,
    pub supported: bool,
    pub reason: Option<&'static str>,
}

pub fn qemu() -> Option<&'static Path> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use std::os::unix::fs::MetadataExt;
        let path = Path::new(if cfg!(target_arch = "aarch64") {
            "/usr/bin/qemu-system-aarch64"
        } else {
            "/usr/bin/qemu-system-x86_64"
        });
        if path.metadata().is_ok_and(|info| {
            info.is_file()
                && info.uid() == 0
                && info.mode() & 0o022 == 0
                && info.mode() & 0o111 != 0
        }) {
            return Some(path);
        }
    }
    None
}

pub fn capabilities() -> Capabilities {
    let mut result = Capabilities {
        version: 1,
        backend: "qemu-kvm",
        architecture: std::env::consts::ARCH,
        virtualization: false,
        nested: false,
        vsock: false,
        supported: false,
        reason: Some("linux_x86_64_or_aarch64_required"),
    };
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let kvm = probe();
        let vsock = vsock();
        result.virtualization = kvm.is_ok();
        result.nested = kvm.as_ref().is_ok_and(|nested| *nested);
        result.vsock = vsock.is_ok();
        result.reason = match kvm {
            Err(error) => Some(error.0),
            Ok(false) => Some("nested_virtualization_unavailable"),
            Ok(true) if vsock.is_err() => vsock.err().map(|error| error.0),
            Ok(true) => match qemu() {
                None => Some("qemu_system_required"),
                Some(path) if !qemu_compatible(path, std::env::consts::ARCH) => {
                    Some("qemu_nested_version_required")
                }
                Some(_) => None,
            },
        };
        result.supported = result.reason.is_none();
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = &mut result;
    }
    result
}

#[cfg(any(target_os = "linux", test))]
fn qemu_compatible(path: &Path, architecture: &str) -> bool {
    // KVM_CAP_ARM_EL2 reached Linux in 6.16, but its userspace vCPU flag was
    // first wired by QEMU 10.1. The controller's EL1-only inner QEMU is separate.
    architecture != "aarch64"
        || qemu_version(
            path,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .is_some_and(|version| version >= (10, 1, 0))
}

#[cfg(any(target_os = "linux", test))]
fn qemu_version(path: &Path, deadline: std::time::Instant) -> Option<(u32, u32, u32)> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};

    // The caller supplies only qemu()'s fixed, trusted root-owned executable.
    // Even diagnostic output is bounded and cannot hold capabilities forever.
    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let result = (|| {
        let mut output = child.stdout.take()?;
        let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return None;
        }
        let mut bytes = Vec::new();
        let mut ended = false;
        loop {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0; 512];
            match output.read(&mut chunk) {
                Ok(0) => ended = true,
                Ok(length) => {
                    if bytes.len() + length > 4096 {
                        return None;
                    }
                    bytes.extend_from_slice(&chunk[..length]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return None,
            }
            if let Some(status) = child.try_wait().ok()? {
                if !status.success() {
                    return None;
                }
                if ended {
                    let release = std::str::from_utf8(&bytes)
                        .ok()?
                        .strip_prefix("QEMU emulator version ")?
                        .split_ascii_whitespace()
                        .next()?;
                    if !release
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
                    {
                        return None;
                    }
                    let mut numbers = release.split('.');
                    let version = (
                        numbers.next()?.parse().ok()?,
                        numbers.next()?.parse().ok()?,
                        numbers.next()?.parse().ok()?,
                    );
                    return numbers.next().is_none().then_some(version);
                }
            }
            let mut ready = libc::pollfd {
                fd: if ended { -1 } else { output.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(20) as i32;
            if unsafe { libc::poll(&mut ready, 1, remaining) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return None;
            }
        }
    })();
    if !matches!(child.try_wait(), Ok(Some(_))) {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

#[cfg(test)]
mod tests {
    use super::{qemu_compatible, qemu_version};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    struct Executable(PathBuf);
    impl Executable {
        fn new(body: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "oblivion-qemu-version-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Executable {
        fn drop(&mut self) {
            fs::remove_file(&self.0).unwrap();
        }
    }

    #[test]
    fn arm64_policy_invokes_only_version_and_checks_the_actual_release() {
        for (release, expected) in [
            ("10.0.13", false),
            ("10.1.0", true),
            ("11.1.2", true),
            ("10.1.0-rc0", false),
            ("garbage", false),
        ] {
            let executable = Executable::new(&format!(
                r#"
[ "$#" -eq 1 ] && [ "$1" = --version ] && [ "$LC_ALL" = C ] && [ "${{HOME+x}}" != x ] || exit 23
printf 'QEMU emulator version {release} (Debian fixture)\n'
"#
            ));
            assert_eq!(
                qemu_compatible(&executable.0, "aarch64"),
                expected,
                "{release}"
            );
        }
        assert!(qemu_compatible(
            std::path::Path::new("/nonexistent-do-not-invoke"),
            "x86_64"
        ));
    }

    #[test]
    fn failed_oversized_and_stalled_version_processes_fail_closed() {
        for body in [
            r#"printf 'QEMU emulator version 11.1.2\n'; exit 1"#,
            r#"printf 'QEMU emulator version 11.1.2\n'; printf '%4097s' ''"#,
            "exec /bin/sleep 10",
        ] {
            let executable = Executable::new(body);
            let started = Instant::now();
            assert!(qemu_version(&executable.0, started + Duration::from_millis(100)).is_none());
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn probe() -> crate::Result<bool> {
    use std::os::fd::AsRawFd;
    let (kvm, _vm) = create_vm()?;
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Entry {
        function: u32,
        index: u32,
        flags: u32,
        eax: u32,
        ebx: u32,
        ecx: u32,
        edx: u32,
        padding: [u32; 3],
    }
    #[repr(C)]
    struct Cpuid {
        count: u32,
        padding: u32,
        entries: [Entry; 1024],
    }
    let mut cpuid = Box::new(Cpuid {
        count: 1024,
        padding: 0,
        entries: [Entry::default(); 1024],
    });
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc008ae05, cpuid.as_mut() as *mut Cpuid) } != 0
        || cpuid.count > 1024
    {
        return Ok(false);
    }
    let supported = &cpuid.entries[..cpuid.count as usize];
    let intel = supported
        .iter()
        .any(|entry| entry.function == 1 && entry.ecx & (1 << 5) != 0);
    let amd = supported
        .iter()
        .any(|entry| entry.function == 0x80000001 && entry.ecx & (1 << 2) != 0);
    let enabled = |module| {
        std::fs::read_to_string(format!("/sys/module/{module}/parameters/nested"))
            .is_ok_and(|value| matches!(value.trim(), "1" | "Y" | "y"))
    };
    Ok(intel && enabled("kvm_intel") || amd && enabled("kvm_amd"))
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn probe() -> crate::Result<bool> {
    use std::os::fd::AsRawFd;
    let (_kvm, vm) = create_vm()?;
    // Linux UAPI KVM_CAP_ARM_EL2=240. Older kernels deliberately fail the
    // capability check; there is no emulation or single-level fallback.
    Ok(unsafe { libc::ioctl(vm.as_raw_fd(), 0xae03, 240) } > 0)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn create_vm() -> crate::Result<(std::fs::File, std::os::fd::OwnedFd)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let kvm = open_device(Device::Kvm)?;
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae00) } != 12 {
        return Err(crate::Error("usable_kvm_required"));
    }
    let vm = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae01, 0) };
    if vm < 0 {
        return Err(crate::Error("usable_kvm_required"));
    }
    Ok((kvm, unsafe { OwnedFd::from_raw_fd(vm) }))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn vsock() -> crate::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let _device = open_device(Device::VhostVsock)?;
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(crate::Error("vhost_vsock_unavailable"));
    }
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
enum Device {
    Kvm,
    VhostVsock,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn open_device(device: Device) -> crate::Result<std::fs::File> {
    use crate::enrollment;
    use std::fs::OpenOptions;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let (path, missing, denied, unavailable) = match device {
        Device::Kvm => (
            enrollment::KVM,
            "kvm_device_missing",
            "kvm_device_access_denied",
            "usable_kvm_required",
        ),
        Device::VhostVsock => (
            enrollment::VHOST_VSOCK,
            "vhost_vsock_device_missing",
            "vhost_vsock_device_access_denied",
            "vhost_vsock_unavailable",
        ),
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            crate::Error(match error.raw_os_error() {
                Some(libc::ENOENT | libc::ENODEV | libc::ENXIO) => missing,
                Some(libc::EACCES | libc::EPERM) => enrollment::required(path).unwrap_or(denied),
                _ => unavailable,
            })
        })?;
    if !file
        .metadata()
        .is_ok_and(|info| info.file_type().is_char_device())
    {
        return Err(crate::Error(unavailable));
    }
    Ok(file)
}
