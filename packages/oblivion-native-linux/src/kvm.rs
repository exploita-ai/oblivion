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
        let (virtualization, nested) = probe();
        result.virtualization = virtualization;
        result.nested = nested;
        result.vsock = vsock();
        result.reason = if !virtualization {
            Some("usable_kvm_required")
        } else if !nested {
            Some("nested_virtualization_unavailable")
        } else if !result.vsock {
            Some("vhost_vsock_unavailable")
        } else if qemu().is_none() {
            Some("qemu_system_required")
        } else {
            None
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn probe() -> (bool, bool) {
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let Ok(kvm) = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/kvm")
    else {
        return (false, false);
    };
    if !kvm
        .metadata()
        .is_ok_and(|info| info.file_type().is_char_device())
        || unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae00) } != 12
    {
        return (false, false);
    }
    let vm = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae01, 0) };
    if vm < 0 {
        return (false, false);
    }
    drop(unsafe { OwnedFd::from_raw_fd(vm) });
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
        return (true, false);
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
    (
        true,
        intel && enabled("kvm_intel") || amd && enabled("kvm_amd"),
    )
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn probe() -> (bool, bool) {
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let Ok(kvm) = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/kvm")
    else {
        return (false, false);
    };
    if !kvm
        .metadata()
        .is_ok_and(|info| info.file_type().is_char_device())
        || unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae00) } != 12
    {
        return (false, false);
    }
    let vm = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae01, 0) };
    if vm < 0 {
        return (false, false);
    }
    let vm = unsafe { OwnedFd::from_raw_fd(vm) };
    // Linux UAPI KVM_CAP_ARM_EL2=240. Older kernels deliberately fail the
    // capability check; there is no emulation or single-level fallback.
    (
        true,
        unsafe { libc::ioctl(vm.as_raw_fd(), 0xae03, 240) } > 0,
    )
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn vsock() -> bool {
    use std::fs::OpenOptions;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/vhost-vsock")
    else {
        return false;
    };
    if !file
        .metadata()
        .is_ok_and(|info| info.file_type().is_char_device())
    {
        return false;
    }
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    true
}
