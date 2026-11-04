//! Kernel-observed process generations for native runtime ownership.
//!
//! A recorded PID alone is not an owner: it can be reused after process exit.
//! These observations complement the supervisor's actual Child handle; they do
//! not authorize signalling a process or replace verified child termination.

use crate::control::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pid: u32,
    pub started: u64,
    pub boot: String,
}

impl Identity {
    pub fn alive(&self) -> Result<bool> {
        Ok(observe(self.pid)?.as_ref() == Some(self))
    }
}

pub fn observe(pid: u32) -> Result<Option<Identity>> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("native_process_invalid_pid".into());
    }
    let boot = boot()?;
    Ok(snapshot(pid)?.map(|process| Identity {
        pid,
        started: process.started,
        boot,
    }))
}

pub fn current() -> Result<Identity> {
    observe(std::process::id())?.ok_or_else(|| "native_process_unavailable".into())
}

pub fn parent() -> Result<Identity> {
    let pid = std::process::id();
    let before = snapshot(pid)?.ok_or("native_process_unavailable")?;
    // A launcher reparented to init cannot adopt init as its original owner.
    if before.parent <= 1 {
        return Err("native_parent_unavailable".into());
    }
    let parent = observe(before.parent)?.ok_or("native_parent_unavailable")?;
    let after = snapshot(pid)?.ok_or("native_process_unavailable")?;
    if before.started != after.started || before.parent != after.parent {
        return Err("native_parent_changed".into());
    }
    Ok(parent)
}

#[derive(Debug, Eq, PartialEq)]
struct Process {
    started: u64,
    parent: u32,
}

fn valid_boot(value: &str) -> Result<String> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                return byte == b'-';
            }
            byte.is_ascii_hexdigit()
        })
    {
        return Err("native_boot_identity_unavailable".into());
    }
    Ok(value.into())
}

#[cfg(target_os = "linux")]
fn boot() -> Result<String> {
    valid_boot(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim())
}

#[cfg(target_os = "macos")]
fn boot() -> Result<String> {
    let mut bytes = [0u8; 64];
    let mut length = bytes.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if length > bytes.len() {
        return Err("native_boot_identity_unavailable".into());
    }
    valid_boot(std::ffi::CStr::from_bytes_with_nul(&bytes[..length])?.to_str()?)
}

#[cfg(target_os = "linux")]
fn process_file(path: String) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn snapshot(pid: u32) -> Result<Option<Process>> {
    let Some(stat) = process_file(format!("/proc/{pid}/stat"))? else {
        return Ok(None);
    };
    let Some(before) = linux_stat(&stat, pid)? else {
        return Ok(None);
    };
    let Some(status) = process_file(format!("/proc/{pid}/status"))? else {
        return Ok(None);
    };
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("native_process_owner_unavailable")?
        .parse::<u32>()?;
    if uid != unsafe { libc::geteuid() } {
        return Err("native_process_owner_mismatch".into());
    }
    let Some(stat) = process_file(format!("/proc/{pid}/stat"))? else {
        return Ok(None);
    };
    let Some(after) = linux_stat(&stat, pid)? else {
        return Ok(None);
    };
    if before.started != after.started {
        return Err("native_process_changed".into());
    }
    Ok(Some(after))
}

#[cfg(any(target_os = "linux", test))]
fn linux_stat(value: &str, pid: u32) -> Result<Option<Process>> {
    let open = value.find('(').ok_or("native_process_invalid_stat")?;
    let close = value.rfind(')').ok_or("native_process_invalid_stat")?;
    if open >= close || value[..open].trim().parse::<u32>()? != pid {
        return Err("native_process_invalid_stat".into());
    }
    // comm may itself contain spaces, parentheses and newlines. Fields after
    // its final ')' start at field3; starttime is field22 (raw kernel ticks).
    let mut fields = value[close + 1..].split_whitespace();
    let state = fields.next().ok_or("native_process_invalid_stat")?;
    if matches!(state, "Z" | "X" | "x") {
        return Ok(None);
    }
    if !matches!(state, "R" | "S" | "D" | "T" | "t" | "W" | "K" | "P" | "I") {
        return Err("native_process_invalid_stat".into());
    }
    let parent = fields
        .next()
        .ok_or("native_process_invalid_stat")?
        .parse::<u32>()?;
    let started = fields
        .nth(17)
        .ok_or("native_process_invalid_stat")?
        .parse::<u64>()?;
    Ok(Some(Process { started, parent }))
}

#[cfg(target_os = "macos")]
fn bsd_info(pid: u32) -> Result<Option<libc::proc_bsdinfo>> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let count = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if count == 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
            return Ok(None);
        }
        return Err(error.into());
    }
    if count != size as i32 {
        return Err("native_process_incomplete_observation".into());
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid {
        return Err("native_process_changed".into());
    }
    if info.pbi_status == libc::SZOMB {
        return Ok(None);
    }
    if info.pbi_uid != unsafe { libc::geteuid() } {
        return Err("native_process_owner_mismatch".into());
    }
    Ok(Some(info))
}

#[cfg(target_os = "macos")]
fn snapshot(pid: u32) -> Result<Option<Process>> {
    let Some(before) = bsd_info(pid)? else {
        return Ok(None);
    };
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v0>::uninit();
    if unsafe {
        libc::proc_pid_rusage(
            pid as i32,
            libc::RUSAGE_INFO_V0,
            usage.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let usage = unsafe { usage.assume_init() };
    let Some(after) = bsd_info(pid)? else {
        return Ok(None);
    };
    if (before.pbi_start_tvsec, before.pbi_start_tvusec)
        != (after.pbi_start_tvsec, after.pbi_start_tvusec)
    {
        return Err("native_process_changed".into());
    }
    if usage.ri_proc_exit_abstime != 0 {
        return Ok(None);
    }
    if usage.ri_proc_start_abstime == 0 {
        return Err("native_process_incomplete_observation".into());
    }
    Ok(Some(Process {
        started: usage.ri_proc_start_abstime,
        parent: after.pbi_ppid,
    }))
}

#[cfg(test)]
mod tests {
    use super::{Identity, Process, current, linux_stat, parent, valid_boot};

    #[test]
    fn current_and_parent_are_observed_without_a_subprocess() {
        let owner = current().unwrap();
        assert_eq!(owner.pid, std::process::id());
        assert!(owner.alive().unwrap());
        if unsafe { libc::getppid() } <= 1 {
            assert!(parent().is_err());
            return;
        }
        let parent = parent().unwrap();
        assert_eq!(parent.pid, unsafe { libc::getppid() } as u32);
        assert!(parent.alive().unwrap());
    }

    #[test]
    fn same_pid_with_a_different_birth_or_boot_is_not_the_owner() {
        let owner = current().unwrap();
        assert!(
            !Identity {
                started: owner.started + 1,
                ..owner.clone()
            }
            .alive()
            .unwrap()
        );
        assert!(
            !Identity {
                boot: "00000000-0000-0000-0000-000000000000".into(),
                ..owner
            }
            .alive()
            .unwrap()
        );
    }

    #[test]
    fn linux_stat_handles_parentheses_in_comm_and_raw_clock_ticks() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[1] = "51";
        fields[19] = "123456789";
        assert_eq!(
            linux_stat(&format!("42 (name (with) )) {}", fields.join(" ")), 42).unwrap(),
            Some(Process {
                parent: 51,
                started: 123456789,
            })
        );
        fields[0] = "Z";
        assert_eq!(
            linux_stat(&format!("42 (name) {}", fields.join(" ")), 42).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_kernel_stat_and_boot_domains_are_rejected() {
        for value in [
            "",
            "42 no-comm",
            "42 (name) R 1",
            "41 (name) R 1",
            "42 (name) ? 1",
        ] {
            assert!(linux_stat(value, 42).is_err());
        }
        for value in ["", "not-a-boot", "00000000-0000-0000-0000-00000000000z"] {
            assert!(valid_boot(value).is_err());
        }
    }
}
