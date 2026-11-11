//! The terminal owns console modes and repainting. The overlay job owns the
//! manager and its local children while they can access the console.
use crate::controller::Result;
use crate::terminal_overlay::Page;
use oblivion_native_windows::broker::Layout;
use std::cmp::Ordering;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};
use zeroize::Zeroizing;

pub(crate) fn manager_command(layout: &Layout) -> Command {
    // The authenticated broker supplies the installed software paths.
    let mut command = Command::new(&layout.manager);
    command
        .env("OBLIVION_LAUNCHER", &layout.launcher)
        .env("OTUI_ASSET_ROOT", &layout.assets)
        .env("OBLIVION_RUNTIME_MODE", "desktop")
        .env_remove("OBLIVION_LIVE_STORAGE")
        .env_remove("OBLIVION_SHOW_INTRO");
    command
}

pub(crate) struct Overlay {
    process: OwnedHandle,
    job: Option<OwnedHandle>,
}

impl Overlay {
    pub(crate) fn start(
        layout: &Layout,
        page: Page,
        safe: &str,
        input: &File,
        output: &File,
        error: &File,
    ) -> Result<Self> {
        if !oblivion_wire::control::valid_id(safe) {
            return Err("invalid_overlay_safe".into());
        }
        let command = manager_command(layout);
        if layout.manager.contains(['\0', '"']) {
            return Err("manager_overlay_path_invalid".into());
        }
        let application: Vec<_> = command.get_program().encode_wide().chain(Some(0)).collect();
        // The broker supplies the absolute executable. The remaining argv is
        // fixed syntax, a typed page and one validated hex identifier.
        let mut arguments: Vec<_> = format!(
            "\"{}\" --native-overlay {} --safe {safe}",
            layout.manager,
            page.argument()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let environment = environment(&command);
        let job = create_job()?;
        let handles = [inherit(input)?, inherit(output)?, inherit(error)?];
        let stdio = handles.each_ref().map(AsRawHandle::as_raw_handle);
        let jobs = [job.as_raw_handle()];
        let mut attributes = Attributes::new(&stdio, &jobs)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        [
            startup.StartupInfo.hStdInput,
            startup.StartupInfo.hStdOutput,
            startup.StartupInfo.hStdError,
        ] = stdio;
        startup.lpAttributeList = attributes.pointer();
        let mut info = PROCESS_INFORMATION::default();
        // JOB_LIST associates the process before its first instruction. The
        // job handle itself is private and cannot escape via HANDLE_LIST.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                arguments.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                null(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err("manager_overlay_process_failed".into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        drop(unsafe { OwnedHandle::from_raw_handle(info.hThread) });
        Ok(Self {
            process,
            job: Some(job),
        })
    }

    pub(crate) fn poll(&mut self) -> Result<Option<ExitStatus>> {
        if !exited(&self.process)? {
            return Ok(None);
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err("manager_overlay_exit_unconfirmed".into());
        }
        Ok(Some(ExitStatus::from_raw(code)))
    }

    /// Even a successful manager exit can leave a CLI reading the console.
    /// Keep the job handle until its active-process count reaches zero.
    pub(crate) fn close(mut self) -> Result<()> {
        let job = self.job.take().ok_or("manager_overlay_job_missing")?;
        stop(&job, &self.process)
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            let _ = stop(&job, &self.process);
        }
    }
}

fn create_job() -> Result<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return Err("manager_overlay_job_failed".into());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err("manager_overlay_job_failed".into());
    }
    Ok(job)
}

fn exited(process: &OwnedHandle) -> Result<bool> {
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err("manager_overlay_exit_unconfirmed".into()),
    }
}

fn active(job: &OwnedHandle) -> Result<u32> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err("manager_overlay_cleanup_unconfirmed".into());
    }
    Ok(accounting.ActiveProcesses)
}

fn stop(job: &OwnedHandle, process: &OwnedHandle) -> Result<()> {
    if active(job)? != 0 && unsafe { TerminateJobObject(job.as_raw_handle(), 1) } == 0 {
        return Err("manager_overlay_cleanup_unconfirmed".into());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if active(job)? == 0 && exited(process)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("manager_overlay_cleanup_unconfirmed".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn inherit(file: &File) -> Result<OwnedHandle> {
    let process = unsafe { GetCurrentProcess() };
    let mut handle = null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            file.as_raw_handle(),
            process,
            &mut handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err("manager_overlay_stdio_failed".into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct Attributes<'a> {
    storage: Vec<usize>,
    _handles: std::marker::PhantomData<&'a [HANDLE]>,
}

impl<'a> Attributes<'a> {
    fn new(stdio: &'a [HANDLE], jobs: &'a [HANDLE]) -> Result<Self> {
        let mut bytes = 0;
        unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) };
        if bytes == 0 {
            return Err("manager_overlay_attributes_failed".into());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            return Err("manager_overlay_attributes_failed".into());
        }
        let mut attributes = Self {
            storage,
            _handles: std::marker::PhantomData,
        };
        for (kind, handles) in [
            (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, stdio),
            (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs),
        ] {
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.pointer(),
                    0,
                    kind as usize,
                    handles.as_ptr().cast(),
                    size_of_val(handles),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err("manager_overlay_attributes_failed".into());
            }
        }
        Ok(attributes)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

fn environment(command: &Command) -> Zeroizing<Vec<u16>> {
    let mut entries: Vec<_> = std::env::vars_os()
        .map(|(key, value)| (key.encode_wide().collect::<Vec<_>>(), value))
        .collect();
    for (key, value) in command.get_envs() {
        let key: Vec<_> = key.encode_wide().collect();
        entries.retain(|(name, _)| compare_names(name, &key) != Ordering::Equal);
        if let Some(value) = value {
            entries.push((key, value.to_owned()));
        }
    }
    entries.sort_unstable_by(|left, right| compare_names(&left.0, &right.0));
    let mut block = Zeroizing::new(Vec::new());
    for (key, value) in entries {
        block.extend(key);
        block.push(b'=' as u16);
        block.extend(value.encode_wide().chain(Some(0)));
    }
    // A Windows Unicode environment block ends with two NULs.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

fn compare_names(left: &[u16], right: &[u16]) -> Ordering {
    (unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        )
    })
    .cmp(&CSTR_EQUAL)
}
