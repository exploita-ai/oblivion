//! Owned synchronous Windows I/O workers. Cancellation is a request; buffers
//! and handles remain owned until the actual thread completion and join.
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NOT_FOUND, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub(crate) fn duplicate(handle: HANDLE) -> io::Result<File> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("standard_handle_missing"));
    }
    let mut owned = null_mut();
    let process = unsafe { GetCurrentProcess() };
    if unsafe {
        DuplicateHandle(
            process,
            handle,
            process,
            &mut owned,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(owned) })
}

pub(crate) fn cancel_and_join(worker: JoinHandle<()>, stopped: &AtomicBool) -> io::Result<()> {
    stopped.store(true, Ordering::Release);
    let mut failed = false;
    // ERROR_NOT_FOUND can race the worker entering its next synchronous call.
    // Repeat until the worker has really exited; never detach its I/O buffers.
    while !worker.is_finished() {
        if unsafe { CancelSynchronousIo(worker.as_raw_handle()) } == 0
            && unsafe { GetLastError() } != ERROR_NOT_FOUND
        {
            failed = true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    worker
        .join()
        .map_err(|_| io::Error::other("windows_io_worker_failed"))?;
    if failed {
        return Err(io::Error::other("windows_io_cancellation_failed"));
    }
    Ok(())
}
