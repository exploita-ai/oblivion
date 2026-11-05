//! Local byte pipes with private ACLs. Every outstanding OVERLAPPED owns its
//! event, file handle and bounded buffer until Windows confirms completion.
use crate::security::Identity;
use crate::{Error, Result};
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
    ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    WaitForMultipleObjects, WaitForSingleObject,
};
use zeroize::Zeroizing;

pub(crate) const BUFFER: usize = 65536;

static DRAIN_FAILED: AtomicBool = AtomicBool::new(false);

pub fn drain_failed() -> bool {
    DRAIN_FAILED.load(Ordering::Acquire)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Purpose {
    Bootstrap,
    Control,
    Supervision,
}

pub struct Endpoint {
    name: Vec<u16>,
    purpose: Purpose,
    identity: Identity,
    listener: Option<Pipe>,
    connect: Option<Operation>,
}

pub struct Pipe {
    handle: Arc<PipeHandle>,
    role: Role,
    closed: bool,
    read: Option<Operation>,
    write: Option<Operation>,
}

/// A zero-access reference keeps only the kernel connection alive. It exposes
/// neither a raw handle nor read/write methods and cannot become a second pump.
pub(crate) struct Lease {
    _handle: OwnedHandle,
}

struct Pending {
    handle: Arc<PipeHandle>,
    event: OwnedHandle,
    overlapped: OVERLAPPED,
    bytes: Zeroizing<Vec<u8>>,
    in_flight: bool,
    completed: Option<usize>,
    offset: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Server,
    Client,
}

// Outstanding buffers may outlive cancellation, but must not keep a client's
// kernel handle open. Taking this sole owner closes once even when a pending
// allocation is retained. No mutex is held across a Win32 call or event wait.
struct PipeHandle(Mutex<Option<OwnedHandle>>);
impl PipeHandle {
    fn raw(&self) -> io::Result<HANDLE> {
        self.0
            .lock()
            .map_err(|_| failed())?
            .as_ref()
            .map(AsRawHandle::as_raw_handle)
            .ok_or_else(closed)
    }
    fn close(&self) -> io::Result<()> {
        let handle = self.0.lock().map_err(|_| failed())?.take();
        drop(handle);
        Ok(())
    }
}

struct Operation(Option<Box<Pending>>);

// The allocation referenced by Windows never moves. Only its owning thread
// reads/writes user data; a move transfers ownership rather than sharing it.
unsafe impl Send for Operation {}

impl Operation {
    fn new(handle: Arc<PipeHandle>, bytes: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(failed());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle();
        Ok(Self(Some(Box::new(Pending {
            handle,
            event,
            overlapped,
            bytes,
            in_flight: false,
            completed: None,
            offset: 0,
        }))))
    }

    fn pending(&self) -> &Pending {
        self.0.as_ref().expect("owned pending I/O")
    }
    fn pending_mut(&mut self) -> &mut Pending {
        self.0.as_mut().expect("owned pending I/O")
    }

    fn submitted(&mut self, success: bool) -> io::Result<()> {
        if !success && unsafe { GetLastError() } != ERROR_IO_PENDING {
            let code = unsafe { GetLastError() };
            if matches!(
                code,
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            ) {
                self.pending_mut().completed = Some(0);
                return Ok(());
            }
            return Err(failed());
        }
        self.pending_mut().in_flight = true;
        Ok(())
    }

    fn read(handle: Arc<PipeHandle>) -> io::Result<Self> {
        let mut operation = Self::new(handle, Zeroizing::new(vec![0; BUFFER]))?;
        let pending = operation.pending_mut();
        let success = unsafe {
            ReadFile(
                pending.handle.raw()?,
                pending.bytes.as_mut_ptr(),
                pending.bytes.len() as u32,
                null_mut(),
                &mut pending.overlapped,
            )
        } != 0;
        operation.submitted(success)?;
        Ok(operation)
    }

    fn write(handle: Arc<PipeHandle>, bytes: &[u8]) -> io::Result<Self> {
        let mut operation = Self::new(handle, Zeroizing::new(bytes.to_vec()))?;
        let pending = operation.pending_mut();
        let success = unsafe {
            WriteFile(
                pending.handle.raw()?,
                pending.bytes.as_ptr(),
                pending.bytes.len() as u32,
                null_mut(),
                &mut pending.overlapped,
            )
        } != 0;
        operation.submitted(success)?;
        Ok(operation)
    }

    fn poll(&mut self) -> io::Result<Option<usize>> {
        if let Some(length) = self.pending().completed {
            return Ok(Some(length));
        }
        let pending = self.pending_mut();
        let mut transferred = 0;
        if unsafe {
            GetOverlappedResult(
                pending.handle.raw()?,
                &pending.overlapped,
                &mut transferred,
                0,
            )
        } != 0
        {
            pending.in_flight = false;
            pending.completed = Some(transferred as usize);
            return Ok(pending.completed);
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_IO_INCOMPLETE {
            return Ok(None);
        }
        pending.in_flight = false;
        if matches!(
            code,
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ) {
            pending.completed = Some(0);
            return Ok(Some(0));
        }
        if code == ERROR_OPERATION_ABORTED {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "private_pipe_cancelled",
            ));
        }
        Err(failed())
    }

    fn cancel(&mut self) -> io::Result<()> {
        if !self.pending().in_flight {
            return Ok(());
        }
        let pending = self.pending();
        let handle = match pending.handle.raw() {
            Ok(handle) => handle,
            Err(_) => return Err(self.abandon()),
        };
        unsafe {
            CancelIoEx(handle, &pending.overlapped);
        }
        if unsafe {
            WaitForSingleObject(
                pending.event.as_raw_handle(),
                if drain_failed() { 0 } else { 2000 },
            )
        } == WAIT_OBJECT_0
        {
            // A signalled completion is safe to release for every result except
            // ERROR_IO_INCOMPLETE. CancelIoEx itself does not provide that proof.
            let _ = self.poll();
            if !self.pending().in_flight {
                return Ok(());
            }
        }
        Err(self.abandon())
    }

    fn abandon(&mut self) -> io::Error {
        // Windows forbids releasing an OVERLAPPED or its buffer while pending.
        // Keep only this bounded operation alive until process exit if a broken
        // kernel cancellation cannot finish. Pipe::close disconnected the peer.
        std::mem::forget(self.0.take());
        DRAIN_FAILED.store(true, Ordering::Release);
        io::Error::other("private_pipe_cancellation_failed")
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.cancel();
        }
    }
}

impl Endpoint {
    pub fn bind(name: &str, purpose: Purpose) -> Result<Self> {
        let tail = name
            .strip_prefix(r"\\.\pipe\oblivion.")
            .ok_or(Error("invalid_private_pipe_name"))?;
        let (runtime, role) = tail
            .split_once('.')
            .ok_or(Error("invalid_private_pipe_name"))?;
        let id = |value: &str| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !id(runtime)
            || match purpose {
                Purpose::Control => role != "control",
                Purpose::Supervision => role != "supervision",
                Purpose::Bootstrap => !role.strip_prefix("auth.").is_some_and(id),
            }
        {
            return Err(Error("invalid_private_pipe_name"));
        }
        let mut endpoint = Self {
            name: name.encode_utf16().chain(Some(0)).collect(),
            purpose,
            identity: Identity::current()?,
            listener: None,
            connect: None,
        };
        endpoint.listener = Some(endpoint.create(true)?);
        Ok(endpoint)
    }

    fn create(&self, first: bool) -> Result<Pipe> {
        let descriptor = self.identity.descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | FILE_FLAG_OVERLAPPED
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                if self.purpose == Purpose::Bootstrap {
                    1
                } else {
                    65
                },
                BUFFER as u32,
                BUFFER as u32,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error("private_pipe_bind_failed"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(Error("private_pipe_bind_failed"));
        }
        Ok(Pipe::new(handle, Role::Server))
    }

    /// One pending listener remains owned between deadline polls. Control
    /// creates the next instance before handing out the connected one.
    pub fn accept(&mut self, stop: &AtomicBool, deadline: Instant) -> Result<Option<Pipe>> {
        let listener = self
            .listener
            .as_ref()
            .ok_or(Error("private_admission_closed"))?;
        if self.connect.is_none() {
            let mut operation =
                Operation::new(Arc::clone(&listener.handle), Zeroizing::new(Vec::new()))
                    .map_err(|_| Error("private_pipe_accept_failed"))?;
            let pending = operation.pending_mut();
            let connected = unsafe {
                ConnectNamedPipe(
                    pending
                        .handle
                        .raw()
                        .map_err(|_| Error("private_pipe_accept_failed"))?,
                    &mut pending.overlapped,
                )
            } != 0;
            if !connected && unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                operation.pending_mut().completed = Some(0);
            } else {
                operation
                    .submitted(connected)
                    .map_err(|_| Error("private_pipe_accept_failed"))?;
            }
            self.connect = Some(operation);
        }
        loop {
            if stop.load(Ordering::Acquire) || drain_failed() {
                self.stop_admission()?;
                return Err(Error("private_pipe_cancelled"));
            }
            let operation = self.connect.as_mut().expect("owned listener operation");
            if operation
                .poll()
                .map_err(|_| Error("private_pipe_accept_failed"))?
                .is_some()
            {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let wait = remaining.as_millis().min(100) as u32;
            if unsafe {
                WaitForSingleObject(operation.pending().event.as_raw_handle(), wait.max(1))
            } == WAIT_FAILED
            {
                return Err(Error("private_pipe_accept_failed"));
            }
        }
        self.connect.take();
        let listener = self.listener.as_ref().expect("owned connected listener");
        let mut pid = 0;
        let identified = unsafe {
            GetNamedPipeClientProcessId(
                listener
                    .handle
                    .raw()
                    .map_err(|_| Error("private_peer_check_failed"))?,
                &mut pid,
            )
        } != 0;
        if !identified
            && !matches!(
                unsafe { GetLastError() },
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            )
        {
            return Err(Error("private_peer_check_failed"));
        }
        let peer = identified
            && self
                .identity
                .permits(pid, self.purpose == Purpose::Bootstrap)
                .unwrap_or(false);
        let next = if self.purpose != Purpose::Bootstrap {
            Some(self.create(false)?)
        } else {
            None
        };
        let mut connected =
            std::mem::replace(&mut self.listener, next).expect("owned connected listener");
        if stop.load(Ordering::Acquire) || drain_failed() {
            drop(connected);
            self.stop_admission()?;
            return Err(Error("private_pipe_cancelled"));
        }
        if !peer {
            // A peer may have exited between connecting and token lookup. Its
            // lost/untrusted identity revokes only this connection; the next
            // listener already owns the namespace for other current clients.
            connected
                .close()
                .map_err(|_| Error("private_pipe_cancellation_failed"))?;
            if drain_failed() {
                return Err(Error("private_pipe_cancellation_failed"));
            }
            return Ok(None);
        }
        Ok(Some(connected))
    }

    pub fn stop_admission(&mut self) -> Result<()> {
        let mut result = Ok(());
        // The listener's connect operation lives outside Pipe. Cancel it before
        // closing the kernel handle; completion may never poll a recycled value.
        if let Some(mut connect) = self.connect.take() {
            if connect.cancel().is_err() {
                result = Err(Error("private_pipe_cancellation_failed"));
            }
        }
        if let Some(mut listener) = self.listener.take() {
            if listener.close().is_err() {
                result = Err(Error("private_pipe_cancellation_failed"));
            }
        }
        result
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.stop_admission();
    }
}

impl Pipe {
    pub(crate) fn verify_server_process(&self, expected: &impl AsRawHandle) -> io::Result<()> {
        let mut pid = 0;
        if self.role != Role::Client
            || unsafe { GetNamedPipeServerProcessId(self.handle.raw()?, &mut pid) } == 0
        {
            return Err(io::Error::other("untrusted_runtime_peer"));
        }
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(io::Error::other("untrusted_runtime_peer"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        if unsafe { CompareObjectHandles(process.as_raw_handle(), expected.as_raw_handle()) } == 0 {
            return Err(io::Error::other("untrusted_runtime_peer"));
        }
        Ok(())
    }
    fn new(handle: OwnedHandle, role: Role) -> Self {
        Self {
            handle: Arc::new(PipeHandle(Mutex::new(Some(handle)))),
            role,
            closed: false,
            read: None,
            write: None,
        }
    }

    pub(crate) fn events(&self, events: &mut Vec<HANDLE>, read: bool) {
        for operation in [if read { &self.read } else { &None }, &self.write]
            .into_iter()
            .flatten()
        {
            if operation.pending().in_flight {
                events.push(operation.pending().event.as_raw_handle());
            }
        }
    }

    fn flush_pending(&mut self) -> io::Result<bool> {
        loop {
            let Some(operation) = &mut self.write else {
                return Ok(true);
            };
            let Some(length) = operation.poll()? else {
                return Ok(false);
            };
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "private_pipe_closed",
                ));
            }
            let pending = operation.pending();
            if length > pending.bytes.len() {
                return Err(failed());
            }
            if length < pending.bytes.len() {
                self.write = Some(Operation::write(
                    Arc::clone(&self.handle),
                    &pending.bytes[length..],
                )?);
                continue;
            }
            self.write.take();
        }
    }

    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if self.role == Role::Server {
            if let Ok(handle) = self.handle.raw() {
                unsafe {
                    DisconnectNamedPipe(handle);
                }
            }
        }
        let mut result = Ok(());
        for operation in [&mut self.read, &mut self.write] {
            if let Some(mut pending) = operation.take() {
                if let Err(error) = pending.cancel() {
                    result = Err(error);
                }
            }
        }
        if let Err(error) = self.handle.close() {
            result = Err(error);
        }
        result
    }

    pub(crate) fn retain_lease(&self) -> io::Result<Lease> {
        if self.closed {
            return Err(closed());
        }
        let mut duplicate = null_mut();
        let process = unsafe { GetCurrentProcess() };
        // No DUPLICATE_SAME_ACCESS: the quiet reference has zero I/O rights.
        // The pipe's sole I/O owner remains self throughout cancellation/drain.
        if unsafe {
            DuplicateHandle(
                process,
                self.handle.raw()?,
                process,
                &mut duplicate,
                0,
                0,
                0,
            )
        } == 0
        {
            return Err(failed());
        }
        Ok(Lease {
            _handle: unsafe { OwnedHandle::from_raw_handle(duplicate) },
        })
    }

    pub(crate) fn wait(&self, deadline: Option<Instant>, read: bool) -> io::Result<()> {
        if self.closed {
            return Err(closed());
        }
        let mut events = Vec::with_capacity(2);
        self.events(&mut events, read);
        if events.is_empty() {
            return Err(failed());
        }
        let milliseconds = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "controller_timeout",
                    ));
                }
                remaining.as_millis().min(100).max(1) as u32
            }
            None => 100,
        };
        if unsafe { WaitForMultipleObjects(events.len() as u32, events.as_ptr(), 0, milliseconds) }
            == WAIT_FAILED
        {
            return Err(failed());
        }
        Ok(())
    }
}

impl Read for Pipe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(closed());
        }
        if drain_failed() {
            return Err(io::Error::other("private_pipe_cancellation_failed"));
        }
        if output.is_empty() {
            return Ok(0);
        }
        self.flush_pending()?;
        if self.read.is_none() {
            self.read = Some(Operation::read(Arc::clone(&self.handle))?);
        }
        let operation = self.read.as_mut().expect("pending pipe read");
        let Some(length) = operation.poll()? else {
            return Err(would_block());
        };
        let pending = operation.pending_mut();
        if length > pending.bytes.len() || pending.offset > length {
            return Err(failed());
        }
        let count = output.len().min(length - pending.offset);
        output[..count].copy_from_slice(&pending.bytes[pending.offset..pending.offset + count]);
        pending.offset += count;
        if pending.offset == length {
            self.read.take();
        }
        Ok(count)
    }
}

impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(closed());
        }
        if drain_failed() {
            return Err(io::Error::other("private_pipe_cancellation_failed"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.flush_pending()? {
            return Err(would_block());
        }
        let length = bytes.len().min(BUFFER);
        self.write = Some(Operation::write(
            Arc::clone(&self.handle),
            &bytes[..length],
        )?);
        // Like a bounded buffered writer, success means this Pipe owns the data.
        // flush() confirms delivery and reports any asynchronous write failure.
        self.flush_pending()?;
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(closed());
        }
        if drain_failed() {
            return Err(io::Error::other("private_pipe_cancellation_failed"));
        }
        if self.flush_pending()? {
            return Ok(());
        }
        Err(would_block())
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn failed() -> io::Error {
    io::Error::other("private_pipe_io_failed")
}
fn would_block() -> io::Error {
    io::Error::from(io::ErrorKind::WouldBlock)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "controller_channel_closed")
}

pub(crate) fn connect_control(
    name: &[u16],
    identity: &Identity,
    stop: &AtomicBool,
    deadline: Instant,
) -> io::Result<Pipe> {
    loop {
        check_connect(stop, deadline)?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            if code != ERROR_PIPE_BUSY {
                return Err(connect_error(code));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let waited = unsafe {
                WaitNamedPipeW(name.as_ptr(), remaining.as_millis().min(100).max(1) as u32)
            };
            if waited == 0 {
                let code = unsafe { GetLastError() };
                if !matches!(code, ERROR_SEM_TIMEOUT | ERROR_PIPE_BUSY) {
                    return Err(connect_error(code));
                }
            }
            continue;
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(failed());
        }
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(handle.as_raw_handle(), &mut pid) } == 0
            || !identity.permits(pid, false).unwrap_or(false)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted_runtime_peer",
            ));
        }
        check_connect(stop, deadline)?;
        return Ok(Pipe::new(handle, Role::Client));
    }
}

fn check_connect(stop: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "controller_cancelled",
        ));
    }
    if drain_failed() {
        return Err(io::Error::other("private_pipe_cancellation_failed"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "controller_timeout",
        ));
    }
    Ok(())
}

fn connect_error(code: u32) -> io::Error {
    io::Error::new(
        match code {
            ERROR_FILE_NOT_FOUND => io::ErrorKind::NotFound,
            ERROR_ACCESS_DENIED => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::Other,
        },
        "runtime_control_unavailable",
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Endpoint, Pipe, Purpose, Role, connect_control, drain_failed};
    use crate::security::Identity;
    use std::io::{self, Read, Write};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    pub(crate) fn name(purpose: Purpose) -> String {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        let id = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            r"\\.\pipe\oblivion.{id}.{}",
            match purpose {
                Purpose::Control => "control".to_owned(),
                Purpose::Supervision => "supervision".to_owned(),
                Purpose::Bootstrap => format!("auth.{id}"),
            }
        )
    }

    pub(crate) fn connected_pair(purpose: Purpose) -> (Endpoint, Pipe, Pipe) {
        let name = name(purpose);
        let mut endpoint = Endpoint::bind(&name, purpose).unwrap();
        let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let client = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        assert_ne!(client, INVALID_HANDLE_VALUE);
        let client = Pipe::new(
            unsafe { OwnedHandle::from_raw_handle(client) },
            Role::Client,
        );
        let server = endpoint
            .accept(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap()
            .unwrap();
        (endpoint, server, client)
    }

    pub(crate) fn receive(pipe: &mut Pipe, count: usize) -> Vec<u8> {
        let mut data = vec![0; count];
        let mut received = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while received < count {
            assert!(
                Instant::now() < deadline,
                "bounded private pipe fixture timed out"
            );
            match pipe.read(&mut data[received..]) {
                Ok(0) => panic!("unexpected private pipe EOF"),
                Ok(count) => received += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("{error}"),
            }
        }
        data
    }

    #[test]
    fn actual_pipe_is_private_noninheritable_first_instance_and_checks_current_peer_sid() {
        let (endpoint, server, mut client) = connected_pair(Purpose::Control);
        assert!(
            Identity::current()
                .unwrap()
                .permits(unsafe { GetCurrentProcessId() }, false)
                .unwrap()
        );
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(server.handle.raw().unwrap(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let mut descriptor = null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    server.handle.raw().unwrap(),
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let mut text = null_mut();
        let mut length = 0;
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    &mut length,
                )
            },
            0
        );
        let sddl =
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, (length - 1) as usize) })
                .unwrap();
        assert_eq!(sddl, Identity::current().unwrap().sddl());
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        let same_name = String::from_utf16(&endpoint.name[..endpoint.name.len() - 1]).unwrap();
        assert!(Endpoint::bind(&same_name, Purpose::Control).is_err());
        client.write_all(b"ordinary private bytes").unwrap();
        let mut server = server;
        assert_eq!(receive(&mut server, 22), b"ordinary private bytes");
        assert!(!drain_failed());
    }

    #[test]
    fn control_rearms_while_first_connection_remains_open() {
        let (mut endpoint, _first, _client) = connected_pair(Purpose::Control);
        let second = unsafe {
            CreateFileW(
                endpoint.name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        assert_ne!(second, INVALID_HANDLE_VALUE);
        let _second = unsafe { OwnedHandle::from_raw_handle(second) };
        let _accepted = endpoint
            .accept(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap()
            .unwrap();
        assert!(endpoint.listener.is_some());
    }

    #[test]
    fn pending_accept_and_pending_read_cancel_without_an_unbounded_wait() {
        let mut endpoint = Endpoint::bind(&name(Purpose::Bootstrap), Purpose::Bootstrap).unwrap();
        assert!(
            endpoint
                .accept(
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_millis(5)
                )
                .unwrap()
                .is_none()
        );
        let started = Instant::now();
        endpoint.stop_admission().unwrap();
        assert!(started.elapsed() < Duration::from_millis(2500));
        let (_endpoint, mut server, _client) = connected_pair(Purpose::Bootstrap);
        assert_eq!(
            server.read(&mut [0; 8]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let started = Instant::now();
        server.close().unwrap();
        assert!(started.elapsed() < Duration::from_millis(2500));
        assert!(!drain_failed());
    }

    #[test]
    fn client_close_cancels_its_read_closes_once_and_never_calls_server_disconnect() {
        let name = name(Purpose::Control);
        let mut endpoint = Endpoint::bind(&name, Purpose::Control).unwrap();
        let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut client = connect_control(
            &wide,
            &Identity::current().unwrap(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let mut server = endpoint
            .accept(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap()
            .unwrap();
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(client.handle.raw().unwrap(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        assert_eq!(
            client.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        client.close().unwrap();
        assert!(client.handle.raw().is_err());
        client.close().unwrap();
        assert_eq!(
            client.write(b"after close").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline);
            match server.read(&mut [0; 1]) {
                Ok(0) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                result => panic!("unexpected close observation: {result:?}"),
            }
        }
        assert!(!drain_failed());
    }

    #[test]
    #[ignore = "Private child fixture; parent tests connect then reap it before admission, no VM"]
    fn disconnected_client_fixture() {
        let Ok(name) = std::env::var("OBLIVION_DISCONNECTED_PIPE_FIXTURE") else {
            return;
        };
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        drop(unsafe { OwnedHandle::from_raw_handle(handle) });
    }

    #[test]
    fn disconnected_or_exited_clients_do_not_revoke_other_connections_or_the_next_listener() {
        for purpose in [Purpose::Control, Purpose::Supervision] {
            for exited in [false, true] {
                let name = name(purpose);
                let mut endpoint = Endpoint::bind(&name, purpose).unwrap();
                let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
                let identity = Identity::current().unwrap();
                let stop = AtomicBool::new(false);
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut held = connect_control(&wide, &identity, &stop, deadline).unwrap();
                let mut held_server = endpoint.accept(&stop, deadline).unwrap().unwrap();
                if exited {
                    let mut child = Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "private::tests::disconnected_client_fixture",
                            "--ignored",
                            "--nocapture",
                        ])
                        .env("OBLIVION_DISCONNECTED_PIPE_FIXTURE", &name)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                    assert!(child.wait().unwrap().success());
                    drop(child);
                } else {
                    drop(connect_control(&wide, &identity, &stop, deadline).unwrap());
                }
                // Some Windows builds retain the disconnected peer PID. Such a
                // same-user connection can still pass identity checks, but must
                // yield only EOF; an unavailable identity is rejected as None.
                if let Some(mut disconnected) = endpoint.accept(&stop, deadline).unwrap() {
                    loop {
                        assert!(Instant::now() < deadline);
                        match disconnected.read(&mut [0]) {
                            Ok(0) => break,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            result => panic!("disconnected peer was not isolated: {result:?}"),
                        }
                    }
                }
                let mut next = connect_control(&wide, &identity, &stop, deadline).unwrap();
                let mut next_server = endpoint.accept(&stop, deadline).unwrap().unwrap();
                assert_eq!(held.write(b"held").unwrap(), 4);
                assert_eq!(next.write(b"next").unwrap(), 4);
                assert_eq!(receive(&mut held_server, 4), b"held");
                assert_eq!(receive(&mut next_server, 4), b"next");
                assert!(!drain_failed());
            }
        }
    }
}
