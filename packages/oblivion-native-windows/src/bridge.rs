//! Hyper-V sockets address the actual HCS runtime GUID, never a guessed VM ID.
//! All transport I/O is nonblocking; only bounded event waits observe stop.
use crate::private::{self, Pipe};
use crate::{Error, Result};
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Networking::WinSock::{
    AF_HYPERV, FD_CLOSE, FD_CONNECT, FD_CONNECT_BIT, FD_READ, FD_WRITE, INVALID_SOCKET, SD_BOTH,
    SOCK_STREAM, SOCKADDR, SOCKET, SOCKET_ERROR, WSA_FLAG_NO_HANDLE_INHERIT, WSACleanup, WSADATA,
    WSAEINTR, WSAEWOULDBLOCK, WSAEnumNetworkEvents, WSAEventSelect, WSAGetLastError,
    WSANETWORKEVENTS, WSASocketW, WSAStartup, closesocket, connect, recv, send, shutdown,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::core::GUID;
use zeroize::Zeroizing;

// hvsocket.h is absent from windows-sys metadata. ABI/constants from Microsoft's
// SDK: github.com/microsoft/win32metadata/.../shared/hvsocket.h.
const HV_PROTOCOL_RAW: i32 = 1;
#[repr(C)]
struct Address {
    family: u16,
    reserved: u16,
    vm: GUID,
    service: GUID,
}

struct Winsock;
impl Winsock {
    fn new() -> Result<Self> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
            return Err(Error("hvsocket_unavailable"));
        }
        if data.wVersion != 0x0202 {
            unsafe {
                WSACleanup();
            }
            return Err(Error("hvsocket_unavailable"));
        }
        Ok(Self)
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

pub struct Guest {
    socket: SOCKET,
    event: OwnedHandle,
    _winsock: Winsock,
}

pub fn connect_guest(vm: &GUID, port: u32, stop: &AtomicBool, deadline: Instant) -> Result<Guest> {
    if port != 4050 || vm.data1 == 0 && vm.data2 == 0 && vm.data3 == 0 && vm.data4 == [0; 8] {
        return Err(Error("invalid_guest_control_endpoint"));
    }
    if stop.load(Ordering::Acquire) || private::drain_failed() {
        return Err(Error("guest_control_cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error("guest_control_timeout"));
    }
    let winsock = Winsock::new()?;
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(Error("hvsocket_unavailable"));
    }
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let socket = unsafe {
        WSASocketW(
            AF_HYPERV as i32,
            SOCK_STREAM,
            HV_PROTOCOL_RAW,
            null(),
            0,
            WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket == INVALID_SOCKET {
        return Err(Error("hvsocket_unavailable"));
    }
    let mut guest = Guest {
        socket,
        event,
        _winsock: winsock,
    };
    // WSAEventSelect also makes the socket nonblocking.
    if unsafe {
        WSAEventSelect(
            socket,
            guest.event.as_raw_handle() as isize,
            (FD_CONNECT | FD_CLOSE) as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(Error("guest_control_unavailable"));
    }
    let address = Address {
        family: AF_HYPERV,
        reserved: 0,
        vm: *vm,
        service: GUID {
            data1: port,
            data2: 0xfacb,
            data3: 0x11e6,
            data4: [0xbd, 0x58, 0x64, 0, 0x6a, 0x79, 0x86, 0xd3],
        },
    };
    if unsafe {
        connect(
            socket,
            (&address as *const Address).cast::<SOCKADDR>(),
            std::mem::size_of::<Address>() as i32,
        )
    } == SOCKET_ERROR
    {
        if unsafe { WSAGetLastError() } != WSAEWOULDBLOCK {
            return Err(Error("guest_control_unavailable"));
        }
        loop {
            if stop.load(Ordering::Acquire) || private::drain_failed() {
                return Err(Error("guest_control_cancelled"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error("guest_control_timeout"));
            }
            let waited = unsafe {
                WaitForSingleObject(
                    guest.event.as_raw_handle(),
                    remaining.as_millis().min(100).max(1) as u32,
                )
            };
            if waited == WAIT_FAILED {
                return Err(Error("guest_control_unavailable"));
            }
            if waited != WAIT_OBJECT_0 {
                continue;
            }
            let mut events = WSANETWORKEVENTS::default();
            if unsafe {
                WSAEnumNetworkEvents(socket, guest.event.as_raw_handle() as isize, &mut events)
            } == SOCKET_ERROR
            {
                return Err(Error("guest_control_unavailable"));
            }
            if events.lNetworkEvents & FD_CONNECT as i32 != 0 {
                if events.iErrorCode[FD_CONNECT_BIT as usize] != 0 {
                    return Err(Error("guest_control_unavailable"));
                }
                break;
            }
            if events.lNetworkEvents & FD_CLOSE as i32 != 0 {
                return Err(Error("guest_control_unavailable"));
            }
        }
    }
    guest.interest((FD_READ | FD_WRITE | FD_CLOSE) as i32)?;
    if stop.load(Ordering::Acquire) || private::drain_failed() {
        return Err(Error("guest_control_cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error("guest_control_timeout"));
    }
    Ok(guest)
}

impl Guest {
    fn interest(&mut self, interest: i32) -> Result<()> {
        let mut previous = WSANETWORKEVENTS::default();
        if unsafe {
            WSAEnumNetworkEvents(
                self.socket,
                self.event.as_raw_handle() as isize,
                &mut previous,
            )
        } == SOCKET_ERROR
            || unsafe { WSAEventSelect(self.socket, self.event.as_raw_handle() as isize, interest) }
                == SOCKET_ERROR
        {
            return Err(Error("guest_control_unavailable"));
        }
        Ok(())
    }

    fn close(&mut self) {
        unsafe {
            shutdown(self.socket, SD_BOTH);
        }
    }
}

impl Read for Guest {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let count = unsafe {
            recv(
                self.socket,
                output.as_mut_ptr(),
                output.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count == SOCKET_ERROR {
            return Err(socket_error());
        }
        Ok(count as usize)
    }
}
impl Write for Guest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = unsafe {
            send(
                self.socket,
                bytes.as_ptr(),
                bytes.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if count == SOCKET_ERROR {
            return Err(socket_error());
        }
        Ok(count as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Guest {
    fn drop(&mut self) {
        self.close();
        unsafe {
            closesocket(self.socket);
        }
    }
}

fn socket_error() -> io::Error {
    match unsafe { WSAGetLastError() } {
        WSAEWOULDBLOCK => io::Error::from(io::ErrorKind::WouldBlock),
        WSAEINTR => io::Error::from(io::ErrorKind::Interrupted),
        _ => io::Error::other("guest_control_unavailable"),
    }
}

struct Pending {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}
impl Pending {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; private::BUFFER]),
            start: 0,
            end: 0,
        }
    }
    fn readable(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }
    fn writable(&mut self) -> &mut [u8] {
        if self.end == self.bytes.len() && self.start != 0 {
            self.bytes.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.bytes[self.end..]
    }
    fn consume(&mut self, length: usize) {
        self.start += length;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }
}

/// Native responses, Exit and file completion are framed. After guest EOF the
/// client consumes those bytes and closes its pipe; it must not wait for an
/// unframed EOF first. DisconnectNamedPipe would discard unread buffered bytes,
/// so final drain requires that client close, bounded to two seconds.
/// Native stdin EOF remains framed; neither transport is half-closed.
pub fn duplex(mut local: Pipe, mut guest: Guest, stop: Arc<AtomicBool>) -> Result<()> {
    let mut to_guest = Pending::new();
    let mut to_local = Pending::new();
    let mut guest_closed = false;
    let mut flush_deadline = None;
    let mut discarded = 0;
    let result = (|| {
        while !stop.load(Ordering::Acquire) && !private::drain_failed() {
            if flush_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Error("bridge_final_drain_unconfirmed"));
            }
            let mut progressed = false;
            if !guest_closed && !to_guest.writable().is_empty() {
                match local.read(to_guest.writable()) {
                    Ok(0) => return Ok(()),
                    Ok(length) => {
                        to_guest.end += length;
                        progressed = true;
                    }
                    Err(error) if retry(&error) => {}
                    Err(_) => return Err(Error("bridge_failed")),
                }
            }
            if !guest_closed && !to_local.writable().is_empty() {
                match guest.read(to_local.writable()) {
                    Ok(0) => {
                        guest_closed = true;
                        guest.close();
                        to_guest.consume(to_guest.readable().len());
                        flush_deadline = Some(Instant::now() + Duration::from_secs(2));
                    }
                    Ok(length) => {
                        to_local.end += length;
                        progressed = true;
                    }
                    Err(error) if retry(&error) => {}
                    Err(_) => return Err(Error("bridge_failed")),
                }
            }
            if !guest_closed && !to_guest.readable().is_empty() {
                match guest.write(to_guest.readable()) {
                    Ok(0) => return Ok(()),
                    Ok(length) => {
                        to_guest.consume(length);
                        progressed = true;
                    }
                    Err(error) if retry(&error) => {}
                    Err(_) => return Err(Error("bridge_failed")),
                }
            }
            if !to_local.readable().is_empty() {
                match local.write(to_local.readable()) {
                    Ok(0) => return Ok(()),
                    Ok(length) => {
                        to_local.consume(length);
                        progressed = true;
                    }
                    Err(error) if retry(&error) => {}
                    Err(_) => return Err(Error("bridge_failed")),
                }
            }
            let flushed = match local.flush() {
                Ok(()) => true,
                Err(error) if retry(&error) => false,
                Err(_) => return Err(Error("bridge_failed")),
            };
            if guest_closed && to_local.readable().is_empty() && flushed {
                match local.read(to_guest.writable()) {
                    Ok(0) => return Ok(()),
                    Ok(length) => {
                        discarded += length;
                        if discarded > private::BUFFER {
                            return Err(Error("bridge_final_drain_unconfirmed"));
                        }
                        progressed = true;
                    }
                    Err(error) if retry(&error) => {}
                    Err(_) => return Err(Error("bridge_failed")),
                }
            }
            if progressed {
                continue;
            }
            let mut handles: Vec<HANDLE> = Vec::with_capacity(3);
            local.events(
                &mut handles,
                (!guest_closed && !to_guest.writable().is_empty())
                    || (guest_closed && to_local.readable().is_empty() && flushed),
            );
            if !guest_closed && (!to_local.writable().is_empty() || !to_guest.readable().is_empty())
            {
                guest.interest(
                    (FD_CLOSE
                        | if to_local.writable().is_empty() {
                            0
                        } else {
                            FD_READ
                        }
                        | if to_guest.readable().is_empty() {
                            0
                        } else {
                            FD_WRITE
                        }) as i32,
                )?;
                handles.push(guest.event.as_raw_handle());
            } else {
                guest.interest(0)?;
            }
            if handles.is_empty() {
                return Err(Error("bridge_failed"));
            }
            if unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 100) }
                == WAIT_FAILED
            {
                return Err(Error("bridge_failed"));
            }
        }
        if private::drain_failed() {
            return Err(Error("private_pipe_cancellation_failed"));
        }
        Ok(())
    })();
    guest.close();
    let closed = local
        .close()
        .map_err(|_| Error("private_pipe_cancellation_failed"));
    result.and(closed)
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::{Guest, Winsock, duplex};
    use crate::{Error, private};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawSocket, OwnedHandle};
    use std::ptr::null;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use windows_sys::Win32::Networking::WinSock::{
        FD_CLOSE, FD_READ, FD_WRITE, SOCKET, SOCKET_ERROR, WSAEventSelect,
    };
    use windows_sys::Win32::System::Threading::CreateEventW;

    fn guest(stream: TcpStream) -> Guest {
        let winsock = Winsock::new().unwrap();
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let socket = stream.into_raw_socket() as SOCKET;
        assert_ne!(
            unsafe {
                WSAEventSelect(
                    socket,
                    event.as_raw_handle() as isize,
                    (FD_READ | FD_WRITE | FD_CLOSE) as i32,
                )
            },
            SOCKET_ERROR
        );
        Guest {
            socket,
            event,
            _winsock: winsock,
        }
    }

    #[test]
    fn actual_bridge_drains_final_bytes_across_full_buffers_before_pipe_eof() {
        let (_endpoint, server, mut client) =
            private::tests::connected_pair(private::Purpose::Control);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let (sender, done) = std::sync::mpsc::sync_channel(1);
        let bridge = std::thread::spawn(move || {
            sender.send(duplex(server, guest(socket), stopped)).unwrap();
        });
        let expected = (0..private::BUFFER * 4 + 379)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        peer.write_all(&expected).unwrap();
        peer.shutdown(Shutdown::Both).unwrap();
        // Let the real named-pipe writer apply backpressure before reading.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            private::tests::receive(&mut client, expected.len()),
            expected
        );
        drop(client);
        assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
        bridge.join().unwrap();
        assert!(!private::drain_failed());
    }

    #[test]
    fn a_client_which_does_not_close_cannot_confirm_final_drain() {
        let (_endpoint, server, mut client) =
            private::tests::connected_pair(private::Purpose::Control);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, done) = std::sync::mpsc::sync_channel(1);
        let bridge = std::thread::spawn(move || {
            sender.send(duplex(server, guest(socket), stop)).unwrap();
        });
        peer.write_all(b"exit").unwrap();
        peer.shutdown(Shutdown::Both).unwrap();
        assert_eq!(private::tests::receive(&mut client, 4), b"exit");
        assert_eq!(
            done.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(Error("bridge_final_drain_unconfirmed"))
        );
        bridge.join().unwrap();
        assert!(!private::drain_failed());
    }

    #[test]
    fn local_eof_and_explicit_stop_revoke_both_transport_directions() {
        for cancelled in [false, true] {
            let (_endpoint, server, client) =
                private::tests::connected_pair(private::Purpose::Control);
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = Arc::clone(&stop);
            let (sender, done) = std::sync::mpsc::sync_channel(1);
            let bridge = std::thread::spawn(move || {
                sender.send(duplex(server, guest(socket), stopped)).unwrap();
            });
            if cancelled {
                stop.store(true, Ordering::Release);
            } else {
                drop(client);
            }
            assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
            bridge.join().unwrap();
            assert_eq!(peer.read(&mut [0; 8]).unwrap(), 0);
            assert!(!private::drain_failed());
        }
    }
}
