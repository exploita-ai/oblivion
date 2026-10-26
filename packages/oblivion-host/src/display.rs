//! Delegate Foot's terminal, never its device access or Wayland connection, to
//! the independently sandboxed manager. Terminal bytes do not cross this socket.
use crate::control::{Result, protect};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DISPLAY_UID: u32 = 1104;
const MANAGER_UID: u32 = 1000;

pub fn run() -> Result<()> {
    protect()?;
    match std::env::args().nth(1).as_deref() {
        Some("--client") if unsafe { libc::geteuid() } == DISPLAY_UID => client(),
        Some("--manager") if unsafe { libc::geteuid() } == MANAGER_UID => manager(),
        _ => Err("invalid_display_role".into()),
    }
}

fn client() -> Result<()> {
    // /dev/tty is a root-owned alias. Transfer Foot's actual PTY descriptor so
    // the manager can verify its owner without exposing the display's /dev.
    let tty = std::io::stdin().as_fd().try_clone_to_owned()?;
    let mut socket = UnixStream::connect("/run/oblivion-terminal.sock")?;
    // The listener is created by systemd, before the unprivileged manager starts.
    if peer_uid(&socket)? != 0 {
        return Err("untrusted_terminal_listener".into());
    }
    unsafe {
        // Hand over the controlling terminal so the manager receives SIGWINCH
        // directly. There is no byte relay, redraw buffer or terminal recording.
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        if libc::ioctl(tty.as_raw_fd(), libc::TIOCNOTTY) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    send_terminal(&socket, tty.as_raw_fd())?;
    let mut result = [0];
    socket.read_exact(&mut result)?;
    if result != [0] {
        return Err("manager_exited".into());
    }
    Ok(())
}

fn manager() -> Result<()> {
    if std::env::var("LISTEN_PID")?.parse::<u32>()? != std::process::id()
        || std::env::var("LISTEN_FDS")? != "1"
    {
        return Err("terminal_socket_activation_required".into());
    }
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    let (mut socket, _) = listener.accept()?;
    drop(listener);
    if peer_uid(&socket)? != DISPLAY_UID {
        return Err("untrusted_display".into());
    }
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let tty = receive_terminal(&socket, DISPLAY_UID)?;
    socket.set_read_timeout(None)?;
    let mut command = Command::new("/usr/bin/oblivion-manager");
    command
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .stdin(Stdio::from(tty.try_clone()?))
        .stdout(Stdio::from(tty))
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            socket.write_all(&[u8::from(!status.success())])?;
            return Ok(());
        }
        let mut event = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut event, 1, 250) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            child.kill()?;
            child.wait()?;
            return Err(error.into());
        }
        if event.revents != 0 {
            // Closing the display closes the trusted UI and invokes the unit's
            // existing recovery/lock operation, even if the PTY survives briefly.
            unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(5);
            while child.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return Ok(());
        }
    }
}

pub fn peer_uid(socket: &UnixStream) -> Result<u32> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { credentials.assume_init().uid })
}

pub fn send_terminal(socket: &UnixStream, fd: i32) -> Result<()> {
    let mut marker = b'T';
    let mut data = libc::iovec {
        iov_base: (&mut marker as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(4) as usize };
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
        if libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

pub fn receive_terminal(socket: &UnixStream, owner: u32) -> Result<OwnedFd> {
    let mut marker = 0u8;
    let mut data = libc::iovec {
        iov_base: (&mut marker as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let size = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if size < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut descriptors = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*header).cmsg_len - libc::CMSG_LEN(0) as usize) / 4;
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<i32>().add(index),
                    )));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if size != 1
        || marker != b'T'
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || descriptors.len() != 1
    {
        return Err("invalid_terminal_transfer".into());
    }
    let fd = descriptors.pop().unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    unsafe {
        if libc::isatty(fd.as_raw_fd()) != 1
            || libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) != 0
            || stat.assume_init().st_uid != owner
        {
            return Err("invalid_display_terminal".into());
        }
    }
    Ok(fd)
}
