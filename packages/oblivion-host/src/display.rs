//! Delegate Foot's terminal, never its device access or Wayland connection, to
//! the independently sandboxed manager. Terminal bytes do not cross this socket.
use crate::control::{Result, protect};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DISPLAY_UID: u32 = 1104;
const MANAGER_UID: u32 = 1000;

pub fn run() -> Result<()> {
    protect()?;
    match std::env::args().nth(1).as_deref() {
        Some("--client") if unsafe { libc::geteuid() } == DISPLAY_UID => client(),
        Some("--launcher") if unsafe { libc::geteuid() } == MANAGER_UID => manager(),
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
    let (socket, _) = listener.accept()?;
    drop(listener);
    if peer_uid(&socket)? != DISPLAY_UID {
        return Err("untrusted_display".into());
    }
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let tty = receive_terminal(&socket, DISPLAY_UID)?;
    socket.set_read_timeout(None)?;
    serve_terminal(
        socket,
        tty,
        Command::new("/usr/lib/oblivion/desktop/bin/oblivion"),
    )
}

/// Keep the delegated PTY open after the launcher exits. Only a physical retry
/// starts another launcher; diagnostics remain terminal bytes, never a log file.
pub fn serve_terminal(socket: UnixStream, tty: OwnedFd, mut command: Command) -> Result<()> {
    let terminal = Terminal::new(tty)?;
    command
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .stdin(Stdio::from(terminal.file.try_clone()?))
        .stdout(Stdio::from(terminal.file.try_clone()?))
        .stderr(Stdio::from(terminal.file.try_clone()?));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    loop {
        let successful = match command.spawn() {
            Ok(child) => {
                let mut child = Launcher(child);
                loop {
                    if let Some(status) = child.0.try_wait()? {
                        break status.success();
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
                        return Err(error.into());
                    }
                    if event.revents != 0 {
                        // Losing the display revokes its launcher. The launcher
                        // lifecycle owns controller/Safe cleanup independently.
                        unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) };
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while child.0.try_wait()?.is_none() && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        return Ok(());
                    }
                }
            }
            Err(_) => {
                (&terminal.file).write_all(b"\r\nOblivion: launcher_unavailable\r\n")?;
                false
            }
        };
        if !terminal.retry(&socket, successful)? {
            return Ok(());
        }
    }
}

struct Launcher(Child);
impl Drop for Launcher {
    fn drop(&mut self) {
        // Child::kill respects an already reaped child; never target a PID
        // recovered from a file or another launcher instance.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Terminal {
    file: File,
    original: libc::termios,
}

impl Terminal {
    fn new(tty: OwnedFd) -> Result<Self> {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(tty.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            file: File::from(tty),
            original: unsafe { original.assume_init() },
        })
    }

    fn retry(&self, socket: &UnixStream, successful: bool) -> Result<bool> {
        let mut raw = self.original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &raw) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // A crashed TUI may leave its alternate screen or cursor hidden.
        (&self.file).write_all(if successful {
            b"\x1b[?1049l\x1b[?25h\r\nOblivion closed.\r\n"
        } else {
            b"\x1b[?1049l\x1b[?25h\r\nOblivion could not start or stopped unexpectedly.\r\n"
        })?;
        (&self.file).write_all(b"Press R to retry, or Ctrl+Q to pause.\r\nDebian network: Ctrl+Alt+F2; keyboard: Ctrl+Alt+F3; time zone: Ctrl+Alt+F4.\r\n")?;
        loop {
            let mut events = [
                libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if unsafe { libc::poll(events.as_mut_ptr(), 2, -1) } < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if events[0].revents != 0
                || events[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
            {
                return Ok(false);
            }
            if events[1].revents & libc::POLLIN == 0 {
                continue;
            }
            let mut byte = [0];
            if (&self.file).read(&mut byte)? == 0 {
                return Ok(false);
            }
            match byte[0] {
                b'r' | b'R' => {
                    if unsafe {
                        libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original)
                    } != 0
                    {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    return Ok(true);
                }
                b'q' | b'Q' | 0x03 | 0x11 => {
                    (&self.file).write_all(b"\r\nOblivion is paused. Press R to start again; the Debian consoles remain available.\r\n")?;
                }
                _ => {}
            }
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original) };
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
