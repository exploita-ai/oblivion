#![cfg(target_os = "linux")]

use oblivion_host::display::{peer_uid, receive_terminal, send_terminal};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[test]
fn display_handoff_preserves_the_real_terminal_and_resize() {
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let (client, server) = UnixStream::pair().unwrap();
    assert_eq!(peer_uid(&server).unwrap(), unsafe { libc::geteuid() });
    send_terminal(&client, slave.as_raw_fd()).unwrap();
    let terminal = receive_terminal(&server, unsafe { libc::geteuid() }).unwrap();
    drop(slave);
    assert_ne!(
        unsafe { libc::fcntl(terminal.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let mut size = libc::winsize {
        ws_row: 50,
        ws_col: 160,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) },
        0
    );
    assert_eq!(
        unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCGWINSZ, &mut size) },
        0
    );
    assert_eq!((size.ws_row, size.ws_col), (50, 160));
    let mut terminal = File::from(terminal);
    terminal.write_all(b"terminal output").unwrap();
    let mut text = [0; 15];
    master.read_exact(&mut text).unwrap();
    assert_eq!(&text, b"terminal output");
    master.write_all(b"input\n").unwrap();
    let mut text = [0; 6];
    terminal.read_exact(&mut text).unwrap();
    assert_eq!(&text, b"input\n");
}

#[test]
fn display_handoff_rejects_files_and_missing_descriptors() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let file = File::open("/dev/null").unwrap();
    send_terminal(&client, file.as_raw_fd()).unwrap();
    assert!(receive_terminal(&server, unsafe { libc::geteuid() }).is_err());
    client.write_all(b"T").unwrap();
    assert!(receive_terminal(&server, unsafe { libc::geteuid() }).is_err());
}

#[test]
fn display_handoff_rejects_another_users_terminal() {
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let _master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let (client, server) = UnixStream::pair().unwrap();
    send_terminal(&client, slave.as_raw_fd()).unwrap();
    assert!(receive_terminal(&server, unsafe { libc::geteuid() } + 1).is_err());
}
