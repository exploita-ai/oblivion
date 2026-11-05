#![cfg(target_os = "linux")]

use oblivion_host::display::{peer_uid, receive_terminal, send_terminal, serve_terminal};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

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

fn terminal_pair() -> (File, OwnedFd) {
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
    unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

fn read_until(master: &mut File, expected: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    while !String::from_utf8_lossy(&output).contains(expected) {
        assert!(
            Instant::now() < deadline,
            "terminal did not show {expected}: {}",
            String::from_utf8_lossy(&output)
        );
        let mut event = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut event, 1, 100) } >= 0);
        if event.revents & libc::POLLIN == 0 {
            continue;
        }
        let mut bytes = [0; 1024];
        let count = master.read(&mut bytes).unwrap();
        assert_ne!(count, 0);
        output.extend_from_slice(&bytes[..count]);
    }
    String::from_utf8(output).unwrap()
}

#[test]
fn launcher_failure_stderr_stays_visible_until_physical_retry() {
    let (mut master, terminal) = terminal_pair();
    let restored = terminal.try_clone().unwrap();
    let mut initial = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(restored.as_raw_fd(), initial.as_mut_ptr()) },
        0
    );
    let initial = unsafe { initial.assume_init() };
    let (client, server) = UnixStream::pair().unwrap();
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "printf 'PRE_TUI_FAILURE\\n' >&2; stty -echo -icanon; exit 7",
    ]);
    let worker = std::thread::spawn(move || serve_terminal(server, terminal, command).unwrap());

    let output = read_until(&mut master, "time zone: Ctrl+Alt+F4.");
    assert!(output.contains("PRE_TUI_FAILURE"));
    assert!(output.contains("Oblivion could not start"));
    assert!(
        !worker.is_finished(),
        "failure must retain the display instead of returning to its restart unit"
    );
    let mut event = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut event, 1, 350) },
        0,
        "no launcher may retry on a timer"
    );

    master.write_all(&[0x11]).unwrap();
    read_until(&mut master, "Oblivion is paused.");
    assert!(!worker.is_finished());
    master.write_all(b"r").unwrap();
    let output = read_until(&mut master, "time zone: Ctrl+Alt+F4.");
    assert!(
        output.contains("PRE_TUI_FAILURE"),
        "R must execute the actual child again"
    );

    drop(client);
    worker.join().unwrap();
    let mut final_mode = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(restored.as_raw_fd(), final_mode.as_mut_ptr()) },
        0
    );
    assert_eq!(unsafe { final_mode.assume_init() }.c_lflag, initial.c_lflag);
}

#[test]
fn display_disconnect_reaps_the_owned_launcher() {
    let (mut master, terminal) = terminal_pair();
    let (client, server) = UnixStream::pair().unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'PID=%s\\n' $$; exec /bin/sleep 60"]);
    let worker = std::thread::spawn(move || serve_terminal(server, terminal, command).unwrap());
    let output = read_until(&mut master, "\n");
    let pid = output
        .trim()
        .strip_prefix("PID=")
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
    drop(client);
    worker.join().unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn successful_manager_exit_waits_for_retry_instead_of_restarting() {
    let (mut master, terminal) = terminal_pair();
    let (client, server) = UnixStream::pair().unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 0"]);
    let worker = std::thread::spawn(move || serve_terminal(server, terminal, command).unwrap());
    let output = read_until(&mut master, "time zone: Ctrl+Alt+F4.");
    assert!(output.contains("Oblivion closed."));
    assert!(!worker.is_finished());
    drop(client);
    worker.join().unwrap();
}
