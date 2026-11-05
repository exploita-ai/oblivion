//! Desktop overlays own the TTY while the parent keeps draining the Safe.

use oblivion_cli::terminal_overlay::{self, Keys, Page, Screen};
use oblivion_host::{agent, control};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub struct Overlay {
    child: Child,
    _handoff: oblivion_host::native_runtime::ManagerHandoff,
    group: libc::pid_t,
    raw: libc::termios,
    restored: bool,
}

impl Overlay {
    pub fn start(page: Page, safe: &str, saved: libc::termios) -> control::Result<Self> {
        let group = unsafe { libc::tcgetpgrp(0) };
        if group < 0 || group != unsafe { libc::getpgrp() } {
            return Err("The Oblivion terminal must be in the foreground".into());
        }
        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        let launcher = std::env::current_exe()?;
        let manager = launcher
            .parent()
            .ok_or("executable_directory_missing")?
            .join("oblivion-manager");
        let mut command = Command::new(manager);
        command
            .args(["--native-overlay", page.argument(), "--safe", safe])
            .env("OBLIVION_LAUNCHER", &launcher);
        // The parent is already raw. Keep queued bytes intact and request
        // paste framing before OpenTUI takes over the foreground terminal.
        terminal_overlay::begin(&mut std::io::stdout())?;
        std::io::stdout().flush()?;
        let mut handoff = oblivion_host::native_runtime::ManagerHandoff::prepare(&mut command)?;
        // The child claims the foreground before exec. A parent/child pipe gate
        // in pre_exec would deadlock Command::spawn's exec-error handshake.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                if libc::tcsetpgrp(0, libc::getpgrp()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::signal(libc::SIGTTOU, libc::SIG_DFL);
                Ok(())
            });
        }
        match command.spawn() {
            Ok(mut child) => {
                if let Err(error) = handoff.bind(&child) {
                    let _ = child.kill();
                    let _ = child.wait();
                    restore(group, &raw)?;
                    return Err(error);
                }
                Ok(Self { child, _handoff: handoff, group, raw, restored: false })
            },
            Err(error) => {
                restore(group, &raw)?;
                Err(error.into())
            }
        }
    }

    pub fn poll(&mut self) -> control::Result<Option<ExitStatus>> {
        let result = self.child.try_wait()?;
        if result.is_some() && !self.restored {
            restore(self.group, &self.raw)?;
            self.restored = true;
        }
        Ok(result)
    }

    pub fn signal(&self, number: i32) {
        unsafe {
            libc::kill(-(self.child.id() as i32), number);
        }
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            self.signal(libc::SIGTERM);
            let until = Instant::now() + Duration::from_millis(250);
            while Instant::now() < until {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                self.signal(libc::SIGKILL);
                let _ = self.child.wait();
            }
        }
        if !self.restored {
            let _ = restore(self.group, &self.raw);
        }
    }
}

fn restore(group: libc::pid_t, raw: &libc::termios) -> control::Result<()> {
    // The parent is intentionally in the background until this operation.
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    let foreground = unsafe { libc::tcsetpgrp(0, group) };
    let settings = unsafe { libc::tcsetattr(0, libc::TCSANOW, raw) };
    unsafe {
        libc::signal(libc::SIGTTOU, previous);
    }
    if foreground != 0 || settings != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // A failed or killed child may skip its OpenTUI cleanup. Leave a usable
    // terminal even if the guest connection also failed before a repaint.
    terminal_overlay::reset(&mut std::io::stdout())?;
    std::io::stdout().flush()?;
    Ok(())
}

pub fn bridge(
    stream: &mut std::os::unix::net::UnixStream,
    interactive: bool,
    safe: &str,
    saved: libc::termios,
    mut activity: Option<oblivion_host::activity::Reporter>,
) -> control::Result<i32> {
    let mut input = true;
    let mut guard = oblivion_host::terminal_guard::Guard::default();
    let mut keys = Keys::default();
    let mut human = oblivion_host::activity::HumanInput::default();
    let mut viewport = super::size();
    let mut parser = interactive.then(|| {
        let mut parser = terminal_overlay::parser(viewport.rows, viewport.cols);
        parser.enable_synchronized_output();
        parser
    });
    let mut overlay: Option<Overlay> = None;
    loop {
        if let Some(child) = overlay.as_mut() {
            if child.poll()?.is_some() {
                overlay.take();
                restore_screen(parser.as_ref().unwrap())?;
                // Native clients may maintain modes outside VT100's visible
                // cell model. Ask for their ordinary resize redraw as well.
                agent::write_frame(stream, 6, &libc::SIGWINCH.to_be_bytes())?;
            }
        }
        let caught = super::SIGNAL.swap(0, Ordering::Relaxed);
        // A foreground overlay receives the terminal SIGWINCH. Observing its
        // dimensions does not consume its input or count as human activity.
        if interactive && (caught == libc::SIGWINCH || overlay.is_some()) {
            let current = super::size();
            if current.rows != viewport.rows
                || current.cols != viewport.cols
                || caught == libc::SIGWINCH
            {
                viewport = current;
                if let Some(parser) = parser.as_mut() {
                    parser.resize(current.rows, current.cols);
                }
                agent::write_frame(
                    stream,
                    3,
                    &[current.rows.to_be_bytes(), current.cols.to_be_bytes()].concat(),
                )?;
            }
        }
        if caught != 0 && caught != libc::SIGWINCH {
            agent::write_frame(stream, 6, &caught.to_be_bytes())?;
            if let Some(child) = overlay.as_ref() {
                child.signal(caught);
            }
        }
        if overlay.is_none() {
            if human.expire(Instant::now()) {
                if let Some(activity) = activity.as_mut() { activity.touch(Instant::now()) }
            }
            let mut expired = Vec::new();
            keys.expire(&mut expired, Instant::now());
            if !expired.is_empty() {
                agent::write_frame(stream, 0, &expired)?;
            }
        }
        let mut polls = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if input && overlay.is_none() { 0 } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), 2, if keys.waiting() { 20 } else { 100 }) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if polls[0].revents != 0 {
            let (kind, bytes) = agent::read_frame(stream)?;
            let bytes = if interactive && matches!(kind, 1 | 2) {
                guard.filter(&bytes)
            } else {
                bytes
            };
            match kind {
                1 | 2 => {
                    if let Some(parser) = parser.as_mut() {
                        parser.process(&bytes);
                        let mut replies = Vec::new();
                        parser.write_replies(&mut replies)?;
                        if overlay.is_some() && !replies.is_empty() {
                            agent::write_frame(stream, 0, &replies)?;
                        }
                    }
                    if overlay.is_none() {
                        if kind == 1 {
                            std::io::stdout().write_all(&bytes)?;
                            std::io::stdout().flush()?;
                        } else {
                            std::io::stderr().write_all(&bytes)?;
                            std::io::stderr().flush()?;
                        }
                    }
                }
                4 if bytes.len() == 4 => {
                    let code = i32::from_be_bytes(bytes.try_into().unwrap());
                    if overlay.take().is_some() {
                        restore_screen(parser.as_ref().unwrap())?;
                    }
                    return Ok(if code < 0 { 128 - code } else { code });
                }
                _ => return Err("Invalid agent response".into()),
            }
        }
        if polls[1].revents != 0 {
            if interactive {
                // Stop at the host key itself. Subsequent bytes remain queued
                // for the overlay's sole foreground TTY reader.
                let mut available: libc::c_int = 0;
                unsafe {
                    libc::ioctl(0, libc::FIONREAD, &mut available);
                }
                let mut outgoing = Vec::new();
                let mut page = None;
                let mut eof = false;
                let mut touched = false;
                for _ in 0..available.clamp(1, 8192) {
                    let mut byte = [0];
                    // Stdin::read uses a process-global buffer and can read
                    // past this byte, stealing the overlay's queued input.
                    let length = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
                    if length < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(error.into());
                    }
                    if length == 0 {
                        eof = true;
                        break;
                    }
                    touched |= human.feed(byte[0], Instant::now());
                    page = keys.feed(byte[0], &mut outgoing, Instant::now());
                    if page.is_some() {
                        break;
                    }
                }
                if eof {
                    keys.finish(&mut outgoing);
                }
                if touched {
                    if let Some(activity) = activity.as_mut() { activity.touch(Instant::now()) }
                }
                if !outgoing.is_empty() {
                    agent::write_frame(stream, 0, &outgoing)?;
                }
                if eof {
                    input = false;
                    agent::write_frame(stream, 5, &[])?;
                }
                if let Some(page) = page {
                    match Overlay::start(page, safe, saved) {
                        Ok(child) => overlay = Some(child),
                        Err(error) => {
                            restore_screen(parser.as_ref().unwrap())?;
                            eprintln!("\r\nOblivion overlay could not open: {error}");
                        }
                    }
                }
            } else {
                let mut bytes = [0; 8192];
                let length = std::io::stdin().read(&mut bytes)?;
                if length == 0 {
                    input = false;
                    agent::write_frame(stream, 5, &[])?;
                } else {
                    agent::write_frame(stream, 0, &bytes[..length])?;
                }
            }
        }
    }
}

fn restore_screen(parser: &Screen) -> control::Result<()> {
    if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
        return Err("Cannot return input to the agent while the terminal is in the background".into());
    }
    let mut stdout = std::io::stdout().lock();
    terminal_overlay::repaint(parser, &mut stdout)?;
    stdout.flush()?;
    // Anything still queued at the handoff belonged to the host panel, even
    // after a failed launch. Do this after replaying the guest's input modes.
    if unsafe { libc::tcflush(0, libc::TCIFLUSH) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
