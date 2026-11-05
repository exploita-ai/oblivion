//! Desktop overlays own the TTY while the parent keeps draining the Safe.

use oblivion_cli::terminal_overlay::{self, Chrome, Keys, Page};
use oblivion_host::{agent, control};
use std::io::{self, Read, Write};
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
        let launcher = oblivion_host::desktop_bundle::launcher_path()?;
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

#[derive(Debug)]
pub struct AgentDisconnected(io::Error);

impl std::fmt::Display for AgentDisconnected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for AgentDisconnected {}

fn agent_channel<T>(result: control::Result<T>) -> control::Result<T> {
    result.map_err(|error| -> Box<dyn std::error::Error> {
        match error.downcast::<io::Error>() {
            Ok(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => {
                AgentDisconnected(*error).into()
            }
            Ok(error) => error,
            Err(error) => error,
        }
    })
}

pub fn bridge(
    stream: &mut std::os::unix::net::UnixStream,
    viewport: Option<agent::Size>,
    safe: &str,
    name: &str,
    saved: libc::termios,
    activity: Option<oblivion_host::activity::Reporter>,
) -> control::Result<i32> {
    let mut chrome = viewport.map(|size| Chrome::new(size, safe, name));
    let result = forward(stream, viewport, safe, saved, activity, chrome.as_mut());
    if let Some(chrome) = chrome.as_mut() {
        chrome.finish(&mut std::io::stdout())?;
    }
    result
}

fn forward(
    stream: &mut std::os::unix::net::UnixStream,
    mut viewport: Option<agent::Size>,
    safe: &str,
    saved: libc::termios,
    mut activity: Option<oblivion_host::activity::Reporter>,
    mut chrome: Option<&mut Chrome>,
) -> control::Result<i32> {
    let interactive = viewport.is_some();
    let mut input = true;
    let mut keys = Keys::default();
    keys.set_viewport(viewport);
    let mut human = oblivion_host::activity::HumanInput::default();
    let mut overlay: Option<Overlay> = None;
    loop {
        if let Some(child) = overlay.as_mut() {
            if child.poll()?.is_some() {
                overlay.take();
                flush_panel_input()?;
                agent_channel(agent::write_frame(stream, 6, &libc::SIGWINCH.to_be_bytes()))?;
            }
        }
        let caught = super::SIGNAL.swap(0, Ordering::Relaxed);
        if let Some(chrome) = chrome.as_deref_mut() {
            // The overlay may receive SIGWINCH instead of the parent.
            let current = super::size();
            if Some(current) != viewport {
                viewport = Some(current);
                keys.set_viewport(viewport);
                chrome.resize(current);
                let guest = terminal_overlay::guest_size(current);
                agent_channel(agent::write_frame(
                    stream,
                    3,
                    &[guest.rows.to_be_bytes(), guest.cols.to_be_bytes()].concat(),
                ))?;
            }
            if overlay.is_none() {
                chrome.paint(&mut std::io::stdout(), Instant::now())?;
            }
        }
        if caught != 0 && caught != libc::SIGWINCH {
            agent_channel(agent::write_frame(stream, 6, &caught.to_be_bytes()))?;
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
                agent_channel(agent::write_frame(stream, 0, &expired))?;
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
        let timeout = if overlay.is_none() && chrome.as_deref().is_some_and(Chrome::has_pending_frame) {
            16
        } else if keys.waiting() {
            20
        } else {
            100
        };
        if unsafe { libc::poll(polls.as_mut_ptr(), 2, timeout) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if polls[0].revents != 0 {
            let (kind, bytes) = agent_channel(agent::read_frame(stream))?;
            match kind {
                1 | 2 => {
                    if let Some(chrome) = chrome.as_deref_mut() {
                        chrome.process(&bytes);
                        keys.set_mouse_utf8(chrome.mouse_utf8());
                        let mut replies = Vec::new();
                        chrome.write_replies(&mut replies)?;
                        if !replies.is_empty() {
                            agent_channel(agent::write_frame(stream, 0, &replies))?;
                        }
                    } else if kind == 1 {
                        std::io::stdout().write_all(&bytes)?;
                        std::io::stdout().flush()?;
                    } else {
                        std::io::stderr().write_all(&bytes)?;
                        std::io::stderr().flush()?;
                    }
                }
                4 if bytes.len() == 4 => {
                    let code = i32::from_be_bytes(bytes.try_into().unwrap());
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
                    if let Some(chrome) = chrome.as_deref_mut() {
                        chrome.user_input();
                    }
                    if let Some(activity) = activity.as_mut() { activity.touch(Instant::now()) }
                }
                if !outgoing.is_empty() {
                    agent_channel(agent::write_frame(stream, 0, &outgoing))?;
                }
                if eof {
                    input = false;
                    agent_channel(agent::write_frame(stream, 5, &[]))?;
                }
                if let Some(page) = page {
                    if let Some(chrome) = chrome.as_deref_mut() {
                        chrome.suspend(&mut std::io::stdout())?;
                    }
                    match Overlay::start(page, safe, saved) {
                        Ok(child) => overlay = Some(child),
                        Err(error) => {
                            flush_panel_input()?;
                            eprintln!("\r\nOblivion overlay could not open: {error}");
                        }
                    }
                }
            } else {
                let mut bytes = [0; 8192];
                let length = std::io::stdin().read(&mut bytes)?;
                if length == 0 {
                    input = false;
                    agent_channel(agent::write_frame(stream, 5, &[]))?;
                } else {
                    agent_channel(agent::write_frame(stream, 0, &bytes[..length]))?;
                }
            }
        }
    }
}

fn flush_panel_input() -> control::Result<()> {
    if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
        return Err("Cannot return input to the agent while the terminal is in the background".into());
    }
    // Anything still queued at the handoff belonged to the host panel, even
    // after a failed launch.
    if unsafe { libc::tcflush(0, libc::TCIFLUSH) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
