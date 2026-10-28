//! A bounded, sanitized guest viewport for the OpenTUI host shell.
use crate::{control::Result, terminal};
use serde::Deserialize;
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const FRAME_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / 60);

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Input { data: Vec<u8> },
    Resize { cols: u16, rows: u16 },
}

pub fn command(bytes: &[u8]) -> Result<Command> {
    let command: Command = serde_json::from_slice(bytes)?;
    match &command {
        Command::Input { data } if data.len() <= 4096 => Ok(command),
        Command::Resize {
            cols: 24..=512,
            rows: 5..=297,
        } => Ok(command),
        _ => Err("invalid_console_message".into()),
    }
}

// Reconstruct only visible cells and a small allowlist of terminal modes. Never
// forward guest OSC/DCS, titles, clipboard, hyperlinks or resize commands.
pub fn frame(screen: &vt100::Screen) -> String {
    // vt100 serializes its parsed cells and known input modes; it never replays
    // raw OSC/DCS. Preserve mouse reporting so OpenCode owns transcript scroll.
    screen.state_formatted()
}

pub fn difference(screen: &vt100::Screen, previous: &vt100::Screen) -> String {
    screen.state_diff(previous)
}

pub fn bridge(stream: UnixStream) -> Result<()> {
    viewport(stream, true)
}

pub fn bridge_terminal(stream: UnixStream) -> Result<()> {
    viewport(stream, false)
}

fn viewport(mut stream: UnixStream, chat: bool) -> Result<()> {
    stream.set_nonblocking(true)?;
    let mut parser = terminal::parser(24, 80);
    // The guest brackets complete updates with DEC mode 2026. Publishing a
    // partial update makes scrolling visibly repaint one line at a time.
    parser.callbacks_mut().enable_synchronized_output();
    let mut pending = Zeroizing::new(Vec::new());
    let mut bytes = Zeroizing::new([0u8; 8192]);
    let mut output = std::io::stdout().lock();
    let mut initialized = false;
    let mut terminal_ready = false;
    let mut previous = None;
    let mut changed = false;
    let mut painted = Instant::now();
    loop {
        let mut poll = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Match OpenCode's 60 Hz target. Wait only until a pending frame is due;
        // a fixed full-interval sleep adds another frame of lag after input.
        // With no pending frame, input or guest output wakes us directly.
        let timeout = if !changed || !initialized {
            -1
        } else if parser.callbacks().synchronized(Instant::now()) {
            FRAME_INTERVAL.as_micros().div_ceil(1000) as i32
        } else {
            FRAME_INTERVAL
                .saturating_sub(painted.elapsed())
                .as_micros()
                .div_ceil(1000) as i32
        };
        if unsafe { libc::poll(poll.as_mut_ptr(), 2, timeout) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if poll[0].revents != 0 {
            let size = std::io::stdin().read(&mut *bytes)?;
            if size == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&bytes[..size]);
            while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                match command(&pending[..end])? {
                    Command::Input { data } => stream.write_all(&Zeroizing::new(data))?,
                    Command::Resize { cols, rows } => {
                        parser.screen_mut().set_size(
                            NonZeroU16::new(rows).unwrap(),
                            NonZeroU16::new(cols).unwrap(),
                        );
                        stream.write_all(format!("\x1b[8;{rows};{cols}t").as_bytes())?;
                        changed = true;
                        initialized = true;
                        previous = None;
                    }
                }
                pending.drain(..=end);
            }
            if pending.len() > 24576 {
                return Err("console_message_too_large".into());
            }
        }
        // Drain a bounded batch before publishing; hidden views also consume it.
        if poll[1].revents != 0 {
            for _ in 0..8 {
                match stream.read(&mut *bytes) {
                    Ok(0) => return Err("console_closed".into()),
                    Ok(size) => {
                        parser.process(&bytes[..size]);
                        changed = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if initialized && parser.callbacks_mut().take_ready() {
                let (rows, cols) = parser.screen().size();
                stream.write_all(format!("\x1b[8;{rows};{cols}t").as_bytes())?;
            }
            if let Some(status) = parser.callbacks_mut().take_startup().filter(|_| chat) {
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"type":"startup", "status":status})
                )?;
                output.flush()?;
            }
            // Shell output is untrusted. It may draw cells but cannot request
            // host navigation, close a volume or acknowledge chat readiness.
            if let Some(action) = parser.callbacks_mut().take_request().filter(|_| chat) {
                let action = match action {
                    terminal::Action::New => "new",
                    terminal::Action::Sessions => "sessions",
                    terminal::Action::Close => "close",
                };
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"type":"request", "action":action})
                )?;
            }
            parser.callbacks_mut().write_replies(&mut stream)?;
        }
        if changed
            && initialized
            && !parser.callbacks().synchronized(Instant::now())
            && (previous.is_none() || painted.elapsed() >= FRAME_INTERVAL)
        {
            if !chat && !terminal_ready && !parser.screen().contents().trim().is_empty() {
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"type":"startup", "status":"started"})
                )?;
                terminal_ready = true;
            }
            let (rows, cols) = parser.screen().size();
            let full = previous.is_none();
            let data = previous.as_ref().map_or_else(
                || frame(parser.screen()),
                |screen| difference(parser.screen(), screen),
            );
            if full || !data.is_empty() {
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"type":"frame", "full":full, "cols":cols.get(), "rows":rows.get(), "data":data})
                )?;
            }
            previous = Some(parser.screen().clone());
            changed = false;
            painted = Instant::now();
        }
        output.flush()?;
    }
}
