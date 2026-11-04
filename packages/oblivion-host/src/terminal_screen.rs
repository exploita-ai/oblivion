//! Bounded VT screen state and terminal replies for native-agent overlays.
use std::io::Write;
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Replies {
    bytes: Vec<u8>,
    synchronized_output: bool,
    synchronized_since: Option<Instant>,
}

impl Replies {
    pub fn enable_synchronized_output(&mut self) {
        self.synchronized_output = true;
    }

    pub fn synchronized(&self, now: Instant) -> bool {
        self.synchronized_since
            .is_some_and(|started| now.saturating_duration_since(started) < Duration::from_secs(1))
    }

    pub fn write_replies(&mut self, stream: &mut impl Write) -> std::io::Result<()> {
        stream.write_all(&self.bytes)?;
        self.bytes.clear();
        Ok(())
    }
}

impl vt100::Callbacks for Replies {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        first: Option<u8>,
        second: Option<u8>,
        params: &[&[u16]],
        command: char,
    ) {
        if self.synchronized_output && first == Some(b'?') && params == [&[2026][..]] {
            match (second, command) {
                (None, 'h') => {
                    self.synchronized_since.get_or_insert_with(Instant::now);
                }
                (None, 'l') => {
                    self.synchronized_since = None;
                }
                (Some(b'$'), 'p') if self.bytes.len() <= 4096 => {
                    self.bytes
                        .extend_from_slice(if self.synchronized(Instant::now()) {
                            b"\x1b[?2026;1$y"
                        } else {
                            b"\x1b[?2026;2$y"
                        });
                }
                _ => {}
            }
            return;
        }
        if first.is_some() || second.is_some() || self.bytes.len() > 4096 {
            return;
        }
        let value = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        let reply = match (command, value) {
            ('n', 5) => "\x1b[0n".to_owned(),
            ('n', 6) => {
                let (row, col) = screen.cursor_position();
                format!("\x1b[{};{}R", row + 1, col + 1)
            }
            ('t', 18) => {
                let (rows, cols) = screen.size();
                format!("\x1b[8;{rows};{cols}t")
            }
            ('c', 0) => "\x1b[?1;2c".to_owned(),
            _ => String::new(),
        };
        self.bytes.extend_from_slice(reply.as_bytes());
    }
}

pub fn parser(rows: u16, cols: u16) -> vt100::Parser<Replies> {
    vt100::Parser::new_with_callbacks(
        NonZeroU16::new(rows.max(1)).unwrap(),
        NonZeroU16::new(cols.max(1)).unwrap(),
        0,
        Replies::default(),
    )
}
