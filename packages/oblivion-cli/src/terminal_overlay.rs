//! Host overlay keys, bounded VT screen state and terminal replies.
use std::io::{self, Write};
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

mod chrome;
pub use chrome::{Chrome, guest_size};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Page {
    Files,
    Network,
}

impl Page {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Network => "network",
        }
    }
}

mod mouse;

#[derive(Default)]
pub struct Keys {
    pending: Vec<u8>,
    pasted: bool,
    since: Option<Instant>,
    viewport: Option<oblivion_wire::agent::Size>,
    mouse_utf8: bool,
}

impl Keys {
    pub fn set_viewport(&mut self, viewport: Option<oblivion_wire::agent::Size>) {
        self.viewport = viewport;
    }

    pub fn set_mouse_utf8(&mut self, enabled: bool) {
        self.mouse_utf8 = enabled;
    }

    pub fn feed(&mut self, byte: u8, output: &mut Vec<u8>, now: Instant) -> Option<Page> {
        const FILES: [&[u8]; 3] = [b"\x1b[18~", b"\x1b[18;1~", b"\x1b[57370u"];
        const NETWORK: [&[u8]; 3] = [b"\x1b[20~", b"\x1b[20;1~", b"\x1b[57372u"];
        const PASTE_START: &[u8] = b"\x1b[200~";
        const PASTE_END: &[u8] = b"\x1b[201~";
        self.pending.push(byte);
        self.since = Some(now);
        loop {
            if self.pasted {
                if self.pending == PASTE_END {
                    self.pasted = false;
                    output.append(&mut self.pending);
                    return None;
                }
                if PASTE_END.starts_with(&self.pending) {
                    return None;
                }
            } else {
                let action = if FILES.contains(&self.pending.as_slice()) {
                    Some(Page::Files)
                } else if NETWORK.contains(&self.pending.as_slice()) {
                    Some(Page::Network)
                } else {
                    None
                };
                if action.is_some() {
                    self.pending.clear();
                    return action;
                }
                if self.pending == PASTE_START {
                    self.pasted = true;
                    output.append(&mut self.pending);
                    return None;
                }
                if let Some(viewport) = self.viewport {
                    match mouse::translate(&self.pending, viewport, self.mouse_utf8, output) {
                        mouse::Packet::Pending => return None,
                        mouse::Packet::Complete => {
                            self.pending.clear();
                            return None;
                        }
                        mouse::Packet::Other => {}
                    }
                }
                if FILES
                    .iter()
                    .chain(NETWORK.iter())
                    .any(|key| key.starts_with(&self.pending))
                    || PASTE_START.starts_with(&self.pending)
                {
                    return None;
                }
            }
            output.push(self.pending.remove(0));
            if self.pending.is_empty() {
                return None;
            }
        }
    }

    pub fn expire(&mut self, output: &mut Vec<u8>, now: Instant) {
        if self.waiting()
            && self
                .since
                .is_some_and(|since| now.duration_since(since) >= Duration::from_millis(50))
        {
            output.append(&mut self.pending);
        }
    }

    pub fn waiting(&self) -> bool {
        !self.pending.is_empty() && !self.pasted
            && !(self.viewport.is_some() && mouse::recognized(&self.pending))
    }

    pub fn finish(&mut self, output: &mut Vec<u8>) {
        output.append(&mut self.pending);
    }
}

#[derive(Default)]
struct Replies {
    bytes: Vec<u8>,
    synchronized_output: bool,
    synchronized_since: Option<Instant>,
}

impl Replies {
    fn enable_synchronized_output(&mut self) {
        self.synchronized_output = true;
    }

    fn synchronized(&self, now: Instant) -> bool {
        self.synchronized_since
            .is_some_and(|started| now.saturating_duration_since(started) < Duration::from_secs(1))
    }

    fn write_replies(&mut self, stream: &mut impl Write) -> std::io::Result<()> {
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
        if second.is_some() || self.bytes.len() > 4096 {
            return;
        }
        let value = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        let reply = match (first, command, value) {
            (None, 'n', 5) => "\x1b[0n".to_owned(),
            (None | Some(b'?'), 'n', 6) => {
                let (row, col) = screen.cursor_position();
                let private = if first.is_some() { "?" } else { "" };
                format!("\x1b[{private}{};{}R", row + 1, col.min(screen.size().1.get() - 1) + 1)
            }
            (None, 't', 18) => {
                let (rows, cols) = screen.size();
                format!("\x1b[8;{rows};{cols}t")
            }
            (None, 'c', 0) => "\x1b[?1;2c".to_owned(),
            _ => String::new(),
        };
        self.bytes.extend_from_slice(reply.as_bytes());
    }
}

pub struct Screen {
    parser: vt100::Parser<Replies>,
}

impl Screen {
    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(
            NonZeroU16::new(rows.max(1)).unwrap(),
            NonZeroU16::new(cols.max(1)).unwrap(),
        );
    }

    pub fn enable_synchronized_output(&mut self) {
        self.parser.callbacks_mut().enable_synchronized_output();
    }

    pub fn write_replies(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.parser.callbacks_mut().write_replies(output)
    }
}

pub fn parser(rows: u16, cols: u16) -> Screen {
    Screen {
        parser: vt100::Parser::new_with_callbacks(
            NonZeroU16::new(rows.max(1)).unwrap(),
            NonZeroU16::new(cols.max(1)).unwrap(),
            0,
            Replies::default(),
        ),
    }
}

/// Request paste framing and clear modes before the host panel takes input.
pub fn begin(output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"\x1b[?2004h\x1b[?2026l\x1b[>0u\x1b[0m\x1b[r\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h")
}

/// Clear modes that a failed or killed host panel may have left behind.
pub fn reset(output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"\x1b[?2026l\x1b[<u\x1b[0m\x1b[r\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[?1049l")
}

pub fn repaint(parser: &Screen, output: &mut impl Write) -> io::Result<()> {
    let screen = parser.parser.screen();
    output.write_all(if screen.alternate_screen() {
        b"\x1b[?1049h"
    } else {
        b"\x1b[?1049l"
    })?;
    output.write_all(b"\x1b[?2026l\x1b[0m\x1b[2J\x1b[H")?;
    // The serializer emits cells, attributes and supported input modes only;
    // guest OSC/DCS envelopes never replay into the desktop on restoration.
    output.write_all(screen.state_formatted().as_bytes())?;
    output.write_all(screen.cursor_state_formatted().as_bytes())?;
    output.write_all(screen.attributes_formatted().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{Keys, Page};
    use std::time::{Duration, Instant};

    #[test]
    fn host_keys_preserve_text_and_modified_keys() {
        let now = Instant::now();
        let mut keys = Keys::default();
        let mut output = Vec::new();
        let mut actions = Vec::new();
        for byte in b"normal\x1b[18~\x1b[20~\x1b[57370u\x1b[20;2~\x1b[A\xc3\xa8" {
            if let Some(page) = keys.feed(*byte, &mut output, now) {
                actions.push(page);
            }
        }
        assert_eq!(actions, [Page::Files, Page::Network, Page::Files]);
        assert_eq!(output, b"normal\x1b[20;2~\x1b[A\xc3\xa8");
    }

    #[test]
    fn pasted_function_keys_cannot_open_host_controls() {
        let now = Instant::now();
        let mut keys = Keys::default();
        let mut output = Vec::new();
        let text = b"\x1b[200~paste\x1b[18~\x1b[20~\x1b[57372u\x1b[201~";
        for byte in text {
            assert!(keys.feed(*byte, &mut output, now).is_none());
        }
        assert_eq!(output, text);
        let action = b"\x1b[20~"
            .iter()
            .find_map(|byte| keys.feed(*byte, &mut output, now));
        assert_eq!(action, Some(Page::Network));
    }

    #[test]
    fn standalone_escape_expires_without_losing_bytes() {
        let now = Instant::now();
        let mut keys = Keys::default();
        let mut output = Vec::new();
        keys.feed(27, &mut output, now);
        keys.expire(&mut output, now + Duration::from_millis(49));
        assert!(output.is_empty());
        keys.expire(&mut output, now + Duration::from_millis(50));
        assert_eq!(output, [27]);
    }
}
