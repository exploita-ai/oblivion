//! The physical screen is owned by Oblivion. Agent VT operations only affect the inset.
use super::{Screen, parser};
use oblivion_wire::{agent::Size, terminal_guard::Guard};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const CLEAR_INPUT_MODES: &str = "\x1b[?1l\x1b>\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[0 q";

pub fn guest_size(size: Size) -> Size {
    Size {
        rows: size.rows.saturating_sub(2).max(1),
        cols: size.cols,
    }
}

pub struct Chrome {
    screen: Screen,
    guard: Guard,
    physical: Size,
    heading: String,
    rows: Vec<String>,
    cursor: Option<(u16, u16)>,
    input_modes: String,
    inline_output: Option<Vec<u8>>,
    active: bool,
    dirty: bool,
    painted_at: Option<Instant>,
}

impl Chrome {
    pub fn new(physical: Size, safe: &str, agent: &str) -> Self {
        let label = match agent {
            "codex" => "Codex",
            "claude" => "Claude",
            "opencode2" => "OpenCode",
            _ => "Workspace",
        };
        let safe: String = safe
            .chars()
            .take(8)
            .filter(char::is_ascii_hexdigit)
            .collect();
        let size = guest_size(physical);
        let mut screen = parser(size.rows, size.cols);
        screen.enable_synchronized_output();
        Self {
            screen,
            guard: Guard::virtual_viewport(),
            physical,
            heading: format!(" OBLIVION  |  Safe {safe}  |  {label}"),
            rows: Vec::new(),
            cursor: None,
            input_modes: String::new(),
            inline_output: Some(Vec::new()),
            active: false,
            dirty: true,
            painted_at: None,
        }
    }

    pub fn process(&mut self, bytes: &[u8]) {
        let bytes = self.guard.filter(bytes);
        if !bytes.is_empty() {
            if let Some(inline) = self.inline_output.as_mut() {
                if inline.len() + bytes.len() <= 16_384 && is_inline(&bytes) {
                    inline.extend_from_slice(&bytes);
                } else {
                    self.inline_output = None;
                }
            }
            self.screen.process(&bytes);
            self.dirty = true;
        }
    }

    pub fn write_replies(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.screen.write_replies(output)
    }

    pub fn user_input(&mut self) {
        self.inline_output = None;
    }

    pub fn mouse_utf8(&self) -> bool {
        self.screen.parser.screen().mouse_protocol_encoding() == vt100::MouseProtocolEncoding::Utf8
    }

    pub fn resize(&mut self, physical: Size) {
        self.physical = physical;
        let size = guest_size(physical);
        self.screen.resize(size.rows, size.cols);
        self.rows.clear();
        self.dirty = true;
    }

    pub fn has_pending_frame(&self) -> bool {
        self.dirty
    }

    pub fn paint(&mut self, output: &mut impl Write, now: Instant) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let full = self.rows.is_empty();
        if self.active
            && !full
            && (self.screen.parser.callbacks().synchronized(now)
                || self.painted_at.is_some_and(|last| {
                    now.saturating_duration_since(last) < Duration::from_millis(16)
                }))
        {
            return Ok(());
        }
        let mut frame = String::new();
        if !self.active {
            // Set active before writing so cleanup also covers a partial write.
            self.active = true;
            frame.push_str("\x1b[?1049h\x1b[?6l\x1b[r\x1b[?7l\x1b[?25l");
        }
        if full {
            frame.push_str("\x1b[0m\x1b[2J");
            bar(
                &mut frame,
                1,
                self.physical.cols,
                &self.heading,
                "\x1b[1;37;48;2;133;26;26m",
            );
            if self.physical.rows >= 2 {
                bar(
                    &mut frame,
                    self.physical.rows,
                    self.physical.cols,
                    " F7 Files  |  F9 Network",
                    "\x1b[37;48;2;42;44;52m",
                );
            }
            self.cursor = None;
        }
        let screen = self.screen.parser.screen();
        let (rows, cols) = screen.size();
        let (rows, cols) = (rows.get(), cols.get());
        let visible = self.physical.rows >= 3;
        for row in 0..if visible { rows } else { 0 } {
            let content = row_content(screen, row, cols);
            if self.rows.get(usize::from(row)) == Some(&content) {
                continue;
            }
            // CUP is physical here. No escape sequences from the guest reach this writer.
            let _ = write!(frame, "\x1b[{};1H\x1b[0m\x1b[2K{content}", row + 2);
            if full {
                self.rows.push(content);
            } else {
                self.rows[usize::from(row)] = content;
            }
        }
        // Keep a full-frame marker even when the terminal is too short for content.
        if self.rows.is_empty() {
            self.rows.push(String::new());
        }
        let modes = screen.input_mode_formatted();
        if full || modes != self.input_modes {
            frame.push_str(CLEAR_INPUT_MODES);
            frame.push_str(&modes);
            self.input_modes = modes;
        }
        let (row, col) = screen.cursor_position();
        let cursor = (visible && !screen.hide_cursor()).then_some((row + 2, col.min(cols - 1) + 1));
        if !frame.is_empty() || self.cursor != cursor {
            frame.push_str("\x1b[0m");
            if let Some((row, col)) = cursor {
                let _ = write!(frame, "\x1b[{row};{col}H\x1b[?25h");
            } else {
                frame.push_str("\x1b[?25l");
            }
            self.cursor = cursor;
            output.write_all(frame.as_bytes())?;
            output.flush()?;
        }
        self.dirty = false;
        self.painted_at = Some(now);
        Ok(())
    }

    pub fn suspend(&mut self, output: &mut impl Write) -> io::Result<()> {
        if self.active {
            output.write_all(CLEAR_INPUT_MODES.as_bytes())?;
            output.write_all(b"\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l")?;
            output.flush()?;
            self.active = false;
            self.rows.clear();
            self.dirty = true;
        }
        Ok(())
    }

    pub fn finish(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.suspend(output)?;
        // Preserve short CLI output and early errors. Interactive screens stay
        // in the alternate buffer, including when an agent crashes.
        if let Some(bytes) = self.inline_output.take().filter(|bytes| !bytes.is_empty()) {
            output.write_all(&bytes)?;
            output.write_all(b"\x1b[0m")?;
            output.flush()?;
        }
        Ok(())
    }
}

fn is_inline(mut bytes: &[u8]) -> bool {
    while let Some((&byte, rest)) = bytes.split_first() {
        bytes = rest;
        if byte == 0x1b {
            let Some(sgr) = bytes.strip_prefix(b"[") else {
                return false;
            };
            let end = sgr
                .iter()
                .position(|byte| !byte.is_ascii_digit() && !matches!(byte, b';' | b':'));
            let Some(end) = end.filter(|end| sgr[*end] == b'm') else {
                return false;
            };
            bytes = &sgr[end + 1..];
        } else if byte.is_ascii_control() && !matches!(byte, b'\t' | b'\r' | b'\n') {
            return false;
        }
    }
    true
}

fn bar(frame: &mut String, row: u16, cols: u16, text: &str, style: &str) {
    // Both labels contain ASCII only. EL paints the background to the edge.
    let _ = write!(
        frame,
        "\x1b[{row};1H{style}\x1b[2K{}\x1b[0m",
        &text[..text.len().min(usize::from(cols))]
    );
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct Style {
    fg: vt100::Color,
    bg: vt100::Color,
    flags: u8,
}

impl Style {
    fn of(cell: &vt100::Cell) -> Self {
        Self {
            fg: cell.fgcolor(),
            bg: cell.bgcolor(),
            flags: u8::from(cell.bold())
                | u8::from(cell.dim()) << 1
                | u8::from(cell.italic()) << 2
                | u8::from(cell.underline()) << 3
                | u8::from(cell.inverse()) << 4,
        }
    }

    fn write(self, row: &mut String) {
        row.push_str("\x1b[0");
        for (bit, sgr) in [1, 2, 3, 4, 7].into_iter().enumerate() {
            if self.flags & (1 << bit) != 0 {
                let _ = write!(row, ";{sgr}");
            }
        }
        for (prefix, color) in [(38, self.fg), (48, self.bg)] {
            match color {
                vt100::Color::Default => {}
                vt100::Color::Idx(index) => {
                    let _ = write!(row, ";{prefix};5;{index}");
                }
                vt100::Color::Rgb(r, g, b) => {
                    let _ = write!(row, ";{prefix};2;{r};{g};{b}");
                }
            }
        }
        row.push('m');
    }
}

fn row_content(screen: &vt100::Screen, row: u16, cols: u16) -> String {
    let mut content = String::new();
    let mut style = Style::default();
    let mut last_visible = 0;
    for col in 0..cols {
        let Some(cell) = screen.cell(row, col) else {
            break;
        };
        if cell.is_wide_continuation() {
            continue;
        }
        let next = Style::of(cell);
        if style != next {
            next.write(&mut content);
            style = next;
        }
        if cell.has_contents() && (!cell.is_wide() || col + 1 < cols) {
            content.push_str(cell.contents());
            last_visible = content.len();
        } else {
            content.push(' ');
            if style != Style::default() {
                last_visible = content.len();
            }
        }
    }
    content.truncate(last_visible);
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU16;

    fn terminal(rows: u16, cols: u16) -> vt100::Parser {
        vt100::Parser::new(
            NonZeroU16::new(rows).unwrap(),
            NonZeroU16::new(cols).unwrap(),
            0,
        )
    }

    #[test]
    fn full_screen_agents_cannot_overwrite_the_bars_and_use_relative_geometry() {
        let size = Size { rows: 7, cols: 48 };
        let now = Instant::now();
        let mut chrome = Chrome::new(size, "17d803c9deadbeef", "codex");
        let mut host = terminal(size.rows, size.cols);
        let mut output = Vec::new();
        chrome.paint(&mut output, now).unwrap();
        host.process(&output);
        output.clear();
        chrome.process(
            b"\x1b[?1049h\x1b[2J\x1b[1;3Hfirst\x1b[5;1H\x1b[38;2;17;34;51mlast\x1b[6n\x1b[18t",
        );
        chrome.write_replies(&mut output).unwrap();
        assert_eq!(output, b"\x1b[5;5R\x1b[8;5;48t");
        output.clear();
        chrome
            .paint(&mut output, now + Duration::from_millis(20))
            .unwrap();
        host.process(&output);
        let lines: Vec<_> = host.screen().rows(0, size.cols).collect();
        assert!(lines[0].contains("OBLIVION  |  Safe 17d803c9  |  Codex"));
        assert_eq!(lines[1], "  first");
        assert_eq!(lines[5], "last");
        assert!(lines[6].contains("F7 Files  |  F9 Network"));
        assert_eq!(
            host.screen().cell(5, 0).unwrap().fgcolor(),
            vt100::Color::Rgb(17, 34, 51)
        );
        assert_eq!(host.screen().cursor_position(), (5, 4));

        chrome.suspend(&mut Vec::new()).unwrap();
        chrome.resize(Size { rows: 9, cols: 48 });
        let mut host = terminal(9, 48);
        output.clear();
        chrome.paint(&mut output, now).unwrap();
        host.process(&output);
        let lines: Vec<_> = host.screen().rows(0, 48).collect();
        assert!(lines[0].contains("OBLIVION"));
        assert_eq!(lines[5], "last");
        assert!(lines[8].contains("F9 Network"));
    }

    #[test]
    fn keeps_short_command_output_without_replaying_interactive_screens() {
        let size = Size { rows: 24, cols: 80 };
        let mut chrome = Chrome::new(size, "17d803c9", "codex");
        chrome.process(b"\x1b[32mcodex-cli 0.159.2\x1b[0m\r\n");
        let mut output = Vec::new();
        chrome.finish(&mut output).unwrap();
        assert_eq!(output, b"\x1b[32mcodex-cli 0.159.2\x1b[0m\r\n\x1b[0m");

        let mut chrome = Chrome::new(size, "17d803c9", "codex");
        chrome.process(b"prompt");
        chrome.user_input();
        chrome.process(b"private echo");
        output.clear();
        chrome.finish(&mut output).unwrap();
        assert!(output.is_empty());
    }
}
