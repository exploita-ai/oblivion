//! Keep guest screen controls inside the terminal presentation boundary.
//!
//! Interactive native TUIs need cursor, color, mouse and alternate-screen
//! sequences. They do not receive authority to use the desktop clipboard,
//! change its title/directory, transfer files or issue window operations.

#[derive(Default)]
pub struct Guard {
    state: State,
    utf8_remaining: u8,
}

#[derive(Default)]
enum State {
    #[default]
    Text,
    Utf8Control,
    Escape,
    Charset(u8),
    Csi(Vec<u8>),
    LongCsi,
    String { osc: bool, escape: bool },
}

impl Guard {
    pub fn filter(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            match &mut self.state {
                State::Text => {
                    if self.utf8_remaining > 0 && (0x80..=0xbf).contains(&byte) {
                        self.utf8_remaining -= 1;
                        output.push(byte);
                        continue;
                    }
                    self.utf8_remaining = 0;
                    match byte {
                        0x1b => self.state = State::Escape,
                        0xc2 => self.state = State::Utf8Control,
                        0x9b => self.state = State::Csi(vec![0x1b, b'[']),
                        0x90 | 0x98 | 0x9d..=0x9f => {
                            self.state = State::String { osc: byte == 0x9d, escape: false };
                        }
                        0x05 | 0x80..=0x9f => {},
                        _ => {
                            self.utf8_remaining = match byte {
                                0xc2..=0xdf => 1,
                                0xe0..=0xef => 2,
                                0xf0..=0xf4 => 3,
                                _ => 0,
                            };
                            output.push(byte);
                        }
                    }
                }
                State::Utf8Control => {
                    self.state = State::Text;
                    // C1 controls can also arrive encoded as UTF-8. Drop the
                    // control character rather than opening a terminal command.
                    if (0xa0..=0xbf).contains(&byte) {
                        output.extend_from_slice(&[0xc2, byte]);
                    } else if !(0x80..=0x9f).contains(&byte) {
                        output.extend(self.filter(&[byte]));
                    }
                }
                State::Escape => match byte {
                    b'[' => self.state = State::Csi(vec![0x1b, b'[']),
                    b']' | b'P' | b'X' | b'^' | b'_' => {
                        self.state = State::String { osc: byte == b']', escape: false };
                    }
                    b'('..=b'+' | b'#' | b'%' => self.state = State::Charset(byte),
                    0x1b => {},
                    0x30..=0x7e => {
                        output.extend_from_slice(&[0x1b, byte]);
                        self.state = State::Text;
                    }
                    _ => self.state = State::Text,
                },
                State::Charset(prefix) => {
                    if (0x20..=0x7e).contains(&byte) {
                        output.extend_from_slice(&[0x1b, *prefix, byte]);
                    }
                    self.state = State::Text;
                }
                State::Csi(sequence) => {
                    if (0x40..=0x7e).contains(&byte) {
                        // Window reports can expose desktop state; printer
                        // controls can hand data to a terminal-side service.
                        if !matches!(byte, b't' | b'i') {
                            output.extend_from_slice(sequence);
                            output.push(byte);
                        }
                        self.state = State::Text;
                    } else if byte == 0x1b {
                        self.state = State::Escape;
                    } else if sequence.len() >= 256 || !(0x20..=0x3f).contains(&byte) {
                        self.state = State::LongCsi;
                    } else {
                        sequence.push(byte);
                    }
                }
                State::LongCsi => {
                    if (0x40..=0x7e).contains(&byte) {
                        self.state = State::Text;
                    } else if byte == 0x1b {
                        self.state = State::Escape;
                    }
                }
                State::String { osc, escape } => {
                    // DCS includes tmux passthrough and terminal file-transfer
                    // protocols. Discard the whole envelope, even across frames.
                    if byte == 0x9c || *escape && byte == b'\\' || *osc && byte == 0x07 {
                        self.state = State::Text;
                    } else {
                        *escape = byte == 0x1b;
                    }
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::Guard;

    #[test]
    fn preserves_native_tui_rendering_at_every_frame_boundary() {
        let screen = "\x1b[?1049h\x1b[2J\x1b[3;4H\x1b[38;2;211;47;47mCittà 🛡\x1b[0m\x1b[?1006h\x1b[?25l".as_bytes();
        for split in 0..screen.len() {
            let mut guard = Guard::default();
            let mut actual = guard.filter(&screen[..split]);
            actual.extend(guard.filter(&screen[split..]));
            assert_eq!(actual, screen);
        }
    }

    #[test]
    fn removes_clipboard_titles_passthrough_and_window_commands() {
        let bytes = b"before\x1b]52;c;ZXhmaWw=\x07\x1b]0;guest title\x1b\\\x1bPtmux;\x1b\x1b]52;c;data\x07\x1b\\\x1b[21t\x1b[5i\x1b[?1049hafter";
        for split in 0..bytes.len() {
            let mut guard = Guard::default();
            let mut actual = guard.filter(&bytes[..split]);
            actual.extend(guard.filter(&bytes[split..]));
            assert_eq!(actual, b"before\x1b[?1049hafter");
        }
    }

    #[test]
    fn bounds_unterminated_controls_and_handles_single_byte_strings() {
        let mut guard = Guard::default();
        assert!(guard.filter(b"\x1b]").is_empty());
        assert!(guard.filter(&vec![b'x'; 65536]).is_empty());
        assert_eq!(guard.filter(b"\x07ok\x90secret\x9cend"), b"okend");
        assert!(guard.filter(b"\x1b[").is_empty());
        assert!(guard.filter(&vec![b'1'; 65536]).is_empty());
        assert_eq!(guard.filter(b"mvisible"), b"visible");
    }

    #[test]
    fn control_encodings_cannot_bypass_the_screen_boundary() {
        let mut guard = Guard::default();
        assert_eq!(guard.filter(b"\x1b\x9d52;payload\x07"), b"52;payload\x07");
        assert_eq!(guard.filter(b"\xc2\x9d52;payload\x07"), b"52;payload\x07");
        assert_eq!(guard.filter("© € Н".as_bytes()), "© € Н".as_bytes());
        assert_eq!(guard.filter(b"\x05"), b"");
    }
}
