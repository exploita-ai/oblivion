//! Desktop-only activity reports contain opening identities, never input bytes.
use crate::{autolock, control, scope};
use serde::Deserialize;
use std::io::Read;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::{Duration, Instant};

pub struct Reporter {
    sender: SyncSender<Instant>,
    sent: Option<Instant>,
}

impl Reporter {
    pub fn current_safe(id: &str) -> control::Result<Self> {
        #[derive(Deserialize)]
        struct Current { idle_lock: autolock::Status }
        let current: Current = serde_json::from_str(&control::request("status", None, &[])?)?;
        let host = current.idle_lock.host.ok_or("Automatic lock state is unavailable. Reopen this Safe.")?;
        let safe = current.idle_lock.safes.into_iter().find(|safe| safe.opening.slot == scope::current()
            && safe.opening.safe_id == id && !safe.closing)
            .ok_or("Automatic lock state is unavailable. Reopen this Safe.")?;
        if host.closing { return Err("Oblivion is closing and locking its Safes".into()) }
        let activity = autolock::Activity { host: host.nonce, safe: Some(safe.opening) };
        Ok(Self::spawn(activity))
    }

    pub fn current_host() -> control::Result<Option<Self>> {
        #[derive(Deserialize)]
        struct Current { idle_lock: autolock::Status }
        let current: Current = serde_json::from_str(&control::request("status", None, &[])?)?;
        Ok(current.idle_lock.host.filter(|host| !host.closing)
            .map(|host| Self::spawn(autolock::Activity { host: host.nonce, safe: None })))
    }

    fn spawn(activity: autolock::Activity) -> Self {
        let slot = activity.safe.as_ref().map(|opening| opening.slot).unwrap_or_default();
        let bytes = serde_json::to_vec(&activity).expect("activity contains serializable identities");
        let (sender, receiver) = sync_channel::<Instant>(1);
        std::thread::spawn(move || scope::within(slot, || {
            let mut sent: Option<Instant> = None;
            for at in receiver {
                // A stalled controller must not receive replayed activity after
                // the original input is stale. No input content enters this queue.
                if at.elapsed() <= Duration::from_secs(2)
                    && sent.is_none_or(|previous| previous.elapsed() >= Duration::from_secs(1)) {
                    sent = Some(Instant::now());
                    let _ = control::request("activity", None, &bytes);
                }
            }
        }));
        Self { sender, sent: None }
    }

    pub fn touch(&mut self, now: Instant) {
        if self.sent.is_some_and(|sent| now.saturating_duration_since(sent) < Duration::from_secs(1)) { return }
        if self.sender.try_send(now).is_ok() { self.sent = Some(now) }
    }
}

pub fn forward_stdin() -> control::Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin().take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 { return Err("Activity report is too large".into()) }
    let activity: autolock::Activity = serde_json::from_slice(&bytes)?;
    let slot = activity.safe.as_ref().map(|opening| opening.slot).unwrap_or_default();
    scope::within(slot, || control::request("activity", None, &bytes))?;
    Ok(0)
}

#[derive(Default)]
pub struct HumanInput {
    state: InputState,
    utf8_remaining: u8,
    escaped: Option<Instant>,
}

#[derive(Default)]
enum InputState {
    #[default]
    Text,
    Escape,
    Ss3,
    Csi(Vec<u8>),
    LongCsi,
    String { escape: bool },
}

impl HumanInput {
    pub fn feed(&mut self, byte: u8, now: Instant) -> bool {
        match &mut self.state {
            InputState::Text => {
                if self.utf8_remaining > 0 && (0x80..=0xbf).contains(&byte) {
                    self.utf8_remaining -= 1;
                    return true;
                }
                self.utf8_remaining = 0;
                match byte {
                    0x1b => { self.state = InputState::Escape; self.escaped = Some(now); false }
                    0x9b => { self.state = InputState::Csi(Vec::new()); false }
                    0x90 | 0x9d | 0x98 | 0x9e | 0x9f => { self.state = InputState::String { escape: false }; false }
                    _ => {
                        self.utf8_remaining = match byte { 0xc2..=0xdf => 1, 0xe0..=0xef => 2, 0xf0..=0xf4 => 3, _ => 0 };
                        true
                    }
                }
            }
            InputState::Escape => {
                self.escaped = None;
                match byte {
                    b'[' => { self.state = InputState::Csi(Vec::new()); false }
                    b'O' => { self.state = InputState::Ss3; false }
                    b']' | b'P' | b'X' | b'^' | b'_' => { self.state = InputState::String { escape: false }; false }
                    0x1b => { self.escaped = Some(now); false }
                    _ => { self.state = InputState::Text; true }
                }
            }
            InputState::Ss3 => {
                self.state = InputState::Text;
                matches!(byte, b'A'..=b'D' | b'F' | b'H' | b'P'..=b'S')
            }
            InputState::Csi(parameters) => {
                if (0x40..=0x7e).contains(&byte) {
                    let human = match byte {
                        b'M' | b'm' => parameters.first() == Some(&b'<'),
                        b'A'..=b'D' | b'F' | b'H' | b'P' | b'Q' | b'S' | b'Z' | b'~' | b'u' => parameters.iter().all(|value| value.is_ascii_digit() || matches!(value, b';' | b':')),
                        // R is deliberately excluded: a cursor-position report
                        // is indistinguishable from some modified F3 encodings.
                        _ => false,
                    };
                    self.state = InputState::Text;
                    human
                } else if parameters.len() >= 256 || !(0x20..=0x3f).contains(&byte) {
                    self.state = InputState::LongCsi;
                    false
                } else { parameters.push(byte); false }
            }
            InputState::LongCsi => {
                if (0x40..=0x7e).contains(&byte) { self.state = InputState::Text }
                false
            }
            InputState::String { escape } => {
                if byte == 0x07 || byte == 0x9c || *escape && byte == b'\\' {
                    self.state = InputState::Text;
                } else { *escape = byte == 0x1b }
                false
            }
        }
    }

    pub fn expire(&mut self, now: Instant) -> bool {
        if self.escaped.is_some_and(|at| now.saturating_duration_since(at) >= Duration::from_secs(1)) {
            self.escaped = None;
            self.state = InputState::Text;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_responses_never_become_activity_even_when_fragmented() {
        let now = Instant::now();
        for reply in [b"\x1b[12;42R".as_slice(), b"\x1b[?1;2c", b"\x1b[>1;4000;0c", b"\x1b[0n", b"\x1b[?7u", b"\x1b[I", b"\x1b[O", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\", b"\x1bP1+r544e=787465726d\x1b\\"] {
            let mut input = HumanInput::default();
            assert!(!reply.iter().any(|byte| input.feed(*byte, now)), "{reply:?}");
            assert!(!input.expire(now + Duration::from_secs(2)));
        }
    }

    #[test]
    fn text_shortcuts_navigation_paste_and_mouse_are_human_input() {
        let now = Instant::now();
        for bytes in ["Città Кириллица 🛡".as_bytes(), b"\x03", b"\x1b[A", b"\x1bOP", b"\x1b[18~", b"\x1b[97;5u", b"\x1b[200~text\x1b[201~", b"\x1b[<64;10;20M"] {
            let mut input = HumanInput::default();
            assert!(bytes.iter().fold(false, |human, byte| input.feed(*byte, now) || human), "{bytes:?}");
        }
        let mut input = HumanInput::default();
        assert!(!input.feed(0x1b, now));
        assert!(!input.expire(now + Duration::from_millis(999)));
        assert!(input.expire(now + Duration::from_secs(1)));
    }
}
