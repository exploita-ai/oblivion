use oblivion_host::chat_screen::{command, difference, frame};
use oblivion_host::terminal::parser;
use std::time::{Duration, Instant};

#[test]
fn synchronized_guest_updates_hide_partial_frames_and_bound_abandoned_updates() {
    let mut guest = parser(24, 80);
    guest.callbacks_mut().enable_synchronized_output();
    guest.process(b"\x1b[?2026$p");
    let mut reply = Vec::new();
    guest.callbacks_mut().write_replies(&mut reply).unwrap();
    assert_eq!(reply, b"\x1b[?2026;2$y");
    for byte in b"\x1b[?2026h\x1b[HFirst line\x1b[2;1HSecond line" {
        guest.process(&[*byte]);
    }
    let now = Instant::now();
    assert!(guest.callbacks().synchronized(now));
    assert!(!guest.callbacks().synchronized(now + Duration::from_secs(1)));
    guest.process(b"\x1b[?2026$p");
    reply.clear();
    guest.callbacks_mut().write_replies(&mut reply).unwrap();
    assert_eq!(reply, b"\x1b[?2026;1$y");
    guest.process(b"\x1b[?2026l");
    assert!(!guest.callbacks().synchronized(Instant::now()));
    let output = frame(guest.screen());
    assert!(!output.contains("2026"));
    let mut embedded = parser(24, 80);
    embedded.process(output.as_bytes());
    assert_eq!(embedded.screen().contents(), "First line\nSecond line");
}

#[test]
fn embedded_frames_preserve_text_and_red_but_strip_guest_controls() {
    for (rows, cols) in [(18, 78), (42, 126)] {
        let mut guest = parser(rows, cols);
        guest.process(b"\x1b]52;c;SECRET\x07\x1b]2;FAKE HOST\x07\x1bPprivate\x1b\\\x1b[8;999;999t\x1b[?1049h\x1b[2J\x1b[H\x1b[38;2;211;47;47mOBLIVION\x1b[2;1HConversation");
        let output = frame(guest.screen());
        assert!(!output.contains("\x1b]"));
        assert!(!output.contains("SECRET"));
        assert!(!output.contains("FAKE HOST"));
        assert!(!output.contains("private"));
        assert!(!output.contains("1049"));
        assert!(!output.contains("999"));
        let mut embedded = parser(rows, cols);
        embedded.process(output.as_bytes());
        assert_eq!(
            embedded
                .screen()
                .contents()
                .lines()
                .take(2)
                .map(str::trim_end)
                .collect::<Vec<_>>(),
            ["OBLIVION", "Conversation"]
        );
        assert_eq!(
            embedded.screen().cell(0, 0).unwrap().fgcolor(),
            vt100::Color::Rgb(211, 47, 47)
        );
    }
}

#[test]
fn viewport_commands_are_bounded_and_do_not_accept_controller_actions() {
    assert!(command(br#"{"type":"resize","cols":78,"rows":18}"#).is_ok());
    assert!(command(br#"{"type":"resize","cols":0,"rows":18}"#).is_err());
    assert!(command(br#"{"type":"resize","cols":80,"rows":1000}"#).is_err());
    assert!(command(br#"{"type":"close"}"#).is_err());
    assert!(command(br#"{"type":"input","data":[27,91,65]}"#).is_ok());
    assert!(command(br#"{"type":"input","data":[256]}"#).is_err());
    assert!(
        command(
            serde_json::to_string(&serde_json::json!({"type":"input","data":vec![65;4097]}))
                .unwrap()
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn streaming_updates_are_small_diffs_and_preserve_scroll_input_modes() {
    let mut guest = parser(42, 126);
    guest.process(b"\x1b[?1002h\x1b[?1006h\x1b[?2004h");
    for row in 1..40 {
        guest.process(format!("\x1b[{row};1HMessage {row}: a conversation that stays visible while the response streams.").as_bytes());
    }
    let previous = guest.screen().clone();
    let initial = frame(&previous);
    guest.process(b"\x1b[40;1Hnew token\x1b]52;c;PRIVATE\x07");
    let delta = difference(guest.screen(), &previous);
    assert!(delta.len() < initial.len() / 10);
    assert!(!delta.contains("\x1b[2J"));
    assert!(!delta.contains("PRIVATE"));
    assert!(difference(guest.screen(), guest.screen()).is_empty());
    let mut embedded = parser(42, 126);
    embedded.process(initial.as_bytes());
    embedded.process(delta.as_bytes());
    assert_eq!(embedded.screen().contents(), guest.screen().contents());
    assert_eq!(
        embedded.screen().mouse_protocol_mode(),
        vt100::MouseProtocolMode::ButtonMotion
    );
    assert_eq!(
        embedded.screen().mouse_protocol_encoding(),
        vt100::MouseProtocolEncoding::Sgr
    );
}
