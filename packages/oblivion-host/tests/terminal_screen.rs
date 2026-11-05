use oblivion_cli::terminal_overlay::{parser, repaint};

#[test]
fn overlay_screen_answers_native_queries_without_replaying_guest_envelopes() {
    let mut screen = parser(24, 80);
    screen.process(b"\x1b]52;c;private-clipboard\x07\x1b]777;oblivion;close\x07\x1b]2;private-title\x07\x1bPprivate-dcs\x1b\\");
    screen.process(b"\x1b[2;3Hvisible\x1b[5n\x1b[6n\x1b[18t\x1b[c");
    let mut replies = Vec::new();
    screen.write_replies(&mut replies).unwrap();
    assert_eq!(replies, b"\x1b[0n\x1b[2;10R\x1b[8;24;80t\x1b[?1;2c");
    let mut restored = Vec::new();
    repaint(&screen, &mut restored).unwrap();
    let restored = String::from_utf8(restored).unwrap();
    assert!(restored.contains("visible"));
    assert!(!restored.contains("private"));
    assert!(!restored.contains("777"));
    replies.clear();
    screen.write_replies(&mut replies).unwrap();
    assert!(replies.is_empty());
}

#[test]
fn synchronized_frame_queries_are_bounded_and_return_to_ready() {
    let mut screen = parser(50, 160);
    screen.enable_synchronized_output();
    screen.process(b"\x1b[?2026h\x1b[?2026$p\x1b[?2026l\x1b[?2026$p");
    let mut replies = Vec::new();
    screen.write_replies(&mut replies).unwrap();
    assert_eq!(replies, b"\x1b[?2026;1$y\x1b[?2026;2$y");
    for _ in 0..100_000 {
        screen.process(b"\x1b[5n");
    }
    replies.clear();
    screen.write_replies(&mut replies).unwrap();
    assert!(replies.len() < 4200);
}
