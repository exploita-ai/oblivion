use oblivion_host::terminal::{Action, Input};
use oblivion_host::terminal::{parser, render_guest};
use std::time::{Duration, Instant};

#[test]
fn guest_session_requests_are_typed_hints_and_pasted_attention_is_data() {
    let mut guest = parser(21, 80);
    guest.process(b"\x1b]777;oblivion;ready\x07");
    assert!(guest.callbacks_mut().take_ready());
    assert!(!guest.callbacks_mut().take_ready());
    assert_eq!(guest.callbacks_mut().take_request(), None);
    guest.process(b"\x1b]777;oblivion;unlock;password\x07");
    assert_eq!(guest.callbacks_mut().take_request(), None);
    for byte in b"\x1b]777;oblivion;new\x07" {
        guest.process(&[*byte]);
    }
    assert_eq!(guest.callbacks_mut().take_request(), Some(Action::New));
    assert_eq!(guest.callbacks_mut().take_request(), None);
    let mut input = Input::default();
    let pasted = b"\x1b[200~paste\x1d\x1econtent\x1b[201~";
    let mut forwarded = Vec::new();
    for byte in pasted {
        let (output, attention) = input.decode(&[*byte], Instant::now());
        assert!(!attention);
        assert!(!input.take_documents());
        forwarded.extend(output);
    }
    assert_eq!(forwarded, pasted);
    assert!(input.decode(b"\x1d", Instant::now()).1);
    assert_eq!(input.decode(b"\x1e", Instant::now()), (Vec::new(), false));
    assert!(input.take_documents());
    assert!(!input.take_documents());
}

#[test]
fn guest_controls_cannot_escape_the_screen_or_change_trusted_header() {
    for (rows, cols) in [(24, 80), (10, 32)] {
        let mut guest = parser(rows - 3, cols);
        guest.process(b"\x1b]52;c;U0VDUkVU\x07\x1b]2;HOSTILE_TITLE\x07\x1b[8;999;999t\x1b[?1049h\x1b[2J\x1b[1;1HFake manager\x1b[999;999HEDGE\x1bPprivate-dcs\x1b\\");
        guest.process(b"\x1b[2;1HVisible guest text");
        let rendered = render_guest(guest.screen());
        assert!(!rendered.contains("U0VDUkVU"));
        assert!(!rendered.contains("HOSTILE_TITLE"));
        assert!(!rendered.contains("private-dcs"));
        assert!(!rendered.contains("\x1b]"));
        let mut host = parser(rows, cols);
        host.process(rendered.as_bytes());
        assert!(
            host.screen()
                .rows(0, cols)
                .next()
                .unwrap()
                .starts_with(" OBLIVION | SESSION OPEN")
        );
        assert!(
            host.screen()
                .rows(0, cols)
                .nth(1)
                .unwrap()
                .starts_with(" Ctrl+]")
        );
        assert!(!host.screen().alternate_screen());
        assert!(
            host.screen()
                .rows(0, cols)
                .nth(4)
                .unwrap()
                .starts_with("Visible guest text")
        );
    }
}

#[test]
fn fragmented_and_long_escape_strings_remain_internal() {
    let mut guest = parser(21, 80);
    for byte in b"\x1b]52;c;secret\x07\x1b[31mvisible" {
        guest.process(&[*byte]);
    }
    guest.process(b"\x1b]");
    for _ in 0..10000 {
        guest.process(&[b'x'; 128]);
    }
    guest.process(b"\x07\x1b[2J\x1b[Hafter");
    let rendered = render_guest(guest.screen());
    assert!(rendered.len() < 100000);
    assert!(!rendered.contains("secret"));
    let mut host = parser(24, 80);
    host.process(rendered.as_bytes());
    assert!(host.screen().contents().contains("after"));
    assert!(host.screen().contents().starts_with(" OBLIVION"));
}

#[test]
fn escape_expires_but_a_slow_paste_does_not_become_an_action() {
    let mut input = Input::default();
    let now = Instant::now();
    assert_eq!(input.decode(b"\x1b", now), (vec![], false));
    assert_eq!(
        input.decode(b"", now + Duration::from_millis(49)),
        (vec![], false)
    );
    assert_eq!(
        input.decode(b"", now + Duration::from_millis(50)),
        (vec![27], false)
    );
    assert_eq!(input.decode(b"\x1b\x1b[200~", now).0, b"\x1b\x1b[200~");
    assert_eq!(input.decode(b"\x1b", now).0, b"");
    assert_eq!(input.decode(b"", now + Duration::from_secs(2)).0, b"");
    assert_eq!(
        input.decode(b"\x1d", now + Duration::from_secs(2)),
        (vec![27, 29], false)
    );
    assert_eq!(input.decode(b"\x1b[201~\x1b", now).0, b"\x1b[201~");
    assert!(input.decode(b"\x1d", now).1);
}
