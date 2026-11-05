use super::{Attachment, Chrome, Input, Keys, Modes, Page, Size, Terminal, mode};
use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleCP,
    GetConsoleOutputCP, GetNumberOfConsoleInputEvents, INPUT_RECORD, KEY_EVENT, SetConsoleCP,
    SetConsoleMode, SetConsoleOutputCP, WriteConsoleInputW,
};
use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

#[test]
fn windows_console_handoff_stops_reader_and_discards_panel_input() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "windows_terminal::overlay_tests::console_handoff_fixture",
        ])
        .creation_flags(CREATE_NEW_CONSOLE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated overlay console did not finish");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "private-console subprocess fixture"]
fn console_handoff_fixture() {
    let open = |name| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap()
    };
    let output = open("CONOUT$");
    let terminal = Terminal::from_files(open("CONIN$"), output.try_clone().unwrap(), output);
    assert!(terminal.size().unwrap().is_some());
    let shell = settings(&terminal);
    let modes = Modes::attach(&terminal, true).unwrap();
    let agent = settings(&terminal);
    assert_eq!((agent.2, agent.3), (65001, 65001));
    terminal.flush_input().unwrap();

    let reader = Input::start(terminal.input.try_clone().unwrap()).unwrap();
    // Win32 virtual-key codes VK_F7 and VK_F9. Let conhost encode them
    // rather than injecting their escape sequences into the decoder.
    let mut f7 = vec![key(0x76, 0)];
    f7.extend("OLD_READER_TAIL".encode_utf16().map(|unit| key(0, unit)));
    inject(&terminal.input, &f7);
    expect_panel(reader, Page::Files, b"");

    let queued = "QUEUED_BEFORE_PANEL"
        .encode_utf16()
        .map(|unit| key(0, unit))
        .collect::<Vec<_>>();
    inject(&terminal.input, &queued);
    assert!(queued_count(&terminal.input) > 0);
    terminal.flush_input().unwrap();
    assert_eq!(queued_count(&terminal.input), 0);

    // Exercise actual changes to the shared console that the panel can leave
    // behind. The agent settings and original shell snapshot are distinct.
    assert_ne!(
        unsafe {
            SetConsoleMode(
                terminal.input.as_raw_handle(),
                shell.0 & !ENABLE_VIRTUAL_TERMINAL_INPUT,
            )
        },
        0
    );
    assert_ne!(
        unsafe {
            SetConsoleMode(
                terminal.output.as_raw_handle(),
                shell.1 & !ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            )
        },
        0
    );
    assert_ne!(unsafe { SetConsoleCP(437) }, 0);
    assert_ne!(unsafe { SetConsoleOutputCP(437) }, 0);
    assert_ne!(settings(&terminal), agent);
    let queued = "QUEUED_AFTER_PANEL"
        .encode_utf16()
        .map(|unit| key(0, unit))
        .collect::<Vec<_>>();
    inject(&terminal.input, &queued);
    assert!(queued_count(&terminal.input) > 0);
    terminal.restore_panel(&modes).unwrap();
    assert_eq!(settings(&terminal), agent);
    assert_eq!(queued_count(&terminal.input), 0);

    let reader = Input::start(terminal.input.try_clone().unwrap()).unwrap();
    inject(&terminal.input, &[key(0, b'z' as u16), key(0x78, 0)]);
    expect_panel(reader, Page::Network, b"z");
    modes.restore().unwrap();
    assert_eq!(settings(&terminal), shell);
}

fn settings(terminal: &Terminal) -> (u32, u32, u32, u32) {
    (
        mode(&terminal.input).unwrap(),
        mode(&terminal.output).unwrap(),
        unsafe { GetConsoleCP() },
        unsafe { GetConsoleOutputCP() },
    )
}

fn key(virtual_key: u16, unit: u16) -> INPUT_RECORD {
    let mut record = INPUT_RECORD::default();
    record.EventType = KEY_EVENT as u16;
    let key = unsafe { &mut record.Event.KeyEvent };
    key.bKeyDown = 1;
    key.wRepeatCount = 1;
    key.wVirtualKeyCode = virtual_key;
    key.uChar.UnicodeChar = unit;
    record
}

fn inject(input: &File, records: &[INPUT_RECORD]) {
    let mut count = 0;
    assert_ne!(
        unsafe {
            WriteConsoleInputW(
                input.as_raw_handle(),
                records.as_ptr(),
                records.len() as u32,
                &mut count,
            )
        },
        0
    );
    assert_eq!(count as usize, records.len());
}

fn queued_count(input: &File) -> u32 {
    let mut count = 0;
    assert_ne!(
        unsafe { GetNumberOfConsoleInputEvents(input.as_raw_handle(), &mut count) },
        0
    );
    count
}

fn expect_panel(reader: Input, page: Page, prefix: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut attachment = Attachment {
        input: Some(reader),
        opening: None,
        overlay: None,
        chrome: Some(Chrome::new(Size { rows: 24, cols: 80 }, "test", "codex")),
    };
    let mut keys = Keys::default();
    let mut human = crate::activity::HumanInput::default();
    let mut forwarded = Vec::new();
    while attachment.opening.is_none() {
        assert!(Instant::now() < deadline, "console key did not arrive");
        assert!(
            !attachment
                .enqueue_input(&mut forwarded, &mut keys, &mut human, true, &mut |_| {})
                .unwrap()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(attachment.opening, Some(page));
    let mut frames = forwarded.as_slice();
    let mut text = Vec::new();
    while !frames.is_empty() {
        let (kind, bytes) = oblivion_wire::agent::read_frame(&mut frames).unwrap();
        assert_eq!(kind, 0);
        text.extend(bytes);
    }
    assert_eq!(text, prefix);
    let reader = attachment.input.as_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !reader.poll_stop().unwrap() {
        assert!(Instant::now() < deadline, "console reader did not join");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(reader.worker.is_none());
}
