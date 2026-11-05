//! Native Windows console/pipe boundary for the existing guest agent stream.
//! Console secrets never consume redirected stdin. One owned reader retains VT
//! input bytes; its synchronous I/O is cancelled and joined before mode restore.
use crate::controller::Result;
use crate::windows_io::{cancel_and_join, duplicate};
use oblivion_native_windows::client::Channel;
use oblivion_wire::agent::{self, Command, Size};
use oblivion_wire::terminal_guard::Guard;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS,
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_QUICK_EDIT_MODE,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT,
    FlushConsoleInputBuffer, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
    GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleCP, SetConsoleCtrlHandler, SetConsoleMode, SetConsoleOutputCP,
};
use windows_sys::Win32::System::Threading::Sleep;
use zeroize::Zeroizing;

static IN_USE: AtomicBool = AtomicBool::new(false);
static SIGNAL: AtomicU32 = AtomicU32::new(0);
static HANDLER_ACTIVE: AtomicBool = AtomicBool::new(false);

pub struct Terminal {
    input: File,
    output: File,
    error: File,
}

impl Terminal {
    pub fn stdio() -> Result<Self> {
        Ok(Self::from_files(
            duplicate(unsafe { GetStdHandle(STD_INPUT_HANDLE) })?,
            duplicate(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })?,
            duplicate(unsafe { GetStdHandle(STD_ERROR_HANDLE) })?,
        ))
    }

    /// Explicit owned handles preserve redirected streams without replacing
    /// process-global standard handles (also used by real Windows pipe tests).
    pub fn from_files(input: File, output: File, error: File) -> Self {
        Self {
            input,
            output,
            error,
        }
    }

    pub fn size(&self) -> Result<Option<Size>> {
        if mode(&self.input).is_none() || mode(&self.output).is_none() {
            return Ok(None);
        }
        let mut screen: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(self.output.as_raw_handle(), &mut screen) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Some(Size {
            rows: (i32::from(screen.srWindow.Bottom) - i32::from(screen.srWindow.Top) + 1)
                .clamp(1, 1000) as u16,
            cols: (i32::from(screen.srWindow.Right) - i32::from(screen.srWindow.Left) + 1)
                .clamp(1, 1000) as u16,
        }))
    }

    /// The caller owns the authenticated AgentAttach channel and keeps its lease
    /// until explicit AgentRelease finishes, including after the guest exits.
    pub fn attach(
        &self,
        channel: &mut Channel,
        command: &Command<'_>,
        mut on_activity: impl FnMut(Instant),
    ) -> Result<i32> {
        let _exclusive = Exclusive::claim()?;
        let initial = self.size()?;
        match command {
            Command::Workspace { .. } if initial.is_none() => {
                return Err("Workspace requires an interactive terminal".into());
            }
            Command::Agent(launch) if launch.terminal.is_some() != initial.is_some() => {
                return Err("agent_terminal_mode_changed".into());
            }
            _ => {}
        }
        let modes = Modes::attach(self, initial.is_some())?;
        let _handler = Handler::install(
            mode(&self.input).is_some()
                || mode(&self.output).is_some()
                || mode(&self.error).is_some(),
        )?;
        command.write(channel)?;
        channel.flush()?;
        let mut input = Input::start(self.input.try_clone()?)?;
        let result = self.bridge(channel, &input, initial, &mut on_activity);
        // Completion is not inferred from CancelSynchronousIo accepting a
        // request. Keep the reader and its buffers until its thread exits.
        let stopped = input.stop();
        let restored = modes.restore();
        stopped?;
        restored?;
        result
    }

    fn bridge(
        &self,
        channel: &mut Channel,
        input: &Input,
        mut viewport: Option<Size>,
        on_activity: &mut impl FnMut(Instant),
    ) -> Result<i32> {
        let mut human = crate::activity::HumanInput::default();
        let interactive = viewport.is_some();
        let mut decoder = agent::Decoder::default();
        let mut pending = Vec::new();
        let mut written = 0;
        let mut ended = false;
        let mut resized = Instant::now();
        let mut output_guard = Guard::default();
        let mut error_guard = Guard::default();
        loop {
            let now = Instant::now();
            if interactive && human.expire(now) {
                on_activity(now);
            }
            // Drain output while writes remain pending: the native channel is
            // deliberately one duplex owner, not locked across blocking I/O.
            for _ in 0..16 {
                let Some((kind, bytes)) = decoder.read(&mut Available(channel))? else {
                    break;
                };
                match kind {
                    1 | 2 => {
                        let (file, guard) = if kind == 1 {
                            (&self.output, &mut output_guard)
                        } else {
                            (&self.error, &mut error_guard)
                        };
                        let bytes = if mode(file).is_some() {
                            guard.filter(&bytes)
                        } else {
                            bytes
                        };
                        let mut file = file;
                        file.write_all(&bytes)?;
                        file.flush()?;
                    }
                    4 if bytes.len() == 4 => {
                        let code = i32::from_be_bytes(bytes.try_into().unwrap());
                        return if code < 0 {
                            128i32
                                .checked_sub(code)
                                .ok_or_else(|| "Invalid agent exit status".into())
                        } else {
                            Ok(code)
                        };
                    }
                    _ => return Err("Invalid agent response".into()),
                }
            }
            if written < pending.len() {
                match channel.try_write(&pending[written..]) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if written == pending.len() {
                match channel.try_flush() {
                    Ok(()) => {
                        pending.clear();
                        written = 0;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if pending.is_empty() {
                let signal = SIGNAL.swap(0, Ordering::AcqRel);
                if signal != 0 {
                    agent::write_frame(&mut pending, 6, &(signal as i32).to_be_bytes())?;
                } else if viewport.is_some() && resized.elapsed() >= Duration::from_millis(50) {
                    resized = Instant::now();
                    let current = self.size()?;
                    if current != viewport {
                        let size = current.ok_or("terminal_console_lost")?;
                        viewport = Some(size);
                        agent::write_frame(
                            &mut pending,
                            3,
                            &[size.rows.to_be_bytes(), size.cols.to_be_bytes()].concat(),
                        )?;
                    }
                } else if !ended {
                    match input.events.try_recv() {
                        Ok(InputEvent::Bytes(bytes)) => {
                            let now = Instant::now();
                            if interactive
                                && bytes
                                    .iter()
                                    .fold(false, |touched, byte| human.feed(*byte, now) || touched)
                            {
                                on_activity(now);
                            }
                            agent::write_frame(&mut pending, 0, &bytes)?;
                        }
                        Ok(InputEvent::Eof) => {
                            ended = true;
                            agent::write_frame(&mut pending, 5, &[])?;
                        }
                        Ok(InputEvent::Failed(error)) => return Err(error.into()),
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => {
                            return Err("terminal_input_lost".into());
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct Available<'a>(&'a mut Channel);
impl Read for Available<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(bytes)
    }
}

fn mode(file: &File) -> Option<u32> {
    let mut value = 0;
    (unsafe { GetConsoleMode(file.as_raw_handle(), &mut value) } != 0).then_some(value)
}

struct Modes {
    saved: Vec<(HANDLE, u32)>,
    input_cp: Option<u32>,
    output_cp: Option<u32>,
    restored: bool,
}
impl Modes {
    fn empty() -> Self {
        Self {
            saved: vec![],
            input_cp: None,
            output_cp: None,
            restored: false,
        }
    }
    fn set(&mut self, file: &File, value: u32) -> Result<()> {
        let old = mode(file).ok_or("Console handle required")?;
        self.saved.push((file.as_raw_handle(), old));
        if unsafe { SetConsoleMode(file.as_raw_handle(), value) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn attach(terminal: &Terminal, interactive: bool) -> Result<Self> {
        let mut guard = Self::empty();
        if interactive {
            let old = mode(&terminal.input).ok_or("Console input required")?;
            guard.set(
                &terminal.input,
                (old | ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT)
                    & !(ENABLE_ECHO_INPUT
                        | ENABLE_LINE_INPUT
                        | ENABLE_PROCESSED_INPUT
                        | ENABLE_QUICK_EDIT_MODE
                        | ENABLE_WINDOW_INPUT),
            )?;
            guard.input_cp = Some(unsafe { GetConsoleCP() });
            if unsafe { SetConsoleCP(65001) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        for file in [&terminal.output, &terminal.error] {
            if let Some(old) = mode(file) {
                guard.set(
                    file,
                    old | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                )?;
            }
        }
        if mode(&terminal.output).is_some() || mode(&terminal.error).is_some() {
            guard.output_cp = Some(unsafe { GetConsoleOutputCP() });
            if unsafe { SetConsoleOutputCP(65001) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(guard)
    }
    fn restore(mut self) -> Result<()> {
        self.restore_inner()
    }
    fn restore_inner(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        let mut failed = false;
        for &(handle, mode) in self.saved.iter().rev() {
            failed |= unsafe { SetConsoleMode(handle, mode) } == 0;
        }
        if let Some(cp) = self.input_cp {
            failed |= unsafe { SetConsoleCP(cp) } == 0;
        }
        if let Some(cp) = self.output_cp {
            failed |= unsafe { SetConsoleOutputCP(cp) } == 0;
        }
        self.restored = !failed;
        if failed {
            return Err("terminal_restore_failed".into());
        }
        Ok(())
    }
}
impl Drop for Modes {
    fn drop(&mut self) {
        let _ = self.restore_inner();
    }
}

struct Exclusive;
impl Exclusive {
    fn claim() -> Result<Self> {
        IN_USE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "terminal_already_in_use")?;
        Ok(Self)
    }
}
impl Drop for Exclusive {
    fn drop(&mut self) {
        IN_USE.store(false, Ordering::Release);
    }
}

struct Handler(bool);
impl Handler {
    fn install(console: bool) -> Result<Self> {
        if !console {
            return Ok(Self(false));
        }
        SIGNAL.store(0, Ordering::Release);
        HANDLER_ACTIVE.store(true, Ordering::Release);
        if unsafe { SetConsoleCtrlHandler(Some(signal), 1) } == 0 {
            HANDLER_ACTIVE.store(false, Ordering::Release);
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(true))
    }
}
impl Drop for Handler {
    fn drop(&mut self) {
        if self.0 {
            HANDLER_ACTIVE.store(false, Ordering::Release);
            unsafe {
                SetConsoleCtrlHandler(Some(signal), 0);
            }
        }
    }
}
unsafe extern "system" fn signal(event: u32) -> i32 {
    let number = match event {
        CTRL_C_EVENT => 2,
        CTRL_BREAK_EVENT => 3,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => 1,
        _ => return 0,
    };
    SIGNAL.store(number, Ordering::Release);
    // Windows can terminate the process when its close handler returns. Allow
    // the sole pump to forward HUP; EOF remains the final lease revocation.
    if number == 1 {
        for _ in 0..100 {
            if !HANDLER_ACTIVE.load(Ordering::Acquire) {
                break;
            }
            unsafe {
                Sleep(10);
            }
        }
    }
    1
}

enum InputEvent {
    Bytes(Zeroizing<Vec<u8>>),
    Eof,
    Failed(io::Error),
}
struct Input {
    stopped: Arc<AtomicBool>,
    events: Receiver<InputEvent>,
    worker: Option<JoinHandle<()>>,
}
impl Input {
    fn start(mut file: File) -> io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let (send, events) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("oblivion-stdin".into())
            .spawn(move || {
                let mut bytes = Zeroizing::new([0; 8192]);
                while !stop.load(Ordering::Acquire) {
                    let mut event = match file.read(&mut *bytes) {
                        Ok(0) => InputEvent::Eof,
                        Ok(count) => InputEvent::Bytes(Zeroizing::new(bytes[..count].to_vec())),
                        Err(error) => InputEvent::Failed(error),
                    };
                    let terminal = !matches!(event, InputEvent::Bytes(_));
                    loop {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        match send.try_send(event) {
                            Ok(()) => break,
                            Err(TrySendError::Disconnected(_)) => return,
                            Err(TrySendError::Full(pending)) => event = pending,
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    if terminal {
                        return;
                    }
                }
            })?;
        Ok(Self {
            stopped,
            events,
            worker: Some(worker),
        })
    }
    fn stop(&mut self) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        cancel_and_join(worker, &self.stopped).map_err(Into::into)
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn password(
    label: &str,
    minimum: usize,
    mut on_activity: impl FnMut(Instant),
) -> Result<Zeroizing<Vec<u8>>> {
    let _exclusive = Exclusive::claim()?;
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|_| "Password entry requires an interactive terminal")?;
    let mut output = OpenOptions::new()
        .write(true)
        .open("CONOUT$")
        .map_err(|_| "Password entry requires an interactive terminal")?;
    let mut guard = Modes::empty();
    let old = mode(&input).ok_or("Password entry requires an interactive terminal")?;
    guard.set(
        &input,
        old & !(ENABLE_ECHO_INPUT
            | ENABLE_LINE_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT),
    )?;
    if unsafe { FlushConsoleInputBuffer(input.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    write!(output, "{label}: ")?;
    output.flush()?;
    let result = (|| -> Result<Zeroizing<Vec<u8>>> {
        let mut value = Zeroizing::new(Vec::<u16>::new());
        loop {
            let mut unit = Zeroizing::new([0u16]);
            let mut count = 0;
            if unsafe {
                ReadConsoleW(
                    input.as_raw_handle(),
                    unit.as_mut_ptr().cast(),
                    1,
                    &mut count,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            if count != 1 {
                return Err("Password entry cancelled".into());
            }
            on_activity(Instant::now());
            match unit[0] {
                10 | 13 => break,
                3 | 4 | 26 => return Err("Password entry cancelled".into()),
                8 | 127 => {
                    if value
                        .pop()
                        .is_some_and(|unit| (0xdc00..=0xdfff).contains(&unit))
                    {
                        value.pop();
                    }
                }
                _ if value.len() >= 1024 => return Err("Password too long".into()),
                _ => value.push(unit[0]),
            }
        }
        let value =
            Zeroizing::new(String::from_utf16(&value).map_err(|_| "invalid_secret_encoding")?);
        if value.is_empty() {
            return Err("Password is empty".into());
        }
        if value.len() > 1024 {
            return Err("Password too long".into());
        }
        if value.len() < minimum {
            return Err("Use at least 16 characters".into());
        }
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    })();
    let restored = guard.restore();
    writeln!(output)?;
    restored?;
    result
}

pub fn new_password(
    label: &str,
    mut on_activity: impl FnMut(Instant),
) -> Result<Zeroizing<Vec<u8>>> {
    let first = password(label, 16, &mut on_activity)?;
    if *first != *password("Confirm password", 0, &mut on_activity)? {
        return Err("Passwords do not match".into());
    }
    Ok(first)
}

pub fn confirm(word: &str, on_activity: impl FnMut(Instant)) -> Result<bool> {
    Ok(password(&format!("Type {word} to confirm"), 0, on_activity)?.as_slice() == word.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{Input, InputEvent, Modes, Terminal, mode, password};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::ptr::null_mut;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_ECHO_INPUT, GetConsoleScreenBufferInfo,
        INPUT_RECORD, KEY_EVENT, ReadConsoleOutputCharacterW, WriteConsoleInputW,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

    fn pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, null_mut(), 8192) },
            0
        );
        unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) }
    }

    #[test]
    fn owned_input_preserves_pipe_bytes_and_reports_only_actual_eof() {
        let (read, mut write) = pipe();
        let mut input = Input::start(read).unwrap();
        write.write_all(&[0, 255, b'\n']).unwrap();
        match input.events.recv_timeout(Duration::from_secs(3)).unwrap() {
            InputEvent::Bytes(bytes) => assert_eq!(&*bytes, &[0, 255, b'\n']),
            _ => panic!("stdin lost pipe data"),
        }
        drop(write);
        assert!(matches!(
            input.events.recv_timeout(Duration::from_secs(3)).unwrap(),
            InputEvent::Eof
        ));
        input.stop().unwrap();
        assert!(input.worker.is_none());
    }

    #[test]
    fn stopping_input_joins_the_owned_reader_without_requiring_pipe_eof() {
        let (read, mut write) = pipe();
        let mut input = Input::start(read).unwrap();
        write.write_all(b"ready").unwrap();
        assert!(matches!(
            input.events.recv_timeout(Duration::from_secs(3)).unwrap(),
            InputEvent::Bytes(_)
        ));
        // Keep the writer alive. A reader cannot finish through transport EOF;
        // cancellation must also cover the race entering its next ReadFile.
        input.stop().unwrap();
        assert!(input.worker.is_none());
        drop(write);
    }

    #[test]
    fn pipe_terminal_does_not_claim_console_or_workspace_support() {
        let (read, _write) = pipe();
        let (_out_read, out_write) = pipe();
        let (_err_read, err_write) = pipe();
        let terminal = Terminal::from_files(read, out_write, err_write);
        assert_eq!(terminal.size().unwrap(), None);
        let guard = Modes::attach(&terminal, false).unwrap();
        assert!(guard.saved.is_empty());
        guard.restore().unwrap();
    }

    #[test]
    fn secret_prompt_uses_an_isolated_console_and_restores_its_input_mode() {
        // Standard handles are pipes; only this child owns the new console.
        // The runner's console and process-global modes remain untouched.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "windows_terminal::tests::console_fixture",
            ])
            .creation_flags(CREATE_NEW_CONSOLE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"PIPE_INPUT_CANARY")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("private console fixture did not finish");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "private-console subprocess fixture"]
    fn console_fixture() {
        let input = OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .unwrap();
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONOUT$")
            .unwrap();
        let saved = mode(&input).unwrap();
        let inject_input = input.try_clone().unwrap();
        let inject_output = output.try_clone().unwrap();
        let injector = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let mut screen: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
                assert_ne!(
                    unsafe {
                        GetConsoleScreenBufferInfo(inject_output.as_raw_handle(), &mut screen)
                    },
                    0
                );
                // Waiting for the prompt also proves the prior input flush is
                // complete. Injection cannot race that deliberate flush.
                if mode(&inject_input).unwrap() & ENABLE_ECHO_INPUT == 0
                    && screen.dwCursorPosition.X >= 14
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "private prompt did not become ready"
                );
                std::thread::yield_now();
            }
            let records = "PASSWORD_SECRET_CANARY\r"
                .encode_utf16()
                .map(|unit| {
                    let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
                    record.EventType = KEY_EVENT as u16;
                    let key = unsafe { &mut record.Event.KeyEvent };
                    key.bKeyDown = 1;
                    key.wRepeatCount = 1;
                    key.uChar.UnicodeChar = unit;
                    record
                })
                .collect::<Vec<_>>();
            let mut count = 0;
            assert_ne!(
                unsafe {
                    WriteConsoleInputW(
                        inject_input.as_raw_handle(),
                        records.as_ptr(),
                        records.len() as u32,
                        &mut count,
                    )
                },
                0
            );
            assert_eq!(count as usize, records.len());
        });
        let mut activity = 0;
        let secret = password("Private test", 16, |_| activity += 1).unwrap();
        injector.join().unwrap();
        assert_eq!(&*secret, b"PASSWORD_SECRET_CANARY");
        assert!(activity >= 16);
        assert_eq!(mode(&input), Some(saved));
        let mut piped = [0; 17];
        std::io::stdin().read_exact(&mut piped).unwrap();
        assert_eq!(&piped, b"PIPE_INPUT_CANARY");
        let mut cells = vec![0u16; 4096];
        let mut count = 0;
        assert_ne!(
            unsafe {
                ReadConsoleOutputCharacterW(
                    output.as_raw_handle(),
                    cells.as_mut_ptr(),
                    cells.len() as u32,
                    COORD { X: 0, Y: 0 },
                    &mut count,
                )
            },
            0
        );
        let screen = String::from_utf16_lossy(&cells[..count as usize]);
        assert!(screen.contains("Private test:"));
        assert!(!screen.contains("PASSWORD_SECRET_CANARY"));
    }
}
