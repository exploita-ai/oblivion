//! One event-mode copy owns its stdin reader, cancellation channel and stdout.
use oblivion_transfer::Receipt;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::native_file_events::{
    self, Event, Identity, Input, Outcome, Phase, Summary,
};
use oblivion_transfer::native_files::Direction;
use oblivion_transfer::selection::{MAPPING_PAGE, Plan};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_secs(3600);
const OUTPUT_BUDGET: Duration = Duration::from_secs(2);

enum Stage {
    Preparing,
    Review(String),
    Approved,
    CancelledBeforeCopy,
    Cancelled,
    Failed,
}
struct State {
    stage: Stage,
    pending: usize,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

pub struct Control {
    identity: Identity,
    direction: Direction,
    name: String,
    shared: Arc<Shared>,
    watch: UnixStream,
    stop: Option<UnixStream>,
    input: File,
    output: File,
    reader: Option<JoinHandle<()>>,
    summary: Option<Summary>,
    mapping: Option<(String, usize)>,
    deadline: Instant,
    progress: Option<(Phase, u64, Instant)>,
    finished: bool,
}

impl Control {
    pub fn stdio(identity: Identity, direction: Direction, name: String) -> io::Result<Self> {
        fn duplicate(descriptor: i32) -> io::Result<File> {
            let fd = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        Self::new(duplicate(0)?, duplicate(1)?, identity, direction, name)
    }

    pub fn new(
        input: File,
        output: File,
        identity: Identity,
        direction: Direction,
        name: String,
    ) -> io::Result<Self> {
        identity.validate()?;
        for file in [&input, &output] {
            let kind = file.metadata()?.file_type();
            if !kind.is_fifo() && !kind.is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file_events_require_pipes",
                ));
            }
        }
        let (watch, revoke) = UnixStream::pair()?;
        let (stop, stopped) = UnixStream::pair()?;
        let probe = input.try_clone()?;
        let descriptor = input.as_raw_fd();
        let mut channel = Channel::new(input, BUDGET)?;
        channel.watch(stopped.try_clone()?.into());
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                stage: Stage::Preparing,
                pending: 0,
            }),
            changed: Condvar::new(),
        });
        let state = Arc::clone(&shared);
        let operation = identity.operation_id.clone();
        let reader = std::thread::spawn(move || {
            read_input(channel, descriptor, stopped, revoke, &operation, &state);
            state.changed.notify_all();
        });
        Ok(Self {
            identity,
            direction,
            name,
            shared,
            watch,
            stop: Some(stop),
            input: probe,
            output,
            reader: Some(reader),
            summary: None,
            mapping: None,
            deadline: Instant::now() + BUDGET,
            progress: None,
            finished: false,
        })
    }

    pub fn plan(&mut self, plan: &Plan) -> io::Result<()> {
        if self.mapping.is_some()
            || self.finished
            || !matches!(
                self.shared.state.lock().map_err(|_| aborted())?.stage,
                Stage::Preparing
            )
        {
            return Err(aborted());
        }
        let digest = plan.sha256()?;
        for (page, entries) in plan.mappings.chunks(MAPPING_PAGE).enumerate() {
            self.emit(
                &Event::Mapping {
                    identity: self.identity.clone(),
                    start: page * MAPPING_PAGE,
                    total: plan.mappings.len(),
                    selected: plan.selected.clone(),
                    entries: entries.to_vec(),
                    mapping_sha256: digest.clone(),
                },
                true,
            )?;
        }
        // A failed or cancelled page never arms a review over an incomplete map.
        self.check()?;
        self.mapping = Some((digest, plan.mappings.len()));
        Ok(())
    }

    pub fn review(&mut self, summary: Summary) -> io::Result<()> {
        summary.validate()?;
        let mut state = self.shared.state.lock().map_err(|_| aborted())?;
        loop {
            match state.stage {
                Stage::CancelledBeforeCopy => return Ok(()),
                Stage::Preparing => {}
                _ => return Err(aborted()),
            }
            // The reader parses under this same mutex. Never arm approval over
            // bytes already buffered before the review, including partial lines.
            let mut input = libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut input, 1, 0) };
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            if ready == 0 && state.pending == 0 {
                break;
            }
            state = self.wait(state)?;
        }
        if !self.mapping.as_ref().is_some_and(|(digest, count)| {
            *digest == summary.mapping_sha256
                && summary.files + summary.directories == summary.entries - usize::from(*count > 1)
        }) {
            return Err(aborted());
        }
        state.stage = Stage::Review(summary.manifest_sha256.clone());
        drop(state);
        self.summary = Some(summary.clone());
        self.emit(
            &Event::Review {
                identity: self.identity.clone(),
                direction: self.direction,
                name: self.name.clone(),
                summary,
            },
            true,
        )
    }

    pub fn wait_approval(&self) -> io::Result<bool> {
        let mut state = self.shared.state.lock().map_err(|_| aborted())?;
        loop {
            match state.stage {
                Stage::Approved => {
                    self.check()?;
                    return Ok(true);
                }
                Stage::CancelledBeforeCopy => return Ok(false),
                Stage::Review(_) => state = self.wait(state)?,
                _ => return Err(aborted()),
            }
        }
    }

    fn wait<'a>(
        &self,
        state: std::sync::MutexGuard<'a, State>,
    ) -> io::Result<std::sync::MutexGuard<'a, State>> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(aborted)?;
        let (state, timeout) = self
            .shared
            .changed
            .wait_timeout(state, remaining)
            .map_err(|_| aborted())?;
        if timeout.timed_out() {
            return Err(aborted());
        }
        Ok(state)
    }

    pub fn watch(&self) -> io::Result<OwnedFd> {
        Ok(self.watch.try_clone()?.into())
    }

    pub fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(aborted());
        }
        let mut descriptor = libc::pollfd {
            fd: self.watch.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.revents != 0 {
            return Err(aborted());
        }
        Ok(())
    }

    pub fn cancelled_before_copy(&self) -> bool {
        self.shared
            .state
            .lock()
            .is_ok_and(|state| matches!(state.stage, Stage::CancelledBeforeCopy))
    }

    pub fn progress(&mut self, phase: Phase, bytes: u64) -> io::Result<()> {
        self.check()?;
        if self.finished
            || !matches!(
                self.shared.state.lock().map_err(|_| aborted())?.stage,
                Stage::Approved
            )
        {
            return Err(aborted());
        }
        let summary = self.summary.as_ref().ok_or_else(aborted)?;
        if bytes > summary.bytes
            || self.progress.as_ref().is_some_and(|(last, sent, _)| {
                bytes < *sent || *last == Phase::Finalizing && phase != Phase::Finalizing
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid_file_progress",
            ));
        }
        if let Some((last, sent, at)) = self.progress {
            if last == phase
                && (bytes != summary.bytes || bytes == sent)
                && at.elapsed() < Duration::from_millis(100)
            {
                self.progress = Some((phase, bytes, at));
                return Ok(());
            }
        }
        self.emit(
            &Event::Progress {
                identity: self.identity.clone(),
                phase,
                bytes,
                total_bytes: summary.bytes,
            },
            true,
        )?;
        self.progress = Some((phase, bytes, Instant::now()));
        Ok(())
    }

    pub fn finish(&mut self, outcome: Outcome, receipt: Option<Receipt>) -> io::Result<()> {
        if self.finished {
            return Err(aborted());
        }
        if outcome == Outcome::Completed {
            self.check()?;
            if !matches!(
                self.shared.state.lock().map_err(|_| aborted())?.stage,
                Stage::Approved
            ) || !self
                .summary
                .as_ref()
                .zip(receipt.as_ref())
                .is_some_and(|(summary, receipt)| summary.matches(receipt, &self.identity))
            {
                return Err(aborted());
            }
        }
        if outcome == Outcome::CancelledBeforeCopy && !self.cancelled_before_copy() {
            return Err(aborted());
        }
        self.finished = true;
        // Cancellation stops progress immediately; its terminal outcome still
        // gets one bounded delivery attempt over an unwatched stdout channel.
        self.emit(
            &Event::Finished {
                identity: self.identity.clone(),
                outcome,
                receipt,
            },
            false,
        )
    }

    fn emit(&self, event: &Event, watched: bool) -> io::Result<()> {
        let bytes = native_file_events::encode(event)?;
        let mut output = Channel::new(self.output.try_clone()?, OUTPUT_BUDGET)?;
        if watched {
            self.check()?;
            output.watch(self.watch()?);
        }
        output.write_all(&bytes)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "file_events_revoked")
}

fn read_input(
    channel: Channel,
    descriptor: i32,
    stopped: UnixStream,
    revoke: UnixStream,
    operation: &str,
    shared: &Shared,
) {
    let result = (|| -> io::Result<()> {
        let mut line = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: descriptor,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stopped.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    2,
                    channel.remaining()?.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if ready <= 0 || descriptors[1].revents != 0 {
                return Err(aborted());
            }
            let mut state = shared.state.lock().map_err(|_| aborted())?;
            channel.check()?;
            // The fd is nonblocking and owned by channel. Never hold the
            // approval mutex while waiting for more input after poll.
            let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(error);
            }
            if read == 0 {
                return Err(aborted());
            }
            for byte in &buffer[..read as usize] {
                if line.len() >= native_file_events::LINE_LIMIT {
                    return Err(aborted());
                }
                line.push(*byte);
                if *byte != b'\n' {
                    continue;
                }
                match native_file_events::input(&line, operation)? {
                    Input::Approve {
                        manifest_sha256, ..
                    } => {
                        if !matches!(&state.stage, Stage::Review(expected) if *expected == manifest_sha256)
                        {
                            return Err(aborted());
                        }
                        state.stage = Stage::Approved;
                    }
                    Input::Cancel { .. } => {
                        state.stage = if matches!(state.stage, Stage::Preparing | Stage::Review(_))
                        {
                            Stage::CancelledBeforeCopy
                        } else {
                            Stage::Cancelled
                        };
                        revoke.shutdown(std::net::Shutdown::Both)?;
                        return Ok(());
                    }
                }
                line.clear();
            }
            state.pending = line.len();
            shared.changed.notify_all();
        }
    })();
    if result.is_err() {
        if let Ok(mut state) = shared.state.lock() {
            state.stage = Stage::Failed;
            let _ = revoke.shutdown(std::net::Shutdown::Both);
        }
    }
    shared.changed.notify_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};

    fn identity() -> Identity {
        Identity {
            operation_id: "a".repeat(32),
            safe_id: "b".repeat(32),
            opening: "c".repeat(32),
        }
    }
    fn summary() -> Summary {
        Summary {
            manifest_sha256: "d".repeat(64),
            mapping_sha256: plan().sha256().unwrap(),
            entries: 1,
            files: 1,
            directories: 0,
            bytes: 8,
        }
    }
    fn plan() -> Plan {
        Plan::new(&[oblivion_transfer::selection::Input {
            path: "/private/note".into(),
            directory: false,
        }])
        .unwrap()
    }
    fn fixture() -> (Control, UnixStream, BufReader<UnixStream>) {
        let (input, user) = UnixStream::pair().unwrap();
        let (output, reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        (
            Control::new(
                File::from(OwnedFd::from(input)),
                File::from(OwnedFd::from(output)),
                identity(),
                Direction::Import,
                "note".into(),
            )
            .unwrap(),
            user,
            BufReader::new(reader),
        )
    }
    fn approve(user: &mut UnixStream) {
        writeln!(
            user,
            "{{\"action\":\"approve\",\"operation_id\":\"{}\",\"manifest_sha256\":\"{}\"}}",
            identity().operation_id,
            summary().manifest_sha256
        )
        .unwrap();
    }
    fn event(reader: &mut BufReader<UnixStream>) -> Event {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn review(control: &mut Control, output: &mut BufReader<UnixStream>) {
        control.plan(&plan()).unwrap();
        assert!(matches!(
            event(output),
            Event::Mapping {
                start: 0,
                total: 1,
                ..
            }
        ));
        control.review(summary()).unwrap();
        assert!(matches!(event(output), Event::Review { .. }));
    }
    fn revoked(control: &Control) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while control.check().is_ok() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn real_approval_progress_and_cancel_revoke_watched_io_but_deliver_terminal_outcome() {
        let (mut control, mut user, mut output) = fixture();
        review(&mut control, &mut output);
        approve(&mut user);
        assert!(control.wait_approval().unwrap());
        control.progress(Phase::Copying, 0).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Progress { bytes: 0, .. }
        ));
        control.progress(Phase::Copying, 2).unwrap();
        assert!(control.progress(Phase::Copying, 1).is_err());
        let (waiting, _held) = UnixStream::pair().unwrap();
        let mut waiting =
            Channel::new(File::from(OwnedFd::from(waiting)), Duration::from_secs(30)).unwrap();
        waiting.watch(control.watch().unwrap());
        let blocked = std::thread::spawn(move || waiting.read(&mut [0]));
        writeln!(
            user,
            "{{\"action\":\"cancel\",\"operation_id\":\"{}\"}}",
            identity().operation_id
        )
        .unwrap();
        revoked(&control);
        assert!(blocked.join().unwrap().is_err());
        assert!(control.progress(Phase::Copying, 3).is_err());
        control.finish(Outcome::Interrupted, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::Interrupted,
                receipt: None,
                ..
            }
        ));
    }

    #[test]
    fn all_mapping_pages_and_their_exact_digest_are_required_before_review() {
        let (mut control, _user, mut output) = fixture();
        assert!(control.review(summary()).is_err());
        let plan = Plan::new(
            &(0..5)
                .map(|index| oblivion_transfer::selection::Input {
                    path: format!("/private/{index}/note"),
                    directory: false,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        control.plan(&plan).unwrap();
        for (start, length) in [(0, 4), (4, 1)] {
            let Event::Mapping {
                identity: observed,
                start: observed_start,
                total,
                selected,
                entries,
                mapping_sha256,
            } = event(&mut output)
            else {
                panic!("mapping page required")
            };
            assert_eq!(observed, identity());
            assert_eq!((observed_start, total, entries.len()), (start, 5, length));
            assert_eq!(selected, "selection");
            assert_eq!(mapping_sha256, plan.sha256().unwrap());
            assert_eq!(entries, plan.mappings[start..start + length]);
        }
        assert!(control.plan(&plan).is_err());
        assert!(control.review(summary()).is_err());
        let mut summary = summary();
        summary.mapping_sha256 = plan.sha256().unwrap();
        assert!(control.review(summary.clone()).is_err());
        summary.entries = 6;
        summary.files = 5;
        control.review(summary).unwrap();
        assert!(matches!(event(&mut output), Event::Review { .. }));
        assert!(control.plan(&plan).is_err());
    }

    #[test]
    fn buffered_premature_or_duplicate_approval_and_eof_are_not_approval() {
        let (input, mut user) = UnixStream::pair().unwrap();
        let (output, _reader) = UnixStream::pair().unwrap();
        approve(&mut user);
        let mut control = Control::new(
            File::from(OwnedFd::from(input)),
            File::from(OwnedFd::from(output)),
            identity(),
            Direction::Import,
            "note".into(),
        )
        .unwrap();
        assert!(control.review(summary()).is_err());
        revoked(&control);
        let (mut control, mut user, mut output) = fixture();
        review(&mut control, &mut output);
        approve(&mut user);
        assert!(control.wait_approval().unwrap());
        approve(&mut user);
        revoked(&control);
        let (mut control, user, mut output) = fixture();
        review(&mut control, &mut output);
        drop(user);
        assert!(control.wait_approval().is_err());
        revoked(&control);
    }

    #[test]
    fn explicit_preparation_cancel_is_honest_and_drop_joins_an_idle_reader() {
        let (mut control, mut user, mut output) = fixture();
        writeln!(
            user,
            "{{\"action\":\"cancel\",\"operation_id\":\"{}\"}}",
            identity().operation_id
        )
        .unwrap();
        revoked(&control);
        assert!(control.cancelled_before_copy());
        control.review(summary()).unwrap();
        assert!(!control.wait_approval().unwrap());
        control.finish(Outcome::CancelledBeforeCopy, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::CancelledBeforeCopy,
                ..
            }
        ));
        let (control, _still_open_input, _output) = fixture();
        let (closed, waiting) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            drop(control);
            closed.send(()).unwrap();
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn completion_requires_the_reviewed_receipt_after_real_copy_totals() {
        let (mut control, mut user, mut output) = fixture();
        review(&mut control, &mut output);
        approve(&mut user);
        assert!(control.wait_approval().unwrap());
        control.progress(Phase::Copying, 8).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Progress {
                phase: Phase::Copying,
                bytes: 8,
                ..
            }
        ));
        control.progress(Phase::Finalizing, 8).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Progress {
                phase: Phase::Finalizing,
                bytes: 8,
                ..
            }
        ));
        assert!(
            control
                .finish(
                    Outcome::Completed,
                    Some(Receipt {
                        id: identity().operation_id,
                        manifest_sha256: "e".repeat(64),
                        entries: 1,
                        bytes: 8
                    })
                )
                .is_err()
        );
        control
            .finish(
                Outcome::Completed,
                Some(Receipt {
                    id: identity().operation_id,
                    manifest_sha256: summary().manifest_sha256,
                    entries: 1,
                    bytes: 8,
                }),
            )
            .unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::Completed,
                receipt: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn malformed_and_oversized_input_revoke_without_more_progress() {
        for bytes in [
            b"not json\n".to_vec(),
            vec![b'x'; native_file_events::LINE_LIMIT + 1],
        ] {
            let (control, mut user, _output) = fixture();
            user.write_all(&bytes).unwrap();
            revoked(&control);
            assert!(!control.cancelled_before_copy());
        }
    }

    #[test]
    fn cancellation_interrupts_a_full_stdout_without_holding_approval_mutex() {
        let (input, mut user) = UnixStream::pair().unwrap();
        let (mut output, reader) = UnixStream::pair().unwrap();
        let mut control = Control::new(
            File::from(OwnedFd::from(input)),
            File::from(OwnedFd::from(output.try_clone().unwrap())),
            identity(),
            Direction::Import,
            "note".into(),
        )
        .unwrap();
        control.plan(&plan()).unwrap();
        let mut unread = BufReader::new(reader);
        assert!(matches!(event(&mut unread), Event::Mapping { .. }));
        output.set_nonblocking(true).unwrap();
        let mut filled = 0;
        loop {
            match output.write(&[0; 4096]) {
                Ok(bytes) => filled += bytes,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                result => panic!("unexpected fill result: {result:?}"),
            }
        }
        assert!(filled > 0);
        let shared = Arc::clone(&control.shared);
        let started = Instant::now();
        let writer = std::thread::spawn(move || control.review(summary()));
        loop {
            if matches!(shared.state.lock().unwrap().stage, Stage::Review(_)) {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(1));
        }
        writeln!(
            user,
            "{{\"action\":\"cancel\",\"operation_id\":\"{}\"}}",
            identity().operation_id
        )
        .unwrap();
        assert_eq!(
            writer.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(started.elapsed() < OUTPUT_BUDGET * 2);
    }

    #[test]
    fn event_mode_rejects_ttys_without_changing_their_open_file_flags() {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let _master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let parent = slave.try_clone().unwrap();
        let before = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFL) };
        let (output, _reader) = UnixStream::pair().unwrap();
        assert!(
            Control::new(
                slave,
                File::from(OwnedFd::from(output)),
                identity(),
                Direction::Import,
                "note".into()
            )
            .is_err()
        );
        assert_eq!(
            unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFL) },
            before
        );
    }
}
