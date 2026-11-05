//! Windows pipe I/O for the shared Files consent flow. One owned reader and
//! writer retain their handles/buffers until cancellation has really drained.
use crate::windows_io::{cancel_and_join, duplicate};
use oblivion_transfer::Receipt;
use oblivion_transfer::file_consent::{Admission, Flow, Review, Stage, revoked};
use oblivion_transfer::native_file_events::{self, Event, Identity, Outcome, Phase, Summary};
use oblivion_transfer::native_files::Direction;
use oblivion_transfer::selection::Plan;
use std::fs::File;
use std::io::{self, Write};
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

const BUDGET: Duration = Duration::from_secs(3600);
const OUTPUT_BUDGET: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_millis(5);

struct Shared {
    admission: Mutex<Admission>,
    changed: Condvar,
    cancellation: Arc<AtomicBool>,
}
impl Shared {
    fn revoke(&self) {
        self.cancellation.store(true, Ordering::Release);
        self.changed.notify_all();
    }
    fn fail(&self) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.fail()
        }
        self.revoke();
    }
}

pub struct Control {
    flow: Flow,
    shared: Arc<Shared>,
    input: File,
    input_stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    output: Output,
    deadline: Instant,
}

impl Control {
    pub fn stdio(identity: Identity, direction: Direction, name: String) -> io::Result<Self> {
        Self::new(
            duplicate(unsafe { GetStdHandle(STD_INPUT_HANDLE) })?,
            duplicate(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })?,
            identity,
            direction,
            name,
        )
    }

    pub fn new(
        input: File,
        output: File,
        identity: Identity,
        direction: Direction,
        name: String,
    ) -> io::Result<Self> {
        for file in [&input, &output] {
            if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_PIPE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file_events_require_pipes",
                ));
            }
        }
        let (flow, admission) = Flow::new(identity, direction, name)?;
        let shared = Arc::new(Shared {
            admission: Mutex::new(admission),
            changed: Condvar::new(),
            cancellation: Arc::new(AtomicBool::new(false)),
        });
        let input_stop = Arc::new(AtomicBool::new(false));
        let state = Arc::clone(&shared);
        let stopped = Arc::clone(&input_stop);
        let reader_input = input.try_clone()?;
        let deadline = Instant::now() + BUDGET;
        let output = Output::new(output, OUTPUT_BUDGET)?;
        let reader = std::thread::Builder::new()
            .name("oblivion-files-input".into())
            .spawn(move || {
                if read_input(reader_input, &state, &stopped, deadline).is_err()
                    && !stopped.load(Ordering::Acquire)
                {
                    state.fail();
                }
                state.changed.notify_all();
            })?;
        Ok(Self {
            flow,
            shared,
            input,
            input_stop,
            reader: Some(reader),
            output,
            deadline,
        })
    }

    pub fn cancellation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shared.cancellation)
    }

    pub fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            self.shared.revoke()
        }
        if self.shared.cancellation.load(Ordering::Acquire) {
            return Err(revoked());
        }
        Ok(())
    }

    pub fn cancelled_before_copy(&self) -> bool {
        self.shared
            .admission
            .lock()
            .is_ok_and(|admission| matches!(admission.stage(), Stage::CancelledBeforeCopy))
    }

    pub fn plan(&mut self, plan: &Plan) -> io::Result<()> {
        let mapping = {
            let admission = self.shared.admission.lock().map_err(|_| revoked())?;
            self.flow.plan(&admission, plan)?
        };
        for event in mapping.events() {
            self.emit(event, true)?
        }
        self.check()?;
        let admission = self.shared.admission.lock().map_err(|_| revoked())?;
        self.flow.mapped(&admission, mapping)
    }

    pub fn review(&mut self, summary: Summary) -> io::Result<()> {
        let shared = Arc::clone(&self.shared);
        let mut admission = shared.admission.lock().map_err(|_| revoked())?;
        loop {
            let ready = match available(&self.input) {
                Ok(ready) => ready,
                Err(error) => {
                    admission.fail();
                    shared.revoke();
                    return Err(error);
                }
            };
            match self.flow.review(
                &mut admission,
                &summary,
                ready.is_none_or(|bytes| bytes > 0),
            )? {
                Review::Waiting if ready.is_none() => {
                    let result = admission.eof();
                    shared.revoke();
                    return result;
                }
                Review::Waiting => admission = self.wait(&shared, admission)?,
                Review::CancelledBeforeCopy => return Ok(()),
                Review::Ready(event) => {
                    drop(admission);
                    return self.emit(&event, true);
                }
            }
        }
    }

    pub fn wait_approval(&self) -> io::Result<bool> {
        let mut admission = self.shared.admission.lock().map_err(|_| revoked())?;
        loop {
            match admission.stage() {
                Stage::Approved => {
                    self.check()?;
                    return Ok(true);
                }
                Stage::CancelledBeforeCopy => return Ok(false),
                Stage::Review(_) => admission = self.wait(&self.shared, admission)?,
                _ => return Err(revoked()),
            }
        }
    }

    fn wait<'a>(
        &self,
        shared: &'a Shared,
        admission: MutexGuard<'a, Admission>,
    ) -> io::Result<MutexGuard<'a, Admission>> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(revoked)?;
        let (admission, timeout) = shared
            .changed
            .wait_timeout(admission, remaining)
            .map_err(|_| revoked())?;
        if timeout.timed_out() {
            shared.revoke();
            return Err(revoked());
        }
        Ok(admission)
    }

    pub fn progress(&mut self, phase: Phase, bytes: u64) -> io::Result<()> {
        self.check()?;
        let event = {
            let admission = self.shared.admission.lock().map_err(|_| revoked())?;
            self.flow
                .progress(&admission, phase, bytes, Instant::now())?
        };
        if let Some(event) = event {
            self.emit(&event, true)?
        }
        Ok(())
    }

    pub fn finish(&mut self, outcome: Outcome, receipt: Option<Receipt>) -> io::Result<()> {
        if outcome == Outcome::Completed {
            self.check()?
        }
        let event = {
            let admission = self.shared.admission.lock().map_err(|_| revoked())?;
            self.flow.finish(&admission, outcome, receipt)?
        };
        self.emit(&event, false)
    }

    fn emit(&mut self, event: &Event, watched: bool) -> io::Result<()> {
        let bytes = native_file_events::encode(event)?;
        if watched {
            self.check()?
        }
        let result = self
            .output
            .write(bytes, watched.then(|| self.cancellation()));
        if result.is_err() {
            self.shared.fail()
        }
        result
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.shared.revoke();
        if let Some(reader) = self.reader.take() {
            let _ = cancel_and_join(reader, &self.input_stop);
        }
        let _ = self.output.stop();
    }
}

fn available(input: &File) -> io::Result<Option<usize>> {
    let mut count = 0;
    if unsafe {
        PeekNamedPipe(
            input.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &mut count,
            null_mut(),
        )
    } == 0
    {
        if matches!(
            unsafe { GetLastError() },
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ) {
            return Ok(None);
        }
        return Err(io::Error::last_os_error());
    }
    Ok(Some(count as usize))
}

fn read_input(
    input: File,
    shared: &Shared,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    let mut bytes = [0u8; 1024];
    while !stopped.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            return Err(revoked());
        }
        let mut admission = shared.admission.lock().map_err(|_| revoked())?;
        let Some(available) = available(&input)? else {
            return admission.eof();
        };
        let count = available.min(bytes.len());
        if count > 0 {
            let mut read = 0;
            let success = unsafe {
                ReadFile(
                    input.as_raw_handle(),
                    bytes.as_mut_ptr(),
                    count as u32,
                    &mut read,
                    null_mut(),
                )
            };
            if success == 0 && unsafe { GetLastError() } != ERROR_MORE_DATA {
                return Err(revoked());
            }
            if read == 0 {
                return admission.eof();
            }
            if admission.feed(&bytes[..read as usize])? {
                shared.revoke();
                return Ok(());
            }
            shared.changed.notify_all();
        }
        drop(admission);
        std::thread::sleep(TICK);
    }
    Ok(())
}

struct Job {
    bytes: Vec<u8>,
    done: SyncSender<io::Result<()>>,
}
struct Output {
    jobs: Option<SyncSender<Job>>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    budget: Duration,
}
impl Output {
    fn new(file: File, budget: Duration) -> io::Result<Self> {
        let (send, receive) = mpsc::sync_channel::<Job>(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let worker = std::thread::Builder::new()
            .name("oblivion-files-output".into())
            .spawn(move || write_output(file, receive, &stop))?;
        Ok(Self {
            jobs: Some(send),
            stopped,
            worker: Some(worker),
            budget,
        })
    }

    fn write(&mut self, bytes: Vec<u8>, watch: Option<Arc<AtomicBool>>) -> io::Result<()> {
        if bytes.len() > native_file_events::LINE_LIMIT || self.stopped.load(Ordering::Acquire) {
            return Err(revoked());
        }
        let deadline = Instant::now() + self.budget;
        if watch
            .as_ref()
            .is_some_and(|cancel| cancel.load(Ordering::Acquire))
        {
            return Err(revoked());
        }
        let (send, receive) = mpsc::sync_channel(1);
        self.jobs
            .as_ref()
            .ok_or_else(revoked)?
            .try_send(Job { bytes, done: send })
            .map_err(|_| revoked())?;
        loop {
            if Instant::now() >= deadline
                || watch
                    .as_ref()
                    .is_some_and(|cancel| cancel.load(Ordering::Acquire))
            {
                self.stop()?;
                return Err(revoked());
            }
            match receive.try_recv() {
                Ok(result) => return result,
                Err(TryRecvError::Disconnected) => return Err(revoked()),
                Err(TryRecvError::Empty) => {}
            }
            std::thread::sleep(TICK);
        }
    }

    fn stop(&mut self) -> io::Result<()> {
        self.jobs.take();
        if let Some(worker) = self.worker.take() {
            cancel_and_join(worker, &self.stopped)?
        }
        Ok(())
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn write_output(mut output: File, jobs: Receiver<Job>, stopped: &AtomicBool) {
    while !stopped.load(Ordering::Acquire) {
        let job = match jobs.recv_timeout(TICK) {
            Ok(job) => job,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let result = (|| {
            let mut written = 0;
            while written < job.bytes.len() {
                if stopped.load(Ordering::Acquire) {
                    return Err(revoked());
                }
                match output.write(&job.bytes[written..]) {
                    Ok(0) => return Err(revoked()),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            if stopped.load(Ordering::Acquire) {
                return Err(revoked());
            }
            output.flush()
        })();
        let failed = result.is_err();
        let _ = job.done.try_send(result);
        if failed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Control, Output, available};
    use oblivion_transfer::Receipt;
    use oblivion_transfer::native_file_events::{
        self, Event, Identity, LINE_LIMIT, Outcome, Phase, Summary,
    };
    use oblivion_transfer::native_files::Direction;
    use oblivion_transfer::selection::{Input, Plan};
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Pipes::{CreatePipe, GetNamedPipeInfo};

    fn pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, null_mut(), 8192) },
            0
        );
        unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) }
    }
    fn identity() -> Identity {
        Identity {
            operation_id: "a".repeat(32),
            safe_id: "b".repeat(32),
            opening: "c".repeat(32),
        }
    }
    fn plan() -> Plan {
        Plan::new(&[Input {
            path: "C:/Documents/note".into(),
            directory: false,
        }])
        .unwrap()
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
    fn fixture() -> (Control, File, BufReader<File>) {
        let (input, user) = pipe();
        let (reader, output) = pipe();
        (
            Control::new(input, output, identity(), Direction::Import, "note".into()).unwrap(),
            user,
            BufReader::new(reader),
        )
    }
    fn event(reader: &mut BufReader<File>) -> Event {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn review(control: &mut Control, output: &mut BufReader<File>) {
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
    fn approval() -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&native_file_events::Input::Approve {
            operation_id: identity().operation_id,
            manifest_sha256: summary().manifest_sha256,
        })
        .unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn approve(user: &mut File) {
        user.write_all(&approval()).unwrap()
    }
    fn cancel(user: &mut File) {
        serde_json::to_writer(
            &mut *user,
            &native_file_events::Input::Cancel {
                operation_id: identity().operation_id,
            },
        )
        .unwrap();
        user.write_all(b"\n").unwrap();
    }
    fn revoked(control: &Control) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while control.check().is_ok() {
            assert!(Instant::now() < deadline, "input did not revoke the copy");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(control.cancellation().load(Ordering::Acquire));
    }

    #[test]
    fn real_pipes_approve_progress_cancel_and_deliver_one_terminal_outcome() {
        let (mut control, mut user, mut output) = fixture();
        review(&mut control, &mut output);
        approve(&mut user);
        assert!(control.wait_approval().unwrap());
        control.progress(Phase::Copying, 0).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Progress { bytes: 0, .. }
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
        cancel(&mut user);
        revoked(&control);
        assert!(!control.cancelled_before_copy());
        control.finish(Outcome::Interrupted, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::Interrupted,
                receipt: None,
                ..
            }
        ));
        assert!(control.finish(Outcome::Interrupted, None).is_err());
        drop(control);
        let mut end = String::new();
        assert_eq!(output.read_line(&mut end).unwrap(), 0);
    }

    #[test]
    fn cancel_before_review_is_distinct_from_unexpected_parent_eof() {
        let (mut control, mut user, mut output) = fixture();
        cancel(&mut user);
        revoked(&control);
        assert!(control.cancelled_before_copy());
        assert!(!control.wait_approval().unwrap());
        control.finish(Outcome::CancelledBeforeCopy, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::CancelledBeforeCopy,
                ..
            }
        ));
        drop(control);
        let (mut control, user, mut output) = fixture();
        drop(user);
        revoked(&control);
        assert!(!control.cancelled_before_copy());
        assert!(control.finish(Outcome::CancelledBeforeCopy, None).is_err());
        control.finish(Outcome::Interrupted, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::Interrupted,
                ..
            }
        ));
    }

    #[test]
    fn admitted_cancel_before_copy_survives_parent_eof_during_review() {
        let (mut control, mut user, mut output) = fixture();
        cancel(&mut user);
        revoked(&control);
        drop(user);
        control.review(summary()).unwrap();
        assert!(!control.wait_approval().unwrap());
        assert!(control.cancelled_before_copy());
        control.finish(Outcome::CancelledBeforeCopy, None).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::CancelledBeforeCopy,
                ..
            }
        ));
    }

    #[test]
    fn input_already_buffered_before_review_cannot_approve() {
        let (mut control, mut user, mut output) = fixture();
        control.plan(&plan()).unwrap();
        assert!(matches!(event(&mut output), Event::Mapping { .. }));
        let approval = approval();
        user.write_all(&approval[..20]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while control.shared.admission.lock().unwrap().pending() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = control.review(summary());
            send.send(result.is_err()).unwrap();
        });
        user.write_all(&approval[20..]).unwrap();
        assert!(receive.recv_timeout(Duration::from_secs(3)).unwrap());
        worker.join().unwrap();
        assert_eq!(available(output.get_ref()).unwrap().unwrap_or(0), 0);
    }

    #[test]
    fn completion_requires_the_shared_flows_exact_approved_receipt() {
        let (mut control, mut user, mut output) = fixture();
        review(&mut control, &mut output);
        approve(&mut user);
        assert!(control.wait_approval().unwrap());
        let wrong = Receipt {
            id: identity().operation_id,
            manifest_sha256: summary().manifest_sha256,
            entries: 1,
            bytes: 7,
        };
        assert!(control.finish(Outcome::Completed, Some(wrong)).is_err());
        let receipt = Receipt {
            id: identity().operation_id,
            manifest_sha256: summary().manifest_sha256,
            entries: 1,
            bytes: 8,
        };
        control.finish(Outcome::Completed, Some(receipt)).unwrap();
        assert!(matches!(
            event(&mut output),
            Event::Finished {
                outcome: Outcome::Completed,
                receipt: Some(Receipt { bytes: 8, .. }),
                ..
            }
        ));
    }

    #[test]
    fn backpressured_output_cancels_and_joins_before_releasing_its_pipe_buffer() {
        let (mut reader, write) = pipe();
        let mut out = 0;
        let mut input = 0;
        assert_ne!(
            unsafe {
                GetNamedPipeInfo(
                    write.as_raw_handle(),
                    null_mut(),
                    &mut out,
                    &mut input,
                    null_mut(),
                )
            },
            0
        );
        let capacity = out.max(input) as usize;
        assert!(capacity > 0 && capacity <= 1024 * 1024);
        let mut output = Output::new(write, Duration::from_millis(20)).unwrap();
        let mut blocked = false;
        for _ in 0..capacity / LINE_LIMIT + 2 {
            if output.write(vec![b'x'; LINE_LIMIT], None).is_err() {
                blocked = true;
                break;
            }
        }
        assert!(blocked);
        assert!(output.worker.is_none());
        assert!(output.write(b"late\n".to_vec(), None).is_err());
        drop(output);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn events_refuse_non_pipe_standard_streams() {
        let (input, _user) = pipe();
        let output = OpenOptions::new().write(true).open("NUL").unwrap();
        assert!(Control::new(input, output, identity(), Direction::Import, "note".into()).is_err());
    }
}
