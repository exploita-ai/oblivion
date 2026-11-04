//! Windows controller adapter for the common frontend. The trusted runtime
//! supervisor supplies the elected runtime ID; discovery/startup live above it.
use crate::controller::{Call, Controller, Result};
use crate::run;
use crate::windows_terminal::{self, Terminal};
use oblivion_native_windows::{client, supervisor};
use oblivion_wire::agent::{Command, Launch, Size};
use oblivion_wire::control::{Operation, Request};
use oblivion_wire::idle;
use oblivion_wire::slot::Slot;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct Client {
    transport: client::Client,
    cancelled: Arc<AtomicBool>,
}

/// A clonable, one-way cancellation capability for a synchronous request or
/// attachment. A signal/input owner can hold it while the client is borrowed.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Client {
    pub fn new(runtime_id: &str) -> Result<Self> {
        Ok(Self {
            transport: client::Client::new(runtime_id)?,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Cancellation revokes this client instance. A new opening must construct
    /// a new client rather than clearing an old cancellation capability.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn cancellation(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.cancelled))
    }

    pub fn attach(&self, call: Call<'_, Slot>) -> Result<(client::Channel, String)> {
        if !call.operation.is_attachment() {
            return Err("invalid_attachment".into());
        }
        self.transport.attach(
            header(&call)?,
            call.secret,
            Arc::clone(&self.cancelled),
            Instant::now() + call.operation.response_budget(),
        )
    }

    fn request_before(&mut self, call: Call<'_, Slot>, deadline: Instant) -> Result<String> {
        self.transport.request(
            header(&call)?,
            call.secret,
            Arc::clone(&self.cancelled),
            deadline,
        )
    }
}

impl Controller for Client {
    type Slot = Slot;

    fn request(&mut self, call: Call<'_, Self::Slot>) -> Result<String> {
        let deadline = Instant::now() + call.operation.response_budget();
        self.request_before(call, deadline)
    }
}

/// Platform hooks for the common launch/storage/administration workflows. The
/// owning supervisor must elect and authenticate the runtime before construction.
pub struct Runtime {
    runtime_id: String,
    client: Client,
    terminal: Option<Terminal>,
    // Kept until terminal/controller handles have been released. Another
    // terminal owns its own lease on the same supervisor and controller VM.
    _supervision: Option<supervisor::Lease>,
}

impl Runtime {
    pub fn new(runtime_id: &str) -> Result<Self> {
        Ok(Self {
            runtime_id: runtime_id.to_owned(),
            client: Client::new(runtime_id)?,
            terminal: None,
            _supervision: None,
        })
    }

    pub fn supervised(
        settings: &supervisor::Settings,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self> {
        let lease = supervisor::acquire(settings, Arc::clone(&stop), deadline)?;
        Self::with_supervision(lease, stop)
    }

    pub fn initialize(
        settings: &supervisor::Settings,
        bytes: u64,
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self> {
        let lease = supervisor::initialize(settings, bytes, Arc::clone(&stop), deadline)?;
        Self::with_supervision(lease, stop)
    }

    fn with_supervision(lease: supervisor::Lease, stop: Arc<AtomicBool>) -> Result<Self> {
        let mut runtime = Self::new(lease.runtime_id())?;
        runtime.client.cancelled = stop;
        runtime._supervision = Some(lease);
        Ok(runtime)
    }

    /// Embedders may supply owned stdio handles without changing the process's
    /// global handles. Management commands do not require terminal discovery.
    pub fn with_terminal(runtime_id: &str, terminal: Terminal) -> Result<Self> {
        let mut runtime = Self::new(runtime_id)?;
        runtime.terminal = Some(terminal);
        Ok(runtime)
    }

    pub fn cancellation(&self) -> Cancellation {
        self.client.cancellation()
    }

    pub fn file_query<T: serde::de::DeserializeOwned>(
        &mut self,
        opening: &idle::Opening<Slot>,
        request: &oblivion_transfer::native_files::Request,
    ) -> Result<T> {
        let (mut channel, client) = self.client.attach(Call {
            operation: Operation::FileAttach,
            slot: Some(opening.slot),
            session: None,
            expected_session: Some(&opening.safe_id),
            secret: &serde_json::to_vec(opening).map_err(|_| "invalid_file_opening")?,
        })?;
        let result = (|| -> Result<T> {
            channel.set_deadline(Instant::now() + Duration::from_secs(60))?;
            oblivion_transfer::endpoint::write_message(&mut channel, request)?;
            channel.flush()?;
            Ok(oblivion_transfer::endpoint::read_message(
                &mut channel,
                8192,
            )?)
        })();
        // Keep the attachment alive through release, even after malformed or
        // truncated metadata. EOF alone is not proof of controller cleanup.
        let released = self.client.request(Call {
            operation: Operation::AgentRelease,
            slot: Some(opening.slot),
            session: Some(&client),
            expected_session: Some(&opening.safe_id),
            secret: &[],
        });
        let closed = channel.close();
        released?;
        closed?;
        result
    }

    fn host_activity(&mut self) -> Result<Option<Activity>> {
        crate::activity::current_host(&mut self.client)?
            .map(|activity| Activity::new(&self.runtime_id, activity))
            .transpose()
    }

    fn terminal_size(&mut self) -> Result<Option<Size>> {
        if self.terminal.is_none() {
            self.terminal = Some(Terminal::stdio()?);
        }
        self.terminal.as_ref().ok_or("terminal_unavailable")?.size()
    }

    fn attach_command(&mut self, slot: Slot, id: &str, command: &Command<'_>) -> Result<i32> {
        let mut activity = if self.terminal_size()?.is_some() {
            Some(Activity::new(
                &self.runtime_id,
                crate::activity::current_safe(&mut self.client, slot, id)?,
            )?)
        } else {
            None
        };
        let (mut channel, client) = self.client.attach(Call {
            operation: Operation::AgentAttach,
            slot: Some(slot),
            session: None,
            expected_session: Some(id),
            secret: &[],
        })?;
        let result = self
            .terminal
            .as_ref()
            .ok_or("terminal_unavailable")?
            .attach(&mut channel, command, |at| {
                if let Some(activity) = activity.as_mut() {
                    activity.touch(at);
                }
            });
        drop(activity);
        let released = self.client.request(Call {
            operation: Operation::AgentRelease,
            slot: Some(slot),
            session: Some(&client),
            expected_session: Some(id),
            secret: &[],
        });
        let closed = channel.close();
        result.and_then(|code| released.and(closed.map_err(Into::into)).map(|_| code))
    }
}

impl Controller for Runtime {
    type Slot = Slot;

    fn request(&mut self, call: Call<'_, Slot>) -> Result<String> {
        self.client.request(call)
    }
}

impl run::Runtime for Runtime {
    type Mark = Instant;

    fn slots(&self) -> Vec<Slot> {
        (0..oblivion_wire::slot::LIMIT)
            .filter_map(|index| Slot::try_from(index).ok())
            .collect()
    }

    fn password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        let mut activity = self.host_activity()?;
        windows_terminal::password(label, 0, |at| {
            if let Some(activity) = activity.as_mut() {
                activity.touch(at);
            }
        })
    }

    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        let mut activity = self.host_activity()?;
        windows_terminal::new_password(label, |at| {
            if let Some(activity) = activity.as_mut() {
                activity.touch(at);
            }
        })
    }

    fn confirm(&mut self, word: &'static str) -> Result<bool> {
        let mut activity = self.host_activity()?;
        windows_terminal::confirm(word, |at| {
            if let Some(activity) = activity.as_mut() {
                activity.touch(at);
            }
        })
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn elapsed(&self, start: &Instant) -> Duration {
        start.elapsed()
    }

    fn wait(&mut self, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        loop {
            if self.client.cancelled.load(Ordering::Acquire) {
                return Err("controller_cancelled".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(50)));
        }
    }

    fn notice(&mut self, notice: run::Notice<'_>) -> Result<()> {
        notice.write(&mut std::io::stderr().lock())
    }

    fn attach(&mut self, slot: Slot, id: &str, agent: &str, argv: &[String]) -> Result<i32> {
        let launch = Launch {
            agent: agent.to_owned(),
            argv: argv.to_vec(),
            terminal: self.terminal_size()?,
            managed: None,
        };
        launch.validate()?;
        self.attach_command(slot, id, &Command::Agent(&launch))
    }

    fn attach_workspace(&mut self, slot: Slot, id: &str) -> Result<i32> {
        let terminal = self
            .terminal_size()?
            .ok_or("Workspace requires an interactive terminal")?;
        self.attach_command(slot, id, &Command::Workspace { terminal })
    }
}

/// Only opening identities and monotonic input timestamps enter this bounded
/// worker. Slow controller I/O cannot block the terminal or replay stale input.
struct Activity {
    sender: Option<SyncSender<Instant>>,
    cancellation: Cancellation,
    worker: Option<JoinHandle<()>>,
    sent: Option<Instant>,
}

impl Activity {
    fn new(runtime_id: &str, activity: idle::Activity<Slot>) -> Result<Self> {
        let mut client = ActivityController(Client::new(runtime_id)?);
        let cancellation = client.0.cancellation();
        let (sender, receiver) = sync_channel::<Instant>(1);
        let worker = std::thread::Builder::new()
            .name("oblivion-activity".into())
            .spawn(move || {
                for at in receiver {
                    if at.elapsed() <= Duration::from_secs(2) {
                        let _ = crate::activity::report(&mut client, &activity);
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            cancellation,
            worker: Some(worker),
            sent: None,
        })
    }

    fn touch(&mut self, now: Instant) {
        if self
            .sent
            .is_some_and(|sent| now.saturating_duration_since(sent) < Duration::from_secs(1))
        {
            return;
        }
        if self
            .sender
            .as_ref()
            .is_some_and(|sender| sender.try_send(now).is_ok())
        {
            self.sent = Some(now);
        }
    }
}

struct ActivityController(Client);

impl Controller for ActivityController {
    type Slot = Slot;

    fn request(&mut self, call: Call<'_, Slot>) -> Result<String> {
        self.0
            .request_before(call, Instant::now() + Duration::from_secs(1))
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn header(call: &Call<'_, Slot>) -> Result<Request<Slot>> {
    Ok(Request {
        operation: call.operation,
        slot: call.slot.unwrap_or(Slot::ZERO),
        expected_session: call.expected_session.map(str::to_owned),
        session: call.session.map(str::to_owned),
        secret_len: u32::try_from(call.secret.len()).map_err(|_| "secret_too_large")?,
    })
}
