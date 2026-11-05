//! Windows controller adapter for the common frontend. The trusted runtime
//! supervisor supplies the elected runtime ID; discovery/startup live above it.
use crate::controller::{Call, Controller, Result};
use crate::run;
use crate::windows_terminal::{self, Terminal};
use oblivion_native_windows::{broker, client};
use oblivion_wire::agent::{Command, Launch, Size};
use oblivion_wire::control::{Operation, Request};
use oblivion_wire::idle;
use oblivion_wire::slot::Slot;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
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

/// An attachment owns both its data stream and a quiet kernel lease. Revoking
/// data I/O never substitutes for an explicit controller release acknowledgement.
pub struct FileAttachment {
    runtime_id: String,
    slot: Slot,
    safe_id: String,
    client_id: String,
    stream: FileStream,
    lease: Option<client::Lease>,
    stop: Arc<AtomicBool>,
    released: bool,
}

pub struct FileStream(client::Channel);

/// Share's source data and its export authorization are separate connections.
/// The source watches only a passive signal, never another source's payload.
pub struct ShareStream {
    stream: FileStream,
    export: Option<Arc<Mutex<ExportSignal>>>,
}

pub struct ShareAttachment {
    stream: ShareStream,
    client_id: String,
    lease: Option<client::Lease>,
}

pub struct ExportLease {
    runtime_id: String,
    signal: Arc<Mutex<ExportSignal>>,
    lease: Option<client::Lease>,
}

struct ExportSignal {
    channel: client::Channel,
    revoked: bool,
}

impl ExportSignal {
    fn check(&mut self) -> io::Result<()> {
        if self.revoked {
            return Err(export_revoked());
        }
        match self.channel.try_read(&mut [0]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => {
                self.revoked = true;
                self.channel.close()?;
                // No byte is part of the passive lease protocol. EOF, data,
                // cancellation and expiry all remove source authority.
                result.map_err(|_| export_revoked())?;
                Err(export_revoked())
            }
        }
    }
}

fn export_revoked() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "share_export_revoked")
}

impl crate::share::io::Lease for ExportLease {
    fn check(&mut self) -> io::Result<()> {
        self.signal.lock().map_err(|_| export_revoked())?.check()
    }
    fn close(&mut self) -> io::Result<()> {
        let result = match self.signal.lock() {
            Ok(mut signal) => {
                signal.revoked = true;
                signal.channel.close()
            }
            Err(_) => Err(export_revoked()),
        };
        drop(self.lease.take());
        result
    }
}

impl Drop for ExportLease {
    fn drop(&mut self) {
        // Watchers must not keep the authorization pipe alive after its owner
        // disappears. This is local close only; End policy remains in Core.
        let _ = crate::share::io::Lease::close(self);
    }
}

impl crate::share::io::Attachment for ShareAttachment {
    type Stream = ShareStream;
    fn stream(&mut self) -> &mut ShareStream {
        &mut self.stream
    }
    fn client_id(&self) -> &str {
        &self.client_id
    }
    fn close(&mut self) -> io::Result<()> {
        let result = self.stream.stream.0.close();
        drop(self.lease.take());
        result
    }
}

impl ShareStream {
    fn check_authority(&mut self) -> io::Result<()> {
        if let Some(export) = &self.export {
            let checked = export
                .lock()
                .map_err(|_| export_revoked())
                .and_then(|mut signal| signal.check());
            if let Err(error) = checked {
                self.stream.0.close()?;
                return Err(error);
            }
        }
        self.stream.0.check()
    }
}

impl Read for ShareStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.export.is_none() {
            return self.stream.read(output);
        }
        loop {
            self.check_authority()?;
            match self.stream.0.try_read(output) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.stream.0.wait_readable()?
                }
                result => {
                    self.check_authority()?;
                    return result;
                }
            }
        }
    }
}
impl Write for ShareStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.export.is_none() {
            return self.stream.write(input);
        }
        loop {
            self.check_authority()?;
            match self.stream.0.try_write(input) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.stream.0.wait_writable()?
                }
                result => {
                    self.check_authority()?;
                    return result;
                }
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.export.is_none() {
            return self.stream.flush();
        }
        loop {
            self.check_authority()?;
            match self.stream.0.try_flush() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.stream.0.wait_writable()?
                }
                result => {
                    self.check_authority()?;
                    return result;
                }
            }
        }
    }
}
impl oblivion_transfer::copy_protocol::Transport for ShareStream {
    fn check(&mut self) -> io::Result<()> {
        self.check_authority()
    }
}

/// Backup authority ends with this pipe, unlike an agent/FileAttachment. The
/// controller reconciles its own worker receipt after EOF; closing is no proof
/// that the encrypted volume was copied or that restoration committed.
pub struct BackupAttachment {
    stream: FileStream,
    stop: Arc<AtomicBool>,
}

impl BackupAttachment {
    pub fn stream(&mut self) -> &mut FileStream {
        &mut self.stream
    }
    pub fn cancellation(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.stop))
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.stream.0.close()
    }
}
impl FileAttachment {
    pub fn stream(&mut self) -> &mut FileStream {
        &mut self.stream
    }
    pub fn cancellation(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.stop))
    }
}
impl FileStream {
    pub fn set_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }
}
impl Read for FileStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output)
    }
}
impl Write for FileStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0.write(input)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl oblivion_transfer::copy_protocol::Transport for FileStream {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
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
    _supervision: Option<broker::Lease>,
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

    pub fn brokered(lease: broker::Lease, stop: Arc<AtomicBool>) -> Result<Self> {
        let mut runtime = Self::new(&lease.layout().runtime_id)?;
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

    pub fn attach_backup(
        &mut self,
        transaction: &str,
        slot: Slot,
        stop: Arc<AtomicBool>,
    ) -> Result<BackupAttachment> {
        if self.client.cancelled.load(Ordering::Acquire) {
            return Err("controller_cancelled".into());
        }
        if !oblivion_wire::control::valid_id(transaction) {
            return Err("invalid_backup_transaction".into());
        }
        let (mut channel, attached) = self.client.transport.attach(
            header(&Call {
                operation: Operation::BackupAttach,
                slot: Some(slot),
                session: Some(transaction),
                expected_session: None,
                secret: &[],
            })?,
            &[],
            Arc::clone(&stop),
            Instant::now() + Operation::BackupAttach.response_budget(),
        )?;
        if attached != transaction {
            channel.close()?;
            return Err("invalid_backup_attachment".into());
        }
        channel.set_deadline(Instant::now() + Duration::from_secs(3600))?;
        Ok(BackupAttachment {
            stream: FileStream(channel),
            stop,
        })
    }

    pub fn attach_file(
        &mut self,
        opening: &idle::Opening<Slot>,
        request: &oblivion_transfer::native_files::Request,
        stop: Arc<AtomicBool>,
    ) -> Result<FileAttachment> {
        use oblivion_transfer::native_files::Request;
        let (safe, nonce) = match request {
            Request::Import {
                safe_id, opening, ..
            }
            | Request::Transfers {
                safe_id, opening, ..
            }
            | Request::Status {
                safe_id, opening, ..
            }
            | Request::Recover {
                safe_id, opening, ..
            }
            | Request::Discard {
                safe_id, opening, ..
            } => (safe_id, opening),
        };
        if safe != &opening.safe_id || nonce != &opening.nonce {
            return Err("invalid_file_opening".into());
        }
        self.attach_file_request(opening, request, stop)
    }

    /// Export uses the existing dispatch frame, followed by the shared bounded
    /// offer exchange; lease ownership is identical to import and metadata.
    pub fn attach_file_export(
        &mut self,
        opening: &idle::Opening<Slot>,
        stop: Arc<AtomicBool>,
    ) -> Result<FileAttachment> {
        self.attach_file_request(opening, &serde_json::json!({"operation":"export"}), stop)
    }

    fn attach_file_request(
        &mut self,
        opening: &idle::Opening<Slot>,
        request: &impl serde::Serialize,
        stop: Arc<AtomicBool>,
    ) -> Result<FileAttachment> {
        if self.client.cancelled.load(Ordering::Acquire) {
            return Err("controller_cancelled".into());
        }
        if !oblivion_wire::control::valid_id(&opening.safe_id)
            || !oblivion_wire::control::valid_id(&opening.nonce)
        {
            return Err("invalid_file_opening".into());
        }
        let secret = serde_json::to_vec(opening).map_err(|_| "invalid_file_opening")?;
        let (mut channel, client_id) = self.client.transport.attach(
            header(&Call {
                operation: Operation::FileAttach,
                slot: Some(opening.slot),
                session: None,
                expected_session: Some(&opening.safe_id),
                secret: &secret,
            })?,
            &secret,
            Arc::clone(&stop),
            Instant::now() + Operation::FileAttach.response_budget(),
        )?;
        let retained = channel.retain_lease();
        let mut attachment = FileAttachment {
            runtime_id: self.runtime_id.clone(),
            slot: opening.slot,
            safe_id: opening.safe_id.clone(),
            client_id,
            stream: FileStream(channel),
            lease: None,
            stop,
            released: false,
        };
        match retained {
            Ok(lease) => attachment.lease = Some(lease),
            Err(error) => {
                self.release_file(&mut attachment)?;
                return Err(error.into());
            }
        }
        let sent = (|| -> Result<()> {
            attachment
                .stream
                .set_deadline(Instant::now() + Duration::from_secs(3600))?;
            oblivion_transfer::endpoint::write_message(&mut attachment.stream, request)?;
            attachment.stream.flush()?;
            Ok(())
        })();
        if let Err(error) = sent {
            self.release_file(&mut attachment)?;
            return Err(error);
        }
        Ok(attachment)
    }

    /// Cleanup uses a new cancellation scope. A cancelled copy must still be
    /// able to release its exact controller client before the quiet lease ends.
    /// Errors remain errors even though all local handles are closed fail-closed.
    pub fn release_file(&mut self, attachment: &mut FileAttachment) -> Result<()> {
        if attachment.runtime_id != self.runtime_id {
            return Err("invalid_file_attachment".into());
        }
        if attachment.released {
            return Ok(());
        }
        let released = Client::new(&self.runtime_id).and_then(|mut client| {
            client.request(Call {
                operation: Operation::AgentRelease,
                slot: Some(attachment.slot),
                session: Some(&attachment.client_id),
                expected_session: Some(&attachment.safe_id),
                secret: &[],
            })
        });
        let closed = attachment.stream.0.close();
        drop(attachment.lease.take());
        released?;
        closed?;
        attachment.released = true;
        Ok(())
    }

    pub fn file_query<T: serde::de::DeserializeOwned>(
        &mut self,
        opening: &idle::Opening<Slot>,
        request: &oblivion_transfer::native_files::Request,
    ) -> Result<T> {
        let mut attachment =
            self.attach_file(opening, request, Arc::new(AtomicBool::new(false)))?;
        let result = (|| -> Result<T> {
            attachment
                .stream
                .set_deadline(Instant::now() + Duration::from_secs(60))?;
            Ok(oblivion_transfer::endpoint::read_message(
                &mut attachment.stream,
                8192,
            )?)
        })();
        self.release_file(&mut attachment)?;
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

impl crate::share::io::Native for Runtime {
    type Attachment = ShareAttachment;
    type ExportLease = ExportLease;

    fn lease_share_export(&mut self, export: &str) -> Result<ExportLease> {
        if !oblivion_wire::control::valid_id(export) {
            return Err("invalid_share_export".into());
        }
        if self.client.cancelled.load(Ordering::Acquire) {
            return Err("controller_cancelled".into());
        }
        let (mut channel, attached) = self.client.transport.attach(
            header(&Call {
                operation: Operation::ShareExportLease,
                slot: Some(Slot::ZERO),
                session: Some(export),
                expected_session: None,
                secret: &[],
            })?,
            &[],
            Arc::clone(&self.client.cancelled),
            Instant::now() + Operation::ShareExportLease.response_budget(),
        )?;
        if attached != export {
            channel.close()?;
            return Err("invalid_share_export_lease".into());
        }
        let lease = channel.retain_lease()?;
        channel.set_deadline(Instant::now() + Duration::from_secs(3600))?;
        Ok(ExportLease {
            runtime_id: self.runtime_id.clone(),
            signal: Arc::new(Mutex::new(ExportSignal {
                channel,
                revoked: false,
            })),
            lease: Some(lease),
        })
    }

    fn attach_share_source(
        &mut self,
        opening: &idle::Opening<Slot>,
        lease: &mut ExportLease,
    ) -> Result<ShareAttachment> {
        if lease.runtime_id != self.runtime_id {
            return Err("invalid_share_export_lease".into());
        }
        crate::share::io::Lease::check(lease)?;
        self.share_attachment(
            Operation::ShareAttach,
            opening,
            Some(Arc::clone(&lease.signal)),
        )
    }

    fn attach_share_import(&mut self, opening: &idle::Opening<Slot>) -> Result<ShareAttachment> {
        self.share_attachment(Operation::ShareImportAttach, opening, None)
    }

    fn cleanup(&mut self, call: Call<'_, Slot>) -> Result<String> {
        Client::new(&self.runtime_id)?.request(call)
    }
}

impl Runtime {
    fn share_attachment(
        &mut self,
        operation: Operation,
        opening: &idle::Opening<Slot>,
        export: Option<Arc<Mutex<ExportSignal>>>,
    ) -> Result<ShareAttachment> {
        if !oblivion_wire::control::valid_id(&opening.safe_id)
            || !oblivion_wire::control::valid_id(&opening.nonce)
        {
            return Err("invalid_share_opening".into());
        }
        if self.client.cancelled.load(Ordering::Acquire) {
            return Err("controller_cancelled".into());
        }
        let (mut channel, client_id) = self.client.transport.attach(
            header(&Call {
                operation,
                slot: Some(opening.slot),
                session: None,
                expected_session: Some(&opening.safe_id),
                secret: &[],
            })?,
            &[],
            Arc::clone(&self.client.cancelled),
            Instant::now() + operation.response_budget(),
        )?;
        let lease = channel.retain_lease()?;
        channel.set_deadline(Instant::now() + Duration::from_secs(3600))?;
        Ok(ShareAttachment {
            stream: ShareStream {
                stream: FileStream(channel),
                export,
            },
            client_id,
            lease: Some(lease),
        })
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
