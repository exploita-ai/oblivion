//! Same-user named-pipe control client. The existing Native codec owns framing;
//! this adapter owns authentication, total exchange deadlines and pipe lifetime.
use crate::Error;
use crate::private::{self, Pipe};
use crate::security::Identity;
use oblivion_wire::control::{Request, valid_id};
use oblivion_wire::control_client::{self, Framing};
use oblivion_wire::slot::Slot;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Child;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION};

pub type BoxResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Client {
    name: Vec<u16>,
    identity: Identity,
    process: Option<OwnedHandle>,
}

/// One exclusive pipe owner; moving the channel transfers both read/write
/// ownership. RPC/attachment handshakes share an absolute deadline. Successful
/// attachment streams then remain governed by cancellation and transport EOF.
pub struct Channel {
    pipe: Pipe,
    stop: Arc<AtomicBool>,
    deadline: Option<Instant>,
    closed: bool,
    attachment: bool,
    retained: bool,
}

/// Opaque connection authority retained through explicit controller release.
/// Dropping it only closes a quiet kernel reference; it performs no RPC or I/O.
pub struct Lease {
    _pipe: private::Lease,
}

impl Client {
    pub fn new(runtime_id: &str) -> crate::Result<Self> {
        if !valid_id(runtime_id) || runtime_id.bytes().all(|byte| byte == b'0') {
            return Err(Error("invalid_runtime_identifier"));
        }
        Ok(Self {
            name: format!(r"\\.\pipe\oblivion.{runtime_id}.control")
                .encode_utf16()
                .chain(Some(0))
                .collect(),
            identity: Identity::current()?,
            process: None,
        })
    }

    pub(crate) fn for_child(runtime_id: &str, child: &Child) -> crate::Result<Self> {
        let mut client = Self::new(runtime_id)?;
        let mut process = null_mut();
        let current = unsafe { GetCurrentProcess() };
        if unsafe {
            DuplicateHandle(
                current,
                child.as_raw_handle(),
                current,
                &mut process,
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                0,
            )
        } == 0
        {
            return Err(Error("runtime_process_identity_unavailable"));
        }
        client.process = Some(unsafe { OwnedHandle::from_raw_handle(process) });
        Ok(client)
    }

    pub fn request(
        &self,
        request: Request<Slot>,
        secret: &[u8],
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> BoxResult<String> {
        if request.operation.is_attachment() {
            return Err(Error("attachment_requires_channel").into());
        }
        let mut channel = self.send(request, secret, stop, deadline)?;
        control_client::read_response(&mut channel, Framing::Native)
            .map_err(control_client::Error::into_boxed)
    }

    pub fn attach(
        &self,
        request: Request<Slot>,
        secret: &[u8],
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> BoxResult<(Channel, String)> {
        if !request.operation.is_attachment() {
            return Err(Error("invalid_attachment").into());
        }
        let mut channel = self.send(request, secret, stop, deadline)?;
        let client = control_client::read_response(&mut channel, Framing::Native)
            .map_err(control_client::Error::into_boxed)?;
        if !valid_id(&client) {
            return Err(Error("invalid_client_id").into());
        }
        channel.claim_lease()?;
        // Agent work and idle periods can outlast the initial RPC. Only a
        // successful attachment handshake can remove that exchange deadline.
        // The same Pipe retains any prefetched bytes after the response frame.
        // Transport close revokes the lease; native stdin EOF stays framed.
        Ok((channel, client))
    }

    fn send(
        &self,
        request: Request<Slot>,
        secret: &[u8],
        stop: Arc<AtomicBool>,
        deadline: Instant,
    ) -> BoxResult<Channel> {
        if request.secret_len as usize != secret.len() {
            return Err(control_client::Error::SecretLengthMismatch.into_boxed());
        }
        if secret.len() > request.operation.native_secret_limit() {
            return Err(Error("secret_too_large").into());
        }
        if request
            .session
            .iter()
            .chain(request.expected_session.iter())
            .any(|id| !valid_id(id))
        {
            return Err(Error("invalid_control_identifier").into());
        }
        let deadline = deadline.min(Instant::now() + request.operation.response_budget());
        let pipe = private::connect_control(&self.name, &self.identity, &stop, deadline)?;
        if let Some(process) = &self.process {
            pipe.verify_server_process(process)?;
        }
        let mut channel = Channel::new(pipe, stop, deadline);
        control_client::write_request(&mut channel, &request, secret, Framing::Native)
            .map_err(control_client::Error::into_boxed)?;
        // Pipe is a bounded buffered writer. Kernel completion must be observed
        // before awaiting a reply; accepted bytes alone are not that proof.
        channel.flush()?;
        Ok(channel)
    }
}

impl Channel {
    pub(crate) fn new(pipe: Pipe, stop: Arc<AtomicBool>, deadline: Instant) -> Self {
        Self {
            pipe,
            stop,
            deadline: Some(deadline),
            closed: false,
            attachment: false,
            retained: false,
        }
    }

    // Only authenticated protocol handshakes inside this crate can grant a
    // long-lived lease. The public deadline setter cannot revive expired I/O.
    pub(crate) fn claim_lease(&mut self) -> io::Result<()> {
        self.check()?;
        self.deadline = None;
        self.attachment = true;
        Ok(())
    }

    /// Only an authenticated attachment ACK can grant one quiet lease. Data
    /// cancellation may close this channel before the controller confirms release.
    pub fn retain_lease(&mut self) -> io::Result<Lease> {
        // A cancellation arriving just after ACK must not close the only
        // connection reference before its cleanup owner can retain it. This
        // grants no I/O rights and never clears cancellation or a deadline.
        if self.closed || !self.attachment || self.retained {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid_attachment_lease",
            ));
        }
        let pipe = self.pipe.retain_lease()?;
        self.retained = true;
        Ok(Lease { _pipe: pipe })
    }

    /// The caller explicitly supplies the next exchange's budget. A timed-out
    /// or cancelled channel is permanently closed and cannot be revived.
    pub fn set_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.check()?;
        if deadline <= Instant::now() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid_controller_deadline",
            ));
        }
        self.deadline = Some(deadline);
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.pipe.close()
    }

    /// Poll owned I/O without waiting for readiness. WouldBlock preserves the
    /// operation; cancellation and terminal errors still revoke the channel.
    pub fn try_read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.pipe.read(output);
        self.check()?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            Err(error) => self.failed(error),
            Ok(0) if !output.is_empty() => {
                self.close()?;
                Ok(0)
            }
            result => result,
        }
    }

    pub fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.pipe.write(bytes);
        self.check()?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            Err(error) => self.failed(error),
            result => result,
        }
    }

    pub fn try_flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.pipe.flush();
        self.check()?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            Err(error) => self.failed(error),
            result => result,
        }
    }

    /// Check revocation/deadline before local filesystem work as well as I/O.
    /// An observed failure seals this owned channel; it cannot be revived.
    pub fn check(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "controller_channel_closed",
            ));
        }
        let error = if private::drain_failed() {
            Some(io::Error::other("private_pipe_cancellation_failed"))
        } else if self.stop.load(Ordering::Acquire) {
            // read_exact retries Interrupted forever. Cancellation is terminal.
            Some(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "controller_cancelled",
            ))
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "controller_timeout",
            ))
        } else {
            None
        };
        if let Some(error) = error {
            self.close()?;
            return Err(error);
        }
        Ok(())
    }

    fn wait(&mut self, read: bool) -> io::Result<()> {
        self.check()?;
        if let Err(error) = self.pipe.wait(self.deadline, read) {
            self.close()?;
            return Err(error);
        }
        self.check()
    }

    /// One owned I/O wait slice (at most 100 ms), so an adapter can also check
    /// an independent authorization signal without a background I/O owner.
    pub fn wait_readable(&mut self) -> io::Result<()> {
        self.wait(true)
    }

    pub fn wait_writable(&mut self) -> io::Result<()> {
        self.wait(false)
    }

    fn failed<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.close()?;
        Err(error)
    }
}

impl Read for Channel {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.try_read(output) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(true)?,
                result => return result,
            }
        }
    }
}

impl Write for Channel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            match self.try_write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(false)?,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            match self.try_flush() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(false)?,
                result => return result,
            }
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, Client};
    use crate::private::{Endpoint, Purpose};
    use oblivion_wire::control::{HEADER_LIMIT, Operation, Request};
    use oblivion_wire::slot::Slot;
    use oblivion_wire::{agent, frame};
    use serde_json::{Value, json};
    use std::io::{self, Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CLIENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn client() -> Client {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        Client::new(
            &bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap()
    }

    fn serve(action: impl FnOnce(Channel) + Send + 'static) -> (Client, JoinHandle<()>) {
        let client = client();
        let name = String::from_utf16(&client.name[..client.name.len() - 1]).unwrap();
        let mut endpoint = Endpoint::bind(&name, Purpose::Control).unwrap();
        let server = std::thread::spawn(move || {
            let stop = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now() + Duration::from_secs(6);
            let pipe = endpoint.accept(&stop, deadline).unwrap().unwrap();
            action(Channel::new(pipe, stop, deadline));
        });
        (client, server)
    }

    fn request(operation: Operation, secret: &[u8]) -> Request<Slot> {
        Request {
            operation,
            slot: Slot::try_from(2).unwrap(),
            session: None,
            expected_session: Some(SAFE.into()),
            secret_len: secret.len() as u32,
        }
    }

    fn received(channel: &mut Channel) -> (Value, Zeroizing<Vec<u8>>) {
        let header: Value =
            serde_json::from_slice(&frame::read(channel, 1..=HEADER_LIMIT).unwrap()).unwrap();
        assert_eq!(header["version"], 1);
        assert_eq!(header["slot"], 2);
        assert_eq!(header["expected_session"], SAFE);
        let mut secret = Zeroizing::new(vec![0; header["secret_len"].as_u64().unwrap() as usize]);
        channel.read_exact(&mut secret).unwrap();
        (header, secret)
    }

    fn reply(channel: &mut Channel, value: &Value) {
        frame::write(
            channel,
            &serde_json::to_vec(value).unwrap(),
            1..=1024 * 1024,
        )
        .unwrap();
        channel.flush().unwrap();
    }

    fn released(channel: &mut Channel) {
        assert_eq!(channel.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn same_user_real_pipe_uses_native_codec_and_keeps_secrets_out_of_header() {
        let (client, server) = serve(|mut channel| {
            let (header, secret) = received(&mut channel);
            assert_eq!(secret.as_slice(), b"PRIVATE_SECRET");
            assert_eq!(header["operation"], "egress");
            assert!(!header.to_string().contains("PRIVATE_SECRET"));
            reply(
                &mut channel,
                &json!({"ok":true,"output":"accepted","error":null}),
            );
            released(&mut channel);
        });
        let result = client
            .request(
                request(Operation::Egress, b"PRIVATE_SECRET"),
                b"PRIVATE_SECRET",
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(result, "accepted");
        server.join().unwrap();
    }

    #[test]
    fn real_pipe_rejections_preserve_only_static_identifiers_and_schema_errors() {
        for (response, expected) in [
            (
                json!({"ok":false,"output":"PRIVATE_CANARY","error":"gateway_not_ready"}),
                "gateway_not_ready",
            ),
            (
                json!({"ok":true,"output":"PRIVATE_CANARY","error":null,"PRIVATE_CANARY":true}),
                "invalid_control_response",
            ),
            (
                json!({"ok":false,"output":"PRIVATE_CANARY","error":"C:\\PRIVATE_CANARY"}),
                "operation_rejected",
            ),
        ] {
            let (client, server) = serve(move |mut channel| {
                received(&mut channel);
                reply(&mut channel, &response);
                released(&mut channel);
            });
            let error = client
                .request(
                    request(Operation::Status, &[]),
                    &[],
                    Arc::new(AtomicBool::new(false)),
                    Instant::now() + Duration::from_secs(3),
                )
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
            server.join().unwrap();
        }
    }

    #[test]
    fn attachment_keeps_coalesced_frame_tail_and_close_releases_the_connection() {
        let (client, server) = serve(|mut channel| {
            let (header, secret) = received(&mut channel);
            assert_eq!(header["operation"], "agent-attach");
            assert!(secret.is_empty());
            let mut combined = Vec::new();
            frame::write(
                &mut combined,
                &serde_json::to_vec(&json!({"ok":true,"output":CLIENT,"error":null})).unwrap(),
                1..=1024,
            )
            .unwrap();
            agent::write_frame(&mut combined, 3, &[0, 255, 12, 42]).unwrap();
            channel.write_all(&combined).unwrap();
            channel.flush().unwrap();
            released(&mut channel);
        });
        let (mut channel, id) = client
            .attach(
                request(Operation::AgentAttach, &[]),
                &[],
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(id, CLIENT);
        channel
            .set_deadline(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            agent::read_frame(&mut channel).unwrap(),
            (3, vec![0, 255, 12, 42])
        );
        channel.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn an_attached_agent_can_be_idle_longer_than_its_completed_handshake_budget() {
        let (client, server) = serve(|mut channel| {
            received(&mut channel);
            reply(
                &mut channel,
                &json!({"ok":true,"output":CLIENT,"error":null}),
            );
            std::thread::sleep(Duration::from_millis(2200));
            agent::write_frame(&mut channel, 1, b"late output").unwrap();
            agent::write_frame(&mut channel, 4, &0_i32.to_be_bytes()).unwrap();
            channel.flush().unwrap();
            released(&mut channel);
        });
        let (mut channel, id) = client
            .attach(
                request(Operation::AgentAttach, &[]),
                &[],
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(id, CLIENT);
        assert_eq!(
            agent::read_frame(&mut channel).unwrap(),
            (1, b"late output".to_vec())
        );
        assert_eq!(
            agent::read_frame(&mut channel).unwrap(),
            (4, 0_i32.to_be_bytes().to_vec())
        );
        channel.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn one_owner_can_send_input_while_an_attached_read_is_pending() {
        let (client, server) = serve(|mut channel| {
            received(&mut channel);
            reply(
                &mut channel,
                &json!({"ok":true,"output":CLIENT,"error":null}),
            );
            let mut input = [0; 5];
            channel.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"input");
            channel.write_all(b"output").unwrap();
            channel.flush().unwrap();
            released(&mut channel);
        });
        let (mut channel, _) = client
            .attach(
                request(Operation::AgentAttach, &[]),
                &[],
                Arc::new(AtomicBool::new(false)),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        channel.set_deadline(deadline).unwrap();
        assert_eq!(channel.try_read(&mut []).unwrap(), 0);
        assert_eq!(channel.try_write(&[]).unwrap(), 0);
        channel.try_flush().unwrap();
        assert_eq!(
            channel.try_read(&mut [0; 6]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(channel.try_write(b"input").unwrap(), 5);
        loop {
            assert!(Instant::now() < deadline);
            match channel.try_flush() {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => panic!("unexpected flush: {result:?}"),
            }
        }
        let mut output = [0; 6];
        let mut offset = 0;
        while offset < output.len() {
            assert!(Instant::now() < deadline);
            match channel.try_read(&mut output[offset..]) {
                Ok(0) => panic!("unexpected output EOF"),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => panic!("unexpected read: {result:?}"),
            }
        }
        assert_eq!(&output, b"output");
        channel.close().unwrap();
        assert_eq!(
            channel.try_flush().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        server.join().unwrap();
    }

    #[test]
    fn cancellation_of_a_polled_attachment_cannot_be_cleared_or_revived() {
        let (client, server) = serve(|mut channel| {
            received(&mut channel);
            reply(
                &mut channel,
                &json!({"ok":true,"output":CLIENT,"error":null}),
            );
            released(&mut channel);
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (mut channel, _) = client
            .attach(
                request(Operation::AgentAttach, &[]),
                &[],
                Arc::clone(&stop),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(
            channel.try_read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        stop.store(true, Ordering::Release);
        assert_eq!(
            channel.try_read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            channel.try_write(b"after cancel").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            channel
                .set_deadline(Instant::now() + Duration::from_secs(3))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        server.join().unwrap();
    }

    #[test]
    fn real_pending_reads_observe_total_deadline_and_cancellation_without_half_close() {
        for cancel in [false, true] {
            let (client, server) = serve(|mut channel| {
                received(&mut channel);
                released(&mut channel);
            });
            let stop = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::clone(&stop);
            let notifier = cancel.then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(50));
                    cancelled.store(true, Ordering::Release);
                })
            });
            let deadline = Instant::now()
                + if cancel {
                    Duration::from_secs(3)
                } else {
                    Duration::from_millis(100)
                };
            let error = client
                .request(request(Operation::Status, &[]), &[], stop, deadline)
                .unwrap_err();
            let error = error
                .downcast_ref::<io::Error>()
                .expect("original I/O classification");
            assert_eq!(
                error.kind(),
                if cancel {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            if let Some(notifier) = notifier {
                notifier.join().unwrap();
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn request_contract_is_validated_before_connecting_to_any_server() {
        let client = client();
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut invalid = request(Operation::Status, &[]);
        invalid.secret_len = 1;
        assert_eq!(
            client
                .request(invalid, &[], Arc::clone(&stop), deadline)
                .unwrap_err()
                .to_string(),
            "secret_length_mismatch"
        );
        let oversized = Zeroizing::new(vec![0; Operation::Status.native_secret_limit() + 1]);
        assert_eq!(
            client
                .request(
                    request(Operation::Status, &oversized),
                    &oversized,
                    Arc::clone(&stop),
                    deadline
                )
                .unwrap_err()
                .to_string(),
            "secret_too_large"
        );
        assert_eq!(
            client
                .request(
                    request(Operation::AgentAttach, &[]),
                    &[],
                    Arc::clone(&stop),
                    deadline
                )
                .unwrap_err()
                .to_string(),
            "attachment_requires_channel"
        );
        assert_eq!(
            client
                .attach(request(Operation::Status, &[]), &[], stop, deadline)
                .err()
                .unwrap()
                .to_string(),
            "invalid_attachment"
        );
    }
}
