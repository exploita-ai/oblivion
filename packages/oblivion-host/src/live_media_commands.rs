//! The launcher owns the USB attachment. The local helper opens and ejects
//! the device, while the isolated transfer guest serves file requests.
use oblivion_cli::{file_copy::MediaBrowse, files};
use oblivion_host::{autolock::Opening, control, remote_control};
use oblivion_transfer::{browser, channel::Channel, endpoint};
use oblivion_wire::control::{Operation, Request};
use oblivion_wire::control_client::{self, Framing};
use oblivion_wire::live_media::{Direction, Reserve};
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub struct Attachment {
    socket: UnixStream,
    removal_proof: [u8; 42],
}

impl Attachment {
    pub fn open(
        opening: &Opening,
        device: &str,
        direction: Direction,
        watch: Option<OwnedFd>,
    ) -> control::Result<Self> {
        let mut path =
            std::env::var_os("OBLIVION_CONTROL_SOCKET").ok_or("native_runtime_required")?;
        path.push(".media");
        let socket = remote_control::connect_peer(Path::new(&path), Duration::from_secs(10))?;
        Self::negotiate(socket, opening, device, direction, watch)
    }

    fn negotiate(
        socket: UnixStream,
        opening: &Opening,
        device: &str,
        direction: Direction,
        watch: Option<OwnedFd>,
    ) -> control::Result<Self> {
        let secret = serde_json::to_vec(&Reserve {
            opening: opening.clone(),
            device_id: device.to_owned(),
            direction,
        })?;
        let request = Request {
            operation: Operation::LiveMediaReserve,
            session: None,
            secret_len: secret.len() as u32,
            slot: opening.slot,
            expected_session: Some(opening.safe_id.clone()),
        };
        let mut channel = Channel::new(
            File::from(OwnedFd::from(socket.try_clone()?)),
            request.operation.response_budget(),
        )?;
        if let Some(watch) = watch {
            channel.watch(watch);
        }
        channel.check()?;
        control_client::write_request(&mut channel, &request, &secret, Framing::Native)?;
        let removal_nonce = control_client::read_response(&mut channel, Framing::Native)?;
        let removal_proof = oblivion_wire::live_media::detach_proof(&removal_nonce)
            .ok_or("Invalid USB removal authority")?;
        Ok(Self {
            socket,
            removal_proof,
        })
    }

    pub fn channel(&self, budget: Duration) -> std::io::Result<Channel> {
        Channel::new(File::from(OwnedFd::from(self.socket.try_clone()?)), budget)
    }

    pub fn finish(self) -> control::Result<()> {
        // The peer can finish cleanup first and leave its proof buffered.
        let _ = self.socket.shutdown(Shutdown::Write);
        let mut status = [0; 42];
        if self
            .channel(Duration::from_secs(75))?
            .read_exact(&mut status)
            .is_err()
            || status != self.removal_proof
        {
            return Err(
                "USB removal was not confirmed. Check the runtime before continuing.".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_while_waiting_for_writable_attachment_closes_the_owner_connection() {
        let opening = Opening {
            slot: Default::default(),
            safe_id: "a".repeat(32),
            nonce: "b".repeat(32),
        };
        let (client, mut peer) = UnixStream::pair().unwrap();
        let (watch, mut cancel) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server = std::thread::spawn(move || {
            let header = oblivion_wire::frame::read(&mut peer, 1..=1024).unwrap();
            let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
            let mut request = vec![0; header["secret_len"].as_u64().unwrap() as usize];
            peer.read_exact(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["direction"], "export");
            cancel.write_all(b"X").unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        });
        assert!(
            Attachment::negotiate(
                client,
                &opening,
                &"c".repeat(64),
                Direction::Export,
                Some(watch.into())
            )
            .is_err()
        );
        server.join().unwrap();
    }
}

pub fn browse(command: MediaBrowse) -> control::Result<i32> {
    let mut controller = control::Client::new();
    let target = files::target(&mut controller, &command.safe)?;
    let opening = files::opening(&mut controller, &target, Some(&command.opening))?;
    let source = Attachment::open(&opening, &command.device, Direction::Import, None)?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        // The manager sends one bounded request, then waits for its reply.
        let mut request = Vec::new();
        if (&mut input).take(8193).read_until(b'\n', &mut request)? == 0 {
            break;
        }
        if request.len() > 8192 || request.last() != Some(&b'\n') {
            return Err("Invalid USB directory request".into());
        }
        let request: browser::Request = serde_json::from_slice(&request)?;
        request.validate()?;
        let mut channel = source.channel(Duration::from_secs(20))?;
        endpoint::write_message(&mut channel, &serde_json::json!({ "browse": request }))?;
        match endpoint::read_message(&mut channel, 64 * 1024)? {
            browser::Response::Page(page) => {
                page.validate(&request)?;
                files::write_directory_page(&mut output, &page)?;
            }
            browser::Response::Unavailable { .. } => {
                writeln!(output, "{{\"error\":\"directory_unavailable\"}}")?
            }
        }
        output.flush()?;
    }
    source.finish()?;
    Ok(0)
}
