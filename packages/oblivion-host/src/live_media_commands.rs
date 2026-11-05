//! The launcher owns the USB browser attachment. The local helper opens and
//! ejects the device; only the isolated transfer guest serves file requests.
use oblivion_cli::{file_copy::MediaBrowse, files};
use oblivion_host::{autolock::Opening, control, remote_control, scope};
use oblivion_transfer::{browser, channel::Channel, endpoint};
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub struct Source {
    socket: UnixStream,
    removal_proof: [u8; 42],
}

impl Source {
    pub fn open(opening: &Opening, device: &str) -> control::Result<Self> {
        let mut socket = std::env::var_os("OBLIVION_CONTROL_SOCKET").ok_or("native_runtime_required")?;
        socket.push(".media");
        let request = oblivion_wire::live_media::Reserve {
            opening: opening.clone(),
            device_id: device.to_owned(),
        };
        let (socket, removal_nonce) = scope::within(opening.slot, || {
            remote_control::attach_scoped_with_secret(
                Path::new(&socket),
                "live-media-reserve",
                None,
                Some(&opening.safe_id),
                &serde_json::to_vec(&request)?,
            )
        })?;
        let removal_proof = oblivion_wire::live_media::detach_proof(&removal_nonce)
            .ok_or("Invalid USB removal authority")?;
        Ok(Self { socket, removal_proof })
    }

    pub fn channel(&self, budget: Duration) -> std::io::Result<Channel> {
        Channel::new(File::from(OwnedFd::from(self.socket.try_clone()?)), budget)
    }

    pub fn finish(self) -> control::Result<()> {
        // The peer can finish cleanup first and leave its proof buffered.
        let _ = self.socket.shutdown(Shutdown::Write);
        let mut status = [0; 42];
        if self.channel(Duration::from_secs(75))?.read_exact(&mut status).is_err()
            || status != self.removal_proof
        {
            return Err("USB removal was not confirmed. Check the runtime before continuing.".into());
        }
        Ok(())
    }
}

pub fn browse(command: MediaBrowse) -> control::Result<i32> {
    let mut controller = control::Client::new();
    let target = files::target(&mut controller, &command.safe)?;
    let opening = files::opening(&mut controller, &target, Some(&command.opening))?;
    let source = Source::open(&opening, &command.device)?;
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
            browser::Response::Unavailable { .. } => writeln!(output, "{{\"error\":\"directory_unavailable\"}}")?,
        }
        output.flush()?;
    }
    source.finish()?;
    Ok(0)
}
