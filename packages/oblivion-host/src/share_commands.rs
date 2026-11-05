//! Unix stream ownership for the shared Share engine. The native launcher and
//! Windows entrypoint consume the same parser, review and container workflow.
use oblivion_cli::controller::{Call, Controller};
use oblivion_cli::share::io::{Attachment, Lease, Native};
use oblivion_host::{autolock::Opening, control, scope};
use oblivion_transfer::channel::Channel;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub fn run(command: oblivion_cli::share::Command) -> control::Result<i32> {
    oblivion_cli::share::run(
        &mut super::UnixRuntime::new(),
        command,
        &mut io::stdout(),
        &mut io::stderr(),
    )
}

pub struct ShareAttachment {
    channel: Option<Channel>,
    lease: Option<UnixStream>,
    client: String,
}
impl Attachment for ShareAttachment {
    type Stream = Channel;
    fn stream(&mut self) -> &mut Channel {
        self.channel.as_mut().expect("open Share attachment")
    }
    fn client_id(&self) -> &str {
        &self.client
    }
    fn close(&mut self) -> io::Result<()> {
        drop(self.channel.take());
        drop(self.lease.take());
        Ok(())
    }
}

pub struct ExportLease {
    signal: Option<UnixStream>,
    lease: Option<UnixStream>,
}
impl Lease for ExportLease {
    fn check(&mut self) -> io::Result<()> {
        let mut watched = libc::pollfd {
            fd: self
                .signal
                .as_ref()
                .ok_or_else(|| io::Error::other("share_export_revoked"))?
                .as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut watched, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if watched.revents != 0 {
            return Err(io::Error::other("share_export_revoked"));
        }
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        // Shutdown also revokes descriptors copied into the source watches.
        if let Some(signal) = self.signal.take() {
            let _ = signal.shutdown(std::net::Shutdown::Both);
        }
        drop(self.lease.take());
        Ok(())
    }
}

impl Drop for ExportLease {
    fn drop(&mut self) {
        // A source watch owns a cloned descriptor. Closing only this object's
        // originals would leave that authorization connection alive.
        let _ = Lease::close(self);
    }
}

impl Native for super::UnixRuntime {
    type Attachment = ShareAttachment;
    type ExportLease = ExportLease;

    fn lease_share_export(&mut self, export: &str) -> control::Result<ExportLease> {
        let (signal, lease, _) =
            scope::within(Default::default(), || control::attach_export(export))?;
        Ok(ExportLease {
            signal: Some(signal),
            lease: Some(lease),
        })
    }
    fn attach_share_source(
        &mut self,
        opening: &Opening,
        lease: &mut ExportLease,
    ) -> control::Result<ShareAttachment> {
        lease.check()?;
        let mut attachment = attach("share-attach", opening)?;
        attachment.stream().watch(OwnedFd::from(
            lease
                .signal
                .as_ref()
                .ok_or("share_export_revoked")?
                .try_clone()?,
        ));
        Ok(attachment)
    }
    fn attach_share_import(&mut self, opening: &Opening) -> control::Result<ShareAttachment> {
        attach("share-import-attach", opening)
    }
    fn cleanup(&mut self, call: Call<'_, scope::Slot>) -> control::Result<String> {
        control::Client::new().request(call)
    }
}

fn attach(operation: &str, opening: &Opening) -> control::Result<ShareAttachment> {
    scope::within(opening.slot, || {
        let (connection, lease, client) = control::attach_client(operation, &opening.safe_id)?;
        let channel = Channel::new(
            File::from(OwnedFd::from(connection)),
            Duration::from_secs(3600),
        )?;
        Ok(ShareAttachment {
            channel: Some(channel),
            lease: Some(lease),
            client,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::ExportLease;
    use oblivion_transfer::channel::Channel;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn dropping_export_owner_revokes_source_watches_that_retain_signal_descriptors() {
        let (signal, mut peer) = UnixStream::pair().unwrap();
        let watch = OwnedFd::from(signal.try_clone().unwrap());
        let lease = ExportLease {
            lease: Some(signal.try_clone().unwrap()),
            signal: Some(signal),
        };
        let (data, _source) = UnixStream::pair().unwrap();
        let mut channel =
            Channel::new(File::from(OwnedFd::from(data)), Duration::from_secs(2)).unwrap();
        channel.watch(watch);
        assert!(channel.check().is_ok());
        drop(lease);
        assert!(channel.check().is_err());
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
