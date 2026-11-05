//! One payload exchange for native Files transports. Platform endpoints own
//! filesystem handles; framing, approval, progress and receipts stay common.
use crate::endpoint::{Approval, ReceiveRequest, read_message, write_message};
use crate::native_file_events::Phase;
use crate::{Manifest, Receipt, require, validate_id};
use std::io::{self, Read, Write};

pub(crate) const DESTINATION_FULL: &[u8; 8] = b"nospace\n";

pub trait Transport: Read + Write {
    fn check(&mut self) -> io::Result<()>;
}

impl<T: Transport + ?Sized> Transport for &mut T {
    fn check(&mut self) -> io::Result<()> {
        (**self).check()
    }
}

pub trait Source {
    fn manifest(&self) -> &Manifest;
    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()>;
}

#[cfg(unix)]
impl Transport for crate::channel::Channel {
    fn check(&mut self) -> io::Result<()> {
        crate::channel::Channel::check(self)
    }
}

pub fn send<T: Transport, S: Source>(
    channel: &mut T,
    source: &mut S,
    id: &str,
    approved_digest: &str,
    observer: &mut dyn FnMut(Phase, u64) -> io::Result<()>,
) -> io::Result<Receipt> {
    validate_id(id)?;
    require(
        source.manifest().sha256() == approved_digest,
        "offer_not_approved",
    )?;
    observer(Phase::Copying, 0)?;
    channel.check()?;
    write_message(
        channel,
        &ReceiveRequest {
            approval: Approval {
                id: id.into(),
                manifest_sha256: approved_digest.into(),
            },
            limits: crate::Limits {
                entries: source.manifest().entries().len(),
                bytes: source.manifest().bytes(),
            },
        },
    )?;
    source.manifest().write(channel)?;
    channel.flush()?;
    let mut accepted = [0; 8];
    channel.read_exact(&mut accepted)?;
    require(&accepted != DESTINATION_FULL, "insufficient_destination_space")?;
    require(&accepted == b"receive\n", "offer_rejected")?;
    let total = source.manifest().bytes();
    source.write_payload(&mut Payload {
        inner: channel,
        observer,
        bytes: 0,
        total,
    })?;
    observer(Phase::Finalizing, total)?;
    channel.check()?;
    channel.flush()?;
    let receipt: Receipt = read_message(channel, 1024)?;
    verify_receipt(&receipt, id, source.manifest())?;
    Ok(receipt)
}

/// Offer/manifest bytes and the terminator never count as document progress.
pub(crate) struct Payload<'a, T> {
    pub inner: &'a mut T,
    pub observer: &'a mut dyn FnMut(Phase, u64) -> io::Result<()>,
    pub bytes: u64,
    pub total: u64,
}
impl<T> Payload<'_, T> {
    fn advance(&mut self, count: usize) -> io::Result<()> {
        self.bytes += (count as u64).min(self.total - self.bytes);
        (self.observer)(Phase::Copying, self.bytes)
    }
}
impl<T: Read> Read for Payload<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (self.observer)(Phase::Copying, self.bytes)?;
        let count = self.inner.read(buffer)?;
        self.advance(count)?;
        Ok(count)
    }
}
impl<T: Write> Write for Payload<'_, T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        (self.observer)(Phase::Copying, self.bytes)?;
        let count = self.inner.write(buffer)?;
        self.advance(count)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        (self.observer)(Phase::Copying, self.bytes)?;
        self.inner.flush()
    }
}

pub(crate) fn verify_receipt(receipt: &Receipt, id: &str, manifest: &Manifest) -> io::Result<()> {
    require(
        receipt.id == id
            && receipt.manifest_sha256 == manifest.sha256()
            && receipt.entries == manifest.entries().len()
            && receipt.bytes == manifest.bytes(),
        "invalid_receipt",
    )
}
