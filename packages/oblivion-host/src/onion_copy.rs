//! Descriptor-only import from sealed OnionShare intake. Reuses the ordinary
//! browser, manifest, approval, hashing, publication and receipt protocol.
use crate::transfers;
use oblivion_transfer::Receipt;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::write_message;
use oblivion_transfer::relay::{self, Permit};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

pub struct Completed {
    approved: relay::Approved,
    control: File,
}

pub fn ready(
    source: &File,
    destination: &File,
    owners: &[OwnedFd],
    deadline: Instant,
) -> io::Result<()> {
    for file in [source, destination] {
        let mut channel = Channel::until(file.try_clone()?, deadline)?;
        for owner in owners {
            channel.watch(owner.try_clone()?);
        }
        let mut marker = [0; 6];
        channel.read_exact(&mut marker)?;
        if &marker != b"ready\n" {
            return Err(io::Error::other("invalid_transfer_guest"));
        }
    }
    Ok(())
}

pub fn stage(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    deadline: Instant,
    id: String,
) -> io::Result<Completed> {
    copy(source, destination, control, owners, deadline, id, false)
}

pub fn share(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    deadline: Instant,
    id: String,
) -> io::Result<Completed> {
    copy(source, destination, control, owners, deadline, id, true)
}

fn copy(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    deadline: Instant,
    id: String,
    exporting: bool,
) -> io::Result<Completed> {
    let reply = control.try_clone()?;
    let mut gate = Channel::until(
        if exporting {
            source.try_clone()?
        } else {
            destination.try_clone()?
        },
        deadline,
    )?;
    for owner in &owners {
        gate.watch(owner.try_clone()?);
    }
    // Only the session launcher requires G to select its fixed import receiver
    // or document sender. The file VM already speaks framed copy messages.
    // Do not watch manager input until the relay owns it: an already buffered
    // initial Browse is work, not cancellation. G grants no file publication.
    gate.write_all(b"G")?;
    drop(gate);
    let approved = relay::stage_selected(
        source,
        destination,
        control,
        owners,
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?,
        Permit {
            id,
            limits: transfers::limits(),
        },
    )?;
    Ok(Completed {
        approved,
        control: reply,
    })
}

impl Completed {
    pub fn paths(&self) -> &[String] {
        &self.approved.paths
    }

    /// The owner first removes the session's temporary port. A verified copy
    /// alone must not report completed cleanup to the manager.
    pub fn acknowledge(self) -> io::Result<Receipt> {
        write_message(
            &mut Channel::new(self.control, Duration::from_secs(5))?,
            &self.approved.receipt,
        )?;
        Ok(self.approved.receipt)
    }
}
