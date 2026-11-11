use crate::channel::Channel;
use crate::endpoint::{
    Approval, ReceiveRequest, SelectionOffer, SourceRequest, read_message, write_message,
};
use crate::{END, Limits, Manifest, Receipt, require, validate_id};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

/// One operation through already authorized private ports. The controller owns
/// VM selection and the user decision; this relay cannot issue an authorization.
/// Cancelling control or observing either VM's death closes both data channels.
pub fn run(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
) -> io::Result<()> {
    run_permitted(source, destination, control, owners, budget, None)
}

pub struct Permit {
    pub id: String,
    pub limits: Limits,
}

/// The paths name the staged objects in the verified manifest's selection
/// order. A later publication can recheck the receipt against those objects.
pub struct Approved {
    pub receipt: Receipt,
    pub paths: Vec<String>,
}

/// A maintenance port reaches only the active guest's receiver. No source VM,
/// external device, arbitrary path or document payload is involved.
pub fn recover(
    destination: File,
    control: File,
    owner: OwnedFd,
    budget: Duration,
) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut destination = Channel::until(destination, deadline)?;
    destination.watch(control.try_clone()?.into());
    destination.watch(owner.try_clone()?);
    let mut control = Channel::until(control, deadline)?;
    control.watch(owner);
    let request: crate::recovery::Request = read_message(&mut control, 1024)?;
    request.validate()?;
    write_message(&mut destination, &request)?;
    let response: crate::recovery::Response = read_message(&mut destination, 64 * 1024)?;
    response.validate(&request)?;
    drop(destination);
    write_message(&mut control, &response)
}

/// The controller supplies the fresh operation ID and ceiling independently of
/// the manager's requested selection. They cannot be widened on the channel.
pub fn run_permitted(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Option<Permit>,
) -> io::Result<()> {
    run_copy(
        source,
        destination,
        control,
        owners,
        budget,
        permit,
        false,
        false,
    )
}

/// The controller chooses the actual source authority. This is never inferred
/// from peer bytes: Documents adds a reviewed collection plan; closed-volume
/// backups expose only the independently delegated ciphertext descriptor.
#[derive(Clone, Copy)]
pub enum ExportSource {
    Documents,
    Ciphertext,
}

pub fn export(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Permit,
    source_mode: ExportSource,
) -> io::Result<()> {
    run_copy(
        source,
        destination,
        control,
        owners,
        budget,
        Some(permit),
        true,
        matches!(source_mode, ExportSource::Documents),
    )
}

fn run_copy(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Option<Permit>,
    external: bool,
    documents: bool,
) -> io::Result<()> {
    let (approved, mut control) = copy(
        source,
        destination,
        control,
        owners,
        budget,
        permit,
        external,
        documents,
    )?;
    write_message(&mut control, &approved.receipt)
}

/// A restore is not published by the copy engine. The controller must durably
/// record the verified ciphertext and release its source before acknowledging
/// the copy to the manager; unlocking/validation happens separately.
pub fn stage(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Permit,
) -> io::Result<Receipt> {
    stage_selected(source, destination, control, owners, budget, permit, false)
        .map(|approved| approved.receipt)
}

pub fn stage_selected(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Permit,
    documents: bool,
) -> io::Result<Approved> {
    copy(
        source,
        destination,
        control,
        owners,
        budget,
        Some(permit),
        false,
        documents,
    )
    .map(|(approved, _)| approved)
}

fn copy(
    source: File,
    destination: File,
    control: File,
    owners: Vec<OwnedFd>,
    budget: Duration,
    permit: Option<Permit>,
    external: bool,
    documents: bool,
) -> io::Result<(Approved, Channel)> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    require(owners.len() == 2, "missing_vm_owners")?;
    let mut source = Channel::until(source, deadline)?;
    let mut destination = Channel::until(destination, deadline)?;
    source.watch(control.try_clone()?.into());
    destination.watch(control.try_clone()?.into());
    let mut control = Channel::until(control, deadline)?;
    for owner in owners {
        source.watch(owner.try_clone()?);
        destination.watch(owner.try_clone()?);
        control.watch(owner);
    }
    let result = exchange(
        &mut source,
        &mut destination,
        &mut control,
        permit,
        documents,
    )
    .and_then(|receipt| {
        if external {
            let mut detached = [0; 9];
            destination.read_exact(&mut detached)?;
            require(&detached == b"detached\n", "export_not_detached")?;
        }
        Ok(receipt)
    });
    // Release both VM ports before returning a receipt or closing the control
    // connection. The controller must still reap this worker before teardown.
    drop(source);
    drop(destination);
    Ok((result?, control))
}

fn exchange(
    source: &mut Channel,
    destination: &mut Channel,
    control: &mut Channel,
    permit: Option<Permit>,
    documents: bool,
) -> io::Result<Approved> {
    let request = loop {
        match read_message::<SourceRequest>(control, 64 * 1024)? {
            SourceRequest::Offer(request) => break request,
            SourceRequest::Browse { browse } => {
                browse.validate()?;
                write_message(source, &serde_json::json!({"browse": &browse}))?;
                let response: crate::browser::Response = read_message(source, 64 * 1024)?;
                if let crate::browser::Response::Page(page) = &response {
                    page.validate(&browse)?;
                }
                write_message(control, &response)?;
            }
        }
    };
    validate_id(&request.id)?;
    if let Some(permit) = permit {
        require(
            request.id == permit.id
                && request.limits.bytes <= permit.limits.bytes
                && request.limits.entries <= permit.limits.entries,
            "transfer_not_permitted",
        )?;
    }
    write_message(source, &request)?;
    let selection = if documents {
        let offer: SelectionOffer = read_message(source, 64 * 1024)?;
        let plan = crate::stream::selection_plan(&request.paths, &offer)?;
        Some((offer, plan))
    } else {
        None
    };
    let manifest = Manifest::read(source, request.limits)?;
    let paths = if let Some((offer, plan)) = selection {
        crate::stream::require_collection(&manifest, &plan, &offer.directories)?;
        plan.mappings
            .iter()
            .filter_map(|mapping| plan.manifest_path(mapping.input_index))
            .collect()
    } else {
        request.paths
    };
    // Media control already reviews the complete output manifest and retains
    // its own source choices; no redundant path/mapping ledger is persisted.
    manifest.write(control)?;
    let approval: Approval = read_message(control, 1024)?;
    require(
        approval.id == request.id && approval.manifest_sha256 == manifest.sha256(),
        "offer_not_approved",
    )?;
    let grant = ReceiveRequest {
        approval,
        limits: request.limits,
    };
    write_message(destination, &grant)?;
    manifest.write(destination)?;
    let mut ready = [0; 8];
    destination.read_exact(&mut ready)?;
    require(&ready == b"receive\n", "receiver_not_ready")?;
    write_message(source, &grant.approval)?;
    crate::stream::relay_payload(source, destination, &manifest)?;
    // The receiver cannot publish until every offered file has also passed
    // validation at the relay. There is no payload buffering on the host disk.
    destination.write_all(END)?;
    let receipt: Receipt = read_message(destination, 1024)?;
    crate::copy_protocol::verify_receipt(&receipt, &request.id, &manifest)?;
    write_message(source, &receipt)?;
    let mut done = [0; 7];
    source.read_exact(&mut done)?;
    require(&done == b"copied\n", "sender_not_complete")?;
    Ok(Approved { receipt, paths })
}

/// Linux 6.5+ pins the process that established this private Unix connection.
/// No numeric PID lookup, PID reuse window or socket-path reopening is involved.
#[cfg(target_os = "linux")]
pub fn peer_process(socket: &File) -> io::Result<OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut fd = -1;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    // SO_PEERPIDFD is 77 on the supported x86_64/aarch64 Linux ABI. The pinned
    // libc does not expose it yet; the host gateway uses this same boundary.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            77,
            (&mut fd as *mut libc::c_int).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
