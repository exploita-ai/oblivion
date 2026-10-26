use oblivion_host::control::{self, Result};
use oblivion_host::terminal::{ACTION, BRAND, CLEAR, FEEDBACK, RESET, Terminal};
use oblivion_host::transfers::{self, Command, Started, Status};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{Approval, OfferRequest, read_message, write_message};
use oblivion_transfer::recovery::{Request, Response, State};
use oblivion_transfer::{Entry, Manifest, Receipt};
use std::fs::File;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

pub fn run(terminal: &mut Terminal) -> Result<()> {
    let mut selected = 0usize;
    loop {
        let status: Status = serde_json::from_str(&command(&Command::List)?)?;
        if !status.configured && !status.export_configured {
            terminal.write(&format!("{CLEAR} Document transfers are not configured in this image.\r\n Press any key to return to the chat."))?;
            terminal.input(-1)?;
            return Ok(());
        }
        selected = selected.min(status.sources.len().saturating_sub(1));
        let mut view = format!(
            "{CLEAR}{BRAND} OBLIVION - DOCUMENT TRANSFERS{RESET}\r\n\r\n USB devices stay unmounted. Imports are read-only; exports require confirmation.\r\n"
        );
        let (rows, _) = terminal.size();
        let count = rows.saturating_sub(12).max(1) as usize;
        for (index, source) in status
            .sources
            .iter()
            .enumerate()
            .skip(selected.saturating_sub(count - 1))
            .take(count)
        {
            if source.name.len() > 64
                || !source
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err("invalid_source_name".into());
            }
            view.push_str(&format!(
                " {} {} - {} MiB\r\n",
                if index == selected { ">" } else { " " },
                source.name,
                source.bytes / 1048576
            ));
        }
        if status.sources.is_empty() {
            view.push_str(" No USB available. Connect a USB and press R.\r\n");
        }
        if status.active {
            view.push_str(" A transfer is active. Press C to cancel it.\r\n");
        }
        view.push_str(&format!("\r\n {ACTION}[Up/Down] Select  [Enter] Import  [E] Export  [R] Refresh\r\n [U] Session copies  [C] Cancel transfer\r\n [B] Lock everything  [Esc] Back{RESET}"));
        terminal.write(&view)?;
        let input = terminal.input(-1)?;
        match input.as_slice() {
            b"\x1b" => return Ok(()),
            b"b" | b"B" => {
                command(&Command::Cancel)?;
                control::request("lock", None, &[])?;
                return Ok(());
            }
            b"u" | b"U" if !status.active => return recovery_menu(terminal),
            b"c" | b"C" => {
                command(&Command::Cancel)?;
            }
            b"j" | b"J" | b"\x1b[B" => {
                selected = (selected + 1).min(status.sources.len().saturating_sub(1))
            }
            b"k" | b"K" | b"\x1b[A" => selected = selected.saturating_sub(1),
            b"\r" | b"\n" | b"e" | b"E" if !status.active && !status.sources.is_empty() => {
                let export = matches!(input.as_slice(), b"e" | b"E");
                if (export && !status.export_configured) || (!export && !status.configured) {
                    continue;
                }
                let Some(path) = terminal.text(if export {
                    "Session path: workspace/... or imports/..."
                } else {
                    "Relative USB path: a file or folder, without a leading /"
                })?
                else {
                    continue;
                };
                if path.is_empty() {
                    continue;
                }
                if export {
                    terminal.write(&format!("{CLEAR}{BRAND} OBLIVION - AUTHORIZE USB WRITES{RESET}\r\n\r\n Destination: {} (ext4, FAT o exFAT)\r\n Exported documents will be ordinary readable copies.\r\n Session encryption does not protect this USB.\r\n Mounting may update filesystem metadata.\r\n\r\n [E] Authorize and prepare  [B] Lock everything\r\n Any other key cancels.", status.sources[selected].name))?;
                    match terminal.input(-1)?.as_slice() {
                        b"e" | b"E" => {}
                        b"b" | b"B" => {
                            control::request("lock", None, &[])?;
                            return Ok(());
                        }
                        _ => continue,
                    }
                }
                terminal.write(&format!("{CLEAR} Preparing transfer..."))?;
                let operation = if export {
                    Command::Export {
                        target: status.sources[selected].id.clone(),
                    }
                } else {
                    Command::Import {
                        source: status.sources[selected].id.clone(),
                    }
                };
                let started: Started = serde_json::from_str(&command(&operation)?)?;
                let result = copy(terminal, &started, path, export);
                // Reap the worker and remove its VM, port and external mapping
                // even after a lost receipt or a locally interrupted dialogue.
                let stopped = command(&Command::Cancel);
                result?;
                stopped?;
                return Ok(());
            }
            _ => {}
        }
    }
}

fn command(value: &Command) -> Result<String> {
    control::request("transfers", None, &serde_json::to_vec(value)?)
}

fn copy(terminal: &mut Terminal, started: &Started, path: String, export: bool) -> Result<()> {
    if started.id.len() != 32
        || !started
            .id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_transfer_id".into());
    }
    let stream = connect()?;
    let mut channel = Channel::new(
        File::from(OwnedFd::from(stream.try_clone()?)),
        Duration::from_secs(transfers::BUDGET_SECONDS),
    )?;
    write_message(
        &mut channel,
        &OfferRequest {
            id: started.id.clone(),
            limits: transfers::limits(),
            paths: vec![path],
        },
    )?;
    terminal.write(&format!(
        "{CLEAR} Reading the manifest and verifying files...\r\n [Esc] Cancel  [B] Lock everything"
    ))?;
    let Some(manifest) = wait(terminal, &stream, |channel| {
        Manifest::read(channel, transfers::limits())
    })?
    else {
        return Ok(());
    };
    let mut selected = 0usize;
    loop {
        let (rows, cols) = terminal.size();
        let count = rows.saturating_sub(14).max(1) as usize;
        let mut view = format!(
            "{CLEAR}{BRAND} OBLIVION - CONFIRM {}{RESET}\r\n\r\n {} entries, {} bytes. {}\r\n\r\n",
            if export { "EXPORT" } else { "IMPORT" },
            manifest.entries().len(),
            manifest.bytes(),
            if export {
                "Readable copies on the selected USB."
            } else {
                "The USB remains unchanged."
            }
        );
        for (index, entry) in manifest
            .entries()
            .iter()
            .enumerate()
            .skip(selected.saturating_sub(count - 1))
            .take(count)
        {
            // Manifest decoding rejects control/bidi characters. Quotes and a
            // fixed ordinal keep source filenames visibly separate from actions.
            let name: String = entry
                .path()
                .chars()
                // A Unicode scalar can occupy two terminal cells. The
                // conservative bound also works without a width database.
                .take(cols.saturating_sub(20) as usize / 2)
                .collect();
            view.push_str(&format!(
                " {} {:4} {} '{}'\r\n",
                if index == selected { ">" } else { " " },
                index + 1,
                if matches!(entry, Entry::Directory { .. }) {
                    "dir "
                } else {
                    "file"
                },
                name
            ));
        }
        if export {
            view.push_str(&format!("\r\n The copy will leave the encrypted session volume.\r\n Existing files will not be overwritten.\r\n {ACTION}[E] Confirm export  [Up/Down] Scroll\r\n [Esc] Cancel  [B] Lock everything{RESET}"));
        } else {
            view.push_str(&format!("\r\n After confirmation, verified files will be available to the chat.\r\n Using them as context may send their contents to Abliteration.\r\n\r\n {ACTION}[I] Import into chat  [Up/Down] Scroll\r\n [Esc] Cancel  [B] Lock everything{RESET}"));
        }
        terminal.write(&view)?;
        let input = terminal.input(1000)?;
        // Refresh against the worker's fixed deadline even while the user is
        // reading; a dead connection must not remain an approvable offer.
        channel.check()?;
        let mut state = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // The protocol is silent until approval. Data, EOF, HUP and errors
        // all invalidate this offer; never consume them as a fresh manifest.
        if unsafe { libc::poll(&mut state, 1, 0) } < 0 || state.revents != 0 {
            return Err("transfer_expired".into());
        }
        match input.as_slice() {
            b"\x1b" => return Ok(()),
            b"b" | b"B" => {
                stream.shutdown(Shutdown::Both)?;
                command(&Command::Cancel)?;
                control::request("lock", None, &[])?;
                return Ok(());
            }
            b"j" | b"J" | b"\x1b[B" => {
                selected = (selected + 1).min(manifest.entries().len().saturating_sub(1))
            }
            b"k" | b"K" | b"\x1b[A" => selected = selected.saturating_sub(1),
            b"i" | b"I" if !export => break,
            b"e" | b"E" if export => break,
            _ => {}
        }
    }
    write_message(
        &mut channel,
        &Approval {
            id: started.id.clone(),
            manifest_sha256: manifest.sha256(),
        },
    )?;
    terminal.write(&format!(
        "{CLEAR} Copying and verifying...\r\n [Esc] Stop  [B] Lock everything"
    ))?;
    let uncertain = if export {
        "export_outcome_unknown"
    } else {
        "transfer_outcome_unknown"
    };
    let Some(receipt): Option<Receipt> =
        wait(terminal, &stream, |channel| read_message(channel, 1024)).map_err(|_| uncertain)?
    else {
        return Err(uncertain.into());
    };
    if receipt.id != started.id
        || receipt.manifest_sha256 != manifest.sha256()
        || receipt.entries != manifest.entries().len()
        || receipt.bytes != manifest.bytes()
    {
        return Err(uncertain.into());
    }
    if export {
        // Receiving the detached marker is necessary, and the host must also
        // finish revoking the writer VM/mapping before declaring safe removal.
        command(&Command::Cancel)?;
        terminal.write(&format!("{CLEAR}{FEEDBACK} Export completed.{RESET}\r\n\r\n USB synchronized, unmounted and released.\r\n You can remove the device.\r\n Folder: Oblivion-{}/files\r\n\r\n Press any key to return to the manager.", started.id))?;
    } else {
        terminal.write(&format!("{CLEAR}{FEEDBACK} Import verified.{RESET}\r\n\r\n Files available in the session:\r\n /vault/imports/{}/files\r\n\r\n Press any key to return to the manager.", started.id))?;
    }
    terminal.input(-1)?;
    Ok(())
}

fn connect() -> Result<UnixStream> {
    let stream = UnixStream::connect(transfers::SOCKET)?;
    #[cfg(target_os = "linux")]
    {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || peer.uid != 0
        {
            return Err("untrusted_transfer_controller".into());
        }
    }
    Ok(stream)
}

fn recover(terminal: &mut Terminal, request: &Request) -> Result<Option<Response>> {
    terminal.write(&format!("{CLEAR} Checking copies in the session volume..."))?;
    command(&Command::Recover)?;
    let result = (|| {
        let stream = connect()?;
        let mut channel = Channel::new(
            File::from(OwnedFd::from(stream.try_clone()?)),
            Duration::from_secs(transfers::BUDGET_SECONDS),
        )?;
        write_message(&mut channel, request)?;
        terminal.write("\r\n [Esc] Stop  [B] Lock everything")?;
        wait(terminal, &stream, |channel| {
            read_message(channel, 64 * 1024)
        })
    })();
    let stopped = command(&Command::Cancel);
    let response = result?;
    stopped?;
    Ok(response)
}

fn recovery_menu(terminal: &mut Terminal) -> Result<()> {
    let mut after = None;
    loop {
        let Some(Response::Inventory { records, next }) = recover(
            terminal,
            &Request::List {
                after: after.clone(),
            },
        )?
        else {
            return Ok(());
        };
        let mut selected = 0usize;
        loop {
            let (rows, _) = terminal.size();
            let count = rows.saturating_sub(16).max(1) as usize;
            let mut view = format!("{CLEAR}{BRAND} OBLIVION - SESSION COPIES{RESET}\r\n\r\n");
            for (index, record) in records
                .iter()
                .enumerate()
                .skip(selected.saturating_sub(count - 1))
                .take(count)
            {
                let state = match record.state {
                    State::Private => "Private, not delivered",
                    State::Available => "Available, confirmation interrupted",
                    State::Published => "Published, editable by the chat",
                    State::Missing => "Unverified, retained",
                };
                view.push_str(&format!(
                    " {} {}  {}\r\n",
                    if index == selected { ">" } else { " " },
                    &record.id[..8],
                    state
                ));
            }
            if let Some(record) = records.get(selected) {
                view.push_str(&format!("\r\n ID: {}\r\n", record.id));
                if matches!(record.state, State::Published | State::Available) {
                    view.push_str(&format!(" /vault/imports/{}/files\r\n", record.id));
                }
                if let Some(receipt) = &record.receipt {
                    view.push_str(&format!(
                        " Original copy: {} entries, {} bytes.\r\n",
                        receipt.entries, receipt.bytes
                    ));
                }
            } else {
                view.push_str(" No copies recorded.\r\n");
            }
            view.push_str(&format!("\r\n The receipt describes the import, before any later edits.\r\n {ACTION}[Up/Down] Select  [D] Delete a private copy\r\n [R] Refresh  [N] Next page  [Esc] Return to chat\r\n [B] Lock everything{RESET}"));
            terminal.write(&view)?;
            match terminal.input(-1)?.as_slice() {
                b"\x1b" => return Ok(()),
                b"b" | b"B" => {
                    control::request("lock", None, &[])?;
                    return Ok(());
                }
                b"j" | b"J" | b"\x1b[B" => {
                    selected = (selected + 1).min(records.len().saturating_sub(1))
                }
                b"k" | b"K" | b"\x1b[A" => selected = selected.saturating_sub(1),
                b"r" | b"R" => {
                    after = None;
                    break;
                }
                b"n" | b"N" if next.is_some() => {
                    after = next;
                    break;
                }
                b"d" | b"D"
                    if records
                        .get(selected)
                        .is_some_and(|record| record.state == State::Private) =>
                {
                    let id = &records[selected].id;
                    terminal.write(&format!("{CLEAR} Permanently delete private copy\r\n {id}\r\n\r\n These files have not been delivered to the chat.\r\n [D] Confirm deletion  [B] Lock everything\r\n Any other key cancels."))?;
                    match terminal.input(-1)?.as_slice() {
                        b"d" | b"D" => {
                            if recover(terminal, &Request::Discard { id: id.clone() })?.is_none() {
                                return Ok(());
                            }
                            after = None;
                            break;
                        }
                        b"b" | b"B" => {
                            control::request("lock", None, &[])?;
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
}

fn wait<T: Send + 'static>(
    terminal: &mut Terminal,
    stream: &UnixStream,
    read: impl FnOnce(&mut Channel) -> io::Result<T> + Send + 'static,
) -> Result<Option<T>> {
    let copy = stream.try_clone()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = Channel::new(
            File::from(OwnedFd::from(copy)),
            Duration::from_secs(transfers::BUDGET_SECONDS),
        )
        .and_then(|mut channel| read(&mut channel));
        let _ = sender.send(result);
    });
    loop {
        match receiver.try_recv() {
            Ok(result) => {
                worker.join().map_err(|_| "transfer_reader_failed")?;
                return result.map(Some).map_err(|_| "transfer_failed".into());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                worker.join().map_err(|_| "transfer_reader_failed")?;
                return Err("transfer_failed".into());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let input = terminal.input(50)?;
        if matches!(input.as_slice(), b"\x1b" | b"b" | b"B") {
            stream.shutdown(Shutdown::Both)?;
            worker.join().map_err(|_| "transfer_reader_failed")?;
            command(&Command::Cancel)?;
            if input.as_slice() != b"\x1b" {
                control::request("lock", None, &[])?;
            }
            return Ok(None);
        }
    }
}
