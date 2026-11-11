//! Personal full-volume backups, separate from credential-free Share. Parsing
//! and transaction orchestration are shared; native adapters own file handles,
//! ciphertext copying, attachment cleanup and atomic output publication.
use crate::controller::{self, Call, Controller, Result, State};
use crate::run::Runtime;
use oblivion_wire::backup::{self, Finished, Kind, Outcome, Status};
use oblivion_wire::control::{Operation, valid_id};
use oblivion_wire::session_title;
use serde::Serialize;
use std::io::Write;
use std::time::Duration;
use zeroize::Zeroizing;

const HELP: &str = "Use backup export --safe SAFE FILE, backup import FILE, backup finish TRANSACTION, backup status [--json] or backup discard TRANSACTION";

pub enum Command {
    Export { safe: String, path: String },
    Import { path: String },
    Control(Control),
}
pub struct Control {
    action: Action,
}
enum Action {
    Finish(String),
    Status { json: bool },
    Discard(String),
}

/// A copy endpoint retains the reviewed native file objects. Copy methods must
/// close their data channel and attachment before returning, including errors.
/// An unpublished Output owns cleanup of its private temporary file.
pub trait Native: Runtime {
    type Source;
    type Destination;
    type Output;

    fn prepare_import(&mut self, path: &str) -> Result<Self::Source>;
    fn source_bytes(source: &Self::Source) -> u64;
    fn prepare_export(&mut self, path: &str) -> Result<Self::Destination>;
    fn send_import(
        &mut self,
        source: &mut Self::Source,
        prepared: &backup::Imported,
        slot: Self::Slot,
    ) -> Result<oblivion_transfer::Receipt>;
    fn receive_export(
        &mut self,
        destination: Self::Destination,
        prepared: &backup::Exported,
        slot: Self::Slot,
    ) -> Result<(Self::Output, oblivion_transfer::Receipt)>;
    fn publish_export(&mut self, output: Self::Output) -> Result<String>;
}

pub fn run<R: Native>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32>
where
    R::Slot: Default + Serialize,
{
    if let Command::Control(command) = command {
        return execute(runtime, command, output, diagnostics);
    }
    let state = writable_state(runtime)?;
    if state.recovery_required {
        return Err("Complete recovery before copying a personal backup".into());
    }
    match command {
        Command::Export { safe, path } => {
            let id = state.find_safe(&safe)?.ok_or("Safe not found")?;
            if !state.sessions.contains(&id) {
                return Err("Personal backups require a persistent Safe".into());
            }
            if state
                .open_sessions
                .iter()
                .any(|safe| safe.id.as_ref() == Some(&id))
            {
                return Err("Close the Safe before exporting its personal backup".into());
            }
            let destination = runtime.prepare_export(&path)?;
            let slot = crate::run::free_slot(runtime, &state)?;
            writeln!(
                diagnostics,
                "A personal backup contains the complete encrypted Safe, including saved logins and installed software. Keep its original Safe password."
            )?;
            let secret = runtime.password("Safe password")?;
            let response = runtime.request(Call {
                operation: Operation::BackupExportBegin,
                slot: Some(slot),
                session: Some(&id),
                expected_session: Some(&id),
                secret: &secret,
            })?;
            drop(secret);
            let prepared: backup::Exported =
                serde_json::from_str(&response).map_err(|_| "invalid_backup_preparation")?;
            if !valid_id(&prepared.transaction) {
                return Err("invalid_backup_preparation".into());
            }
            let result = (|| {
                if prepared.safe_id != id || !backup::volume_size(prepared.bytes) {
                    return Err("invalid_backup_preparation".into());
                }
                let (publication, receipt) =
                    runtime.receive_export(destination, &prepared, slot)?;
                verify_receipt(&receipt, &prepared.transaction, prepared.bytes)?;
                copied(runtime, &prepared.transaction, slot)?;
                let path = runtime.publish_export(publication)?;
                writeln!(output, "{}", serde_json::to_string(&receipt)?)?;
                writeln!(diagnostics, "Personal backup saved to {path:?}")?;
                Ok(0)
            })();
            finish_attempt(runtime, &prepared.transaction, slot, result, diagnostics)
        }
        Command::Import { path } => {
            let mut source = runtime.prepare_import(&path)?;
            let bytes = R::source_bytes(&source);
            if !backup::volume_size(bytes) {
                return Err("invalid_backup_source".into());
            }
            let slot = crate::run::free_slot(runtime, &state)?;
            writeln!(
                diagnostics,
                "Restore the complete Safe with its original identity and saved logins. It will remain offline after restoration."
            )?;
            let response = runtime.request(Call {
                operation: Operation::BackupImportBegin,
                slot: Some(slot),
                session: None,
                expected_session: None,
                secret: &[],
            })?;
            let prepared: backup::Imported =
                serde_json::from_str(&response).map_err(|_| "invalid_backup_preparation")?;
            if !valid_id(&prepared.transaction) {
                return Err("invalid_backup_preparation".into());
            }
            let result = (|| {
                if !backup::volume_size(prepared.maximum) {
                    return Err("invalid_backup_preparation".into());
                }
                if bytes > prepared.maximum {
                    return Err("insufficient_restore_space".into());
                }
                let receipt = runtime.send_import(&mut source, &prepared, slot)?;
                verify_receipt(&receipt, &prepared.transaction, bytes)?;
                copied(runtime, &prepared.transaction, slot)?;
                let finished = finish_import(runtime, &prepared.transaction, slot, diagnostics)?;
                writeln!(output, "{}", serde_json::to_string(&finished)?)?;
                writeln!(diagnostics, "Safe {} restored offline.", finished.safe_id)?;
                Ok(0)
            })();
            finish_attempt(runtime, &prepared.transaction, slot, result, diagnostics)
        }
        Command::Control(_) => unreachable!("management commands return before copy preparation"),
    }
}

fn verify_receipt(
    receipt: &oblivion_transfer::Receipt,
    transaction: &str,
    bytes: u64,
) -> Result<()> {
    if receipt.id != transaction || receipt.entries != 1 || receipt.bytes != bytes {
        return Err("invalid_backup_receipt".into());
    }
    Ok(())
}

pub fn parse(args: &[String]) -> Result<Command> {
    let Some((action, rest)) = args.split_first() else {
        return Err(HELP.into());
    };
    match (action.as_str(), rest) {
        ("export", [flag, safe, path]) if flag == "--safe" && input(safe) && input(path) => {
            session_title::validate(safe)?;
            Ok(Command::Export {
                safe: safe.clone(),
                path: path.clone(),
            })
        }
        ("export", [path, flag, safe]) if flag == "--safe" && input(safe) && input(path) => {
            session_title::validate(safe)?;
            Ok(Command::Export {
                safe: safe.clone(),
                path: path.clone(),
            })
        }
        ("import", [path]) if input(path) => Ok(Command::Import { path: path.clone() }),
        ("finish", [transaction]) if valid_id(transaction) => Ok(Command::Control(Control {
            action: Action::Finish(transaction.clone()),
        })),
        ("status", []) => Ok(Command::Control(Control {
            action: Action::Status { json: false },
        })),
        ("status", [flag]) if flag == "--json" => Ok(Command::Control(Control {
            action: Action::Status { json: true },
        })),
        ("discard", [transaction]) if valid_id(transaction) => Ok(Command::Control(Control {
            action: Action::Discard(transaction.clone()),
        })),
        _ => Err(HELP.into()),
    }
}

fn input(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-') && !value.contains('\0')
}

/// Default is the controller's maintenance slot. Global reads must not inherit
/// the calling Safe's slot; all transaction mutations use their recorded slot.
pub fn writable_state<C: Controller>(controller: &mut C) -> Result<State<C::Slot>>
where
    C::Slot: Default,
{
    let state = controller::status_at(controller, Some(Default::default()))?;
    if !state.app_open || state.app_mode != controller::AppMode::Persistent {
        return Err("Unlock writable encrypted storage before using personal backups".into());
    }
    Ok(state)
}

pub fn execute<R: Runtime>(
    runtime: &mut R,
    command: Control,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32>
where
    R::Slot: Default + Serialize,
{
    writable_state(runtime)?;
    let state = status(runtime)?;
    match command.action {
        Action::Status { json } => {
            if json {
                writeln!(output, "{}", serde_json::to_string(&state)?)?;
                return Ok(0);
            }
            for entry in state.transactions {
                writeln!(
                    output,
                    "{}\t{}\t{}{}",
                    entry.transaction,
                    if entry.kind == Kind::Export {
                        "Export"
                    } else {
                        "Import"
                    },
                    outcome(entry.outcome),
                    entry
                        .safe_id
                        .map(|id| format!("\t{id}"))
                        .unwrap_or_default()
                )?;
            }
            Ok(0)
        }
        Action::Finish(transaction) => {
            let entry = state
                .transactions
                .iter()
                .find(|entry| entry.transaction == transaction)
                .ok_or("Backup transaction not found")?;
            if entry.kind != Kind::Import || entry.outcome != Outcome::Copied || entry.active {
                return Err(
                    "Only a verified copy from this unlocked Oblivion opening can be finished"
                        .into(),
                );
            }
            let result = finish_import(runtime, &transaction, entry.slot, diagnostics).and_then(
                |finished| {
                    writeln!(output, "{}", serde_json::to_string(&finished)?)?;
                    writeln!(diagnostics, "Safe {} restored offline.", finished.safe_id)?;
                    Ok(0)
                },
            );
            finish_attempt(runtime, &transaction, entry.slot, result, diagnostics)
        }
        Action::Discard(transaction) => {
            let entry = state
                .transactions
                .iter()
                .find(|entry| entry.transaction == transaction)
                .ok_or("Backup transaction not found")?;
            if entry.outcome == Outcome::Committed || entry.active {
                return Err("A committed or active backup cannot be discarded".into());
            }
            writeln!(
                diagnostics,
                "Discard incomplete backup {transaction}. Existing Safes and committed restores remain intact."
            )?;
            if !runtime.confirm("DISCARD")? {
                return Ok(130);
            }
            runtime.request(Call {
                operation: Operation::BackupDiscard,
                slot: Some(entry.slot),
                session: Some(&transaction),
                expected_session: None,
                secret: &[],
            })?;
            writeln!(diagnostics, "Incomplete backup removed.")?;
            Ok(0)
        }
    }
}

pub fn status<C: Controller>(controller: &mut C) -> Result<Status<C::Slot>>
where
    C::Slot: Default,
{
    let response = controller.request(Call {
        operation: Operation::BackupStatus,
        slot: Some(Default::default()),
        session: None,
        expected_session: None,
        secret: &[],
    })?;
    let status: Status<C::Slot> =
        serde_json::from_str(&response).map_err(|_| "invalid_backup_status")?;
    status.validate()?;
    Ok(status)
}

/// Called both for an already copied transaction and by the native import copy
/// engine. A lost reply is reconciled by status; the restore is never repeated.
pub fn finish_import<R: Runtime>(
    runtime: &mut R,
    transaction: &str,
    slot: R::Slot,
    diagnostics: &mut impl Write,
) -> Result<Finished>
where
    R::Slot: Default,
{
    if !valid_id(transaction) {
        return Err("invalid_backup_transaction".into());
    }
    let secret = runtime.password("Original Safe password")?;
    let password = Zeroizing::new(
        std::str::from_utf8(&secret)
            .map_err(|_| "invalid_secret_encoding")?
            .to_owned(),
    );
    let body = Zeroizing::new(
        serde_json::to_vec(&backup::Finish {
            transaction: transaction.into(),
            password,
        })
        .map_err(|_| "invalid_backup_request")?,
    );
    let response = runtime.request(Call {
        operation: Operation::BackupImportFinish,
        slot: Some(slot),
        session: None,
        expected_session: None,
        secret: &body,
    });
    drop(body);
    let finished: Finished = match response {
        Ok(response) => serde_json::from_str(&response).map_err(|_| "invalid_backup_completion")?,
        Err(error) => match committed(&status(runtime)?, transaction, slot)? {
            Some(finished) => {
                writeln!(
                    diagnostics,
                    "Restoration was confirmed by status after the connection ended; it was not repeated."
                )?;
                finished
            }
            None => return Err(error),
        },
    };
    if finished.transaction != transaction || !valid_id(&finished.safe_id) {
        return Err("invalid_backup_completion".into());
    }
    Ok(finished)
}

pub fn finish_attempt<C: Controller>(
    controller: &mut C,
    transaction: &str,
    slot: C::Slot,
    result: Result<i32>,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    if result.is_err() {
        writeln!(
            diagnostics,
            "Personal backup transaction {transaction}. Inspect `oblivion backup status --json`; do not repeat an uncertain restore."
        )?;
        if let Err(error) = controller.request(Call {
            operation: Operation::BackupCancel,
            slot: Some(slot),
            session: Some(transaction),
            expected_session: None,
            secret: &[],
        }) {
            writeln!(diagnostics, "Backup cleanup needs review: {error}")?;
        }
    }
    result
}

pub fn copied<R: Runtime>(runtime: &mut R, transaction: &str, slot: R::Slot) -> Result<()>
where
    R::Slot: Default,
{
    let started = runtime.now();
    loop {
        let state = status(runtime)?;
        let entry = state
            .transactions
            .iter()
            .find(|entry| entry.transaction == transaction)
            .ok_or("backup_status_missing")?;
        if entry.slot != slot {
            return Err("invalid_backup_status".into());
        }
        if entry.outcome == Outcome::Copied && !entry.active {
            return Ok(());
        }
        if !matches!(
            entry.outcome,
            Outcome::Prepared | Outcome::Copying | Outcome::Copied
        ) || runtime.elapsed(&started) >= Duration::from_secs(10)
        {
            return Err("backup_copy_requires_recovery".into());
        }
        runtime.wait(Duration::from_millis(100))?;
    }
}

fn committed<S: Copy + Eq>(
    status: &Status<S>,
    transaction: &str,
    slot: S,
) -> Result<Option<Finished>> {
    let Some(entry) = status
        .transactions
        .iter()
        .find(|entry| entry.transaction == transaction)
    else {
        return Ok(None);
    };
    if entry.slot != slot {
        return Err("invalid_backup_status".into());
    }
    if entry.kind != Kind::Import || entry.outcome != Outcome::Committed {
        return Ok(None);
    }
    Ok(Some(Finished {
        transaction: transaction.into(),
        safe_id: entry.safe_id.clone().ok_or("invalid_backup_completion")?,
    }))
}

fn outcome(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Prepared => "Prepared",
        Outcome::Copying => "Copying",
        Outcome::Copied => "Copied",
        Outcome::Committed => "Restored",
        Outcome::RecoveryRequired => "Recovery required",
        Outcome::Cancelled => "Cancelled",
    }
}
