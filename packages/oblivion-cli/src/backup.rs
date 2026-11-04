//! Personal full-volume backups, separate from credential-free Share. Parsing
//! is shared for every command; ciphertext copying stays in the native adapter.
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
