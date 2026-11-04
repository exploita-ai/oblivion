//! Family password-wrapper controls shared by native frontends. Only Runtime
//! owns private password entry and human confirmation; no data key is replaced.
use crate::controller::{self, AppMode, Call, Result};
use crate::run::Runtime;
use oblivion_wire::control::{Operation, valid_id};
use oblivion_wire::{family_rotation, idle, session_title};
use serde::{Deserialize, de::DeserializeOwned};
use std::io::Write;
use zeroize::Zeroizing;

const HELP: &str = "Use safe password SAFE [--confirmed-plan SHA], safe password preview SAFE --json, safe password status [--json], or safe password recover TRANSACTION --complete|--rollback";

pub struct Command {
    action: Action,
}

enum Action {
    Status {
        json: bool,
    },
    Preview {
        safe: String,
    },
    Change {
        safe: String,
        confirmed: Option<String>,
    },
    Recover {
        transaction: String,
        direction: family_rotation::Direction,
    },
}

/// Pure syntax only. Confirmed plans cannot suppress the interactive CHANGE
/// confirmation, and command arguments never carry the human passwords.
pub fn parse(args: &[String]) -> Result<Command> {
    let action = match args {
        [status] if status == "status" => Action::Status { json: false },
        [status, json] if status == "status" && json == "--json" => Action::Status { json: true },
        [preview, safe, json] if preview == "preview" && json == "--json" => {
            session_title::validate(safe)?;
            Action::Preview { safe: safe.clone() }
        }
        [recover, transaction, direction] if recover == "recover" && valid_id(transaction) => {
            Action::Recover {
                transaction: transaction.clone(),
                direction: match direction.as_str() {
                    "--complete" => family_rotation::Direction::Complete,
                    "--rollback" => family_rotation::Direction::Rollback,
                    _ => return Err(HELP.into()),
                },
            }
        }
        [safe] if !matches!(safe.as_str(), "status" | "preview" | "recover") => {
            session_title::validate(safe)?;
            Action::Change {
                safe: safe.clone(),
                confirmed: None,
            }
        }
        [safe, option, sha]
            if !matches!(safe.as_str(), "status" | "preview" | "recover")
                && option == "--confirmed-plan"
                && sha.len() == 64
                && sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            session_title::validate(safe)?;
            Action::Change {
                safe: safe.clone(),
                confirmed: Some(sha.clone()),
            }
        }
        _ => return Err(HELP.into()),
    };
    Ok(Command { action })
}

pub fn execute<R: Runtime>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    let state = controller::status(runtime)?;
    if !state.app_open || state.app_mode != AppMode::Persistent {
        return Err(
            "Unlock writable encrypted storage before changing a Safe family's password".into(),
        );
    }
    match command.action {
        Action::Status { json } => {
            let status = status(runtime)?;
            if json {
                writeln!(output, "{}", serde_json::to_string(&status)?)?;
                return Ok(0);
            }
            for entry in status.transactions {
                writeln!(
                    output,
                    "{}\t{}\t{} Safes",
                    entry.transaction,
                    label(entry.outcome),
                    entry.members.len()
                )?;
            }
            Ok(0)
        }
        Action::Recover {
            transaction,
            direction,
        } => {
            let status = status(runtime)?;
            let entry = status
                .transactions
                .iter()
                .find(|entry| entry.transaction == transaction)
                .ok_or("Password change transaction not found")?;
            if entry.outcome != family_rotation::Outcome::Pending {
                return Err("This password change has already finished".into());
            }
            show(&entry.members, diagnostics)?;
            let complete = direction == family_rotation::Direction::Complete;
            writeln!(
                diagnostics,
                "{} the recorded password-wrapper update for this entire local family.",
                if complete { "Complete" } else { "Roll back" }
            )?;
            if !runtime.confirm(if complete { "COMPLETE" } else { "ROLLBACK" })? {
                return Ok(130);
            }
            let body = serde_json::to_vec(&family_rotation::Recover {
                transaction,
                host_opening: status.host_opening,
                direction,
            })
            .map_err(|_| "invalid_family_password_request")?;
            finish(
                global(runtime, Operation::FamilyPasswordRecover, &body),
                if complete {
                    family_rotation::Outcome::Complete
                } else {
                    family_rotation::Outcome::RolledBack
                },
                output,
                diagnostics,
            )
        }
        Action::Preview { ref safe } | Action::Change { ref safe, .. } => {
            let id = state.find_safe(&safe)?.ok_or("Safe not found")?;
            if !valid_id(&id) {
                return Err("invalid_safe_id".into());
            }
            if !state.sessions.contains(&id) {
                return Err(
                    "Only persistent Safe families have a changeable human password".into(),
                );
            }
            let response = runtime.request(Call {
                operation: Operation::FamilyPasswordPreview,
                slot: None,
                session: Some(&id),
                expected_session: Some(&id),
                secret: &[],
            })?;
            let plan: family_rotation::Plan = decode(&response)?;
            plan.validate()?;
            if plan.host_opening != current_host(runtime)?
                || !plan.members.iter().any(|member| member.safe_id == id)
            {
                return Err(
                    "Family preview no longer belongs to the current Oblivion opening".into(),
                );
            }
            let confirmed = match command.action {
                Action::Preview { .. } => {
                    writeln!(output, "{}", serde_json::to_string(&plan)?)?;
                    return Ok(0);
                }
                Action::Change { confirmed, .. } => confirmed,
                _ => unreachable!(),
            };
            if confirmed.is_some_and(|sha| sha != plan.sha256) {
                return Err("The password change plan changed. Review the current family before continuing.".into());
            }
            show(&plan.members, diagnostics)?;
            writeln!(
                diagnostics,
                "Every local Safe in this family must be closed. Existing external backups keep their previous password."
            )?;
            writeln!(
                diagnostics,
                "This updates the password wrapper; copied old headers and known family keys are not revoked."
            )?;
            if !runtime.confirm("CHANGE")? {
                return Ok(130);
            }
            let current = runtime.password("Current family password")?;
            let current_password = Zeroizing::new(
                std::str::from_utf8(&current)
                    .map_err(|_| "invalid_secret_encoding")?
                    .to_owned(),
            );
            let new = runtime.new_password("New family password")?;
            let new_password = Zeroizing::new(
                std::str::from_utf8(&new)
                    .map_err(|_| "invalid_secret_encoding")?
                    .to_owned(),
            );
            let body = Zeroizing::new(
                serde_json::to_vec(&family_rotation::Change {
                    safe_id: id,
                    host_opening: plan.host_opening,
                    plan_sha256: plan.sha256,
                    current_password,
                    new_password,
                })
                .map_err(|_| "invalid_family_password_request")?,
            );
            finish(
                global(runtime, Operation::FamilyPasswordChange, &body),
                family_rotation::Outcome::Complete,
                output,
                diagnostics,
            )
        }
    }
}

fn global<R: Runtime>(runtime: &mut R, operation: Operation, secret: &[u8]) -> Result<String> {
    runtime.request(Call {
        operation,
        slot: None,
        session: None,
        expected_session: None,
        secret,
    })
}

fn status<R: Runtime>(runtime: &mut R) -> Result<family_rotation::Status> {
    let status: family_rotation::Status =
        decode(&global(runtime, Operation::FamilyPasswordStatus, &[])?)?;
    status.validate()?;
    if status.host_opening != current_host(runtime)? {
        return Err("Oblivion opening changed while reading password changes".into());
    }
    Ok(status)
}

fn current_host<R: Runtime>(runtime: &mut R) -> Result<String> {
    #[derive(Deserialize)]
    struct Current<S> {
        idle_lock: idle::Status<S>,
    }
    let current: Current<R::Slot> = decode(&global(runtime, Operation::Status, &[])?)?;
    let host = current
        .idle_lock
        .host
        .filter(|host| !host.closing && valid_id(&host.nonce))
        .ok_or("Oblivion is closing or its opening changed")?;
    Ok(host.nonce)
}

fn decode<T: DeserializeOwned>(response: &str) -> Result<T> {
    serde_json::from_str(response).map_err(|_| "invalid_family_password_response".into())
}

fn show(members: &[family_rotation::Member], diagnostics: &mut impl Write) -> Result<()> {
    writeln!(diagnostics, "Local family members ({}):", members.len())?;
    for member in members {
        writeln!(diagnostics, "  {}  {}", member.safe_id, member.title)?;
    }
    Ok(())
}

fn label(outcome: family_rotation::Outcome) -> &'static str {
    match outcome {
        family_rotation::Outcome::Pending => "Recovery required",
        family_rotation::Outcome::Complete => "Complete",
        family_rotation::Outcome::RolledBack => "Rolled back",
    }
}

fn finish(
    result: Result<String>,
    expected: family_rotation::Outcome,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32> {
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            writeln!(
                diagnostics,
                "Read `oblivion safe password status` before another attempt. A pending update must be explicitly completed or rolled back."
            )?;
            return Err(error);
        }
    };
    let entry: family_rotation::Entry = decode(&response)?;
    entry.validate()?;
    if entry.outcome != expected {
        return Err(
            "Password update is not complete. Read `oblivion safe password status` for recovery."
                .into(),
        );
    }
    writeln!(output, "{}", serde_json::to_string(&entry)?)?;
    writeln!(
        diagnostics,
        "{} for {} local Safes.",
        label(entry.outcome),
        entry.members.len()
    )?;
    Ok(0)
}
