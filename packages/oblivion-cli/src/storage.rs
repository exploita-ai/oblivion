//! Shared encrypted-storage lifecycle. Human confirmation and secret entry stay
//! in the native Runtime; this module owns admission and controller operations.
use crate::controller::{self, AppMode, Call, Result};
use crate::run::{Notice, Runtime};
use oblivion_wire::control::Operation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Init {
        reset_incomplete: bool,
        confirmed_reset: bool,
    },
    Unlock {
        read_only: bool,
    },
    Ephemeral,
    Lock,
}

impl Command {
    pub fn parse(args: &[String]) -> Result<Option<Self>> {
        match args.first().map(String::as_str) {
            Some("init") => {
                let mut reset_incomplete = false;
                let mut confirmed_reset = false;
                for argument in &args[1..] {
                    match argument.as_str() {
                        "--reset-incomplete" if !reset_incomplete => reset_incomplete = true,
                        "--confirmed-reset" if !confirmed_reset => confirmed_reset = true,
                        _ => {
                            return Err(
                                "Use oblivion init [--reset-incomplete [--confirmed-reset]]".into(),
                            );
                        }
                    }
                }
                if confirmed_reset && !reset_incomplete {
                    return Err("--confirmed-reset requires --reset-incomplete".into());
                }
                Ok(Some(Self::Init {
                    reset_incomplete,
                    confirmed_reset,
                }))
            }
            Some("unlock") if args.len() == 1 => Ok(Some(Self::Unlock { read_only: false })),
            Some("unlock") if args.len() == 2 && args[1] == "--read-only" => {
                Ok(Some(Self::Unlock { read_only: true }))
            }
            Some("unlock") => Err("Use oblivion unlock [--read-only]".into()),
            Some("ephemeral") if args.len() == 1 => Ok(Some(Self::Ephemeral)),
            Some("ephemeral") => Err("Use oblivion ephemeral".into()),
            Some("lock") if args.len() == 1 => Ok(Some(Self::Lock)),
            Some("lock") => Err("Use oblivion lock".into()),
            _ => Ok(None),
        }
    }
}

pub fn execute<R: Runtime>(runtime: &mut R, command: Command) -> Result<i32> {
    match command {
        Command::Init {
            reset_incomplete,
            confirmed_reset,
        } => {
            if confirmed_reset && !reset_incomplete {
                return Err("--confirmed-reset requires --reset-incomplete".into());
            }
            let current = controller::status(runtime)?;
            if current.app_open {
                return Err("Lock Oblivion before creating or resetting encrypted storage.".into());
            }
            if current.general_present {
                return Err("Encrypted storage already exists. Run oblivion unlock.".into());
            }
            if current.general_incomplete != reset_incomplete {
                return Err(if current.general_incomplete { "An incomplete storage setup exists. Review it with oblivion init --reset-incomplete." } else { "There is no incomplete storage setup to reset." }.into());
            }
            if reset_incomplete {
                runtime.notice(Notice::IncompleteStorageReview)?;
                if !confirmed_reset && !runtime.confirm("RESET")? {
                    return Err("Storage reset cancelled. Nothing was changed.".into());
                }
                global(runtime, Operation::DiscardGeneralPending, &[])?;
                runtime.notice(Notice::IncompleteStorageDiscarded)?;
                return Ok(0);
            }
            runtime.notice(Notice::StorageCapacity(current.general_bytes))?;
            let secret = runtime.new_password("Oblivion password")?;
            global(runtime, Operation::InitGeneral, &secret)?;
            runtime.notice(Notice::StorageCreated)?;
        }
        Command::Unlock { read_only } => {
            let current = controller::status(runtime)?;
            if current.app_open {
                if current.app_mode
                    != if read_only {
                        AppMode::ReadOnly
                    } else {
                        AppMode::Persistent
                    }
                {
                    return Err("Lock Oblivion before changing its storage mode".into());
                }
                return Ok(0);
            }
            if !current.general_present {
                return Err("Encrypted storage is missing. Run oblivion init.".into());
            }
            let secret = runtime.password("Oblivion password")?;
            global(
                runtime,
                if read_only {
                    Operation::UnlockReadOnly
                } else {
                    Operation::Unlock
                },
                &secret,
            )?;
        }
        Command::Ephemeral => {
            let current = controller::status(runtime)?;
            if current.app_mode == AppMode::RamOnly {
                return Ok(0);
            }
            if current.app_open {
                return Err("Lock Oblivion, then enter Ephemeral mode. Active work must close before changing storage modes.".into());
            }
            global(runtime, Operation::EnterRam, &[])?;
        }
        Command::Lock => {
            global(runtime, Operation::Lock, &[])?;
        }
    }
    Ok(0)
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
