//! Installed Windows frontend. Syntax is admitted before installation discovery,
//! private prompts or VM startup; the shared executors own product behavior.
use crate::command::{self, Command, Files, RuntimeCommand};
use crate::controller::{self, Result};
use crate::windows::{Client, Runtime};
use crate::{
    activity, backup, child_task, family_password, file_copy, files, network, proxy,
    proxy_profiles, run, safe, settings, share, shell, storage, windows_file_copy,
};
use oblivion_native_windows::broker::{self, Action, Layout};
use oblivion_native_windows::bundle::VerifiedBundle;
use oblivion_native_windows::installation::Root;
use oblivion_native_windows::security::Identity;
use oblivion_native_windows::user_command::{self, Change};
use oblivion_wire::idle::Activity;
use oblivion_wire::slot::Slot;
use std::io::{IsTerminal, Read};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const STARTUP: Duration = Duration::from_secs(400);
const DATA_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub fn run() -> Result<i32> {
    let args = std::env::args_os()
        .skip(1)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "Arguments must use valid UTF-8")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let command = command::parse(&args, file_copy::parse, share::parse)?;
    // Reject unavailable endpoints and missing review before discovering or
    // booting a runtime. Files uses native local endpoints after this admission.
    match &command {
        Command::Help => {
            print!("{}", command::HELP);
            return Ok(0);
        }
        Command::Version => {
            println!("oblivion {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Command::Files(Files::Copy(command))
            if !command.events_output && !command.confirmed && !std::io::stdin().is_terminal() =>
        {
            return Err("A file copy needs review in a terminal, --yes for an explicit unattended copy, or --events for the manager".into());
        }
        Command::Shell(_) if !interactive() => {
            return Err("Workspace requires an interactive terminal".into());
        }
        Command::Runtime(command)
            if !matches!(
                command,
                RuntimeCommand::InstallBundle(_)
                    | RuntimeCommand::Update(_)
                    | RuntimeCommand::Start
                    | RuntimeCommand::Stop
                    | RuntimeCommand::Recover
                    | RuntimeCommand::Gc
                    | RuntimeCommand::Uninstall
            ) =>
        {
            return Err("windows_runtime_operation_not_implemented".into());
        }
        _ => {}
    }
    match command {
        Command::Activity => forward_activity(),
        Command::Runtime(command) => runtime_command(command),
        // A polling manager already owns a supervisor lease. Reading status
        // must not hash a whole controller image or start a VM at every poll.
        Command::Controller(controller::Command::StatusJson) => controller::execute(
            &mut Client::new(&control_id()?)?,
            controller::Command::StatusJson,
            &mut std::io::stdout().lock(),
        ),
        command => {
            let stop = Arc::new(AtomicBool::new(false));
            let lease = broker::acquire(source_id()?, Arc::clone(&stop), Instant::now() + STARTUP)?;
            let layout = lease.layout().clone();
            let mut runtime = Runtime::brokered(lease, stop)?;
            execute(command, &layout, &mut runtime)
        }
    }
}

fn execute(
    command: Command<file_copy::CopyCommand, share::Command>,
    layout: &Layout,
    runtime: &mut Runtime,
) -> Result<i32> {
    match command {
        Command::Manager => manager(layout),
        Command::Controller(command) => {
            controller::execute(runtime, command, &mut std::io::stdout().lock())
        }
        Command::Storage(command) => storage::execute(runtime, command),
        Command::Run(options) => {
            let options = options.resolve_transport(|request| proxy::complete(request, runtime))?;
            run::execute(
                runtime,
                options,
                run::Context {
                    prefer_ephemeral: false,
                },
            )
        }
        Command::Shell(command) => shell::execute(runtime, command, interactive()),
        Command::Network(command) => network::execute(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        Command::Proxy(command) => proxy_profiles::execute(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        Command::Settings(command) => {
            settings::execute(runtime, command, &mut std::io::stdout().lock())
        }
        Command::Safe(command) => safe::execute(runtime, command, &mut std::io::stdout().lock()),
        Command::FamilyPassword(command) => family_password::execute(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        Command::ChildTask(command) => {
            child_task::execute(runtime, command, &mut std::io::stdout().lock())
        }
        Command::Backup(command) => backup::run(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        Command::Files(Files::Inspect(command)) => files::execute(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        Command::Files(Files::Copy(command)) => windows_file_copy::run(runtime, command),
        Command::Share(command) => share::run(
            runtime,
            command,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
        _ => Err("Command was not handled by the platform adapter".into()),
    }
}

fn manager(layout: &Layout) -> Result<i32> {
    // The authenticated broker supplies administrator-owned software paths.
    // This child and every explicit host-side file copy remain unelevated.
    let status = std::process::Command::new(&layout.manager)
        .env("OBLIVION_LAUNCHER", &layout.launcher)
        .env("OTUI_ASSET_ROOT", &layout.assets)
        .env("OBLIVION_RUNTIME_MODE", "desktop")
        .env_remove("OBLIVION_LIVE_STORAGE")
        .env_remove("OBLIVION_SHOW_INTRO")
        .status()
        .map_err(|_| "manager_process_failed")?;
    status
        .code()
        .ok_or_else(|| "manager_exit_unconfirmed".into())
}

fn runtime_command(command: RuntimeCommand) -> Result<i32> {
    let stop = Arc::new(AtomicBool::new(false));
    match command {
        RuntimeCommand::InstallBundle(path) => {
            maintenance_outcome(oblivion_native_windows::setup::execute(
                bundle_input(&path, Some(source_id()?))?,
                oblivion_native_windows::setup::Operation::Install { bytes: DATA_BYTES },
                stop,
                Instant::now() + STARTUP,
                &mut || {
                    eprintln!(
                        "Oblivion needs the Windows Hyper-V feature. Setup may require a restart."
                    );
                    crate::windows_terminal::confirm("ENABLE", |_| {})
                        .map_err(|_| oblivion_native_windows::Error("setup_review_interrupted"))
                },
            )?)
        }
        RuntimeCommand::Update(path) => {
            maintenance_outcome(oblivion_native_windows::setup::execute(
                bundle_input(&path, None)?,
                oblivion_native_windows::setup::Operation::Update {},
                stop,
                Instant::now() + STARTUP,
                &mut || Err(oblivion_native_windows::Error("unexpected_setup_review")),
            )?)
        }
        RuntimeCommand::Gc | RuntimeCommand::Uninstall => {
            let operation = if command == RuntimeCommand::Gc {
                oblivion_native_windows::setup::Operation::Gc {}
            } else {
                oblivion_native_windows::setup::Operation::Uninstall {}
            };
            maintenance_outcome(oblivion_native_windows::setup::execute(
                VerifiedBundle::current_launcher(source_id()?)?,
                operation,
                stop,
                Instant::now() + STARTUP,
                &mut || Err(oblivion_native_windows::Error("unexpected_setup_review")),
            )?)
        }
        RuntimeCommand::Start => {
            broker::command(Action::Start, source_id()?, stop, Instant::now() + STARTUP)?;
            Ok(0)
        }
        RuntimeCommand::Stop => {
            broker::command(
                Action::Stop,
                source_id()?,
                stop,
                Instant::now() + Duration::from_secs(180),
            )?;
            Ok(0)
        }
        RuntimeCommand::Recover => {
            if let Err(error) = broker::command(
                Action::Recover,
                source_id()?,
                stop,
                Instant::now() + Duration::from_secs(180),
            ) {
                if error.0 == "runtime_busy" {
                    return Err("The protected runtime is active. Use oblivion runtime stop before recovery.".into());
                }
                return Err(error.into());
            }
            Ok(0)
        }
        _ => Err("windows_runtime_operation_not_implemented".into()),
    }
}

fn maintenance_outcome(outcome: oblivion_native_windows::setup::Outcome) -> Result<i32> {
    use oblivion_native_windows::setup::Outcome;
    match outcome {
        Outcome::Installed { registration } => {
            println!("Oblivion installed.");
            println!("\"{}\"", registration.launcher);
            println!("Runtime {}", registration.runtime_id);
            Ok(command_registration(
                user_command::register(&registration.runtime_id, &registration.bundle_id),
                "Open a new terminal and run oblivion to continue.",
            ))
        }
        Outcome::Updated { registration } => {
            println!("Oblivion updated. Encrypted data and runtime identity were preserved.");
            println!("\"{}\"", registration.launcher);
            println!("Runtime {}", registration.runtime_id);
            Ok(command_registration(
                user_command::register(&registration.runtime_id, &registration.bundle_id),
                "Open a new terminal to use the updated oblivion command.",
            ))
        }
        Outcome::Collected { cleanup, .. } => {
            println!("{}", serde_json::to_string(&cleanup)?);
            Ok(0)
        }
        Outcome::Uninstalled {
            runtime_id,
            cleanup,
        } => {
            println!("{}", serde_json::to_string(&cleanup)?);
            println!(
                "Encrypted data and runtime identity are retained at \"{}\".",
                Root::current()?.path().display()
            );
            let command = command_registration(
                user_command::unregister(&runtime_id),
                "Reopen your terminal to refresh its PATH.",
            );
            if !cleanup.software_removed {
                eprintln!(
                    "Software removal is incomplete. Close installed programs and retry from a verified external bundle. Unknown files were preserved."
                );
                return Ok(2);
            }
            Ok(command)
        }
        Outcome::RebootRequired => {
            println!(
                "Windows needs a restart before setup can continue. Restart Windows, then run this installer again."
            );
            Ok(2)
        }
        Outcome::Declined => {
            println!("Operation cancelled.");
            Ok(0)
        }
        Outcome::Blocked { reason } => {
            Err(format!("Windows setup prerequisites are unavailable: {reason}").into())
        }
    }
}

fn command_registration(result: oblivion_native_windows::Result<Change>, success: &str) -> i32 {
    let change = match result {
        Ok(change) => change,
        Err(error) => {
            eprintln!(
                "The user command could not be updated ({error}). Rerun this operation to retry."
            );
            return 2;
        }
    };
    if change.reopen_terminal {
        println!("{success}");
    }
    0
}

fn bundle_input(path: &str, expected_source: Option<&str>) -> Result<VerifiedBundle> {
    // Resolve lexically. Canonicalizing a user-supplied UNC/junction path would
    // access it before the native bundle boundary can reject it.
    let path = std::path::absolute(path)?;
    let mut path = path
        .to_str()
        .ok_or("unsupported_bundle_path")?
        .replace('/', r"\");
    if path.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
        path.replace_range(..1, &path[..1].to_ascii_uppercase());
    }
    match expected_source {
        Some(source) => Ok(VerifiedBundle::open(
            &path,
            Some(source),
            &Identity::current()?,
        )?),
        None => Ok(VerifiedBundle::update_input(&path)?),
    }
}

fn forward_activity() -> Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin().take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err("invalid_activity_request".into());
    }
    let activity: Activity<Slot> =
        serde_json::from_slice(&bytes).map_err(|_| "invalid_activity_request")?;
    activity::report(&mut Client::new(&control_id()?)?, &activity)?;
    Ok(0)
}

fn control_id() -> Result<String> {
    Ok(broker::control_id(
        source_id()?,
        Arc::new(AtomicBool::new(false)),
        Instant::now() + Duration::from_secs(10),
    )?)
}

fn source_id() -> Result<&'static str> {
    option_env!("OBLIVION_DESKTOP_SOURCE_SHA256")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| {
            "Build a current source-bound desktop bundle before using the Windows runtime".into()
        })
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}
