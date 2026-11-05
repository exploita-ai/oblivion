//! Installed Windows frontend. Syntax is admitted before installation discovery,
//! private prompts or VM startup; the shared executors own product behavior.
use crate::command::{self, Command, Files, RuntimeCommand};
use crate::controller::{self, Result};
use crate::windows::{Client, Runtime};
use crate::{
    activity, backup, child_task, family_password, file_copy, files, network, proxy,
    proxy_profiles, run, safe, settings, shell, storage, windows_file_copy,
};
use oblivion_native_windows::bundle::VerifiedBundle;
use oblivion_native_windows::installation::{self, Installed, Root};
use oblivion_native_windows::security::Identity;
use oblivion_native_windows::supervisor;
use oblivion_wire::idle::Activity;
use oblivion_wire::slot::Slot;
use std::convert::Infallible;
use std::io::{IsTerminal, Read};
use std::path::Path;
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
    let command = command::parse(&args, file_copy::parse, |_| unavailable_share())?;
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
        Command::Backup(backup::Command::Export { .. } | backup::Command::Import { .. }) => {
            return Err("windows_backup_endpoint_not_implemented".into());
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
                    | RuntimeCommand::Start
                    | RuntimeCommand::Stop
                    | RuntimeCommand::Recover
            ) =>
        {
            return Err("windows_runtime_operation_not_implemented".into());
        }
        _ => {}
    }
    let root = Root::current()?;
    match command {
        Command::Activity => forward_activity(&root),
        Command::Runtime(command) => runtime_command(&root, command),
        // A polling manager already owns a supervisor lease. Reading status
        // must not hash a whole controller image or start a VM at every poll.
        Command::Controller(controller::Command::StatusJson) => controller::execute(
            &mut Client::new(&installation::control_id(&root)?)?,
            controller::Command::StatusJson,
            &mut std::io::stdout().lock(),
        ),
        command => {
            let installed = installation::discover(&root)?;
            if installed.source() != source_id()? {
                return Err("installed_runtime_source_mismatch".into());
            }
            let mut runtime = Runtime::supervised(
                &installed.settings()?,
                Arc::new(AtomicBool::new(false)),
                Instant::now() + STARTUP,
            )?;
            execute(command, &installed, &mut runtime)
        }
    }
}

fn execute(
    command: Command<file_copy::CopyCommand, Infallible>,
    installed: &Installed,
    runtime: &mut Runtime,
) -> Result<i32> {
    match command {
        Command::Manager => manager(installed),
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
        Command::Backup(backup::Command::Control(command)) => backup::execute(
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
        Command::Share(never) => match never {},
        _ => Err("Command was not handled by the platform adapter".into()),
    }
}

fn manager(installed: &Installed) -> Result<i32> {
    // Installed owns the verified bundle's non-deletable asset handles until
    // this actual child has exited. The caller keeps the runtime lease too.
    let status = std::process::Command::new(installed.manager())
        .env("OBLIVION_LAUNCHER", installed.launcher())
        .env("OTUI_ASSET_ROOT", installed.assets())
        .env("OBLIVION_RUNTIME_MODE", "desktop")
        .env_remove("OBLIVION_LIVE_STORAGE")
        .env_remove("OBLIVION_SHOW_INTRO")
        .status()
        .map_err(|_| "manager_process_failed")?;
    status
        .code()
        .ok_or_else(|| "manager_exit_unconfirmed".into())
}

fn runtime_command(root: &Root, command: RuntimeCommand) -> Result<i32> {
    let stop = Arc::new(AtomicBool::new(false));
    match command {
        RuntimeCommand::InstallBundle(path) => {
            installation::preflight()?;
            let path = Path::new(&path)
                .canonicalize()
                .map_err(|_| "bundle_directory_unavailable")?;
            // The I/O boundary accepts drive paths, not Win32 extended aliases.
            let path = path.to_str().ok_or("unsupported_bundle_path")?;
            let path = path.strip_prefix(r"\\?\").unwrap_or(path);
            let bundle = VerifiedBundle::open(path, Some(source_id()?), &Identity::current()?)?;
            let installed = installation::install_bundle(
                root,
                bundle,
                DATA_BYTES,
                stop,
                Instant::now() + STARTUP,
            )?;
            println!(
                "Oblivion installed. Open the installed launcher to create encrypted storage:"
            );
            println!("{}", installed.launcher());
            println!("Runtime {}", installed.runtime_id());
            Ok(0)
        }
        RuntimeCommand::Start => {
            let installed = installation::discover(root)?;
            if installed.source() != source_id()? {
                return Err("installed_runtime_source_mismatch".into());
            }
            let lease = installed.acquire(Arc::clone(&stop), Instant::now() + STARTUP)?;
            lease.start_resident(stop, Instant::now() + Duration::from_secs(10))?;
            Ok(0)
        }
        RuntimeCommand::Stop => {
            supervisor::stop(
                &installation::owned_settings(root)?,
                stop,
                Instant::now() + Duration::from_secs(180),
            )?;
            Ok(0)
        }
        RuntimeCommand::Recover => {
            supervisor::recover(&installation::owned_settings(root)?)?;
            Ok(0)
        }
        _ => Err("windows_runtime_operation_not_implemented".into()),
    }
}

fn forward_activity(root: &Root) -> Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin().take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err("invalid_activity_request".into());
    }
    let activity: Activity<Slot> =
        serde_json::from_slice(&bytes).map_err(|_| "invalid_activity_request")?;
    activity::report(
        &mut Client::new(&installation::control_id(root)?)?,
        &activity,
    )?;
    Ok(0)
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

fn unavailable_share() -> Result<Infallible> {
    Err("windows_share_endpoint_not_implemented".into())
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}
