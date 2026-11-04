//! One top-level grammar for native frontends. Platform-owned copy commands
//! supply typed parsers; the common dispatcher never passes unparsed argv on.
use crate::controller::Result;
use crate::{
    backup, child_task, controller, family_password, files, network, proxy, proxy_profiles, run,
    safe, settings, shell, storage,
};

// Run/proxy options may own credentials. Deliberately no Debug implementation.
pub enum Command<F, S> {
    Manager,
    Help,
    Version,
    Activity,
    Runtime(RuntimeCommand),
    Controller(controller::Command),
    Storage(storage::Command),
    Run(run::Options<proxy::Request>),
    Shell(shell::Options),
    Network(network::Command),
    Proxy(proxy_profiles::Command),
    Settings(settings::Command),
    Safe(safe::Command),
    FamilyPassword(family_password::Command),
    ChildTask(child_task::Command),
    Backup(backup::Command),
    Files(Files<F>),
    Share(S),
}

pub enum Files<F> {
    Inspect(files::Command),
    Copy(F),
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeCommand {
    InstallBundle(String),
    Deploy(String),
    Install(String),
    Update(String),
    Start,
    Supervise(String),
    ChooseStorage,
    Recover,
    Stop,
    Gc,
    Uninstall,
}

pub fn parse<F, S>(
    args: &[String],
    files_copy: impl FnOnce(&[String]) -> Result<F>,
    share: impl FnOnce(&[String]) -> Result<S>,
) -> Result<Command<F, S>> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(Command::Manager);
    };
    // Preserve the frontend's existing help/version spellings. Arguments after
    // an agent are handled only by run::parse and remain opaque to this grammar.
    if matches!(first, "--help" | "-h" | "help") {
        return Ok(Command::Help);
    }
    if first == "--version" {
        return Ok(Command::Version);
    }
    if let Some(command) = controller::Command::parse(args)? {
        return Ok(Command::Controller(command));
    }
    if let Some(command) = storage::Command::parse(args)? {
        return Ok(Command::Storage(command));
    }
    Ok(match first {
        "activity" if args.len() == 1 => Command::Activity,
        "runtime" => Command::Runtime(runtime(&args[1..])?),
        "run" => Command::Run(run::parse(&args[1..])?),
        "shell" => Command::Shell(shell::parse(&args[1..])?),
        "network" => Command::Network(network::parse(&args[1..])?),
        "proxy" => Command::Proxy(proxy_profiles::parse(&args[1..])?),
        "settings" => Command::Settings(settings::parse(&args[1..])?),
        "safe" if args.get(1).is_some_and(|value| value == "password") => {
            Command::FamilyPassword(family_password::parse(&args[2..])?)
        }
        "safe" if args.get(1).is_some_and(|value| value == "task") => {
            Command::ChildTask(child_task::parse(&args[2..])?)
        }
        "safe" => Command::Safe(safe::parse(&args[1..])?),
        "backup" => Command::Backup(backup::parse(&args[1..])?),
        "files" => Command::Files(match files::parse(&args[1..])? {
            Some(command) => Files::Inspect(command),
            None => Files::Copy(files_copy(&args[1..])?),
        }),
        "share" => Command::Share(share(&args[1..])?),
        _ => return Err("Unknown command. Run oblivion --help.".into()),
    })
}

impl<F, S> Command<F, S> {
    /// A storage choice is made only for commands which already specified it.
    /// Runtime setup and the actual encrypted-storage admission stay native.
    pub fn live_storage(&self) -> Option<bool> {
        match self {
            Self::Storage(storage::Command::Ephemeral) => Some(true),
            Self::Storage(storage::Command::Init { .. } | storage::Command::Unlock { .. }) => {
                Some(false)
            }
            Self::Run(options) if options.ephemeral => Some(true),
            Self::Run(options) if options.name.is_some() => Some(false),
            _ => None,
        }
    }
}

fn runtime(args: &[String]) -> Result<RuntimeCommand> {
    use RuntimeCommand::{
        ChooseStorage, Deploy, Gc, Install, InstallBundle, Recover, Start, Stop, Supervise,
        Uninstall, Update,
    };
    Ok(match args.first().map(String::as_str) {
        Some("install-bundle") if args.len() == 2 => InstallBundle(args[1].clone()),
        Some("deploy") if args.len() == 2 => Deploy(args[1].clone()),
        Some("install") if args.len() == 2 => Install(args[1].clone()),
        Some("update") if args.len() == 2 => Update(args[1].clone()),
        Some("supervise") if args.len() == 2 => Supervise(args[1].clone()),
        Some("start") if args.len() == 1 => Start,
        Some("choose-storage") if args.len() == 1 => ChooseStorage,
        Some("recover") if args.len() == 1 => Recover,
        Some("stop") if args.len() == 1 => Stop,
        Some("gc") if args.len() == 1 => Gc,
        Some("uninstall") if args.len() == 1 => Uninstall,
        _ => {
            return Err(
                "Use oblivion runtime install-bundle BUNDLE, start, stop, recover, gc or uninstall"
                    .into(),
            )
        }
    })
}

pub const HELP: &str = "Oblivion — isolated, encrypted workspaces for coding agents

  oblivion                         Open the manager
  oblivion init                    Create encrypted storage
  oblivion init --reset-incomplete Review and reset unfinished app storage
  oblivion unlock                  Unlock encrypted storage
  oblivion unlock --read-only      Read the encrypted archive without saving
  oblivion ephemeral               Enter RAM-only mode
  oblivion safes                   List Safes
  oblivion status --json           Read controller state
  oblivion run [OPTIONS] AGENT [AGENT_ARGUMENTS...]
  oblivion shell --safe SAFE        Open the Safe's tmux workspace
  oblivion shell --safe SAFE --policy offline
  oblivion close SAFE              Close and lock one Safe
  oblivion lock                    Lock Oblivion and all Safes

Safe management
  oblivion safe open SAFE          Open offline for files
  oblivion safe rename SAFE NAME   Change its title
  oblivion safe grow SAFE MIB      Increase a closed Safe's capacity
  oblivion safe password SAFE [--confirmed-plan SHA]
  oblivion safe password preview SAFE --json
  oblivion safe password status [--json]
  oblivion safe password recover TRANSACTION --complete|--rollback
  oblivion safe task status SAFE [--json]
  oblivion safe task review SAFE [--json]
  oblivion safe task start|retry|cancel SAFE [--request ID] [--json]

Desktop runtime bundles
  oblivion runtime install-bundle BUNDLE
  oblivion runtime install BUNDLE
  oblivion runtime update BUNDLE
  oblivion runtime deploy BUNDLE
  oblivion runtime start|stop|recover
  oblivion runtime choose-storage  Choose Live backing after stopping its VM
  oblivion runtime gc              Remove stopped, verified old software
  oblivion runtime uninstall       Remove desktop software; keep encrypted data

Files
  oblivion files list --safe SAFE [workspace/PATH] --json
  oblivion files import --safe SAFE --source PATH [--source PATH...] [--name NAME]
  oblivion files export --safe SAFE --path workspace/PATH [--path imports/PATH...]
                       --destination DIR [--name NAME]
  Multiple selections require --name NAME and publish one collection.
  Copy commands review before copying; --yes approves an unattended copy.
  oblivion files transfers --safe SAFE [--destination DIR] [--cursor ID] --json
  Enumerate receiver records; select a directory explicitly for local exports.
  oblivion files status --safe SAFE --operation ID [--destination DIR] --json
  oblivion files recover --safe SAFE --operation ID [--destination DIR]
  oblivion files discard --safe SAFE --operation ID [--destination DIR]
  Copy commands accept --operation ID; exports reconcile only inside DIR.
  Discard removes private incomplete staging, never published files.

Personal backup (complete encrypted Safe, including saved logins)
  oblivion backup export --safe SAFE FILE
  oblivion backup import FILE
  oblivion backup finish TRANSACTION
  oblivion backup status [--json]
  oblivion backup discard TRANSACTION

Share (closed persistent Safes, no provider credentials)
  oblivion share export --safe SAFE FILE [--path workspace/PATH] [--no-chats]
  oblivion share export --branch SAFE FILE
  oblivion share export --all FILE
  oblivion share import FILE [--apply-settings]
  oblivion share imports [--json]   Inspect incomplete and committed imports
  oblivion share discard TRANSACTION
  --exclude PATH / --exclude-chat UUID omit reviewed content

Network, scoped to an open Safe
  oblivion network status --safe SAFE --json
  oblivion network set --safe SAFE --policy open-internet|strict|offline
  oblivion network set --safe SAFE --tor
  oblivion network set --safe SAFE -x socks5h://[USER:PASS@]IP:PORT
  oblivion network set --safe SAFE --proxy-profile NAME

Automatic lock
  oblivion settings idle [--json]
  oblivion settings idle --safe-minutes 15 --host-minutes 30
  Set a timer to 0 explicitly to disable it. Idle locks stop active agents.

Saved SOCKS5 profiles
  oblivion proxy list [--json]      Show profile names and public metadata
  oblivion proxy add NAME [-x URL]  Save a proxy; omitted URL is entered privately
  oblivion proxy remove NAME       Remove a profile without changing active Safes

Run options (before the agent)
  --safe NAME                      Open or reuse an existing Safe
  --name NAME                      Create a new named Safe
  --ephemeral                      Create a RAM-only Safe
  --tor                            Route through Tor
  -x, --proxy socks5h://[USER:PASS@]IP:PORT
  --proxy-profile NAME             Select saved proxy inside the controller
  --policy open-internet|strict|offline

Agents: codex, claude, opencode2
All arguments after the agent are passed unchanged inside the Safe.
File copies review their prepared content before confirmation; --yes explicitly
approves an unattended copy. The manager uses a private event/approval channel.
Proxy USER without :PASS prompts privately for its password.
In an interactive agent: F7 opens Files, F9 opens Network. The agent keeps running.
Esc returns from the trusted overlay. Function keys in pasted text are passed through.
";
