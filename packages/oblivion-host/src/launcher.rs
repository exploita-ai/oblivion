use oblivion_host::{agent, control, scope};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
mod file_commands;
mod backup_commands;
mod idle_commands;
mod init_commands;
mod network_commands;
mod native_overlay;
mod proxy_commands;
mod safe_commands;
mod share_commands;
mod shell_commands;
mod child_task_commands;

const HELP: &str = "Oblivion — isolated, encrypted workspaces for coding agents

  oblivion                         Open the manager
  oblivion init                    Create encrypted storage
  oblivion init --reset-incomplete Review and reset unfinished app storage
  oblivion unlock                  Unlock encrypted storage
  oblivion unlock --read-only      Read the encrypted archive without saving
  oblivion ephemeral               Enter RAM-only mode
  oblivion safes                   List Safes
  oblivion status --json           Read controller state
  oblivion intro --json            Claim the direct runtime's boot wordmark
  oblivion run [OPTIONS] AGENT [AGENT_ARGUMENTS...]
  oblivion shell --safe SAFE        Open the Safe's tmux workspace
  oblivion shell --safe SAFE --policy offline
  oblivion close SAFE              Close and lock one Safe
  oblivion lock                    Lock Oblivion and all Safes

Safe management
  oblivion safe open SAFE          Open offline for files
  oblivion safe rename SAFE NAME   Change its title
  oblivion safe grow SAFE MIB      Increase a closed Safe's capacity
  oblivion safe task status SAFE [--json]
  oblivion safe task review SAFE [--json]
  oblivion safe task start|retry|cancel SAFE [--request ID] [--json]

Desktop runtime bundles
  oblivion runtime install-bundle BUNDLE
  oblivion runtime install BUNDLE
  oblivion runtime update BUNDLE
  oblivion runtime deploy BUNDLE
  oblivion runtime start|stop|recover

Files
  oblivion files list --safe SAFE [workspace/PATH] --json
  oblivion files import --safe SAFE SOURCE [--name NAME]
  oblivion files export --safe SAFE workspace/PATH DESTINATION

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
Proxy USER without :PASS prompts privately for its password.
In an interactive agent: F7 opens Files, F9 opens Network. The agent keeps running.
Esc returns from the trusted overlay. Function keys in pasted text are passed through.
";

static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(value: i32) {
    SIGNAL.store(value, Ordering::Relaxed);
}

fn main() {
    let result = run();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| matches!(arg.to_str(), Some("run" | "shell" | "files" | "share" | "close" | "lock")))
        && std::env::var_os("OBLIVION_CONTROL_SOCKET").is_some()
    {
        let cleanup = oblivion_host::native_runtime::stop_if_idle();
        result.and_then(|code| cleanup.map(|()| code))
    } else {
        result
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Oblivion: {error}");
            std::process::exit(1);
        }
    }
}

#[derive(Deserialize)]
struct Status {
    app_open: bool,
    app_mode: AppMode,
    general_present: bool,
    general_incomplete: bool,
    persistence: Option<oblivion_host::persistence::Status>,
    recovery_required: bool,
    sessions: Vec<String>,
    session_titles: BTreeMap<String, String>,
    open_sessions: Vec<Opened>,
    agent_safes: Vec<AgentSafe>,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AppMode { Locked, Persistent, ReadOnly, RamOnly }
#[derive(Deserialize)]
struct Opened {
    slot: scope::Slot,
    id: Option<String>,
    mode: Option<String>,
}
#[derive(Deserialize)]
struct AgentSafe {
    id: String,
    ephemeral: bool,
    state: AgentSafeState,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AgentSafeState { AwaitingStart, Failed, RecoveryRequired }
fn status() -> control::Result<Status> {
    Ok(serde_json::from_str(&control::request(
        "status",
        None,
        &[],
    )?)?)
}

fn run() -> control::Result<i32> {
    control::protect()?;
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "Arguments must use valid UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "--help" | "-h" | "help"))
    {
        print!("{HELP}");
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("oblivion {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    // Event reports must never boot or unlock a runtime that has already shut
    // down. They can only address the existing trusted control connection.
    if args.len() == 1 && args[0] == "activity" {
        return oblivion_host::activity::forward_stdin();
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if args.first().is_some_and(|arg| arg == "runtime") {
            match args.get(1).map(String::as_str) {
                Some("install-bundle") if args.len() == 3 => {
                    oblivion_host::native_runtime::install_bundle(std::path::Path::new(&args[2]))?
                }
                Some("deploy") if args.len() == 3 => {
                    oblivion_host::native_runtime::deploy(std::path::Path::new(&args[2]))?
                }
                Some("install") if args.len() == 3 => {
                    oblivion_host::native_runtime::install(std::path::Path::new(&args[2]))?
                }
                Some("update") if args.len() == 3 => {
                    oblivion_host::native_runtime::update(std::path::Path::new(&args[2]))?
                }
                Some("start") if args.len() == 2 => oblivion_host::native_runtime::start()?,
                Some("recover") if args.len() == 2 => oblivion_host::native_runtime::recover()?,
                Some("stop") if args.len() == 2 => oblivion_host::native_runtime::stop()?,
                _ => {
                    return Err(
                        "Use oblivion runtime install-bundle BUNDLE or oblivion runtime start".into(),
                    );
                }
            }
            return Ok(0);
        }
        if oblivion_host::native_runtime::mode()? == oblivion_host::native_runtime::Mode::Desktop {
            oblivion_host::desktop_bundle::prepare_environment()?;
        }
        oblivion_host::native_runtime::ensure()?;
    }
    if args.is_empty() {
        let launcher = std::env::current_exe()?;
        let manager = launcher
            .parent()
            .ok_or("executable_directory_missing")?
            .join("oblivion-manager");
        return Err(Command::new(manager)
            .env("OBLIVION_LAUNCHER", launcher)
            .exec()
            .into());
    }
    match args[0].as_str() {
        "settings" => idle_commands::run(&args[1..]),
        "status" if args.len() == 2 && args[1] == "--json" => {
            println!("{}", control::request("status", None, &[])?);
            Ok(0)
        }
        "intro" if args.len() == 2 && args[1] == "--json" => {
            println!("{}", control::request("claim-intro", None, &[])?);
            Ok(0)
        }
        "init" => init_commands::run(&args[1..]),
        "unlock" if args.len() == 1 => {
            unlock(false)?;
            Ok(0)
        }
        "unlock" if args.len() == 2 && args[1] == "--read-only" => {
            unlock(true)?;
            Ok(0)
        }
        "ephemeral" if args.len() == 1 => {
            let state = status()?;
            if state.app_mode == AppMode::RamOnly { return Ok(0) }
            if state.app_open { return Err("Lock Oblivion, then enter Ephemeral mode. Active work must close before changing storage modes.".into()) }
            control::request("enter-ram", None, &[])?;
            Ok(0)
        }
        "lock" if args.len() == 1 => {
            control::request("lock", None, &[])?;
            Ok(0)
        }
        "safes" if args.len() == 1 => {
            let state = status()?;
            if !state.app_open {
                return Err("Oblivion is locked. Run oblivion unlock.".into());
            }
            for id in safe_ids(&state) {
                let name = state
                    .session_titles
                    .get(id)
                    .map(String::as_str)
                    .unwrap_or(id);
                let mode = state
                    .open_sessions
                    .iter()
                    .find(|opened| opened.id.as_ref() == Some(id))
                    .and_then(|opened| opened.mode.as_deref())
                    .unwrap_or_else(|| match state.agent_safes.iter().find(|safe| safe.id == *id).map(|safe| safe.state) {
                        Some(AgentSafeState::AwaitingStart) => "awaiting-start",
                        Some(AgentSafeState::Failed) => "creation-failed",
                        Some(AgentSafeState::RecoveryRequired) => "recovery-required",
                        None => "locked",
                    });
                println!("{name}\t{id}\t{mode}");
            }
            Ok(0)
        }
        "close" if args.len() == 2 => {
            let state = status()?;
            let id = find_safe(&state, &args[1])?.ok_or("Safe not found")?;
            let opened = state
                .open_sessions
                .iter()
                .find(|opened| opened.id.as_deref() == Some(&id))
                .ok_or("Safe is already locked")?;
            scope::within(opened.slot, || {
                control::request_for(&id, "close", None, &[])
            })?;
            Ok(0)
        }
        "run" => launch(&args[1..]),
        "shell" => shell_commands::run(&args[1..]),
        "files" => file_commands::run(&args[1..]),
        "backup" => backup_commands::run(&args[1..]),
        "share" => share_commands::run(&args[1..]),
        "safe" => safe_commands::run(&args[1..]),
        "network" => network_commands::run(&args[1..]),
        "proxy" => proxy_commands::run(&args[1..]),
        _ => Err("Unknown command. Run oblivion --help.".into()),
    }
}

fn unlock(read_only: bool) -> control::Result<()> {
    let state = status()?;
    if state.app_open {
        if state.app_mode != if read_only { AppMode::ReadOnly } else { AppMode::Persistent } {
            return Err("Lock Oblivion before changing its storage mode".into());
        }
        return Ok(());
    }
    if !state.general_present {
        return Err("Encrypted storage is missing. Run oblivion init.".into());
    }
    control::request(
        if read_only {
            "unlock-read-only"
        } else {
            "unlock"
        },
        None,
        &password("Oblivion password", false)?,
    )?;
    Ok(())
}

struct Options {
    safe: Option<String>,
    name: Option<String>,
    ephemeral: bool,
    transport: Option<oblivion_transport::Transport>,
    proxy_profile: Option<String>,
    policy: Option<&'static str>,
    agent: String,
    argv: Vec<String>,
}
fn options(args: &[String]) -> control::Result<Options> {
    let mut result = Options {
        safe: None,
        name: None,
        ephemeral: false,
        transport: None,
        proxy_profile: None,
        policy: None,
        agent: String::new(),
        argv: vec![],
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--safe" => {
                if result.safe.is_some() {
                    return Err("Duplicate --safe".into());
                }
                result.safe = Some(args.next().ok_or("Missing Safe name")?.clone());
            }
            "--name" => {
                if result.name.is_some() {
                    return Err("Duplicate --name".into());
                }
                result.name = Some(args.next().ok_or("Missing Safe name")?.clone());
            }
            "--ephemeral" => result.ephemeral = true,
            "--tor" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                result.transport = Some(oblivion_transport::Transport::Tor {});
            }
            "--proxy" | "-x" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                result.transport = Some(proxy(args.next().ok_or("Missing proxy URL")?)?);
            }
            "--proxy-profile" => {
                if result.transport.is_some() || result.proxy_profile.is_some() {
                    return Err("Choose one transport".into());
                }
                let name = args.next().ok_or("Missing proxy profile name")?;
                oblivion_host::proxy_profiles::valid_name(name)?;
                result.proxy_profile = Some(name.clone());
            }
            "--policy" => {
                if result.policy.is_some() {
                    return Err("Duplicate --policy".into());
                }
                result.policy = Some(match args.next().map(String::as_str) {
                    Some("open-internet") => "open",
                    Some("strict") => "strict",
                    Some("offline") => "offline",
                    _ => return Err("Policy must be open-internet, strict or offline".into()),
                });
            }
            "codex" | "claude" | "opencode2" => {
                result.agent = arg.clone();
                result.argv = args.cloned().collect();
                break;
            }
            _ => {
                return Err("Expected an Oblivion option or an agent. Run oblivion --help.".into());
            }
        }
    }
    if result.agent.is_empty() {
        return Err("Choose codex, claude or opencode2".into());
    }
    if (result.ephemeral && (result.safe.is_some() || result.name.is_some()))
        || (result.safe.is_some() && result.name.is_some())
    {
        return Err("A named Safe and --ephemeral cannot be combined".into());
    }
    for name in result.safe.iter().chain(result.name.iter()) {
        oblivion_host::session_title::validate(name)?;
    }
    Ok(result)
}

fn proxy(url: &str) -> control::Result<oblivion_transport::Transport> {
    use oblivion_transport::{Authentication, Transport};
    let value = url
        .strip_prefix("socks5h://")
        .or_else(|| url.strip_prefix("socks5://"))
        .ok_or("Expected socks5h://[USER:PASS@]IP:PORT")?;
    let (endpoint, authentication) = match value.rsplit_once('@') {
        None => (value, None),
        Some((credentials, endpoint)) => {
            let (user, pass) = match credentials.split_once(':') {
                Some((user, pass)) => (decode(user)?, Zeroizing::new(decode(pass)?)),
                None => (
                    decode(credentials)?,
                    Zeroizing::new(String::from_utf8(
                        password("Proxy password", false)?.to_vec(),
                    )?),
                ),
            };
            (
                endpoint,
                Some(Authentication {
                    username: Zeroizing::new(user),
                    password: pass,
                }),
            )
        }
    };
    let result = Transport::Socks5 {
        endpoint: endpoint
            .parse()
            .map_err(|_| "Proxy endpoint must be an IPv4 address and port")?,
        authentication,
    };
    result.validate()?;
    Ok(result)
}
fn decode(value: &str) -> control::Result<String> {
    let mut bytes = Vec::new();
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let digit = |byte: u8| {
            (byte as char)
                .to_digit(16)
                .map(|n| n as u8)
                .ok_or("Invalid proxy URL encoding")
        };
        bytes.push(
            digit(input.next().ok_or("Invalid proxy URL encoding")?)? * 16
                + digit(input.next().ok_or("Invalid proxy URL encoding")?)?,
        );
    }
    Ok(String::from_utf8(bytes)?)
}

fn find_safe(state: &Status, name: &str) -> control::Result<Option<String>> {
    let ids: std::collections::BTreeSet<_> = safe_ids(state).into_iter()
        .filter(|id| {
            id.as_str() == name
                || state
                    .session_titles
                    .get(*id)
                    .is_some_and(|title| title == name)
        })
        .collect();
    match ids.len() {
        0 => Ok(None),
        1 => Ok(ids.first().map(|id| (*id).clone())),
        _ => Err("Ambiguous Safe name. Use its full identifier.".into()),
    }
}

fn safe_ids(state: &Status) -> std::collections::BTreeSet<&String> {
    state
        .sessions
        .iter()
        .chain(
            state
                .open_sessions
                .iter()
                .filter_map(|safe| safe.id.as_ref()),
        )
        .chain(state.agent_safes.iter().filter(|safe| safe.ephemeral).map(|safe| &safe.id))
        .collect()
}

fn open_existing(state: &Status, id: &str) -> control::Result<()> {
    let child = state.agent_safes.iter().find(|safe| safe.id == id);
    if child.is_some_and(|safe| safe.state != AgentSafeState::AwaitingStart) {
        return Err("The child Safe was not created successfully. Review its recovery state before opening.".into());
    }
    if child.is_some_and(|safe| safe.ephemeral) {
        control::request_for(id, "open-child-documents", Some(id), &[])?;
        return Ok(());
    }
    control::request("open-documents", Some(id), &password("Safe password", false)?)?;
    Ok(())
}

fn free_slot(state: &Status) -> control::Result<scope::Slot> {
    (0..scope::LIMIT)
        .filter_map(|index| scope::Slot::try_from(index).ok())
        .find(|slot| {
            !state
                .open_sessions
                .iter()
                .any(|opened| opened.slot == *slot)
        })
        .ok_or_else(|| "No Safe slots available".into())
}

fn start_agent(id: &str) -> control::Result<()> {
    let started = Instant::now();
    let mut waiting = false;
    loop {
        match control::request_for(id, "start-agent", None, &[]) {
            Ok(_) => return Ok(()),
            Err(error)
                if error.to_string() == "gateway_not_ready"
                    && started.elapsed() < Duration::from_secs(240) =>
            {
                if !waiting {
                    eprintln!("Waiting for the protected connection…");
                    waiting = true;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(error) => return Err(error),
        }
    }
}

fn launch(args: &[String]) -> control::Result<i32> {
    let options = options(args)?;
    let initial = status()?;
    if !initial.app_open {
        if options.ephemeral {
            control::request("enter-ram", None, &[])?;
        } else {
            // An explicit new-Safe launch can guide first-run setup. An
            // existing-Safe request must never replace a missing archive.
            if options.safe.is_none() && !initial.general_present {
                init_commands::run(&[])?;
            }
            unlock(false)?;
        }
    }
    let state = status()?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
    }
    if options.ephemeral && state.app_mode == AppMode::Persistent {
        return Err("Lock Oblivion, then enter Ephemeral mode before creating a RAM-only Safe.".into());
    }
    if options.name.is_some() && state.app_mode != AppMode::Persistent {
        return Err("Named persistent Safes require persistent mode. Lock and unlock encrypted storage first.".into());
    }
    let existing = options
        .safe
        .as_deref()
        .map(|name| find_safe(&state, name))
        .transpose()?
        .flatten();
    if options.safe.is_some() && existing.is_none() {
        return Err("Safe not found. Create it explicitly with --name NAME.".into());
    }
    if options
        .name
        .as_deref()
        .map(|name| find_safe(&state, name))
        .transpose()?
        .flatten()
        .is_some()
    {
        return Err("A Safe with this name already exists".into());
    }
    if let Some(opened) = state
        .open_sessions
        .iter()
        .find(|opened| opened.id == existing && existing.is_some())
    {
        if options.transport.is_some() || options.proxy_profile.is_some() || options.policy.is_some() {
            return Err(
                "Safe is active. Change its network through the trusted network controls.".into(),
            );
        }
        return scope::within(opened.slot, || {
            start_agent(existing.as_deref().unwrap())?;
            attach(existing.as_deref().unwrap(), options)
        });
    }
    let slot = free_slot(&state)?;
    scope::within(slot, || {
        let id = if let Some(id) = existing {
            open_existing(&state, &id)?;
            id
        } else if options.ephemeral || state.app_mode != AppMode::Persistent {
            control::request("open-documents-ephemeral", None, &[])?;
            status()?
                .open_sessions
                .into_iter()
                .find(|opened| opened.slot == slot)
                .and_then(|opened| opened.id)
                .ok_or("Safe failed to open")?
        } else {
            let secret = new_password("New Safe password")?;
            let id = control::request("create", None, &secret)?.trim().to_owned();
            let title = options
                .name
                .clone()
                .unwrap_or_else(|| format!("Safe {}", &id[..8]));
            control::request(
                "rename-session",
                None,
                &serde_json::to_vec(&json!({"id":id,"title":title}))?,
            )?;
            control::request("open-documents", Some(&id), &secret)?;
            eprintln!("Safe {} opened", &id[..8]);
            id
        };
        let result = (|| {
            if let Some(transport) = options.transport {
                let command = if state.app_mode != AppMode::Persistent {
                    oblivion_host::egress::Command::Select { transport }
                } else {
                    oblivion_host::egress::Command::Save { transport }
                };
                control::request("egress", None, &Zeroizing::new(serde_json::to_vec(&command)?))?;
            }
            if let Some(name) = &options.proxy_profile {
                control::request_for(
                    &id, "proxy-profiles", None,
                    &serde_json::to_vec(&oblivion_host::proxy_profiles::Command::Select { name: name.clone() })?,
                )?;
            }
            if let Some(policy) = options.policy {
                control::request_for(
                    &id,
                    "safe-access",
                    None,
                    &serde_json::to_vec(
                        &json!({"mode":policy,"save":state.app_mode == AppMode::Persistent}),
                    )?,
                )?;
            }
            start_agent(&id)?;
            attach(
                &id,
                Options {
                    transport: None,
                    ..options
                },
            )
        })();
        // A failed attachment may leave a fully booted agent VM with no client.
        // The controller checks ownership under its lock before closing it.
        if result.is_err() {
            if let Err(error) = control::request_for(&id, "close-idle", None, &[]) {
                if error.to_string() != "session_changed" { return Err(error); }
            }
        }
        result
    })
}

fn password(label: &str, confirm: bool) -> control::Result<Zeroizing<Vec<u8>>> {
    let mut activity = oblivion_host::activity::Reporter::current_host()?;
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "Password entry requires an interactive terminal")?;
    write!(tty, "{label}: ")?;
    tty.flush()?;
    let mut saved = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut saved) } != 0 {
        return Err("Password requires a terminal".into());
    }
    let mut hidden = saved;
    hidden.c_lflag &= !(libc::ECHO | libc::ISIG);
    if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
        return Err("Cannot hide password input".into());
    }
    let mut result = Zeroizing::new(Vec::new());
    let input = (|| -> control::Result<()> {
        let mut byte = [0];
        loop {
            tty.read_exact(&mut byte)?;
            if let Some(activity) = activity.as_mut() { activity.touch(Instant::now()) }
            if byte[0] == b'\n' || byte[0] == b'\r' {
                break;
            }
            if byte[0] == 3 {
                return Err("Password entry cancelled".into());
            }
            if result.len() >= 1024 {
                return Err("Password too long".into());
            }
            result.push(byte[0]);
        }
        if confirm && result.len() < 16 {
            return Err("Use at least 16 characters".into());
        }
        if result.is_empty() {
            return Err("Password is empty".into());
        }
        Ok(())
    })();
    unsafe {
        libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &saved);
    }
    writeln!(tty)?;
    input?;
    Ok(result)
}
fn new_password(label: &str) -> control::Result<Zeroizing<Vec<u8>>> {
    let first = password(label, true)?;
    if *first != *password("Confirm password", false)? {
        return Err("Passwords do not match".into());
    }
    Ok(first)
}

fn attach(id: &str, options: Options) -> control::Result<i32> {
    let launch = agent::Launch {
        agent: options.agent,
        argv: options.argv,
        managed: None,
        terminal: if unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 } {
            Some(size())
        } else {
            None
        },
    };
    attach_command(id, agent::Command::Agent(&launch))
}

fn attach_workspace(id: &str) -> control::Result<i32> {
    if unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        return Err("Workspace requires an interactive terminal".into());
    }
    attach_command(id, agent::Command::Workspace { terminal: size() })
}

fn attach_command(id: &str, command: agent::Command<'_>) -> control::Result<i32> {
    let (mut stream, lease, client) = control::attach_client("agent-attach", id)?;
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    let mut saved = unsafe { std::mem::zeroed() };
    if tty && unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
        return Err("Cannot read terminal settings".into());
    }
    let activity = if tty { Some(oblivion_host::activity::Reporter::current_safe(id)?) } else { None };
    command.write(&mut stream)?;
    if tty {
        let mut raw = saved;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw) } != 0 {
            return Err("Cannot configure terminal".into());
        }
    }
    let signals = [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGWINCH,
    ];
    let handlers: Vec<_> = signals
        .iter()
        .map(|value| unsafe { libc::signal(*value, signal as *const () as libc::sighandler_t) })
        .collect();
    let result = native_overlay::bridge(&mut stream, tty, id, saved, activity);
    for (value, handler) in signals.iter().zip(handlers) {
        unsafe {
            libc::signal(*value, handler);
        }
    }
    if tty {
        unsafe {
            libc::tcsetattr(0, libc::TCSAFLUSH, &saved);
        }
    }
    // Closing the lease is observable even if the launcher is SIGKILLed.
    let released = control::release_agent(&client, id);
    drop(lease);
    released?;
    result
}
fn size() -> agent::Size {
    let mut value: libc::winsize = unsafe { std::mem::zeroed() };
    unsafe {
        libc::ioctl(0, libc::TIOCGWINSZ, &mut value);
    }
    agent::Size {
        rows: value.ws_row.clamp(1, 1000),
        cols: value.ws_col.clamp(1, 1000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> control::Result<Options> {
        options(
            &values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn agent_arguments_are_opaque_after_its_name() {
        let result = parse(&[
            "--safe",
            "GB",
            "codex",
            "--resume",
            "chat-1",
            "--safe",
            "other",
            "",
            "$(touch /tmp/never)",
            "a b",
            "città",
        ])
        .unwrap();
        assert_eq!(result.safe.as_deref(), Some("GB"));
        assert_eq!(result.agent, "codex");
        assert_eq!(
            result.argv,
            [
                "--resume",
                "chat-1",
                "--safe",
                "other",
                "",
                "$(touch /tmp/never)",
                "a b",
                "città"
            ]
        );
    }

    #[test]
    fn conflicting_launch_options_are_rejected() {
        assert!(parse(&["--safe", "GB", "--ephemeral", "codex"]).is_err());
        assert!(parse(&["--safe", "GB", "--safe", "GB", "codex"]).is_err());
        assert!(parse(&["--policy", "direct", "codex"]).is_err());
        assert!(parse(&["--tor", "-x", "socks5h://192.0.2.1:1080", "codex"]).is_err());
        assert!(parse(&["--proxy-profile", "Office", "--tor", "codex"]).is_err());
        assert!(parse(&["--proxy-profile", "Office", "--proxy-profile", "Other", "codex"]).is_err());
        assert!(parse(&["--proxy-profile", "../outside", "codex"]).is_err());
    }

    #[test]
    fn named_proxy_is_only_a_controller_reference() {
        let result = parse(&["--proxy-profile", "Office", "codex", "--proxy-profile", "native-argument"]).unwrap();
        assert_eq!(result.proxy_profile.as_deref(), Some("Office"));
        assert!(result.transport.is_none());
        assert_eq!(result.argv, ["--proxy-profile", "native-argument"]);
    }

    #[test]
    fn closed_ram_children_resolve_to_their_existing_identity() {
        let mut state: Status = serde_json::from_value(json!({
            "app_open":true,"app_mode":"ram-only","general_present":false,
            "general_incomplete":false,"persistence":null,"recovery_required":false,
            "sessions":[],"session_titles":{},"open_sessions":[],
            "agent_safes":[{"id":"a".repeat(32),"ephemeral":true,"state":"awaiting-start"},
                {"id":"b".repeat(32),"ephemeral":false,"state":"awaiting-start"}],
        })).unwrap();
        assert_eq!(find_safe(&state, &"a".repeat(32)).unwrap().as_deref(), Some("a".repeat(32).as_str()));
        assert!(find_safe(&state, &"b".repeat(32)).unwrap().is_none());
        assert!(find_safe(&state, "missing").unwrap().is_none());
        state.agent_safes[0].state = AgentSafeState::Failed;
        assert!(open_existing(&state, &"a".repeat(32)).unwrap_err().to_string().contains("not created successfully"));
        state.agent_safes[0].state = AgentSafeState::RecoveryRequired;
        assert!(open_existing(&state, &"a".repeat(32)).is_err());
    }

    #[test]
    fn authenticated_proxy_decodes_without_resolving_destinations() {
        let oblivion_transport::Transport::Socks5 {
            endpoint,
            authentication,
        } = proxy("socks5://a%40b:c%3Ad@192.0.2.1:1080").unwrap()
        else {
            panic!()
        };
        assert_eq!(endpoint.to_string(), "192.0.2.1:1080");
        let auth = authentication.unwrap();
        assert_eq!(&*auth.username, "a@b");
        assert_eq!(&*auth.password, "c:d");
        assert!(proxy("socks5h://localhost:1080").is_err());
        assert!(proxy("socks5h://127.0.0.1:1080").is_err());
        assert!(proxy("socks5h://user:%zz@192.0.2.1:1080").is_err());
    }

    #[test]
    fn agent_frames_preserve_binary_output_and_bound_memory() {
        let mut wire = vec![];
        agent::write_frame(&mut wire, 1, &[0, 255, b'\n']).unwrap();
        let (kind, bytes) = agent::read_frame(&mut wire.as_slice()).unwrap();
        assert_eq!(kind, 1);
        assert_eq!(bytes, [0, 255, b'\n']);
        assert!(agent::read_frame(&mut [1, 0, 1, 0, 1].as_slice()).is_err());
    }
}
