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

const HELP: &str = "Oblivion — isolated, encrypted workspaces for coding agents\n\n  oblivion                         Open the manager\n  oblivion init                    Create encrypted storage\n  oblivion unlock                  Unlock encrypted storage\n  oblivion safes                   List Safes\n  oblivion run [OPTIONS] AGENT [AGENT_ARGUMENTS...]\n  oblivion close SAFE               Close and lock one Safe\n  oblivion lock                     Lock Oblivion and all Safes\n  oblivion files import --safe SAFE SOURCE [--name NAME]\n  oblivion files export --safe SAFE workspace/PATH DESTINATION\n\nRun options (before the agent)\n  --safe NAME                      Open or reuse an existing Safe\n  --name NAME                      Create a new named Safe\n  --ephemeral                      Create a RAM-only Safe\n  --tor                            Route through Tor\n  -x, --proxy socks5h://[USER:PASS@]IP:PORT\n  --policy open-internet|strict|offline\n\nAgents: codex, claude, opencode2\nAll arguments after the agent are passed unchanged inside the Safe.\n";

static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(value: i32) {
    SIGNAL.store(value, Ordering::Relaxed);
}

fn main() {
    let result = run();
    #[cfg(target_os = "macos")]
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| matches!(arg.to_str(), Some("run" | "files" | "close" | "lock")))
        && std::env::var_os("OBLIVION_CONTROL_SOCKET").is_some()
    {
        oblivion_host::native_runtime::stop_if_idle().and(result)
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
    general_present: bool,
    general_open: bool,
    general_readonly: bool,
    recovery_required: bool,
    sessions: Vec<String>,
    session_titles: BTreeMap<String, String>,
    open_sessions: Vec<Opened>,
}
#[derive(Deserialize)]
struct Opened {
    slot: scope::Slot,
    id: Option<String>,
    mode: Option<String>,
}
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
    #[cfg(target_os = "macos")]
    {
        if args.first().is_some_and(|arg| arg == "runtime") {
            match args.get(1).map(String::as_str) {
                Some("install") if args.len() == 3 => {
                    oblivion_host::native_runtime::install(std::path::Path::new(&args[2]))?
                }
                Some("start") if args.len() == 2 => oblivion_host::native_runtime::ensure()?,
                Some("stop") if args.len() == 2 => oblivion_host::native_runtime::stop()?,
                _ => {
                    return Err(
                        "Use oblivion runtime install IMAGE or oblivion runtime start".into(),
                    );
                }
            }
            return Ok(0);
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
        "status" if args.len() == 2 && args[1] == "--json" => {
            println!("{}", control::request("status", None, &[])?);
            Ok(0)
        }
        "init" if args.len() == 1 => {
            let password = new_password("Oblivion password")?;
            control::request("init-general", None, &password)?;
            eprintln!("Encrypted storage created. Run oblivion unlock.");
            Ok(0)
        }
        "unlock" if args.len() == 1 => {
            unlock(false)?;
            Ok(0)
        }
        "ephemeral" if args.len() == 1 => {
            unlock(true)?;
            Ok(0)
        }
        "lock" if args.len() == 1 => {
            control::request("lock", None, &[])?;
            Ok(0)
        }
        "safes" if args.len() == 1 => {
            let state = status()?;
            if !state.general_open {
                return Err("Oblivion is locked. Run oblivion unlock.".into());
            }
            for id in &state.sessions {
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
                    .unwrap_or("locked");
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
            scope::within(opened.slot, || control::request("close", None, &[]))?;
            Ok(0)
        }
        "run" => launch(&args[1..]),
        "files" => file_commands::run(&args[1..]),
        _ => Err("Unknown command. Run oblivion --help.".into()),
    }
}

fn unlock(ephemeral: bool) -> control::Result<()> {
    let state = status()?;
    if state.general_open {
        if ephemeral && !state.general_readonly {
            return Err("Lock Oblivion before entering ephemeral mode".into());
        }
        return Ok(());
    }
    if !state.general_present {
        return Err("Encrypted storage is missing. Run oblivion init.".into());
    }
    control::request("unlock", None, &password("Oblivion password", false)?)?;
    Ok(())
}

struct Options {
    safe: Option<String>,
    name: Option<String>,
    ephemeral: bool,
    transport: Option<oblivion_transport::Transport>,
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
                if result.transport.is_some() {
                    return Err("Choose one transport".into());
                }
                result.transport = Some(oblivion_transport::Transport::Tor {});
            }
            "--proxy" | "-x" => {
                if result.transport.is_some() {
                    return Err("Choose one transport".into());
                }
                result.transport = Some(proxy(args.next().ok_or("Missing proxy URL")?)?);
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
    let ids: std::collections::BTreeSet<_> = state
        .sessions
        .iter()
        .chain(
            state
                .open_sessions
                .iter()
                .filter_map(|safe| safe.id.as_ref()),
        )
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

fn launch(args: &[String]) -> control::Result<i32> {
    let options = options(args)?;
    if !status()?.general_open {
        unlock(options.ephemeral)?;
    }
    let state = status()?;
    if state.recovery_required {
        return Err("Oblivion requires recovery before opening a Safe".into());
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
        if options.transport.is_some() || options.policy.is_some() {
            return Err(
                "Safe is active. Change its network through the trusted network controls.".into(),
            );
        }
        return scope::within(opened.slot, || {
            attach(existing.as_deref().unwrap(), options)
        });
    }
    let slot = (0..scope::LIMIT)
        .filter_map(|index| scope::Slot::try_from(index).ok())
        .find(|slot| {
            !state
                .open_sessions
                .iter()
                .any(|opened| opened.slot == *slot)
        })
        .ok_or("No Safe slots available")?;
    scope::within(slot, || {
        let id = if options.ephemeral || state.general_readonly {
            control::request("open-documents-ephemeral", None, &[])?;
            status()?
                .open_sessions
                .into_iter()
                .find(|opened| opened.slot == slot)
                .and_then(|opened| opened.id)
                .ok_or("Safe failed to open")?
        } else {
            if state.general_readonly {
                return Err("Named Safes need persistent mode".into());
            }
            let (id, secret) = match existing {
                Some(id) => (id, password("Safe password", false)?),
                None => {
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
                    (id, secret)
                }
            };
            control::request("open-documents", Some(&id), &secret)?;
            eprintln!("Safe {} opened", &id[..8]);
            id
        };
        let result = (|| {
            if let Some(transport) = options.transport {
                let command = if state.general_readonly {
                    oblivion_host::egress::Command::Select { transport }
                } else {
                    oblivion_host::egress::Command::Save { transport }
                };
                control::request("egress", None, &serde_json::to_vec(&command)?)?;
            }
            if let Some(policy) = options.policy {
                control::request(
                    "settings",
                    None,
                    &serde_json::to_vec(
                        &json!({"action":"access","mode":policy,"save":!state.general_readonly}),
                    )?,
                )?;
            }
            let started = Instant::now();
            let mut waiting = false;
            loop {
                match control::request("start-agent", None, &[]) {
                    Ok(_) => break,
                    Err(error)
                        if error.to_string() == "gateway_not_ready"
                            && started.elapsed() < Duration::from_secs(240) =>
                    {
                        if !waiting {
                            eprintln!("Waiting for the protected connection…");
                            waiting = true;
                        }
                        std::thread::sleep(Duration::from_millis(500))
                    }
                    Err(error) => return Err(error),
                }
            }
            attach(
                &id,
                Options {
                    transport: None,
                    ..options
                },
            )
        })();
        // The attachment lease owns normal teardown. Startup failures still
        // revoke the gateway and close the newly opened volume.
        if result.is_err() {
            let current = status()?;
            if current.open_sessions.iter().any(|opened| {
                opened.id.as_deref() == Some(&id) && opened.mode.as_deref() != Some("agent")
            }) {
                control::request("close", None, &[])?;
            }
        }
        result
    })
}

fn password(label: &str, confirm: bool) -> control::Result<Zeroizing<Vec<u8>>> {
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
    let (mut stream, lease, client) = control::attach_client("agent-attach", id)?;
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    let mut saved = unsafe { std::mem::zeroed() };
    if tty && unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
        return Err("Cannot read terminal settings".into());
    }
    let launch = agent::Launch {
        agent: options.agent,
        argv: options.argv,
        terminal: if tty { Some(size()) } else { None },
    };
    launch.write(&mut stream)?;
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
    let result = bridge(&mut stream);
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
fn bridge(stream: &mut std::os::unix::net::UnixStream) -> control::Result<i32> {
    let mut input = true;
    loop {
        let caught = SIGNAL.swap(0, Ordering::Relaxed);
        if caught == libc::SIGWINCH {
            let size = size();
            agent::write_frame(
                stream,
                3,
                &[size.rows.to_be_bytes(), size.cols.to_be_bytes()].concat(),
            )?;
        } else if caught != 0 {
            agent::write_frame(stream, 6, &caught.to_be_bytes())?;
        }
        let mut polls = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if input { 0 } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), 2, 100) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if polls[0].revents != 0 {
            let (kind, bytes) = agent::read_frame(stream)?;
            match kind {
                1 => {
                    std::io::stdout().write_all(&bytes)?;
                    std::io::stdout().flush()?;
                }
                2 => {
                    std::io::stderr().write_all(&bytes)?;
                    std::io::stderr().flush()?;
                }
                4 if bytes.len() == 4 => {
                    let code = i32::from_be_bytes(bytes.try_into().unwrap());
                    return Ok(if code < 0 { 128 - code } else { code });
                }
                _ => return Err("Invalid agent response".into()),
            }
        }
        if polls[1].revents != 0 {
            let mut bytes = [0; 8192];
            let length = std::io::stdin().read(&mut bytes)?;
            if length == 0 {
                input = false;
                agent::write_frame(stream, 5, &[])?;
            } else {
                agent::write_frame(stream, 0, &bytes[..length])?;
            }
        }
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
