use oblivion_cli::command;
#[cfg(test)]
use oblivion_cli::controller::{AgentSafeState, State};
use oblivion_cli::controller;
use oblivion_host::{agent, control, scope};
#[cfg(test)]
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
mod backup_commands;
mod child_task_commands;
mod family_password_commands;
mod file_commands;
mod file_events;
mod idle_commands;
mod init_commands;
mod native_overlay;
mod network_commands;
mod proxy_commands;
mod safe_commands;
mod share_commands;
mod shell_commands;

static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(value: i32) {
    SIGNAL.store(value, Ordering::Relaxed);
}

fn main() {
    let result = run();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let result = {
        let cleanup = oblivion_host::native_runtime::release_owner();
        result.and_then(|code| cleanup.map(|()| code))
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Oblivion: {error}");
            std::process::exit(1);
        }
    }
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
    let command = command::parse(&args, oblivion_cli::file_copy::parse, oblivion_cli::share::parse)?;
    match &command {
        command::Command::Help => {
            print!("{}", command::HELP);
            return Ok(0);
        }
        command::Command::Version => {
            println!("oblivion {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        // Reports only address the already-open private control connection.
        command::Command::Activity => return oblivion_host::activity::forward_stdin(),
        _ => {}
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if let command::Command::Runtime(command) = &command {
            use command::RuntimeCommand;
            match command {
                RuntimeCommand::InstallBundle(path) => {
                    oblivion_host::native_runtime::install_bundle(std::path::Path::new(path))?
                }
                RuntimeCommand::Deploy(path) => {
                    oblivion_host::native_runtime::deploy(std::path::Path::new(path))?
                }
                RuntimeCommand::Install(path) => {
                    oblivion_host::native_runtime::install(std::path::Path::new(path))?
                }
                RuntimeCommand::Update(path) => {
                    oblivion_host::native_runtime::update(std::path::Path::new(path))?
                }
                RuntimeCommand::Start => oblivion_host::native_runtime::start()?,
                RuntimeCommand::Supervise(generation) => {
                    oblivion_host::native_runtime::supervise(generation)?
                }
                RuntimeCommand::ChooseStorage => {
                    oblivion_host::native_runtime::choose_live_storage()?
                }
                RuntimeCommand::Recover => oblivion_host::native_runtime::recover()?,
                RuntimeCommand::Stop => oblivion_host::native_runtime::stop()?,
                RuntimeCommand::Gc => oblivion_host::native_runtime::gc()?,
                RuntimeCommand::Uninstall => oblivion_host::native_runtime::uninstall()?,
            }
            return Ok(0);
        }
        oblivion_host::desktop_bundle::prepare_environment()?;
        oblivion_host::native_runtime::request_live_storage(command.live_storage())?;
        match &command {
            command::Command::Manager => oblivion_host::native_runtime::prepare_manager()?,
            command::Command::Controller(controller::Command::StatusJson) => {
                oblivion_host::native_runtime::ensure_status()?
            }
            _ => oblivion_host::native_runtime::ensure()?,
        }
    }
    match command {
        command::Command::Manager => {
            let launcher = std::env::current_exe()?;
            let manager = launcher
                .parent()
                .ok_or("executable_directory_missing")?
                .join("oblivion-manager");
            Err(Command::new(manager)
                .env("OBLIVION_LAUNCHER", launcher)
                .exec()
                .into())
        }
        command::Command::Controller(command) => controller::execute(
            &mut control::Client::new(),
            command,
            &mut std::io::stdout().lock(),
        ),
        command::Command::Storage(command) => {
            oblivion_cli::storage::execute(&mut UnixRuntime::new(), command)
        }
        command::Command::Run(options) => oblivion_cli::run::execute(
            &mut UnixRuntime::new(),
            options.resolve_transport(resolve_proxy)?,
            oblivion_cli::run::Context {
                prefer_ephemeral: std::env::var("OBLIVION_LIVE_STORAGE").as_deref()
                    == Ok("ephemeral"),
            },
        ),
        command::Command::Shell(command) => shell_commands::run(command),
        command::Command::Network(command) => network_commands::run(command),
        command::Command::Proxy(command) => proxy_commands::run(command),
        command::Command::Settings(command) => idle_commands::run(command),
        command::Command::Safe(command) => safe_commands::run(command),
        command::Command::FamilyPassword(command) => family_password_commands::run(command),
        command::Command::ChildTask(command) => child_task_commands::run(command),
        command::Command::Backup(command) => backup_commands::run(command),
        command::Command::Files(command::Files::Inspect(command)) => {
            file_commands::inspect(command)
        }
        command::Command::Files(command::Files::Copy(command)) => file_commands::run(command),
        command::Command::Share(command) => share_commands::run(command),
        command::Command::Help
        | command::Command::Version
        | command::Command::Activity
        | command::Command::Runtime(_) => {
            Err("Command was not handled by the platform adapter".into())
        }
    }
}

#[cfg(test)]
type Options = oblivion_cli::run::Options<oblivion_transport::Transport>;

#[cfg(test)]
fn options(args: &[String]) -> control::Result<Options> {
    let parsed = oblivion_cli::run::parse(args)?;
    parsed.resolve_transport(resolve_proxy)
}

#[cfg(test)]
fn proxy(url: &str) -> control::Result<oblivion_transport::Transport> {
    resolve_proxy(oblivion_cli::proxy::parse(url)?)
}

fn resolve_proxy(
    request: oblivion_cli::proxy::Request,
) -> control::Result<oblivion_transport::Transport> {
    oblivion_cli::proxy::complete(request, &mut UnixRuntime::new())
}

pub(crate) struct UnixRuntime {
    client: control::Client,
}

impl UnixRuntime {
    pub(crate) fn new() -> Self {
        Self {
            client: control::Client::new(),
        }
    }
}

impl controller::Controller for UnixRuntime {
    type Slot = scope::Slot;
    fn request(&mut self, call: controller::Call<'_, Self::Slot>) -> control::Result<String> {
        self.client.request(call)
    }
}

impl oblivion_cli::run::Runtime for UnixRuntime {
    type Mark = Instant;
    fn slots(&self) -> Vec<scope::Slot> {
        (0..scope::LIMIT)
            .filter_map(|index| scope::Slot::try_from(index).ok())
            .collect()
    }
    fn password(&mut self, label: &'static str) -> control::Result<Zeroizing<Vec<u8>>> {
        password(label, false)
    }
    fn new_password(&mut self, label: &'static str) -> control::Result<Zeroizing<Vec<u8>>> {
        new_password(label)
    }
    fn confirm(&mut self, word: &'static str) -> control::Result<bool> {
        init_commands::confirm(word)
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn elapsed(&self, start: &Instant) -> Duration {
        start.elapsed()
    }
    fn wait(&mut self, duration: Duration) -> control::Result<()> {
        std::thread::sleep(duration);
        Ok(())
    }
    fn notice(&mut self, notice: oblivion_cli::run::Notice<'_>) -> control::Result<()> {
        notice.write(&mut std::io::stderr().lock())
    }
    fn attach(
        &mut self,
        slot: scope::Slot,
        id: &str,
        agent: &str,
        argv: &[String],
    ) -> control::Result<i32> {
        scope::within(slot, || attach_agent(id, agent, argv))
    }
    fn attach_workspace(&mut self, slot: scope::Slot, id: &str) -> control::Result<i32> {
        scope::within(slot, || attach_workspace(id))
    }
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
            if let Some(activity) = activity.as_mut() {
                activity.touch(Instant::now())
            }
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

fn attach_agent(id: &str, agent: &str, argv: &[String]) -> control::Result<i32> {
    let launch = agent::Launch {
        agent: agent.to_owned(),
        argv: argv.to_vec(),
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
    let activity = if tty {
        Some(oblivion_host::activity::Reporter::current_safe(id)?)
    } else {
        None
    };
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
        assert!(parse(&["--safe", "GB", "--name", "Other", "codex"]).is_err());
        assert!(parse(&["--name", " GB", "codex"]).is_err());
        assert!(parse(&["--safe", "GB\u{202e}", "codex"]).is_err());
        assert!(parse(&["--policy", "direct", "codex"]).is_err());
        assert!(parse(&["--tor", "-x", "socks5h://192.0.2.1:1080", "codex"]).is_err());
        assert!(parse(&["--proxy-profile", "Office", "--tor", "codex"]).is_err());
        assert!(parse(&[
            "--proxy-profile",
            "Office",
            "--proxy-profile",
            "Other",
            "codex"
        ])
        .is_err());
        assert!(parse(&["--proxy-profile", "../outside", "codex"]).is_err());
    }

    #[test]
    fn named_proxy_is_only_a_controller_reference() {
        let result = parse(&[
            "--proxy-profile",
            "Office",
            "codex",
            "--proxy-profile",
            "native-argument",
        ])
        .unwrap();
        assert_eq!(result.proxy_profile.as_deref(), Some("Office"));
        assert!(result.transport.is_none());
        assert_eq!(result.argv, ["--proxy-profile", "native-argument"]);
    }

    #[test]
    fn closed_ram_children_resolve_to_their_existing_identity() {
        let mut state: State<scope::Slot> = serde_json::from_value(json!({
            "app_open":true,"app_mode":"ram-only","general_present":false,
            "general_incomplete":false,"general_bytes":8589934592_u64,"recovery_required":false,
            "sessions":[],"session_titles":{},"open_sessions":[],
            "agent_safes":[{"id":"a".repeat(32),"ephemeral":true,"state":"awaiting-start"},
                {"id":"b".repeat(32),"ephemeral":false,"state":"awaiting-start"}],
        }))
        .unwrap();
        assert_eq!(
            state.find_safe(&"a".repeat(32)).unwrap().as_deref(),
            Some("a".repeat(32).as_str())
        );
        assert!(state.find_safe(&"b".repeat(32)).unwrap().is_none());
        assert!(state.find_safe("missing").unwrap().is_none());
        state.agent_safes[0].state = AgentSafeState::Failed;
        assert!(oblivion_cli::run::open_existing(
            &mut UnixRuntime::new(),
            &state,
            scope::current(),
            &"a".repeat(32)
        )
        .unwrap_err()
        .to_string()
        .contains("not created successfully"));
        state.agent_safes[0].state = AgentSafeState::RecoveryRequired;
        assert!(oblivion_cli::run::open_existing(
            &mut UnixRuntime::new(),
            &state,
            scope::current(),
            &"a".repeat(32)
        )
        .is_err());
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
