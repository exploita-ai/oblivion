use oblivion_cli::command;
#[cfg(test)]
use oblivion_cli::controller::{AgentSafeState, State};
use oblivion_cli::controller;
use oblivion_host::activity::Reporter;
use oblivion_host::{agent, control, scope};
#[cfg(test)]
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
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
mod live_media_commands;
mod manager_terminal;
mod native_overlay;
mod network_commands;
mod proxy_commands;
mod safe_commands;
mod share_commands;
mod shell_commands;
use manager_terminal::ManagerTerminal;

static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn signal(value: i32) {
    SIGNAL.store(value, Ordering::Relaxed);
}

fn main() {
    let terminal = match ManagerTerminal::open() {
        Ok(value) => value.map(Arc::new),
        Err(_) => std::process::exit(1),
    };
    let result = run(terminal.as_ref());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let result = {
        let cleanup = oblivion_host::native_runtime::release_owner();
        result.and_then(|code| cleanup.map(|()| code))
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            match (terminal.as_ref(), error.to_string().as_str()) {
                (Some(terminal), "gateway_start_failed") => { let _ = terminal.event(b'F'); }
                (Some(terminal), "gateway_not_ready") => { let _ = terminal.event(b'T'); }
                (Some(terminal), "insufficient_ephemeral_storage") => { let _ = terminal.event(b'S'); }
                (Some(terminal), "safe_closed_before_agent_exit") => { let _ = terminal.event(b'D'); }
                (Some(_), _) => {}
                (None, "gateway_start_failed") => eprintln!("Oblivion: The protected gateway failed to start. The Safe stayed offline."),
                (None, "gateway_not_ready") => eprintln!("Oblivion: The protected connection timed out. The Safe stayed offline."),
                (None, "insufficient_ephemeral_storage") => eprintln!("Oblivion: The controller has insufficient RAM-only storage for another Safe. Close an unused RAM-only Safe and retry."),
                (None, "safe_closed_before_agent_exit") => eprintln!("Oblivion: The Safe closed before the agent could report its exit."),
                (None, _) => eprintln!("Oblivion: {error}"),
            }
            std::process::exit(1);
        }
    }
}

fn run(terminal: Option<&Arc<ManagerTerminal>>) -> control::Result<i32> {
    control::protect()?;
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "Arguments must use valid UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let command = command::parse(&args, oblivion_cli::file_copy::parse, oblivion_cli::share::parse)?;
    let live_media = match &command {
        command::Command::Files(command::Files::MediaBrowse(_)) => true,
        command::Command::Files(command::Files::Copy(command)) => command.needs_live_media(),
        command::Command::Files(command::Files::Inspect(command)) => command.needs_live_media(),
        _ => false,
    };
    if live_media && oblivion_host::native_runtime::mode()? != oblivion_host::native_runtime::Mode::Live {
        return Err("USB transfers are available only on Oblivion Live".into());
    }
    match &command {
        command::Command::Help => {
            use oblivion_host::native_runtime::{Mode, mode};
            let profile = match mode()? {
                Mode::Live => command::HelpProfile::Live,
                Mode::Desktop if oblivion_host::desktop_bundle::packaged_entry()? => {
                    command::HelpProfile::PackagedLinux
                }
                Mode::Desktop => command::HelpProfile::Desktop,
            };
            print!("{}", command::help(profile));
            return Ok(0);
        }
        command::Command::Version => {
            println!("oblivion {}", command::PRODUCT_VERSION);
            return Ok(0);
        }
        // Reports only address the already-open private control connection.
        command::Command::Activity => return oblivion_host::activity::forward_stdin(),
        _ => {}
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "linux")]
        if oblivion_host::desktop_bundle::packaged_entry()? {
            let launcher = match &command {
                command::Command::Controller(controller::Command::StatusJson) => {
                    oblivion_host::native_runtime::observe_packaged()?;
                    return controller::execute(
                        &mut control::Client::new(),
                        controller::Command::StatusJson,
                        &mut std::io::stdout().lock(),
                    );
                }
                command::Command::Runtime(command::RuntimeCommand::Start) => {
                    Some(oblivion_host::native_runtime::packaged_launcher(false)?)
                }
                command::Command::Runtime(
                    command::RuntimeCommand::InstallBundle(_)
                    | command::RuntimeCommand::Install(_)
                    | command::RuntimeCommand::Update(_)
                    | command::RuntimeCommand::Deploy(_),
                ) => {
                    return Err("Install or update the Oblivion desktop package through APT, then run oblivion as your regular user.".into());
                }
                command::Command::Runtime(_) => None,
                _ => Some(oblivion_host::native_runtime::packaged_launcher(true)?),
            };
            if let Some(launcher) = launcher {
                return Err(Command::new(launcher)
                    .args(std::env::args_os().skip(1))
                    .exec()
                    .into());
            }
        }
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
                RuntimeCommand::LiveMedia => oblivion_host::native_runtime::live_media()?,
                RuntimeCommand::Recover => oblivion_host::native_runtime::recover()?,
                RuntimeCommand::Stop => oblivion_host::native_runtime::stop()?,
                RuntimeCommand::Gc => oblivion_host::native_runtime::gc()?,
                RuntimeCommand::Uninstall => oblivion_host::native_runtime::uninstall()?,
                RuntimeCommand::Atomic => oblivion_host::native_runtime::atomic()?,
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
            _ if terminal.is_some() => oblivion_host::native_runtime::ensure_quiet()?,
            _ => oblivion_host::native_runtime::ensure()?,
        }
    }
    match command {
        command::Command::Manager => {
            let launcher = oblivion_host::desktop_bundle::launcher_path()?;
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
        command::Command::Run(options) => {
            let mut runtime = UnixRuntime::new();
            runtime.terminal = terminal.cloned();
            let options = options.resolve_transport(|request| oblivion_cli::proxy::complete(request, &mut runtime))?;
            oblivion_cli::run::execute(&mut runtime, options, oblivion_cli::run::Context {
                prefer_ephemeral: std::env::var("OBLIVION_LIVE_STORAGE").as_deref() == Ok("ephemeral"),
            })
        }
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
        command::Command::Files(command::Files::MediaBrowse(command)) => live_media_commands::browse(command),
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

#[cfg(test)]
fn resolve_proxy(
    request: oblivion_cli::proxy::Request,
) -> control::Result<oblivion_transport::Transport> {
    oblivion_cli::proxy::complete(request, &mut UnixRuntime::new())
}

pub(crate) struct UnixRuntime {
    client: control::Client,
    terminal: Option<Arc<ManagerTerminal>>,
}

impl UnixRuntime {
    pub(crate) fn new() -> Self {
        Self {
            client: control::Client::new(),
            terminal: None,
        }
    }

    fn prompt<T>(&self, read: impl FnOnce() -> control::Result<T>) -> control::Result<T> {
        match self.terminal.as_ref() {
            Some(terminal) => terminal.prompt(read),
            None => read(),
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
        let mut activity = Reporter::current_host()?;
        self.prompt(|| read_password(label, false, &mut activity))
    }
    fn new_password(&mut self, label: &'static str) -> control::Result<Zeroizing<Vec<u8>>> {
        self.prompt(|| new_password(label))
    }
    fn confirm(&mut self, word: &'static str) -> control::Result<bool> {
        self.prompt(|| init_commands::confirm(word))
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
        if let Some(terminal) = self.terminal.as_ref() {
            if matches!(notice, oblivion_cli::run::Notice::WaitingForConnection) {
                terminal.event(b'G')?;
            }
            return Ok(());
        }
        notice.write(&mut std::io::stderr().lock())
    }
    fn attach(
        &mut self,
        slot: scope::Slot,
        id: &str,
        agent: &str,
        argv: &[String],
    ) -> control::Result<i32> {
        scope::within(slot, || attach_agent(id, agent, argv, self.terminal.as_deref()))
    }
    fn attach_workspace(&mut self, slot: scope::Slot, id: &str) -> control::Result<i32> {
        scope::within(slot, || attach_workspace(id))
    }
}

fn read_password(
    label: &str,
    confirm: bool,
    activity: &mut Option<Reporter>,
) -> control::Result<Zeroizing<Vec<u8>>> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "Password entry requires an interactive terminal")?;
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
        write!(tty, "{label}: ")?;
        tty.flush()?;
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
    let mut activity = Reporter::current_host()?;
    let first = read_password(label, true, &mut activity)?;
    if *first != *read_password("Confirm password", false, &mut activity)? {
        return Err("Passwords do not match".into());
    }
    Ok(first)
}

fn attach_agent(id: &str, agent: &str, argv: &[String], terminal: Option<&ManagerTerminal>) -> control::Result<i32> {
    let viewport = (unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }).then(size);
    let launch = agent::Launch {
        agent: agent.to_owned(),
        argv: argv.to_vec(),
        managed: None,
        terminal: viewport.map(oblivion_cli::terminal_overlay::guest_size),
    };
    attach_command(id, agent::Command::Agent(&launch), viewport, terminal)
}

fn attach_workspace(id: &str) -> control::Result<i32> {
    if unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        return Err("Workspace requires an interactive terminal".into());
    }
    let viewport = size();
    let terminal = oblivion_cli::terminal_overlay::guest_size(viewport);
    attach_command(id, agent::Command::Workspace { terminal }, Some(viewport), None)
}

fn attach_command(id: &str, command: agent::Command<'_>, viewport: Option<agent::Size>, terminal: Option<&ManagerTerminal>) -> control::Result<i32> {
    let (mut stream, lease, client) = control::attach_client("agent-attach", id)?;
    let tty = viewport.is_some();
    let name = match &command {
        agent::Command::Agent(launch) => &launch.agent,
        agent::Command::Workspace { .. } => "workspace",
    };
    let activity = if tty {
        Some(oblivion_host::activity::Reporter::current_safe(id)?)
    } else {
        None
    };
    if let Some(terminal) = terminal { terminal.event(b'R')?; }
    let mut saved = unsafe { std::mem::zeroed() };
    if tty && unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
        return Err("Cannot read terminal settings".into());
    }
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
    let result = native_overlay::bridge(&mut stream, viewport, id, name, saved, activity);
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
    agent_outcome(result, released, || {
        tty && controller::status(&mut control::Client::new()).is_ok_and(|state| {
            !state.recovery_required && state.open_sessions.iter().all(|entry| {
                entry.slot != scope::current() && entry.id.as_deref() != Some(id)
            })
        })
    })
}

fn agent_outcome(
    result: control::Result<i32>,
    released: control::Result<()>,
    verified_closed: impl FnOnce() -> bool,
) -> control::Result<i32> {
    let stale_release = matches!(
        released.as_ref().err().and_then(|error| error.downcast_ref()),
        Some(oblivion_wire::control_client::Error::Rejected(reason)) if reason == "session_changed"
    );
    if !stale_release { released?; }
    let relay_failure = result.as_ref().is_err_and(|error| error.is::<native_overlay::AgentRelayFailure>());
    // The controller rejected the release for this Safe and slot. Before
    // describing a lost agent channel as a closure, require verified teardown.
    if stale_release
        && (relay_failure || result.as_ref().is_err_and(|error| error.is::<native_overlay::AgentDisconnected>()))
        && verified_closed()
    {
        return Err("safe_closed_before_agent_exit".into());
    }
    if relay_failure { return Ok(oblivion_wire::agent::RELAY_FAILURE_STATUS); }
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

    #[test]
    fn only_a_lost_agent_channel_with_verified_stale_release_reports_closure() {
        fn bridge(frames: &[(u8, &[u8])]) -> control::Result<i32> {
            let (mut stream, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
            for (kind, payload) in frames {
                agent::write_frame(&mut guest, *kind, payload).unwrap();
            }
            guest.shutdown(std::net::Shutdown::Write).unwrap();
            native_overlay::bridge(&mut stream, None, "test-safe", "opencode2", unsafe { std::mem::zeroed() }, None)
        }

        let stale_release = || Err(oblivion_wire::control_client::Error::Rejected("session_changed".into()).into());
        for code in [0i32, 1, 19, 125, 137] {
            assert_eq!(agent_outcome(bridge(&[(4, &code.to_be_bytes())]), stale_release(), || panic!("guest exit is known")).unwrap(), code);
        }
        assert_eq!(
            agent_outcome(bridge(&[]), stale_release(), || true).unwrap_err().to_string(),
            "safe_closed_before_agent_exit"
        );
        assert!(agent_outcome(bridge(&[]), stale_release(), || false).unwrap_err().is::<native_overlay::AgentDisconnected>());
        assert!(agent_outcome(bridge(&[]), Ok(()), || panic!("release is current")).unwrap_err().is::<native_overlay::AgentDisconnected>());
        assert_eq!(
            agent_outcome(bridge(&[]), Err("controller_busy".into()), || panic!("release is unverified")).unwrap_err().to_string(),
            "controller_busy"
        );

        let status = oblivion_wire::agent::RELAY_FAILURE_STATUS.to_be_bytes();
        let diagnostic = b"The agent connection could not be completed.\n";
        let native_exit = bridge(&[(2, diagnostic), (4, &status)]);
        assert_eq!(agent_outcome(native_exit, stale_release(), || panic!("guest exit is known")).unwrap(), 125);
        let relay_failure = || bridge(&[(oblivion_wire::agent::RELAY_FAILURE_KIND, b"")]);
        assert_eq!(agent_outcome(relay_failure(), stale_release(), || true).unwrap_err().to_string(),
            "safe_closed_before_agent_exit");
        assert_eq!(agent_outcome(relay_failure(), stale_release(), || false).unwrap(), 125);
        assert_eq!(agent_outcome(relay_failure(), Ok(()), || panic!("release is current")).unwrap(), 125);
        for frames in [
            vec![(oblivion_wire::agent::RELAY_FAILURE_KIND, &status[..])],
            vec![(2, &b""[..]), (4, &status[..])],
        ] {
            assert_eq!(agent_outcome(bridge(&frames), stale_release(), || panic!("response is malformed")).unwrap_err().to_string(),
                "Invalid agent response");
        }
    }

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
            "general_incomplete":false,"backing_recovery_required":false,"general_bytes":8589934592_u64,"recovery_required":false,
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
