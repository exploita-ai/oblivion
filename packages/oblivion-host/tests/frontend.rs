use oblivion_cli::controller::{self, Command};
use oblivion_cli::{network, proxy_profiles, run, shell, storage};
use oblivion_host::{control, scope};
use oblivion_wire::control::{HEADER_LIMIT, Operation, RESPONSE_LIMIT, Request, Response};
use oblivion_wire::frame;
use std::collections::VecDeque;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> (Self, UnixListener) {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        let directory =
            PathBuf::from("/tmp").join(format!("ob-frontend-{:016x}", u64::from_be_bytes(bytes)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (Self { directory, path }, listener)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(3) =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("frontend connection failed: {error}"),
        }
    }
}
fn read(stream: &mut UnixStream) -> Request<scope::Slot> {
    let (request, secret) = receive(stream);
    assert!(secret.is_empty());
    request
}
fn receive(stream: &mut UnixStream) -> (Request<scope::Slot>, Zeroizing<Vec<u8>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header: serde_json::Value =
        serde_json::from_slice(&frame::read(stream, 1..=HEADER_LIMIT).unwrap()).unwrap();
    assert_eq!(
        header.as_object_mut().unwrap().remove("version"),
        Some(serde_json::json!(1))
    );
    let request: Request<scope::Slot> = serde_json::from_value(header).unwrap();
    assert!(request.secret_len <= 4096);
    let mut secret = Zeroizing::new(vec![0; request.secret_len as usize]);
    stream.read_exact(&mut secret).unwrap();
    (request, secret)
}
fn reply(stream: &mut UnixStream, output: &str, error: Option<&str>) {
    frame::write(
        stream,
        &serde_json::to_vec(&Response {
            ok: error.is_none(),
            output,
            error,
        })
        .unwrap(),
        1..=RESPONSE_LIMIT,
    )
    .unwrap();
}
fn state() -> serde_json::Value {
    serde_json::json!({
        "app_open":true,"app_mode":"persistent","general_present":true,
        "general_incomplete":false,"general_bytes":8589934592_u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},
        "open_sessions":[{"slot":4,"id":SAFE,"mode":"documents"}],
        "agent_safes":[],"platform_details":{"preserve_this_field":true}
    })
}
fn missing_storage(incomplete: bool) -> serde_json::Value {
    let mut source = state();
    source["app_open"] = serde_json::json!(false);
    source["app_mode"] = serde_json::json!("locked");
    source["general_present"] = serde_json::json!(false);
    source["general_incomplete"] = serde_json::json!(incomplete);
    source["sessions"] = serde_json::json!([]);
    source["open_sessions"] = serde_json::json!([]);
    source
}

// Only terminal interaction and time are substituted. Controller requests use
// the production Unix adapter, codec, socket authentication and slot scoping.
struct RunTerminal {
    controller: control::Client,
    prompts: Vec<&'static str>,
    answers: VecDeque<Zeroizing<Vec<u8>>>,
    confirmations: Vec<&'static str>,
    confirmed: bool,
    now: Duration,
    notices: Vec<String>,
    attached: Vec<(u8, String, String, Vec<String>)>,
    fail_attach: bool,
}
impl RunTerminal {
    fn new(path: &std::path::Path) -> Self {
        Self {
            controller: control::Client::remote(path),
            prompts: vec![],
            answers: VecDeque::new(),
            confirmations: vec![],
            confirmed: false,
            now: Duration::ZERO,
            notices: vec![],
            attached: vec![],
            fail_attach: false,
        }
    }
}
impl controller::Controller for RunTerminal {
    type Slot = scope::Slot;
    fn request(&mut self, call: controller::Call<'_, Self::Slot>) -> controller::Result<String> {
        self.controller.request(call)
    }
}
impl run::Runtime for RunTerminal {
    type Mark = Duration;
    fn slots(&self) -> Vec<scope::Slot> {
        (0..scope::LIMIT)
            .map(|index| scope::Slot::try_from(index).unwrap())
            .collect()
    }
    fn password(&mut self, label: &'static str) -> controller::Result<Zeroizing<Vec<u8>>> {
        self.prompts.push(label);
        Ok(self
            .answers
            .pop_front()
            .unwrap_or_else(|| Zeroizing::new(b"SYNTHETIC_PASSWORD_CANARY".to_vec())))
    }
    fn new_password(&mut self, label: &'static str) -> controller::Result<Zeroizing<Vec<u8>>> {
        self.password(label)
    }
    fn confirm(&mut self, word: &'static str) -> controller::Result<bool> {
        self.confirmations.push(word);
        Ok(self.confirmed)
    }
    fn now(&self) -> Self::Mark {
        self.now
    }
    fn elapsed(&self, mark: &Self::Mark) -> Duration {
        self.now - *mark
    }
    fn wait(&mut self, duration: Duration) -> controller::Result<()> {
        self.now += duration;
        Ok(())
    }
    fn notice(&mut self, notice: run::Notice<'_>) -> controller::Result<()> {
        self.notices.push(match notice {
            run::Notice::WaitingForConnection => "waiting".into(),
            run::Notice::SafeOpened(id) => format!("opened {id}"),
            run::Notice::StorageCapacity(bytes) => format!("capacity {bytes}"),
            run::Notice::StorageCreated => "storage-created".into(),
            run::Notice::IncompleteStorageReview => "review-incomplete".into(),
            run::Notice::IncompleteStorageDiscarded => "discarded-incomplete".into(),
        });
        Ok(())
    }
    fn attach(
        &mut self,
        slot: scope::Slot,
        id: &str,
        agent: &str,
        argv: &[String],
    ) -> controller::Result<i32> {
        scope::within(slot, || {
            self.attached.push((
                scope::current().index(),
                id.into(),
                agent.into(),
                argv.to_vec(),
            ));
        });
        if self.fail_attach {
            return Err("attachment_failed".into());
        }
        Ok(19)
    }
    fn attach_workspace(&mut self, slot: scope::Slot, id: &str) -> controller::Result<i32> {
        self.attach(slot, id, "workspace", &[])
    }
}
fn run_options(args: &[&str]) -> run::Options<oblivion_transport::Transport> {
    run::parse(&args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>())
        .unwrap()
        .resolve_transport(|request| match request {
            oblivion_cli::proxy::Request::Ready(transport) => Ok(transport),
            oblivion_cli::proxy::Request::NeedsPassword(_) => Err("Unexpected proxy prompt"),
        })
        .unwrap()
}

#[test]
fn shared_run_reuses_an_active_safe_preserves_argv_and_waits_only_for_its_gateway() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut attempts = 0;
        loop {
            let mut stream = accept(&listener);
            let request = read(&mut stream);
            match request.operation {
                Operation::Status => reply(&mut stream, &state().to_string(), None),
                Operation::StartAgent => {
                    assert_eq!(request.slot.index(), 4);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none());
                    attempts += 1;
                    if attempts < 3 {
                        reply(&mut stream, "", Some("gateway_not_ready"));
                        continue;
                    }
                    reply(&mut stream, "", None);
                    break;
                }
                operation => panic!("Unexpected operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let options = run_options(&[
        "--safe",
        "GB",
        "codex",
        "resume",
        "native-id",
        "",
        "$(literal)",
    ]);
    assert_eq!(
        run::execute(
            &mut terminal,
            options,
            run::Context {
                prefer_ephemeral: false
            }
        )
        .unwrap(),
        19
    );
    assert_eq!(terminal.now, Duration::from_secs(1));
    assert_eq!(terminal.notices, ["waiting"]);
    assert!(terminal.prompts.is_empty());
    assert!(terminal.confirmations.is_empty());
    assert_eq!(
        terminal.attached,
        [(
            4,
            SAFE.into(),
            "codex".into(),
            vec![
                "resume".into(),
                "native-id".into(),
                "".into(),
                "$(literal)".into()
            ]
        )]
    );
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn shared_run_fences_transport_configuration_and_cleanup_to_the_opened_safe() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut opened = false;
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => {
                    let mut source = state();
                    source["open_sessions"] = serde_json::json!([]);
                    reply(&mut stream, &source.to_string(), None);
                }
                Operation::OpenDocuments => {
                    assert!(!opened);
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.session.as_deref(), Some(SAFE));
                    assert!(request.expected_session.is_none());
                    assert_eq!(secret.as_slice(), b"SYNTHETIC_PASSWORD_CANARY");
                    opened = true;
                    reply(&mut stream, "", None);
                }
                Operation::Egress => {
                    assert!(opened);
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none());
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                        serde_json::json!({"action":"save","transport":{"mode":"tor"}})
                    );
                    reply(&mut stream, "", Some("session_changed"));
                }
                Operation::CloseIdle => {
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none());
                    assert!(secret.is_empty());
                    reply(&mut stream, "", Some("session_changed"));
                    break;
                }
                operation => panic!("Unexpected operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let error = run::execute(
        &mut terminal,
        run_options(&["--safe", "GB", "--tor", "codex"]),
        run::Context {
            prefer_ephemeral: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "session_changed");
    assert_eq!(terminal.prompts, ["Safe password"]);
    assert!(terminal.attached.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn shared_run_reopens_ram_children_without_allocating_a_replacement_and_reports_failed_cleanup() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut opened = false;
        loop {
            let mut stream = accept(&listener);
            let request = read(&mut stream);
            match request.operation {
                Operation::Status => {
                    let mut source = state();
                    source["app_mode"] = serde_json::json!("ram-only");
                    source["sessions"] = serde_json::json!([]);
                    source["open_sessions"] = serde_json::json!([]);
                    source["agent_safes"] =
                        serde_json::json!([{"id":SAFE,"ephemeral":true,"state":"awaiting-start"}]);
                    reply(&mut stream, &source.to_string(), None);
                }
                Operation::OpenChildDocuments => {
                    assert!(!opened);
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.session.as_deref(), Some(SAFE));
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    opened = true;
                    reply(&mut stream, "", None);
                }
                Operation::StartAgent => {
                    assert!(opened);
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    reply(&mut stream, "", None);
                }
                Operation::CloseIdle => {
                    assert!(opened);
                    assert_eq!(request.slot.index(), 0);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    reply(&mut stream, "", Some("cleanup_failed"));
                    break;
                }
                operation => panic!("Unexpected operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    terminal.fail_attach = true;
    let error = run::execute(
        &mut terminal,
        run_options(&["--safe", SAFE, "claude"]),
        run::Context {
            prefer_ephemeral: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "cleanup_failed");
    assert!(terminal.prompts.is_empty());
    assert!(terminal.confirmations.is_empty());
    assert_eq!(terminal.attached.len(), 1);
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn shared_run_rejects_a_malformed_created_identifier_before_any_followup_request() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => reply(&mut stream, &state().to_string(), None),
                Operation::Create => {
                    assert_eq!(secret.as_slice(), b"SYNTHETIC_PASSWORD_CANARY");
                    reply(&mut stream, "PRIVATE_ID_CANARY", None);
                    break;
                }
                operation => panic!("Unexpected operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let error = run::execute(
        &mut terminal,
        run_options(&["codex"]),
        run::Context {
            prefer_ephemeral: false,
        },
    )
    .unwrap_err();
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(terminal.attached.is_empty());
    assert_eq!(terminal.prompts, ["New Safe password"]);
    assert!(terminal.notices.is_empty());
    server.join().unwrap();
}

#[test]
fn shared_workspace_sets_only_the_selected_safe_policy_before_scoped_attachment() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => reply(&mut stream, &state().to_string(), None),
                Operation::SafeAccess => {
                    assert_eq!(request.slot.index(), 4);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none());
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                        serde_json::json!({"mode":"offline","save":true})
                    );
                    reply(&mut stream, "", None);
                }
                Operation::StartAgent => {
                    assert_eq!(request.slot.index(), 4);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(secret.is_empty());
                    reply(&mut stream, "", None);
                    break;
                }
                operation => panic!("Unexpected operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let options = shell::parse(&["--safe", "GB", "--policy", "offline"].map(String::from)).unwrap();
    assert_eq!(shell::execute(&mut terminal, options, true).unwrap(), 19);
    assert!(terminal.prompts.is_empty());
    assert_eq!(
        terminal.attached,
        [(4, SAFE.into(), "workspace".into(), vec![])]
    );
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn shared_workspace_rejects_pipes_before_any_controller_or_password_request() {
    let (fixture, listener) = Fixture::new();
    let mut terminal = RunTerminal::new(&fixture.path);
    let options = shell::parse(&["--safe", "GB"].map(String::from)).unwrap();
    assert_eq!(
        shell::execute(&mut terminal, options, false)
            .unwrap_err()
            .to_string(),
        "Workspace requires an interactive terminal"
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(terminal.prompts.is_empty());
    assert!(terminal.attached.is_empty());
}

#[test]
fn common_storage_setup_creates_the_archive_without_unlocking_or_entering_a_mode() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            assert_eq!(request.slot.index(), 0);
            assert!(request.session.is_none() && request.expected_session.is_none());
            match request.operation {
                Operation::Status => reply(&mut stream, &missing_storage(false).to_string(), None),
                Operation::InitGeneral => {
                    assert_eq!(secret.as_slice(), b"SYNTHETIC_PASSWORD_CANARY");
                    reply(&mut stream, "", None);
                    break;
                }
                operation => panic!("Unexpected setup operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    assert_eq!(
        storage::execute(
            &mut terminal,
            storage::Command::Init {
                reset_incomplete: false,
                confirmed_reset: false
            }
        )
        .unwrap(),
        0
    );
    assert_eq!(terminal.prompts, ["Oblivion password"]);
    assert_eq!(terminal.notices, ["capacity 8589934592", "storage-created"]);
    assert!(terminal.confirmations.is_empty());
    assert!(terminal.attached.is_empty());
    server.join().unwrap();
}

#[test]
fn common_storage_reset_can_be_cancelled_or_discard_only_the_incomplete_archive() {
    for confirmed_reset in [false, true] {
        let (fixture, listener) = Fixture::new();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            assert_eq!(read(&mut stream).operation, Operation::Status);
            reply(&mut stream, &missing_storage(true).to_string(), None);
            drop(stream);
            if confirmed_reset {
                let mut stream = accept(&listener);
                let request = read(&mut stream);
                assert_eq!(request.operation, Operation::DiscardGeneralPending);
                assert!(request.session.is_none() && request.expected_session.is_none());
                reply(&mut stream, "", None);
            }
        });
        let mut terminal = RunTerminal::new(&fixture.path);
        let result = storage::execute(
            &mut terminal,
            storage::Command::Init {
                reset_incomplete: true,
                confirmed_reset,
            },
        );
        if confirmed_reset {
            assert_eq!(result.unwrap(), 0);
            assert!(terminal.confirmations.is_empty());
            assert_eq!(
                terminal.notices,
                ["review-incomplete", "discarded-incomplete"]
            );
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "Storage reset cancelled. Nothing was changed."
            );
            assert_eq!(terminal.confirmations, ["RESET"]);
            assert_eq!(terminal.notices, ["review-incomplete"]);
        }
        assert!(terminal.prompts.is_empty() && terminal.attached.is_empty());
        server.join().unwrap();
    }
}

#[test]
fn common_ram_mode_and_global_lock_use_the_existing_authenticated_controller() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        for operation in [Operation::Status, Operation::EnterRam, Operation::Lock] {
            let mut stream = accept(&listener);
            let request = read(&mut stream);
            assert_eq!(request.operation, operation);
            assert_eq!(request.slot.index(), 0);
            assert!(request.session.is_none() && request.expected_session.is_none());
            reply(
                &mut stream,
                &if operation == Operation::Status {
                    missing_storage(false).to_string()
                } else {
                    String::new()
                },
                None,
            );
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    assert_eq!(
        storage::execute(&mut terminal, storage::Command::Ephemeral).unwrap(),
        0
    );
    assert_eq!(
        storage::execute(&mut terminal, storage::Command::Lock).unwrap(),
        0
    );
    assert!(terminal.prompts.is_empty() && terminal.confirmations.is_empty());
    assert!(terminal.attached.is_empty());
    server.join().unwrap();
}

#[test]
fn common_network_change_keeps_proxy_password_private_and_targets_the_read_only_safe() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut changed = false;
        loop {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            match request.operation {
                Operation::Status => {
                    let mut source = state();
                    source["app_mode"] = serde_json::json!("read-only");
                    if changed {
                        assert_eq!(request.slot.index(), 4);
                        assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                        source["network_status"] = serde_json::json!({"label":"SOCKS5 READY"});
                        source["safe_access"] = serde_json::json!({"current":"open"});
                    }
                    reply(&mut stream, &source.to_string(), None);
                    if changed {
                        break;
                    }
                }
                Operation::Egress => {
                    assert!(!changed);
                    assert_eq!(request.slot.index(), 4);
                    assert_eq!(request.expected_session.as_deref(), Some(SAFE));
                    assert!(request.session.is_none());
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
                        serde_json::json!({
                            "action":"select", "transport":{"mode":"socks5","endpoint":"192.0.2.5:1080",
                                "authentication":{"username":"alice","password":"SYNTHETIC_PASSWORD_CANARY"}}
                        })
                    );
                    changed = true;
                    reply(&mut stream, "", None);
                }
                operation => panic!("Unexpected network operation: {operation:?}"),
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = network::parse(
        &[
            "set",
            "--safe",
            "GB",
            "-x",
            "socks5h://alice@192.0.2.5:1080",
        ]
        .map(String::from),
    )
    .unwrap();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    assert_eq!(
        network::execute(&mut terminal, command, &mut output, &mut diagnostics).unwrap(),
        0
    );
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "SOCKS5 READY · open-internet\n"
    );
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(diagnostics.contains("aaaaaaaa"));
    assert!(!diagnostics.contains("CANARY") && !diagnostics.contains("alice"));
    assert_eq!(terminal.prompts, ["Proxy password"]);
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn common_proxy_profile_creation_prompts_privately_and_leaves_active_safes_unchanged() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let (request, secret) = receive(&mut stream);
        assert_eq!(request.operation, Operation::ProxyProfiles);
        assert_eq!(request.slot.index(), 0);
        assert!(request.expected_session.is_none() && request.session.is_none());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
            serde_json::json!({
                "action":"add", "name":"Office", "transport":{"mode":"socks5","endpoint":"192.0.2.5:1080",
                    "authentication":{"username":"alice","password":"PROXY_PRIVATE_CANARY"}}
            })
        );
        reply(&mut stream, "", None);
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    terminal.answers.push_back(Zeroizing::new(
        b"socks5h://alice:PROXY_PRIVATE_CANARY@192.0.2.5:1080".to_vec(),
    ));
    let command = proxy_profiles::parse(&["add", "Office"].map(String::from)).unwrap();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    assert_eq!(
        proxy_profiles::execute(&mut terminal, command, &mut output, &mut diagnostics).unwrap(),
        0
    );
    assert!(output.is_empty());
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(diagnostics.contains("Active Safes keep their current transport"));
    assert!(!diagnostics.contains("CANARY") && !diagnostics.contains("alice"));
    assert_eq!(terminal.prompts, ["SOCKS5 URL (hidden)"]);
    assert!(terminal.answers.is_empty());
    server.join().unwrap();
}

#[test]
fn common_proxy_profile_listing_does_not_surface_secret_fields_from_a_malformed_reply() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let (request, secret) = receive(&mut stream);
        assert_eq!(request.operation, Operation::ProxyProfiles);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&secret).unwrap(),
            serde_json::json!({"action":"list"})
        );
        reply(
            &mut stream,
            r#"{"entries":[],"PROXY_SECRET_CANARY":"hidden"}"#,
            None,
        );
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = proxy_profiles::parse(&["list", "--json"].map(String::from)).unwrap();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let error =
        proxy_profiles::execute(&mut terminal, command, &mut output, &mut diagnostics).unwrap_err();
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(error.source().is_none());
    assert!(output.is_empty() && diagnostics.is_empty());
    assert!(terminal.prompts.is_empty());
    server.join().unwrap();
}

#[test]
fn common_status_executor_preserves_full_json_through_the_real_authenticated_unix_adapter() {
    let (fixture, listener) = Fixture::new();
    let source = state().to_string();
    let expected = source.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::Status);
        assert_eq!(request.slot.index(), 0);
        assert!(request.session.is_none() && request.expected_session.is_none());
        reply(&mut stream, &source, None);
    });
    let command = Command::parse(&["status".into(), "--json".into()])
        .unwrap()
        .unwrap();
    let mut output = Vec::new();
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            command,
            &mut output
        )
        .unwrap(),
        0
    );
    assert_eq!(String::from_utf8(output).unwrap(), format!("{expected}\n"));
    server.join().unwrap();
}

#[test]
fn common_safe_listing_uses_the_portable_model_and_keeps_native_child_states() {
    let (fixture, listener) = Fixture::new();
    let mut source = state();
    source["sessions"] = serde_json::json!([SAFE, SAFE]);
    source["agent_safes"] = serde_json::json!([
        {"id":"b".repeat(32),"ephemeral":true,"state":"awaiting-start"},
        {"id":"c".repeat(32),"ephemeral":true,"state":"failed"},
        {"id":"d".repeat(32),"ephemeral":false,"state":"awaiting-start"}
    ]);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &source.to_string(), None);
    });
    let mut output = Vec::new();
    controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::Safes,
        &mut output,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!(
            "GB\t{SAFE}\tdocuments\n{b}\t{b}\tawaiting-start\n{c}\t{c}\tcreation-failed\n",
            b = "b".repeat(32),
            c = "c".repeat(32)
        )
    );
    server.join().unwrap();
}

#[test]
fn common_close_uses_fresh_safe_resolution_explicit_slot_and_expected_identity() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &state().to_string(), None);
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::Close);
        assert_eq!(request.slot.index(), 4);
        assert_eq!(request.expected_session.as_deref(), Some(SAFE));
        assert!(request.session.is_none());
        reply(&mut stream, "", None);
    });
    let mut output = Vec::new();
    controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::Close { name: "GB".into() },
        &mut output,
    )
    .unwrap();
    assert!(output.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn common_close_refuses_ambiguous_names_and_closed_safes_before_any_mutation() {
    for ambiguous in [true, false] {
        let (fixture, listener) = Fixture::new();
        let mut source = state();
        if ambiguous {
            source["sessions"] = serde_json::json!([SAFE, "b".repeat(32)]);
            source["session_titles"]["b".repeat(32)] = serde_json::json!("GB");
        } else {
            source["open_sessions"] = serde_json::json!([]);
        }
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read(&mut stream).operation, Operation::Status);
            reply(&mut stream, &source.to_string(), None);
        });
        let error = controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::Close { name: "GB".into() },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            if ambiguous {
                "Ambiguous Safe name. Use its full identifier."
            } else {
                "Safe is already locked"
            }
        );
        server.join().unwrap();
    }
}

#[test]
fn the_common_frontend_keeps_unix_socket_authentication_and_sanitized_rejections() {
    let (fixture, _listener) = Fixture::new();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::StatusJson,
            &mut Vec::new()
        )
        .unwrap_err()
        .to_string(),
        "untrusted_runtime_socket"
    );
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(
            &mut stream,
            "must not be shown",
            Some("private /vault/path or arbitrary guest text"),
        );
    });
    assert_eq!(
        controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::StatusJson,
            &mut Vec::new()
        )
        .unwrap_err()
        .to_string(),
        "operation_rejected"
    );
    server.join().unwrap();
}

#[test]
fn common_read_model_rejects_peer_values_with_a_static_error() {
    for invalid_slot in [false, true] {
        let (fixture, listener) = Fixture::new();
        let mut source = state();
        if invalid_slot {
            source["open_sessions"][0]["slot"] = serde_json::json!(33);
        } else {
            source["app_mode"] = serde_json::json!("SYNTHETIC_PRIVATE_STATE_CANARY");
        }
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read(&mut stream).operation, Operation::Status);
            reply(&mut stream, &source.to_string(), None);
        });
        let error = controller::execute(
            &mut control::Client::remote(&fixture.path),
            Command::Safes,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_controller_state");
        assert!(!format!("{error:?}").contains("CANARY"));
        server.join().unwrap();
    }
}

#[test]
fn the_compiled_launcher_uses_shared_metadata_grammar_before_runtime_start() {
    for args in [vec!["status"], vec!["safes", "extra"], vec!["close"]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "Oblivion: Use oblivion status --json, safes, or close NAME\n"
        );
    }
}

#[test]
fn the_compiled_launcher_checks_shared_workspace_syntax_before_booting_a_runtime() {
    for (args, error) in [
        (vec!["shell"], "Choose an existing Safe with --safe NAME"),
        (
            vec!["shell", "--safe", "GB", "--policy", "direct"],
            "Policy must be open-internet, strict or offline",
        ),
        (
            vec!["shell", "--safe", "GB", "codex"],
            "Use oblivion shell --safe SAFE [--policy open-internet|strict|offline]",
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Oblivion: {error}\n")
        );
    }
}

#[test]
fn the_compiled_launcher_checks_storage_network_and_proxy_commands_before_runtime_start() {
    for (args, error) in [
        (
            vec!["init", "--confirmed-reset"],
            "--confirmed-reset requires --reset-incomplete",
        ),
        (
            vec!["unlock", "unexpected"],
            "Use oblivion unlock [--read-only]",
        ),
        (vec!["ephemeral", "unexpected"], "Use oblivion ephemeral"),
        (
            vec!["network", "status", "--safe", "GB", "--tor"],
            "Use network set to change the selected transport or policy",
        ),
        (
            vec![
                "network", "set", "--safe", "GB", "--tor", "--policy", "offline",
            ],
            "Choose either a transport or a policy for this change",
        ),
        (
            vec!["proxy", "remove", "../PRIVATE_CANARY"],
            "invalid_proxy_profile_name",
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Oblivion: {error}\n")
        );
    }
}

#[test]
fn malformed_response_envelopes_do_not_expose_peer_json_in_frontend_errors() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read(&mut stream).operation, Operation::Status);
        let body = serde_json::to_vec(&serde_json::json!({"ok":true,"output":"", "error":null,"SYNTHETIC_PRIVATE_ENVELOPE_CANARY":true})).unwrap();
        frame::write(&mut stream, &body, 1..=RESPONSE_LIMIT).unwrap();
    });
    let error = controller::execute(
        &mut control::Client::remote(&fixture.path),
        Command::StatusJson,
        &mut Vec::new(),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(
        !message.is_empty()
            && message.len() <= 80
            && message
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    );
    assert!(!format!("{error:?}").contains("CANARY"));
    assert!(error.source().is_none());
    server.join().unwrap();
}
