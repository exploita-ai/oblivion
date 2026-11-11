#![cfg(windows)]
use oblivion_cli::controller::{self, Command};
use oblivion_cli::run::Runtime;
use oblivion_cli::windows_terminal::Terminal;
use oblivion_native_windows::security::Identity;
use oblivion_wire::agent;
use oblivion_wire::control::{HEADER_LIMIT, Operation, RESPONSE_LIMIT};
use oblivion_wire::frame;
use serde_json::{Value, json};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null_mut;
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
};

const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn connect(pipe: &mut File) -> Value {
    let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), null_mut()) } != 0;
    assert!(connected || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
    serde_json::from_slice(&frame::read(pipe, 1..=HEADER_LIMIT).unwrap()).unwrap()
}
fn disconnect(pipe: &mut File) {
    match pipe.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => panic!("client did not release its pipe: {other:?}"),
    }
    assert_ne!(unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) }, 0);
}

fn listener() -> (String, File) {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).unwrap();
    let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let pipe = instance(&id, true);
    (id, pipe)
}

fn instance(id: &str, first: bool) -> File {
    let name: Vec<u16> = format!(r"\\.\pipe\oblivion.{id}.control")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let identity = Identity::current().unwrap();
    let descriptor = identity.descriptor().unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // A real synchronous named-pipe server: the production client remains the
    // asynchronous authenticated transport. No VM or privileged service runs.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            64,
            65536,
            65536,
            0,
            &attributes,
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    unsafe { File::from_raw_handle(handle) }
}

fn fixture(
    exchanges: Vec<(Operation, u8, Option<&'static str>, String)>,
) -> (oblivion_cli::windows::Client, JoinHandle<()>) {
    let (id, mut pipe) = listener();
    let server = std::thread::spawn(move || {
        for (operation, slot, expected, output) in exchanges {
            let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), null_mut()) } != 0;
            assert!(connected || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
            let request: Value =
                serde_json::from_slice(&frame::read(&mut pipe, 1..=HEADER_LIMIT).unwrap()).unwrap();
            assert_eq!(request["version"], 1);
            assert_eq!(request["operation"], json!(operation));
            assert_eq!(request["slot"], slot);
            assert_eq!(request["expected_session"], json!(expected));
            assert_eq!(request["secret_len"], 0);
            assert!(request["session"].is_null());
            let reply = serde_json::to_vec(&json!({"ok":true,"output":output})).unwrap();
            frame::write(&mut pipe, &reply, 1..=RESPONSE_LIMIT).unwrap();
            // Framed responses are consumed before the client closes. Waiting
            // here avoids discarding unread output with an early Disconnect.
            match pipe.read(&mut [0]) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
                result => panic!("control client did not close its completed frame: {result:?}"),
            }
            unsafe {
                DisconnectNamedPipe(pipe.as_raw_handle());
            }
        }
    });
    (oblivion_cli::windows::Client::new(&id).unwrap(), server)
}

fn state(slot: u8) -> String {
    json!({"app_open":true,"app_mode":"persistent","general_present":true,
        "general_incomplete":false,"backing_recovery_required":false,"general_bytes":1_073_741_824u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},
        "open_sessions":[{"slot":slot,"id":SAFE,"mode":"persistent","recovery_required":false}],"agent_safes":[]})
    .to_string()
}

#[test]
fn shared_close_frontend_uses_the_real_windows_controller_and_exact_safe_slot() {
    let (mut client, server) = fixture(vec![
        (Operation::Status, 0, None, state(4)),
        (Operation::Close, 4, Some(SAFE), String::new()),
    ]);
    let mut output = vec![];
    assert_eq!(
        controller::execute(
            &mut client,
            Command::Close { name: "GB".into() },
            &mut output
        )
        .unwrap(),
        0
    );
    assert!(output.is_empty());
    server.join().unwrap();
}

#[test]
fn malformed_peer_slot_is_rejected_before_a_safe_command_or_output() {
    let (mut client, server) = fixture(vec![(Operation::Status, 0, None, state(255))]);
    let mut output = vec![];
    let error = controller::execute(&mut client, Command::Safes, &mut output).unwrap_err();
    assert_eq!(error.to_string(), "invalid_controller_state");
    assert!(output.is_empty());
    server.join().unwrap();
}

#[test]
fn runtime_attaches_native_argv_and_duplex_pipes_then_releases_the_exact_safe_client() {
    for code in [7i32, agent::RELAY_FAILURE_STATUS] {
        assert_eq!(agent_attachment(vec![(4, code.to_be_bytes().to_vec())]).unwrap(), code);
    }
}

#[test]
fn relay_failure_uses_its_own_terminal_frame_and_rejects_the_legacy_marker() {
    assert_eq!(agent_attachment(vec![(agent::RELAY_FAILURE_KIND, vec![])]).unwrap(), agent::RELAY_FAILURE_STATUS);
    for frames in [
        vec![(agent::RELAY_FAILURE_KIND, vec![1])],
        vec![(2, vec![]), (4, agent::RELAY_FAILURE_STATUS.to_be_bytes().to_vec())],
    ] {
        assert_eq!(agent_attachment(frames).unwrap_err(), "Invalid agent response");
    }
}

fn agent_attachment(frames: Vec<(u8, Vec<u8>)>) -> Result<i32, String> {
    fn pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, null_mut(), 8192) },
            0
        );
        unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) }
    }

    let (id, mut control) = listener();
    let mut release_channel = instance(&id, false);
    let (stdin, mut input) = pipe();
    let (mut stdout, output) = pipe();
    let (mut stderr, error) = pipe();
    let incoming = [0, 255, b'\n'];
    let outgoing = [0, 255, b'\n', 0x1b, b'[', b'3', b'1', b'm'];
    input.write_all(&incoming).unwrap();
    drop(input);
    let server = std::thread::spawn(move || {
        let attach = connect(&mut control);
        assert_eq!(attach["operation"], json!(Operation::AgentAttach));
        assert_eq!(attach["slot"], 4);
        assert_eq!(attach["expected_session"], SAFE);
        assert!(attach["session"].is_null());
        assert_eq!(attach["secret_len"], 0);
        let client = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let ack = serde_json::to_vec(&json!({"ok":true,"output":client})).unwrap();
        frame::write(&mut control, &ack, 1..=RESPONSE_LIMIT).unwrap();
        let launch: Value =
            serde_json::from_slice(&frame::read(&mut control, 1..=agent::LIMIT).unwrap()).unwrap();
        assert_eq!(
            launch,
            json!({"kind":"agent","agent":"codex",
            "argv":["exec","--json","spaces; $(not a shell)",""],
            "terminal":null,"managed":null})
        );
        let mut received = vec![];
        loop {
            let (kind, bytes) = agent::read_frame(&mut control).unwrap();
            match kind {
                0 => received.extend(bytes),
                5 if bytes.is_empty() => break,
                _ => panic!("unexpected stdin frame"),
            }
        }
        assert_eq!(received, incoming);
        agent::write_frame(&mut control, 1, &outgoing).unwrap();
        agent::write_frame(&mut control, 2, b"diagnostic\n").unwrap();
        for (kind, payload) in frames {
            agent::write_frame(&mut control, kind, &payload).unwrap();
        }
        let release = connect(&mut release_channel);
        assert_eq!(release["operation"], json!(Operation::AgentRelease));
        assert_eq!(release["slot"], 4);
        assert_eq!(release["expected_session"], SAFE);
        assert_eq!(release["session"], client);
        assert_eq!(release["secret_len"], 0);
        // The actual controller auto-releases on this pipe's EOF. Its lease
        // must still be held while the explicit release is being confirmed.
        assert_ne!(
            unsafe {
                PeekNamedPipe(
                    control.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            },
            0
        );
        let ack = serde_json::to_vec(&json!({"ok":true,"output":""})).unwrap();
        frame::write(&mut release_channel, &ack, 1..=RESPONSE_LIMIT).unwrap();
        disconnect(&mut control);
        disconnect(&mut release_channel);
    });
    let mut runtime = oblivion_cli::windows::Runtime::with_terminal(
        &id,
        Terminal::from_files(stdin, output, error),
    )
    .unwrap();
    let result = runtime
            .attach(
                4.try_into().unwrap(),
                SAFE,
                "codex",
                &[
                    "exec".into(),
                    "--json".into(),
                    "spaces; $(not a shell)".into(),
                    "".into(),
                ]
            )
            .map_err(|error| error.to_string());
    drop(runtime);
    let mut bytes = vec![];
    stdout.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, outgoing);
    let mut bytes = vec![];
    stderr.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"diagnostic\n");
    server.join().unwrap();
    result
}

#[test]
fn files_browser_uses_the_open_safe_slot_and_validates_its_guest_page() {
    let (id, mut control) = listener();
    let server = std::thread::spawn(move || {
        let request = connect(&mut control);
        assert_eq!(request["operation"], json!(Operation::Status));
        assert_eq!(request["slot"], 0);
        assert!(request["expected_session"].is_null());
        frame::write(
            &mut control,
            &serde_json::to_vec(&json!({"ok":true,"output":state(4)})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut control);
        let request = connect(&mut control);
        assert_eq!(request["operation"], json!(Operation::Browse));
        assert_eq!(request["slot"], 4);
        assert_eq!(request["expected_session"], SAFE);
        assert!(request["session"].is_null());
        let mut secret = vec![0; request["secret_len"].as_u64().unwrap() as usize];
        control.read_exact(&mut secret).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&secret).unwrap(),
            json!({"path":"workspace/project","after":null,"limit":100})
        );
        let page = json!({"path":"workspace/project","entries":[{"name":"readme.txt","directory":false,"bytes":7}],"next":null,"skipped":0});
        frame::write(
            &mut control,
            &serde_json::to_vec(&json!({"ok":true,"output":page.to_string()})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut control);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let command = oblivion_cli::files::parse(
        &["list", "--safe", "GB", "workspace/project", "--json"].map(str::to_owned),
    )
    .unwrap()
    .unwrap();
    let mut output = vec![];
    let mut diagnostics = vec![];
    assert_eq!(
        oblivion_cli::files::execute(&mut runtime, command, &mut output, &mut diagnostics).unwrap(),
        0
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"path":"workspace/project","entries":[{"name":"readme.txt","path":"workspace/project/readme.txt","kind":"file","bytes":7}],"next_cursor":null,"skipped":0})
    );
    assert!(diagnostics.is_empty());
    server.join().unwrap();
}

#[test]
fn guest_file_metadata_holds_the_exact_opening_lease_until_explicit_release_even_on_bad_reply() {
    use oblivion_cli::files::Backend;
    use oblivion_transfer::native_files::{Action, Direction, State, TransfersQuery};
    use oblivion_wire::idle::Opening;
    let (id, mut control) = listener();
    let mut release = instance(&id, false);
    let opening = Opening {
        slot: 4.try_into().unwrap(),
        safe_id: SAFE.into(),
        nonce: "cccccccccccccccccccccccccccccccc".into(),
    };
    let expected_opening = serde_json::to_value(&opening).unwrap();
    let server = std::thread::spawn(move || {
        for action in ["transfers", "status", "recover", "discard", "malformed"] {
            let request = connect(&mut control);
            assert_eq!(request["operation"], json!(Operation::FileAttach));
            assert_eq!(request["slot"], 4);
            assert_eq!(request["expected_session"], SAFE);
            assert!(request["session"].is_null());
            let mut secret = vec![0; request["secret_len"].as_u64().unwrap() as usize];
            control.read_exact(&mut secret).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&secret).unwrap(),
                expected_opening
            );
            let client = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            frame::write(
                &mut control,
                &serde_json::to_vec(&json!({"ok":true,"output":client})).unwrap(),
                1..=RESPONSE_LIMIT,
            )
            .unwrap();
            let metadata: Value =
                serde_json::from_slice(&frame::read(&mut control, 1..=8192).unwrap()).unwrap();
            let mut expected = json!({"operation":if action == "malformed" { "status" } else { action },"safe_id":SAFE,"opening":expected_opening["nonce"]});
            if action == "transfers" {
                expected["after"] = Value::Null;
                expected["limit"] = json!(8);
            } else {
                expected["id"] = json!("dddddddddddddddddddddddddddddddd");
            }
            assert_eq!(metadata, expected);
            let page = if action == "transfers" {
                json!({"safe_id":SAFE,"opening":expected_opening["nonce"],"direction":"import","entries":[],"next_cursor":null,"skipped":0})
            } else {
                json!({"operation_id":"dddddddddddddddddddddddddddddddd","safe_id":SAFE,"opening":expected_opening["nonce"],"source_opening":null,"state":"unknown","receipt":null,"can_recover":false,"can_discard":false})
            };
            let reply = if action == "malformed" {
                b"PRIVATE_CANARY invalid JSON".to_vec()
            } else {
                serde_json::to_vec(&page).unwrap()
            };
            frame::write(&mut control, &reply, 1..=8192).unwrap();
            let request = connect(&mut release);
            assert_eq!(request["operation"], json!(Operation::AgentRelease));
            assert_eq!(request["slot"], 4);
            assert_eq!(request["expected_session"], SAFE);
            assert_eq!(request["session"], client);
            assert_eq!(request["secret_len"], 0);
            assert_ne!(
                unsafe {
                    PeekNamedPipe(
                        control.as_raw_handle(),
                        null_mut(),
                        0,
                        null_mut(),
                        null_mut(),
                        null_mut(),
                    )
                },
                0
            );
            frame::write(
                &mut release,
                &serde_json::to_vec(&json!({"ok":true,"output":""})).unwrap(),
                1..=RESPONSE_LIMIT,
            )
            .unwrap();
            disconnect(&mut control);
            disconnect(&mut release);
        }
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let page = runtime
        .transfers(
            &opening,
            &TransfersQuery {
                safe_id: SAFE.into(),
                opening: opening.nonce.clone(),
                direction: Direction::Import,
                after: None,
                limit: 8,
            },
            None,
        )
        .unwrap();
    assert!(page.entries.is_empty());
    for action in [Action::Status, Action::Recover, Action::Discard] {
        let status = runtime
            .manage(&opening, "dddddddddddddddddddddddddddddddd", action, None)
            .unwrap();
        status
            .validate("dddddddddddddddddddddddddddddddd", SAFE, &opening.nonce)
            .unwrap();
    }
    let error = runtime
        .manage(
            &opening,
            "dddddddddddddddddddddddddddddddd",
            Action::Status,
            None,
        )
        .unwrap_err();
    assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
    server.join().unwrap();
    let area = CopyArea::new();
    let status = runtime
        .manage(
            &opening,
            "dddddddddddddddddddddddddddddddd",
            Action::Status,
            Some(area.0.to_str().unwrap()),
        )
        .unwrap();
    status
        .validate("dddddddddddddddddddddddddddddddd", SAFE, &opening.nonce)
        .unwrap();
    assert_eq!(status.state, State::Unknown);
    assert!(status.receipt.is_none() && !status.can_recover && !status.can_discard);
}

#[test]
fn cancelled_pending_file_read_keeps_quiet_lease_until_fresh_scoped_release() {
    use oblivion_transfer::native_files::Request;
    use oblivion_wire::idle::Opening;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    for (export, refused) in [(false, false), (false, true), (true, false)] {
        let (id, mut data) = listener();
        let mut release = instance(&id, false);
        let opening = Opening {
            slot: 5.try_into().unwrap(),
            safe_id: SAFE.into(),
            nonce: "cccccccccccccccccccccccccccccccc".into(),
        };
        let expected = serde_json::to_value(&opening).unwrap();
        let server = std::thread::spawn(move || {
            let request = connect(&mut data);
            assert_eq!(request["operation"], json!(Operation::FileAttach));
            assert_eq!(request["slot"], 5);
            assert_eq!(request["expected_session"], SAFE);
            let mut secret = vec![0; request["secret_len"].as_u64().unwrap() as usize];
            data.read_exact(&mut secret).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&secret).unwrap(), expected);
            let client = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            frame::write(
                &mut data,
                &serde_json::to_vec(&json!({"ok":true,"output":client})).unwrap(),
                1..=RESPONSE_LIMIT,
            )
            .unwrap();
            let metadata: Value =
                serde_json::from_slice(&frame::read(&mut data, 1..=8192).unwrap()).unwrap();
            if export {
                assert_eq!(metadata, json!({"operation":"export"}));
            } else {
                assert_eq!(metadata["operation"], "status");
                assert_eq!(metadata["safe_id"], SAFE);
                assert_eq!(metadata["opening"], expected["nonce"]);
            }
            // No reply: the real client starts an overlapped read and cancels it.
            let request = connect(&mut release);
            assert_eq!(request["operation"], json!(Operation::AgentRelease));
            assert_eq!(request["slot"], 5);
            assert_eq!(request["expected_session"], SAFE);
            assert_eq!(request["session"], client);
            assert_ne!(
                unsafe {
                    PeekNamedPipe(
                        data.as_raw_handle(),
                        null_mut(),
                        0,
                        null_mut(),
                        null_mut(),
                        null_mut(),
                    )
                },
                0,
                "cancelling pending data IO must retain a kernel lease through AgentRelease"
            );
            let response = if refused {
                json!({"ok":false,"output":"","error":"release_refused"})
            } else {
                json!({"ok":true,"output":""})
            };
            frame::write(
                &mut release,
                &serde_json::to_vec(&response).unwrap(),
                1..=RESPONSE_LIMIT,
            )
            .unwrap();
            disconnect(&mut data);
            disconnect(&mut release);
        });
        let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut attachment = if export {
            runtime.attach_file_export(&opening, stop).unwrap()
        } else {
            runtime
                .attach_file(
                    &opening,
                    &Request::Status {
                        id: "dddddddddddddddddddddddddddddddd".into(),
                        safe_id: SAFE.into(),
                        opening: opening.nonce.clone(),
                    },
                    stop,
                )
                .unwrap()
        };
        let cancellation = attachment.cancellation();
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            cancellation.cancel();
        });
        let started = Instant::now();
        assert!(attachment.stream().read(&mut [0]).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        cancel.join().unwrap();
        runtime.cancellation().cancel();
        assert_eq!(
            runtime.release_file(&mut attachment).is_err(),
            refused,
            "a cancelled Runtime/data scope cannot cancel the independent cleanup RPC, and denied cleanup cannot become success"
        );
        server.join().unwrap();
    }
}

struct CopyArea(std::path::PathBuf);
impl CopyArea {
    fn new() -> Self {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).unwrap();
        let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("PRIVATE_HOST_COPY_{id}"));
        let identity = Identity::current().unwrap();
        let descriptor = identity.file_descriptor().unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let path_wide = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        assert_ne!(
            unsafe {
                windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(
                    path_wide.as_ptr(),
                    &attributes,
                )
            },
            0
        );
        Self(path)
    }
}
impl Drop for CopyArea {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

const COPY_OPERATION: &str = "dddddddddddddddddddddddddddddddd";
const COPY_OPENING: &str = "cccccccccccccccccccccccccccccccc";
const COPY_CLIENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn share_source_revocation_interrupts_pending_io_but_keeps_release_authority() {
    use oblivion_cli::controller::Call;
    use oblivion_cli::share::io::{Attachment, Lease, Native};
    use oblivion_share::control::ExportIdentity;
    use oblivion_wire::idle::Opening;
    use std::sync::mpsc::sync_channel;
    use std::time::{Duration, Instant};

    let (id, mut signal) = listener();
    let mut data = instance(&id, false);
    let mut release = instance(&id, false);
    let mut end = instance(&id, false);
    let opening = Opening {
        slot: 4.try_into().unwrap(),
        safe_id: SAFE.into(),
        nonce: COPY_OPENING.into(),
    };
    let expected = serde_json::to_value(&opening).unwrap();
    let (pending, started) = sync_channel(0);
    let server = std::thread::spawn(move || {
        let request = connect(&mut signal);
        assert_eq!(request["operation"], json!(Operation::ShareExportLease));
        assert_eq!(request["slot"], 0);
        assert_eq!(request["session"], COPY_OPERATION);
        assert!(request["expected_session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut signal,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_OPERATION})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        let request = connect(&mut data);
        assert_eq!(request["operation"], json!(Operation::ShareAttach));
        assert_eq!(request["slot"], 4);
        assert_eq!(request["expected_session"], SAFE);
        assert!(request["session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_CLIENT})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        // The common Share engine owns this banner. It may arrive in the same
        // byte-pipe buffer as the ACK, and must not disappear in the adapter.
        data.write_all(b"OBSH1\n").unwrap();
        started.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_ne!(unsafe { DisconnectNamedPipe(signal.as_raw_handle()) }, 0);
        let request = connect(&mut release);
        assert_eq!(request["operation"], json!(Operation::ShareRelease));
        assert_eq!(request["slot"], 4);
        assert_eq!(request["session"], COPY_CLIENT);
        assert_eq!(request["expected_session"], SAFE);
        let mut body = vec![0; request["secret_len"].as_u64().unwrap() as usize];
        release.read_exact(&mut body).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
        assert_ne!(
            unsafe {
                PeekNamedPipe(
                    data.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            },
            0,
            "signal revocation must not substitute EOF for ShareRelease"
        );
        frame::write(
            &mut release,
            &serde_json::to_vec(&json!({"ok":true,"output":""})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut data);
        disconnect(&mut release);
        let request = connect(&mut end);
        assert_eq!(request["operation"], json!(Operation::ShareExportEnd));
        assert_eq!(request["slot"], 0);
        assert!(request["session"].is_null());
        assert!(request["expected_session"].is_null());
        let mut body = vec![0; request["secret_len"].as_u64().unwrap() as usize];
        end.read_exact(&mut body).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"export_id":COPY_OPERATION})
        );
        frame::write(
            &mut end,
            &serde_json::to_vec(&json!({"ok":true,"output":""})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut end);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let mut lease = runtime.lease_share_export(COPY_OPERATION).unwrap();
    let mut attachment = runtime.attach_share_source(&opening, &mut lease).unwrap();
    assert_eq!(attachment.client_id(), COPY_CLIENT);
    let mut banner = [0; 6];
    attachment.stream().read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"OBSH1\n");
    pending.send(()).unwrap();
    let started = Instant::now();
    assert!(attachment.stream().read(&mut [0]).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    runtime.cancellation().cancel();
    runtime
        .cleanup(Call {
            operation: Operation::ShareRelease,
            slot: Some(opening.slot),
            session: Some(attachment.client_id()),
            expected_session: Some(&opening.safe_id),
            secret: &serde_json::to_vec(&opening).unwrap(),
        })
        .unwrap();
    attachment.close().unwrap();
    runtime
        .cleanup(Call {
            operation: Operation::ShareExportEnd,
            slot: Some(oblivion_wire::slot::Slot::ZERO),
            session: None,
            expected_session: None,
            secret: &serde_json::to_vec(&ExportIdentity {
                export_id: COPY_OPERATION.into(),
            })
            .unwrap(),
        })
        .unwrap();
    lease.close().unwrap();
    server.join().unwrap();
}

#[test]
fn dropping_share_export_lease_revokes_watchers_without_a_background_owner() {
    use oblivion_cli::share::io::{Attachment, Native};
    use oblivion_wire::idle::Opening;

    let (id, mut signal) = listener();
    let mut data = instance(&id, false);
    let server = std::thread::spawn(move || {
        assert_eq!(
            connect(&mut signal)["operation"],
            json!(Operation::ShareExportLease)
        );
        frame::write(
            &mut signal,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_OPERATION})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        assert_eq!(
            connect(&mut data)["operation"],
            json!(Operation::ShareAttach)
        );
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_CLIENT})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut signal);
        disconnect(&mut data);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let mut lease = runtime.lease_share_export(COPY_OPERATION).unwrap();
    let mut attachment = runtime
        .attach_share_source(
            &Opening {
                slot: 4.try_into().unwrap(),
                safe_id: SAFE.into(),
                nonce: COPY_OPENING.into(),
            },
            &mut lease,
        )
        .unwrap();
    drop(lease);
    assert!(attachment.stream().read(&mut [0]).is_err());
    attachment.close().unwrap();
    server.join().unwrap();
}

#[test]
fn share_import_finish_is_independent_of_cancel_and_precedes_data_lease_close() {
    use oblivion_cli::controller::Call;
    use oblivion_cli::share::io::{Attachment, Native};
    use oblivion_share::control::Finish;
    use oblivion_wire::idle::Opening;
    use std::time::Duration;

    let (id, mut data) = listener();
    let mut finish = instance(&id, false);
    let opening = Opening {
        slot: 4.try_into().unwrap(),
        safe_id: SAFE.into(),
        nonce: COPY_OPENING.into(),
    };
    let body = serde_json::to_vec(&Finish {
        transaction: COPY_OPERATION.into(),
        nonce: COPY_OPENING.into(),
        package_id: SAFE.into(),
        receipt: oblivion_transfer::Receipt {
            id: COPY_OPERATION.into(),
            manifest_sha256: ABC_SHA256.into(),
            entries: 1,
            bytes: 3,
        },
    })
    .unwrap();
    let expected = body.clone();
    let server = std::thread::spawn(move || {
        let request = connect(&mut data);
        assert_eq!(request["operation"], json!(Operation::ShareImportAttach));
        assert_eq!(request["slot"], 4);
        assert_eq!(request["expected_session"], SAFE);
        assert!(request["session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_CLIENT})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        data.write_all(b"OBSH1\n").unwrap();
        let request = connect(&mut finish);
        assert_eq!(request["operation"], json!(Operation::ShareImportFinish));
        assert_eq!(request["slot"], 4);
        assert_eq!(request["expected_session"], SAFE);
        assert_eq!(request["session"], COPY_CLIENT);
        let mut body = vec![0; request["secret_len"].as_u64().unwrap() as usize];
        finish.read_exact(&mut body).unwrap();
        assert_eq!(body, expected);
        assert_ne!(
            unsafe {
                PeekNamedPipe(
                    data.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            },
            0
        );
        // Denial remains an error; local close is never a commit receipt.
        frame::write(
            &mut finish,
            &serde_json::to_vec(&json!({"ok":false,"output":"","error":"finish_refused"})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut data);
        disconnect(&mut finish);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let mut attachment = runtime.attach_share_import(&opening).unwrap();
    let mut banner = [0; 6];
    attachment.stream().read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"OBSH1\n");
    let cancellation = runtime.cancellation();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancellation.cancel();
    });
    assert!(attachment.stream().read(&mut [0]).is_err());
    cancel.join().unwrap();
    assert_eq!(
        runtime
            .cleanup(Call {
                operation: Operation::ShareImportFinish,
                slot: Some(opening.slot),
                session: Some(attachment.client_id()),
                expected_session: Some(&opening.safe_id),
                secret: &body,
            })
            .unwrap_err()
            .to_string(),
        "finish_refused"
    );
    attachment.close().unwrap();
    server.join().unwrap();
}

fn copy_preflight(pipe: &mut File) {
    let mut status: Value = serde_json::from_str(&state(4)).unwrap();
    status["idle_lock"] = json!({"preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
        "host":{"nonce":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","remaining_seconds":100,"closing":false},
        "safes":[{"opening":{"slot":4,"safe_id":SAFE,"nonce":COPY_OPENING},"remaining_seconds":100,"closing":false}],
        "last_error":null,"storage":"saved-encrypted","writable":true});
    for scoped in [false, true] {
        let request = connect(pipe);
        assert_eq!(request["operation"], json!(Operation::Status));
        assert_eq!(request["slot"], if scoped { 4 } else { 0 });
        assert_eq!(
            request["expected_session"],
            if scoped { json!(SAFE) } else { Value::Null }
        );
        assert_eq!(request["secret_len"], 0);
        frame::write(
            pipe,
            &serde_json::to_vec(&json!({"ok":true,"output":status.to_string()})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(pipe);
    }
    let request = connect(pipe);
    assert_eq!(request["operation"], json!(Operation::FileAttach));
    assert_eq!(request["slot"], 4);
    assert_eq!(request["expected_session"], SAFE);
    let mut secret = vec![0; request["secret_len"].as_u64().unwrap() as usize];
    pipe.read_exact(&mut secret).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&secret).unwrap(),
        json!({"slot":4,"safe_id":SAFE,"nonce":COPY_OPENING})
    );
    frame::write(
        pipe,
        &serde_json::to_vec(&json!({"ok":true,"output":COPY_CLIENT})).unwrap(),
        1..=RESPONSE_LIMIT,
    )
    .unwrap();
}

fn copy_release(data: &mut File, release: &mut File, refused: bool) {
    let request = connect(release);
    assert_eq!(request["operation"], json!(Operation::AgentRelease));
    assert_eq!(request["slot"], 4);
    assert_eq!(request["expected_session"], SAFE);
    assert_eq!(request["session"], COPY_CLIENT);
    assert_eq!(request["secret_len"], 0);
    assert_ne!(
        unsafe {
            PeekNamedPipe(
                data.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        },
        0
    );
    let reply = if refused {
        json!({"ok":false,"output":"","error":"release_refused"})
    } else {
        json!({"ok":true,"output":""})
    };
    frame::write(
        release,
        &serde_json::to_vec(&reply).unwrap(),
        1..=RESPONSE_LIMIT,
    )
    .unwrap();
    disconnect(data);
    disconnect(release);
}

#[test]
fn complete_windows_import_command_sends_only_selected_manifest_and_verified_payload() {
    use oblivion_cli::file_copy::{CopyCommand, CopyInput};
    use oblivion_transfer::endpoint::{ReceiveRequest, read_message, write_message};
    use oblivion_transfer::{Entry, Manifest, Receipt, relay_payload};
    let area = CopyArea::new();
    let source = area.0.join("chosen.txt");
    std::fs::write(&source, b"abc").unwrap();
    std::fs::write(area.0.join("not-selected.txt"), b"do not transmit").unwrap();
    let (id, mut data) = listener();
    let mut release = instance(&id, false);
    let server = std::thread::spawn(move || {
        copy_preflight(&mut data);
        let dispatch: Value = read_message(&mut data, 8192).unwrap();
        assert_eq!(
            dispatch,
            json!({"operation":"import","id":COPY_OPERATION,"safe_id":SAFE,"opening":COPY_OPENING,"name":"imported"})
        );
        assert!(!dispatch.to_string().contains("PRIVATE_HOST_COPY_"));
        let receive: ReceiveRequest = read_message(&mut data, 4096).unwrap();
        assert_eq!(receive.approval.id, COPY_OPERATION);
        let manifest = Manifest::read(&mut data, receive.limits).unwrap();
        assert_eq!(manifest.sha256(), receive.approval.manifest_sha256);
        assert_eq!(manifest.entries().len(), 1);
        let Entry::File { path, size, sha256 } = &manifest.entries()[0] else {
            panic!("selected file expected");
        };
        assert_eq!(
            (path.as_str(), *size, sha256.as_str()),
            ("chosen.txt", 3, ABC_SHA256)
        );
        let mut encoded = Vec::new();
        manifest.write(&mut encoded).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("PRIVATE_HOST_COPY_"));
        assert!(!String::from_utf8_lossy(&encoded).contains(":\\"));
        data.write_all(b"receive\n").unwrap();
        let mut payload = Vec::new();
        relay_payload(&mut data, &mut payload, &manifest).unwrap();
        assert_eq!(payload, b"abcOBLVEND1");
        write_message(
            &mut data,
            &Receipt {
                id: COPY_OPERATION.into(),
                manifest_sha256: manifest.sha256(),
                entries: 1,
                bytes: 3,
            },
        )
        .unwrap();
        copy_release(&mut data, &mut release, false);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    assert_eq!(
        oblivion_cli::windows_file_copy::run(
            &mut runtime,
            CopyCommand {
                safe: "GB".into(),
                name: Some("imported".into()),
                selection: CopyInput::Upload(vec![source.to_str().unwrap().into()]),
                operation_id: Some(COPY_OPERATION.into()),
                expected_opening: Some(COPY_OPENING.into()),
                events_output: false,
                confirmed: true,
            }
        )
        .unwrap(),
        0
    );
    server.join().unwrap();
    assert_eq!(std::fs::read(source).unwrap(), b"abc");
}

#[test]
fn complete_windows_export_command_publishes_recovers_and_never_reports_denied_release_as_complete()
{
    use oblivion_cli::file_copy::{CopyCommand, CopyInput};
    use oblivion_cli::files::Backend;
    use oblivion_transfer::endpoint::{
        Approval, OfferRequest, SelectionOffer, read_message, write_message,
    };
    use oblivion_transfer::native_files::{Action, Direction, State, TransfersQuery};
    use oblivion_transfer::selection::{Input, Plan};
    use oblivion_transfer::{Entry, Limits, Manifest, Receipt, relay_payload};
    use oblivion_wire::idle::Opening;
    for refused in [false, true] {
        let area = CopyArea::new();
        let (id, mut data) = listener();
        let mut release = instance(&id, false);
        let server = std::thread::spawn(move || {
            copy_preflight(&mut data);
            let dispatch: Value = read_message(&mut data, 4096).unwrap();
            assert_eq!(dispatch, json!({"operation":"export"}));
            let offer: OfferRequest = read_message(&mut data, 65536).unwrap();
            assert_eq!(offer.id, COPY_OPERATION);
            assert_eq!(offer.paths, ["workspace/project"]);
            let encoded = serde_json::to_string(&offer).unwrap();
            assert!(!encoded.contains("PRIVATE_HOST_COPY_") && !encoded.contains(":\\"));
            let plan = Plan::new(&[Input {
                path: "workspace/project".into(),
                directory: true,
            }])
            .unwrap();
            let manifest = Manifest::new(
                vec![
                    Entry::Directory {
                        path: "project".into(),
                    },
                    Entry::Directory {
                        path: "project/empty".into(),
                    },
                    Entry::File {
                        path: "project/report.txt".into(),
                        size: 3,
                        sha256: ABC_SHA256.into(),
                    },
                ],
                Limits {
                    entries: 3,
                    bytes: 3,
                },
            )
            .unwrap();
            write_message(
                &mut data,
                &SelectionOffer {
                    directories: vec![true],
                    plan,
                },
            )
            .unwrap();
            manifest.write(&mut data).unwrap();
            let approval: Approval = read_message(&mut data, 4096).unwrap();
            assert_eq!(approval.id, COPY_OPERATION);
            assert_eq!(approval.manifest_sha256, manifest.sha256());
            relay_payload(
                &mut std::io::Cursor::new(b"abcOBLVEND1"),
                &mut data,
                &manifest,
            )
            .unwrap();
            let receipt: Receipt = read_message(&mut data, 4096).unwrap();
            assert_eq!(
                receipt,
                Receipt {
                    id: COPY_OPERATION.into(),
                    manifest_sha256: manifest.sha256(),
                    entries: 3,
                    bytes: 3
                }
            );
            data.write_all(b"copied\n").unwrap();
            copy_release(&mut data, &mut release, refused);
        });
        let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
        let result = oblivion_cli::windows_file_copy::run(
            &mut runtime,
            CopyCommand {
                safe: "GB".into(),
                name: Some("exported project".into()),
                selection: CopyInput::Download {
                    selected: vec!["workspace/project".into()],
                    destination: area.0.to_str().unwrap().into(),
                },
                operation_id: Some(COPY_OPERATION.into()),
                expected_opening: Some(COPY_OPENING.into()),
                events_output: false,
                confirmed: true,
            },
        );
        if refused {
            assert!(
                result.is_err(),
                "published bytes do not prove controller cleanup"
            );
        } else {
            assert_eq!(result.unwrap(), 0);
        }
        server.join().unwrap();
        let opening = Opening {
            slot: 4.try_into().unwrap(),
            safe_id: SAFE.into(),
            nonce: COPY_OPENING.into(),
        };
        let destination = area.0.to_str().unwrap();
        let published = runtime
            .manage(&opening, COPY_OPERATION, Action::Status, Some(destination))
            .unwrap();
        assert_eq!(published.state, State::Published);
        assert_eq!(
            std::fs::read(area.0.join("exported project/report.txt")).unwrap(),
            b"abc"
        );
        assert!(area.0.join("exported project/empty").is_dir());
        let query = TransfersQuery {
            safe_id: SAFE.into(),
            opening: COPY_OPENING.into(),
            direction: Direction::Export,
            after: None,
            limit: 8,
        };
        let page = runtime
            .transfers(&opening, &query, Some(destination))
            .unwrap();
        page.validate(&query).unwrap();
        assert_eq!(page.entries[0].operation_id, COPY_OPERATION);
        // Simulate publication persisted before its completion marker, then let
        // the user edit the working tree. Recovery must finish without recopying.
        std::fs::remove_file(
            area.0
                .join(".oblivion-transfers")
                .join(COPY_OPERATION)
                .join("published"),
        )
        .unwrap();
        std::fs::write(area.0.join("exported project/report.txt"), b"user edit").unwrap();
        let ready = runtime
            .manage(&opening, COPY_OPERATION, Action::Status, Some(destination))
            .unwrap();
        assert!(ready.state == State::Ready && ready.can_recover && !ready.can_discard);
        assert_eq!(
            runtime
                .manage(&opening, COPY_OPERATION, Action::Recover, Some(destination))
                .unwrap()
                .state,
            State::Published
        );
        assert_eq!(
            std::fs::read(area.0.join("exported project/report.txt")).unwrap(),
            b"user edit"
        );
    }
}

#[test]
fn backup_attachment_ends_at_pipe_eof_then_waits_for_controller_copied_proof() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let (id, mut data) = listener();
    let mut status = instance(&id, false);
    let server = std::thread::spawn(move || {
        let request = connect(&mut data);
        assert_eq!(request["operation"], json!(Operation::BackupAttach));
        assert_eq!(request["slot"], 7);
        assert_eq!(request["session"], COPY_OPERATION);
        assert!(request["expected_session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_OPERATION})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        data.write_all(b"ciphertext").unwrap();
        // A quiet Agent/File lease here would prevent this EOF and deadlock the
        // controller's transaction cleanup/status reconciliation.
        disconnect(&mut data);
        for (outcome, active) in [("copying", true), ("copied", false)] {
            let request = connect(&mut status);
            assert_eq!(
                request["operation"],
                json!(Operation::BackupStatus),
                "backup streams never send AgentRelease"
            );
            assert_eq!(
                request["slot"], 0,
                "catalog status uses the maintenance slot"
            );
            assert!(request["session"].is_null() && request["expected_session"].is_null());
            assert_eq!(request["secret_len"], 0);
            let catalog = json!({"transactions":[{"transaction":COPY_OPERATION,"slot":7,"kind":"export",
                "safe_id":SAFE,"bytes":33_554_432u64,"outcome":outcome,"active":active}]});
            frame::write(
                &mut status,
                &serde_json::to_vec(&json!({"ok":true,"output":catalog.to_string()})).unwrap(),
                1..=RESPONSE_LIMIT,
            )
            .unwrap();
            disconnect(&mut status);
        }
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let slot = 7.try_into().unwrap();
    let mut attachment = runtime
        .attach_backup(COPY_OPERATION, slot, Arc::new(AtomicBool::new(false)))
        .unwrap();
    let mut bytes = [0; 10];
    attachment.stream().read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ciphertext");
    attachment.close().unwrap();
    oblivion_cli::backup::copied(&mut runtime, COPY_OPERATION, slot).unwrap();
    server.join().unwrap();
}

#[test]
fn cancelled_backup_pending_read_closes_pipe_and_requires_status_recovery_not_agent_release() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    let (id, mut data) = listener();
    let mut control = instance(&id, false);
    let server = std::thread::spawn(move || {
        let request = connect(&mut data);
        assert_eq!(request["operation"], json!(Operation::BackupAttach));
        assert_eq!(request["slot"], 7);
        assert_eq!(request["session"], COPY_OPERATION);
        assert!(request["expected_session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":COPY_OPERATION})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut data);
        let request = connect(&mut control);
        assert_eq!(request["operation"], json!(Operation::BackupStatus));
        assert_eq!(request["slot"], 0);
        let catalog = json!({"transactions":[{"transaction":COPY_OPERATION,"slot":7,"kind":"import",
            "safe_id":null,"bytes":null,"outcome":"recovery-required","active":false}]});
        frame::write(
            &mut control,
            &serde_json::to_vec(&json!({"ok":true,"output":catalog.to_string()})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut control);
        let request = connect(&mut control);
        assert_eq!(request["operation"], json!(Operation::BackupCancel));
        assert_eq!(request["slot"], 7);
        assert_eq!(request["session"], COPY_OPERATION);
        assert!(request["expected_session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            &mut control,
            &serde_json::to_vec(&json!({"ok":true,"output":""})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut control);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let slot = 7.try_into().unwrap();
    let mut attachment = runtime
        .attach_backup(COPY_OPERATION, slot, Arc::new(AtomicBool::new(false)))
        .unwrap();
    let cancellation = attachment.cancellation();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancellation.cancel();
    });
    assert!(attachment.stream().read(&mut [0]).is_err());
    cancel.join().unwrap();
    attachment.close().unwrap();
    let copied = oblivion_cli::backup::copied(&mut runtime, COPY_OPERATION, slot).unwrap_err();
    assert_eq!(copied.to_string(), "backup_copy_requires_recovery");
    let mut diagnostics = Vec::new();
    assert!(
        oblivion_cli::backup::finish_attempt(
            &mut runtime,
            COPY_OPERATION,
            slot,
            Err(copied),
            &mut diagnostics
        )
        .is_err()
    );
    assert!(
        String::from_utf8(diagnostics)
            .unwrap()
            .contains(COPY_OPERATION)
    );
    server.join().unwrap();
}

#[test]
fn backup_attachment_refuses_a_different_acknowledged_transaction_and_closes_without_agent_release()
{
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let (id, mut data) = listener();
    let server = std::thread::spawn(move || {
        let request = connect(&mut data);
        assert_eq!(request["operation"], json!(Operation::BackupAttach));
        assert_eq!(request["session"], COPY_OPERATION);
        frame::write(
            &mut data,
            &serde_json::to_vec(&json!({"ok":true,"output":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}))
                .unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(&mut data);
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let error = runtime
        .attach_backup(
            COPY_OPERATION,
            7.try_into().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "invalid_backup_attachment");
    server.join().unwrap();
}

#[test]
fn native_backup_adapter_copies_a_real_synthetic_luks_volume_and_publishes_only_after_status() {
    use oblivion_cli::backup::Native;
    use oblivion_transfer::backup::Source;
    use oblivion_transfer::copy_protocol;
    use oblivion_transfer::endpoint::{
        Approval, OfferRequest, ReceiveRequest, read_message, write_message,
    };
    use oblivion_transfer::{ENCRYPTED_VOLUME_NAME, Manifest, Receipt, relay_payload};
    use oblivion_wire::backup::{Exported, Imported};
    const BYTES: u64 = 32 * 1024 * 1024;
    const EXPORT: &str = "ffffffffffffffffffffffffffffffff";
    struct Witness {
        prefix: Vec<u8>,
        count: u64,
    }
    impl Write for Witness {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.prefix
                .extend_from_slice(&bytes[..bytes.len().min(8 - self.prefix.len())]);
            self.count += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn copied_status(pipe: &mut File, transaction: &str, slot: u8, kind: &str) {
        let request = connect(pipe);
        assert_eq!(request["operation"], json!(Operation::BackupStatus));
        assert_eq!(request["slot"], 0);
        assert!(request["session"].is_null() && request["expected_session"].is_null());
        let catalog = json!({"transactions":[{"transaction":transaction,"slot":slot,"kind":kind,
            "safe_id":if kind=="export" {json!(SAFE)} else {Value::Null},"bytes":BYTES,"outcome":"copied","active":false}]});
        frame::write(
            pipe,
            &serde_json::to_vec(&json!({"ok":true,"output":catalog.to_string()})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
        disconnect(pipe);
    }
    fn backup_attach(pipe: &mut File, transaction: &str, slot: u8) {
        let request = connect(pipe);
        assert_eq!(request["operation"], json!(Operation::BackupAttach));
        assert_eq!(request["slot"], slot);
        assert_eq!(request["session"], transaction);
        assert!(request["expected_session"].is_null());
        assert_eq!(request["secret_len"], 0);
        frame::write(
            pipe,
            &serde_json::to_vec(&json!({"ok":true,"output":transaction})).unwrap(),
            1..=RESPONSE_LIMIT,
        )
        .unwrap();
    }
    let area = CopyArea::new();
    let source_path = area.0.join("opaque-backup.oblivion");
    let target_path = area.0.join("saved.oblivion");
    let mut file = File::create(&source_path).unwrap();
    file.write_all(b"LUKS\xba\xbe\x00\x02").unwrap();
    file.set_len(BYTES).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let (id, mut data) = listener();
    let mut status = instance(&id, false);
    let peer_source_path = source_path.clone();
    let server = std::thread::spawn(move || {
        backup_attach(&mut data, COPY_OPERATION, 7);
        let receive: ReceiveRequest = read_message(&mut data, 4096).unwrap();
        assert_eq!(receive.approval.id, COPY_OPERATION);
        let manifest = Manifest::read(&mut data, receive.limits).unwrap();
        assert_eq!(manifest.sha256(), receive.approval.manifest_sha256);
        assert_eq!(manifest.entries().len(), 1);
        assert_eq!(manifest.entries()[0].path(), ENCRYPTED_VOLUME_NAME);
        assert_eq!(manifest.bytes(), BYTES);
        let mut encoded = Vec::new();
        manifest.write(&mut encoded).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("PRIVATE_HOST_COPY_"));
        data.write_all(b"receive\n").unwrap();
        let mut witness = Witness {
            prefix: Vec::new(),
            count: 0,
        };
        relay_payload(&mut data, &mut witness, &manifest).unwrap();
        assert_eq!(witness.prefix, b"LUKS\xba\xbe\x00\x02");
        assert_eq!(witness.count, BYTES + 8);
        write_message(
            &mut data,
            &Receipt {
                id: COPY_OPERATION.into(),
                manifest_sha256: manifest.sha256(),
                entries: 1,
                bytes: BYTES,
            },
        )
        .unwrap();
        disconnect(&mut data);
        copied_status(&mut status, COPY_OPERATION, 7, "import");

        backup_attach(&mut data, EXPORT, 8);
        let offer: OfferRequest = read_message(&mut data, 4096).unwrap();
        assert_eq!(offer.id, EXPORT);
        assert_eq!(offer.paths, [ENCRYPTED_VOLUME_NAME]);
        assert_eq!(offer.limits.entries, 1);
        assert_eq!(offer.limits.bytes, BYTES);
        assert!(
            !serde_json::to_string(&offer)
                .unwrap()
                .contains("PRIVATE_HOST_COPY_")
        );
        let mut source = Source::open(&peer_source_path, BYTES).unwrap();
        source.manifest().write(&mut data).unwrap();
        let approval: Approval = read_message(&mut data, 4096).unwrap();
        assert_eq!(approval.id, EXPORT);
        assert_eq!(approval.manifest_sha256, source.manifest().sha256());
        copy_protocol::Source::write_payload(&mut source, &mut data).unwrap();
        let receipt: Receipt = read_message(&mut data, 4096).unwrap();
        assert_eq!(receipt.id, EXPORT);
        assert_eq!(receipt.manifest_sha256, source.manifest().sha256());
        assert_eq!((receipt.entries, receipt.bytes), (1, BYTES));
        data.write_all(b"copied\n").unwrap();
        disconnect(&mut data);
        copied_status(&mut status, EXPORT, 8, "export");
    });
    let mut runtime = oblivion_cli::windows::Runtime::new(&id).unwrap();
    let mut source = runtime
        .prepare_import(source_path.to_str().unwrap())
        .unwrap();
    assert_eq!(
        <oblivion_cli::windows::Runtime as Native>::source_bytes(&source),
        BYTES
    );
    let receipt = runtime
        .send_import(
            &mut source,
            &Imported {
                transaction: COPY_OPERATION.into(),
                maximum: BYTES,
            },
            7.try_into().unwrap(),
        )
        .unwrap();
    assert_eq!(
        (receipt.id.as_str(), receipt.entries, receipt.bytes),
        (COPY_OPERATION, 1, BYTES)
    );
    oblivion_cli::backup::copied(&mut runtime, COPY_OPERATION, 7.try_into().unwrap()).unwrap();
    let destination = runtime
        .prepare_export(target_path.to_str().unwrap())
        .unwrap();
    let (output, receipt) = runtime
        .receive_export(
            destination,
            &Exported {
                transaction: EXPORT.into(),
                safe_id: SAFE.into(),
                bytes: BYTES,
            },
            8.try_into().unwrap(),
        )
        .unwrap();
    assert_eq!(
        (receipt.id.as_str(), receipt.entries, receipt.bytes),
        (EXPORT, 1, BYTES)
    );
    assert!(
        !target_path.exists(),
        "a verified receipt alone must not publish the personal backup"
    );
    oblivion_cli::backup::copied(&mut runtime, EXPORT, 8.try_into().unwrap()).unwrap();
    assert_eq!(
        runtime.publish_export(output).unwrap(),
        target_path.to_string_lossy()
    );
    assert_eq!(std::fs::metadata(&target_path).unwrap().len(), BYTES);
    let mut prefix = [0; 8];
    File::open(target_path)
        .unwrap()
        .read_exact(&mut prefix)
        .unwrap();
    assert_eq!(&prefix, b"LUKS\xba\xbe\x00\x02");
    server.join().unwrap();
}
