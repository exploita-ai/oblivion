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
        "general_incomplete":false,"general_bytes":1_073_741_824u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},
        "open_sessions":[{"slot":slot,"id":SAFE,"mode":"persistent"}],"agent_safes":[]})
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
    fn pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, null_mut(), 8192) },
            0
        );
        unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) }
    }
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
        agent::write_frame(&mut control, 4, &7i32.to_be_bytes()).unwrap();
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
    assert_eq!(
        runtime
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
            .unwrap(),
        7
    );
    drop(runtime);
    let mut bytes = vec![];
    stdout.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, outgoing);
    let mut bytes = vec![];
    stderr.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"diagnostic\n");
    server.join().unwrap();
}
