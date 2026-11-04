#![cfg(windows)]
use oblivion_cli::controller::{self, Command};
use oblivion_native_windows::security::Identity;
use oblivion_wire::control::{HEADER_LIMIT, Operation, RESPONSE_LIMIT};
use oblivion_wire::frame;
use serde_json::{Value, json};
use std::fs::File;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null_mut;
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture(
    exchanges: Vec<(Operation, u8, Option<&'static str>, String)>,
) -> (oblivion_cli::windows::Client, JoinHandle<()>) {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).unwrap();
    let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
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
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &attributes,
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    let mut pipe = unsafe { File::from_raw_handle(handle) };
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
