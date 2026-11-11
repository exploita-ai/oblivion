use oblivion_host::remote_control;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::Duration;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = PathBuf::from("/tmp").join(format!(
            "oblivion-share-control-{}",
            u64::from_be_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn private_share_attachment_preserves_stream_magic_and_connection_lease() {
    let fixture = Fixture::new();
    let path = fixture.0.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut payload).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(request["version"], 1);
        assert_eq!(request["operation"], "share-attach");
        assert_eq!(request["expected_session"], "a".repeat(32));
        assert_eq!(request["secret_len"], 0);
        assert!(request["session"].is_null());
        let response = serde_json::to_vec(
            &serde_json::json!({"ok":true,"output":"b".repeat(32),"error":null}),
        )
        .unwrap();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
        stream.write_all(b"OBSH1\n").unwrap();
        let mut done = [0; 4];
        stream.read_exact(&mut done).unwrap();
        assert_eq!(&done, b"done");
        assert_eq!(stream.read(&mut done).unwrap(), 0);
    });
    let (mut stream, client) =
        remote_control::attach(&path, "share-attach", &"a".repeat(32)).unwrap();
    assert_eq!(client, "b".repeat(32));
    let mut magic = [0; 6];
    stream.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"OBSH1\n");
    stream.write_all(b"done").unwrap();
    drop(stream);
    server.join().unwrap();
}

#[test]
fn import_begin_carries_u32_sized_metadata_without_expanding_other_operations() {
    let fixture = Fixture::new();
    let path = fixture.0.join("import.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let body = vec![42; 70000];
    assert!(remote_control::request(&path, "unlock", None, &body, None).is_err());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut header = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut header).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["operation"], "share-import-begin");
        assert_eq!(header["secret_len"], 70000);
        let mut data = vec![0; 70000];
        stream.read_exact(&mut data).unwrap();
        assert!(data.iter().all(|byte| *byte == 42));
        let response = br#"{"ok":true,"output":"accepted","error":null}"#;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(response).unwrap();
    });
    assert_eq!(
        remote_control::request(&path, "share-import-begin", None, &body, None).unwrap(),
        "accepted"
    );
    server.join().unwrap();
}

#[test]
fn family_password_change_carries_maximum_json_escaping_without_widening_other_requests() {
    let fixture = Fixture::new();
    let path = fixture.0.join("password.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let change = oblivion_host::family_rotation::Change {
        safe_id: "a".repeat(32), host_opening: "b".repeat(32), plan_sha256: "c".repeat(64),
        current_password: zeroize::Zeroizing::new("\u{1}".repeat(1024)),
        new_password: zeroize::Zeroizing::new("\u{2}".repeat(1024)),
    };
    let body = zeroize::Zeroizing::new(serde_json::to_vec(&change).unwrap());
    assert!(body.len() > 4096 && body.len() <= oblivion_host::family_rotation::CHANGE_LIMIT);
    for operation in ["unlock", "egress", "family-password-recover"] {
        assert!(remote_control::request(&path, operation, None, &body, None).is_err());
    }
    assert!(remote_control::request(&path, "family-password-change", None,
        &vec![0; oblivion_host::family_rotation::CHANGE_LIMIT + 1], None).is_err());
    let expected = body.len();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut header = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut header).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["operation"], "family-password-change");
        assert_eq!(header["secret_len"], expected);
        let mut payload = zeroize::Zeroizing::new(vec![0; expected]);
        stream.read_exact(&mut payload).unwrap();
        let decoded: oblivion_host::family_rotation::Change = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded.current_password.as_str(), "\u{1}".repeat(1024));
        assert_eq!(decoded.new_password.as_str(), "\u{2}".repeat(1024));
        let response = br#"{"ok":true,"output":"accepted-synthetic-body","error":null}"#;
        stream.write_all(&(response.len() as u32).to_be_bytes()).unwrap();
        stream.write_all(response).unwrap();
    });
    assert_eq!(remote_control::request(&path, "family-password-change", None, &body, None).unwrap(), "accepted-synthetic-body");
    server.join().unwrap();

    // Exercise the actual Debian relay's limit owner without starting any
    // listener or touching a controller, user profile, password KDF or disk.
    let output = std::process::Command::new("python3")
        .args(["-B", "-c", r#"
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('relay_fixture',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps({operation:module.secret_limit(operation) for operation in ['family-password-change','family-password-recover','unlock','egress']}))
"#])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("host/control-relay.py"))
        .output().unwrap();
    assert!(output.status.success());
    let limits: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(limits["family-password-change"], oblivion_host::family_rotation::CHANGE_LIMIT);
    for operation in ["family-password-recover", "unlock", "egress"] { assert_eq!(limits[operation], 4096); }
}

#[test]
fn supervisor_request_expires_while_a_peer_keeps_trickling_a_response() {
    let fixture = Fixture::new();
    let path = fixture.0.join("budget.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let request = oblivion_wire::frame::read(&mut stream, 1..=oblivion_wire::control::HEADER_LIMIT).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["operation"], "shutdown-idle");
        let response = br#"{"ok":true,"output":"done","error":null}"#;
        for byte in (response.len() as u32).to_be_bytes().into_iter().chain(response.iter().copied()) {
            if stream.write_all(&[byte]).is_err() { break; }
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let error = remote_control::request_with_budget(&path, "shutdown-idle", None, &[], None,
        Duration::from_millis(75)).unwrap_err();
    assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::TimedOut);
    server.join().unwrap();
}
