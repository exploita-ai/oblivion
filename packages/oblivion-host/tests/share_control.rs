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
