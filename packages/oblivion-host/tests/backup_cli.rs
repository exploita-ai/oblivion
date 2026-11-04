use oblivion_host::{remote_control, scope};
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
        let path = PathBuf::from("/tmp").join(format!("oblivion-backup-control-{}", u64::from_be_bytes(nonce)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

#[test]
fn private_backup_attachment_binds_the_transaction_and_preserves_binary_duplex_until_eof() {
    let fixture = Fixture::new();
    let path = fixture.0.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let transaction = "a".repeat(32);
    let server_transaction = transaction.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size) as usize;
        assert!(size <= 1024);
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(header["version"], 1);
        assert_eq!(header["operation"], "backup-attach");
        assert_eq!(header["session"], server_transaction);
        assert!(header["expected_session"].is_null());
        assert_eq!(header["slot"], 3);
        assert_eq!(header["secret_len"], 0);
        let response = serde_json::to_vec(&serde_json::json!({"ok":true,"output":"b".repeat(32),"error":null})).unwrap();
        stream.write_all(&(response.len() as u32).to_be_bytes()).unwrap();
        stream.write_all(&response).unwrap();
        stream.write_all(b"LUKS\xba\xbe\x00\x02\xff\x00").unwrap();
        let mut input = [0; 4];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"\xff\x00OK");
        assert_eq!(stream.read(&mut input).unwrap(), 0);
    });
    let (mut stream, client) = scope::within(scope::Slot::try_from(3).unwrap(), || {
        remote_control::attach_scoped(&path, "backup-attach", Some(&transaction), None)
    }).unwrap();
    assert_eq!(client, "b".repeat(32));
    let mut content = [0; 10];
    stream.read_exact(&mut content).unwrap();
    assert_eq!(&content, b"LUKS\xba\xbe\x00\x02\xff\x00");
    stream.write_all(b"\xff\x00OK").unwrap();
    drop(stream);
    server.join().unwrap();
}
