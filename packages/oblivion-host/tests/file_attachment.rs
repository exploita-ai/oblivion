use oblivion_host::{autolock::Opening, remote_control, scope};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::time::Duration;

#[test]
fn native_file_attachment_carries_exact_safe_slot_and_opening_in_its_admission_request() {
    let mut bytes = [0; 8];
    getrandom::getrandom(&mut bytes).unwrap();
    let directory = std::path::PathBuf::from("/tmp")
        .join(format!("ob-file-attach-{:016x}", u64::from_be_bytes(bytes)));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let opening = Opening {
        slot: scope::Slot::try_from(4).unwrap(),
        safe_id: "a".repeat(32),
        nonce: "b".repeat(32),
    };
    let expected = opening.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(header["version"], 1);
        assert_eq!(header["operation"], "file-attach");
        assert_eq!(header["slot"], 4);
        assert_eq!(header["expected_session"], expected.safe_id);
        assert!(header["session"].is_null());
        let mut secret = vec![0; header["secret_len"].as_u64().unwrap() as usize];
        stream.read_exact(&mut secret).unwrap();
        assert_eq!(
            serde_json::from_slice::<Opening>(&secret).unwrap(),
            expected
        );
        let response = serde_json::to_vec(
            &serde_json::json!({"ok":true,"output":"c".repeat(32),"error":null}),
        )
        .unwrap();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
        stream.write_all(b"READY").unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    let secret = serde_json::to_vec(&opening).unwrap();
    let (mut stream, client) = scope::within(opening.slot, || {
        remote_control::attach_scoped_with_secret(
            &path,
            "file-attach",
            None,
            Some(&opening.safe_id),
            &secret,
        )
    })
    .unwrap();
    assert_eq!(client, "c".repeat(32));
    let mut ready = [0; 5];
    stream.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"READY");
    drop(stream);
    server.join().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
