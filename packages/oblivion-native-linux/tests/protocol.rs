use oblivion_native_linux::{
    bridge,
    config::RuntimeConfig,
    private::Endpoint,
    qemu::{Qmp, SerialGuard, arguments},
};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(format!(
            "/tmp/oblivion-linux-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(root: &Directory) -> RuntimeConfig {
    serde_json::from_value(serde_json::json!({
        "version":1,"backend":"qemu-kvm","runtimeId":"00112233445566778899aabbccddeeff",
        "kernel":root.0.join("kernel"),"initrd":null,
        "commandLine":"boot=live console=hvc0 oblivion.runtime=1 oblivion.runtime-backend=qemu-kvm oblivion.runtime-id=00112233445566778899aabbccddeeff",
        "disks":[{"path":root.0.join("public,format=qcow2.iso"),"readOnly":true},{"path":root.0.join("data.raw"),"readOnly":false}],
        "cpuCount":2,"memoryMiB":2048,"controlSocket":root.0.join("control.sock"),
        "controlPort":4050,"guestCID":45032,"network":false,"serialStdio":false,
    })).unwrap()
}

#[test]
fn runtime_config_keeps_qemu_options_and_paths_separate() {
    let root = Directory::new();
    let mut settings = config(&root);
    settings.validate().unwrap();
    let args = arguments(&settings).unwrap();
    assert!(args.windows(2).any(|args| args == ["-accel", "kvm"]));
    assert!(args.windows(2).any(|args| args == ["-cpu", "host"]));
    assert!(
        !args
            .iter()
            .any(|arg| arg == "-netdev" || arg == "-fsdev" || arg == "-virtfs" || arg == "tcg")
    );
    let block = args.windows(2).find(|args| args[0] == "-blockdev").unwrap();
    let block: serde_json::Value = serde_json::from_str(block[1].to_str().unwrap()).unwrap();
    assert_eq!(block["driver"], "raw");
    assert_eq!(
        block["file"]["filename"],
        settings.disks[0].path.to_str().unwrap()
    );
    let block = args
        .windows(2)
        .filter(|args| args[0] == "-blockdev")
        .nth(1)
        .unwrap();
    let block: serde_json::Value = serde_json::from_str(block[1].to_str().unwrap()).unwrap();
    assert_eq!(block["file"]["cache"]["direct"], true);
    assert_eq!(block["file"]["cache"]["no-flush"], false);
    assert_eq!(block["file"]["locking"], "on");
    settings.guest_cid = 2;
    assert!(settings.validate().is_err());
    settings.guest_cid = 45032;
    settings.disks[0].read_only = false;
    assert!(settings.validate().is_err());
}

#[test]
fn fresh_dedicated_raw_identity_and_exclusive_disk_lease_are_required() {
    let root = Directory::new();
    let settings = config(&root);
    fs::write(&settings.kernel, b"synthetic kernel asset").unwrap();
    let mut iso = fs::File::create(&settings.disks[0].path).unwrap();
    let mut bytes = vec![0; 32774];
    bytes[32769..32774].copy_from_slice(b"CD001");
    iso.write_all(&bytes).unwrap();
    let mut disk = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&settings.disks[1].path)
        .unwrap();
    disk.set_len(4 * 1024 * 1024 * 1024).unwrap();
    disk.write_all(format!("OBLIVION-RUNTIME-1\n{}\n", settings.runtime_id).as_bytes())
        .unwrap();
    let lease = settings.disk_lease().unwrap();
    assert_eq!(
        settings.disk_lease().err().unwrap().0,
        "runtime_disk_in_use"
    );
    drop(lease);
    fs::hard_link(&settings.disks[1].path, root.0.join("alias.raw")).unwrap();
    assert_eq!(
        settings.disk_lease().err().unwrap().0,
        "private_runtime_file_required"
    );
}

#[test]
fn private_unix_endpoint_checks_uid_permissions_and_election() {
    let root = Directory::new();
    let path = root.0.join("control.sock");
    let mut endpoint = Endpoint::bind(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert!(Endpoint::bind(&path).is_err());
    let client = UnixStream::connect(&path).unwrap();
    assert_eq!(
        oblivion_native_linux::private::peer_uid(&client).unwrap(),
        unsafe { libc::getuid() }
    );
    assert!(endpoint.accept().unwrap().is_some());
    endpoint.stop_admission();
    assert!(UnixStream::connect(&path).is_err());
    assert!(Endpoint::bind(&path).is_err());
    drop(endpoint);
    assert!(!path.exists());
    assert!(Endpoint::bind(&path).is_ok());
}

#[test]
fn bounded_bridge_preserves_binary_data_and_flushes_guest_final_bytes() {
    let (mut client, local) = UnixStream::pair().unwrap();
    let (guest, mut server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = std::thread::spawn(move || bridge::duplex(local, guest, stop));
    let mut sending = client.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let bytes: Vec<u8> = (0..2 * 1024 * 1024).map(|n| (n % 256) as u8).collect();
        sending.write_all(&bytes).unwrap();
        bytes
    });
    let echo = std::thread::spawn(move || {
        let mut remaining = 2 * 1024 * 1024;
        let mut bytes = [0; 16384];
        while remaining > 0 {
            let length = server.read(&mut bytes).unwrap();
            assert!(length > 0);
            server.write_all(&bytes[..length]).unwrap();
            remaining -= length;
        }
        server.shutdown(Shutdown::Write).unwrap();
    });
    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap();
    let expected = writer.join().unwrap();
    assert_eq!(received.len(), expected.len(), "bridge truncated its final bytes");
    assert!(received == expected, "bridge changed the binary stream");
    echo.join().unwrap();
    worker.join().unwrap().unwrap();
}

#[test]
fn local_disconnect_releases_the_guest_connection_lease() {
    let (client, local) = UnixStream::pair().unwrap();
    let (guest, mut server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let worker =
        std::thread::spawn(move || bridge::duplex(local, guest, Arc::new(AtomicBool::new(false))));
    drop(client);
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
    worker.join().unwrap().unwrap();
}

// The production backend runs on Linux; this fixture exercises its hangup
// notification while socket data is still queued behind backpressure.
#[cfg(target_os = "linux")]
#[test]
fn stalled_bridge_releases_its_lease_without_waiting_for_the_guest_to_read() {
    let (mut client, local) = UnixStream::pair().unwrap();
    let (guest, _server) = UnixStream::pair().unwrap();
    for (stream, bytes) in [(&client, 256 * 1024_i32), (&guest, 4096_i32)] {
        assert_eq!(unsafe { libc::setsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
            (&bytes as *const i32).cast(), std::mem::size_of::<i32>() as libc::socklen_t) }, 0);
    }
    client.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = stop.clone();
    let (finished, observed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = bridge::duplex(local, guest, cancelled);
        let _ = finished.send(());
        result
    });
    let bytes = vec![0x5a; 1024 * 1024];
    let mut written = 0;
    while written < bytes.len() {
        match client.write(&bytes[written..]) {
            Ok(0) => break,
            Ok(length) => written += length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    drop(client);
    let released = observed.recv_timeout(Duration::from_secs(2));
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap().unwrap();
    assert!(written > 65536, "fixture did not fill the outbound buffer");
    assert!(released.is_ok(), "a disconnected client retained its guest lease");
}

#[test]
fn qmp_real_unix_fixture_handles_fragmented_greeting_and_interleaved_events() {
    let root = Directory::new();
    let path = root.0.join("qmp.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"{\"QMP\":").unwrap();
        stream.write_all(b"{\"version\":{}}}\n").unwrap();
        let mut input = BufReader::new(stream.try_clone().unwrap());
        for expected in ["qmp_capabilities", "query-status", "system_powerdown"] {
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            let command: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(command["execute"], expected);
            stream.write_all(b"{\"event\":\"RESUME\"}\n").unwrap();
            writeln!(
                stream,
                "{}",
                serde_json::json!({"return":{"status":"running"},"id":command["id"]})
            )
            .unwrap();
        }
    });
    let mut qmp = Qmp::connect(&path, Instant::now() + Duration::from_secs(3)).unwrap();
    assert_eq!(
        qmp.command("query-status", Instant::now() + Duration::from_secs(3))
            .unwrap()["status"],
        "running"
    );
    qmp.command("system_powerdown", Instant::now() + Duration::from_secs(3))
        .unwrap();
    server.join().unwrap();
}

#[test]
fn fatal_console_markers_are_detected_across_every_chunk_boundary() {
    for marker in [
        "Kernel panic - not syncing",
        "Internal error: Oops",
        "Oops: 0000",
        "BUG: Bad rss-counter state",
    ] {
        for boundary in 0..marker.len() {
            let mut guard = SerialGuard::default();
            let detected = guard.observe(&marker.as_bytes()[..boundary]);
            assert!(
                detected
                    .or_else(|| guard.observe(&marker.as_bytes()[boundary..]))
                    .is_some()
            );
        }
    }
}

#[test]
fn qmp_rejects_oversized_frames_without_retaining_an_unbounded_log() {
    let root = Directory::new();
    let path = root.0.join("qmp.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.write_all(&vec![b'x'; 65537]);
    });
    assert_eq!(
        Qmp::connect(&path, Instant::now() + Duration::from_secs(3))
            .err()
            .unwrap()
            .0,
        "qmp_message_too_large"
    );
    server.join().unwrap();
}

#[test]
fn private_provisioning_and_authentication_match_the_actual_guest_python_code() {
    let root = Directory::new();
    let (mut host, guest) = UnixStream::pair().unwrap();
    let guest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oblivion-host/host");
    let script = r#"
import importlib.util, os, socket, sys
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
bootstrap = load('bootstrap', sys.argv[1] + '/runtime-auth.py')
relay = load('relay', sys.argv[1] + '/control-relay.py')
bootstrap.provision(0, sys.argv[2], os.getuid(), os.getgid())
with open(sys.argv[2], 'rb') as source:
    token = bytearray(source.read())
assert os.stat(sys.argv[2]).st_mode & 0o777 == 0o600
stream = socket.socket(fileno=os.dup(0))
relay.authenticate_linux(stream, token)
assert relay.exact(stream, 10) == b'AFTER_AUTH'
token[:] = bytes(32)
"#;
    let mut child = Command::new("python3")
        .args(["-I", "-c", script])
        .arg(guest_root)
        .arg(root.0.join("fixture-token"))
        .stdin(Stdio::from(OwnedFd::from(guest)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let token = oblivion_native_linux::auth::Token::random().unwrap();
    let stop = AtomicBool::new(false);
    oblivion_native_linux::auth::provision(
        &mut host,
        &token,
        &stop,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    oblivion_native_linux::auth::authenticate(&mut host, &token, &stop).unwrap();
    host.set_nonblocking(false).unwrap();
    host.write_all(b"AFTER_AUTH").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn guest_relay_rejects_wrong_token_and_plain_v1_frames_before_controller_access() {
    let root = Directory::new();
    let guest_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oblivion-host/host/control-relay.py");
    let script = r#"
import importlib.util, socket, sys
spec = importlib.util.spec_from_file_location('relay', sys.argv[1])
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
relay.serve_client(socket.socket(fileno=0), bytearray(range(32)), sys.argv[2])
"#;
    let header = serde_json::to_vec(&serde_json::json!({"version":1,"operation":"status","secret_len":0,"slot":0,"session":null,"expected_session":null})).unwrap();
    let plain = [
        (header.len() as u32).to_be_bytes().as_slice(),
        header.as_slice(),
    ]
    .concat();
    let wrong = [oblivion_native_linux::auth::HELLO.as_slice(), &[0; 32]].concat();
    for payload in [plain, wrong] {
        let (mut host, guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut child = Command::new("python3")
            .args(["-I", "-c", script])
            .arg(&guest_root)
            .arg(root.0.join("no-controller.sock"))
            .stdin(Stdio::from(OwnedFd::from(guest)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        host.write_all(&payload).unwrap();
        assert_eq!(host.read(&mut [0; 1]).unwrap(), 0);
        assert!(child.wait().unwrap().success());
    }
}
