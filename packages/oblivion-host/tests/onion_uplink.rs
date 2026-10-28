use oblivion_host::onion_uplink;
use serde_json::{Value, json};
use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn runtime_paths_cannot_inject_qemu_options_or_escape_the_private_directory() {
    for path in [
        "relative",
        "/tmp/../outside",
        "/tmp/x,server=on",
        "/tmp/x:y",
        "/tmp/x\n",
        "/tmp/x%00",
        "/tmp/space here",
    ] {
        assert!(onion_uplink::arguments(Path::new(path)).is_err());
    }
    assert!(onion_uplink::arguments(Path::new(&format!("/tmp/{}", "x".repeat(100)))).is_err());
    assert!(onion_uplink::arguments(Path::new(onion_uplink::RUNTIME)).is_ok());
}

struct Fixture {
    child: Child,
    directory: PathBuf,
    qmp: Option<BufReader<UnixStream>>,
}

impl Fixture {
    fn new() -> Self {
        let name = if cfg!(target_arch = "aarch64") {
            "qemu-system-aarch64"
        } else {
            "qemu-system-x86_64"
        };
        let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .expect("This integration test requires the platform's QEMU package");
        let directory = PathBuf::from(format!("/tmp/oblivion-uplink-test-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let child = Command::new(binary)
            .args(onion_uplink::arguments(&directory).unwrap())
            .args(oblivion_host::onion_vm::session_lifetime(&directory).unwrap())
            .env_clear()
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Own the process before readiness checks so a failed assertion also
        // reaps it. The test never leaves a network actor running on its host.
        let mut fixture = Self {
            child,
            directory,
            qmp: None,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !["qmp.sock", "network.sock", "lifetime.sock"]
            .iter()
            .all(|name| {
                fs::symlink_metadata(fixture.directory.join(name))
                    .is_ok_and(|metadata| metadata.file_type().is_socket())
            })
        {
            if let Some(status) = fixture.child.try_wait().unwrap() {
                let mut diagnostic = String::new();
                fixture
                    .child
                    .stderr
                    .as_mut()
                    .unwrap()
                    .read_to_string(&mut diagnostic)
                    .unwrap();
                panic!("Uplink exited during startup: {diagnostic} ({status})");
            }
            assert!(
                Instant::now() < deadline,
                "Uplink did not create its private sockets"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let socket = UnixStream::connect(fixture.directory.join("qmp.sock")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut qmp = BufReader::new(socket);
        let mut line = String::new();
        qmp.read_line(&mut line).unwrap();
        assert!(
            serde_json::from_str::<Value>(&line)
                .unwrap()
                .get("QMP")
                .is_some()
        );
        fixture.qmp = Some(qmp);
        fixture.command("qmp_capabilities");
        fixture
    }

    fn command(&mut self, operation: &str) -> Value {
        let qmp = self.qmp.as_mut().unwrap();
        serde_json::to_writer(qmp.get_mut(), &json!({"execute": operation})).unwrap();
        qmp.get_mut().write_all(b"\n").unwrap();
        loop {
            let mut line = String::new();
            assert!(qmp.read_line(&mut line).unwrap() > 0);
            let value: Value = serde_json::from_str(&line).unwrap();
            assert!(value.get("error").is_none(), "{value}");
            if let Some(result) = value.get("return") {
                return result.clone();
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(qmp) = self.qmp.as_mut() {
            let _ = qmp.get_mut().write_all(b"{\"execute\":\"quit\"}\n");
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

// Compiler-only images do not contain QEMU. CI runs this explicitly after
// installing the platform package; native Mac development uses the same test.
#[test]
#[ignore = "requires the platform QEMU executable; run with --include-ignored"]
fn actual_qemu_routes_a_private_dhcp_exchange_without_cpus_or_disks() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.command("query-status")["running"], true);
    assert_eq!(fixture.command("query-cpus-fast"), json!([]));
    assert_eq!(fixture.command("query-block"), json!([]));
    let lifetime = UnixStream::connect(fixture.directory.join("lifetime.sock")).unwrap();
    // Holding the lifetime monitor does not replace the normal QMP channel or
    // either chat/terminal console. Linux additionally pins the real peer PID.
    assert_eq!(fixture.command("query-status")["running"], true);
    #[cfg(target_os = "linux")]
    let owner = {
        use std::os::fd::OwnedFd;
        let file = std::fs::File::from(OwnedFd::from(lifetime.try_clone().unwrap()));
        oblivion_transfer::relay::peer_process(&file).unwrap()
    };
    let mut wire = UnixStream::connect(fixture.directory.join("network.sock")).unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    wire.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // A fixed DHCP discover talks only to the emulated local router. There is
    // no guest/OS, public destination, provider request, API key or user data.
    let mac = [0x52, 0x54, 0x00, 0x6f, 0x00, 0x02];
    let mut bootp = vec![0u8; 240];
    bootp[..3].copy_from_slice(&[1, 1, 6]);
    bootp[4..8].copy_from_slice(&0x4f424c56u32.to_be_bytes());
    bootp[10] = 0x80;
    bootp[28..34].copy_from_slice(&mac);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend([53, 1, 1, 55, 3, 1, 3, 6, 255]);
    let mut frame = vec![0u8; 42 + bootp.len()];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((28 + bootp.len()) as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[30..34].fill(0xff);
    let checksum = frame[14..34]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>();
    let checksum = (checksum & 0xffff) + (checksum >> 16);
    frame[24..26].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
    frame[34..36].copy_from_slice(&68u16.to_be_bytes());
    frame[36..38].copy_from_slice(&67u16.to_be_bytes());
    frame[38..40].copy_from_slice(&((bootp.len() + 8) as u16).to_be_bytes());
    frame[42..].copy_from_slice(&bootp);
    wire.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    wire.write_all(&frame).unwrap();
    loop {
        let mut length = [0; 4];
        wire.read_exact(&mut length).unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!((14..=65536).contains(&length));
        let mut frame = vec![0; length];
        wire.read_exact(&mut frame).unwrap();
        if frame[12..14] != [8, 0] {
            continue;
        }
        assert!(frame.len() >= 42 && frame[23] == 17);
        let udp = 14 + usize::from(frame[14] & 15) * 4;
        assert_eq!(&frame[udp..udp + 4], &[0, 67, 0, 68]);
        let reply = &frame[udp + 8..];
        assert!(reply.len() >= 240);
        assert_eq!(reply[0], 2);
        assert_eq!(&reply[4..8], &0x4f424c56u32.to_be_bytes());
        assert_eq!(&reply[16..20], &[10, 0, 2, 15]);
        assert_eq!(&reply[28..34], &mac);
        assert_eq!(&reply[236..240], &[99, 130, 83, 99]);
        break;
    }
    fixture.command("quit");
    assert!(fixture.child.wait().unwrap().success());
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut descriptor = libc::pollfd {
            fd: owner.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 1);
        assert!(descriptor.revents != 0);
    }
    drop(lifetime);
}
