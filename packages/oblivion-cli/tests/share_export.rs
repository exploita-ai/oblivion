#![cfg(unix)]
mod support;

use oblivion_cli::controller::{Call, Controller, Result};
use oblivion_cli::run::{Notice, Runtime};
use oblivion_cli::share;
use oblivion_cli::share::io::{Attachment, Lease, Native};
use oblivion_transfer::copy_protocol::Transport;
use oblivion_transfer::endpoint::{read_message, write_message};
use oblivion_transfer::{Receipt, Selection};
use oblivion_wire::control::Operation;
use oblivion_wire::idle::Opening;
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use support::{ID, response, state, status};
use zeroize::Zeroizing;

const EXPORT: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const CLIENT: &str = "cccccccccccccccccccccccccccccccc";
const CONTENT: &[u8] = b"public synthetic Share payload\n";

struct Scope(PathBuf);
impl Scope {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oblivion-share-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(path.join("workspace")).unwrap();
        std::fs::write(path.join("workspace/note.txt"), CONTENT).unwrap();
        Self(path)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Socket(UnixStream);
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl Transport for Socket {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Attached {
    socket: Socket,
    output: PathBuf,
    closed: Arc<AtomicUsize>,
}
impl Attachment for Attached {
    type Stream = Socket;
    fn stream(&mut self) -> &mut Socket {
        &mut self.socket
    }
    fn client_id(&self) -> &str {
        CLIENT
    }
    fn close(&mut self) -> io::Result<()> {
        assert!(!self.output.exists(), "publication preceded source closure");
        self.closed.fetch_add(1, Ordering::SeqCst);
        self.socket.0.shutdown(std::net::Shutdown::Both)
    }
}
struct ExportLease {
    output: PathBuf,
    closed: Arc<AtomicBool>,
}
impl Lease for ExportLease {
    fn check(&mut self) -> io::Result<()> {
        assert!(!self.closed.load(Ordering::SeqCst));
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        assert!(!self.output.exists(), "publication preceded export closure");
        assert!(!self.closed.swap(true, Ordering::SeqCst));
        Ok(())
    }
}

struct Frontend {
    rpc: support::Runtime,
    root: PathBuf,
    output: PathBuf,
    changed: bool,
    attached: usize,
    confirmed: bool,
    first_plan: Arc<Mutex<Option<Value>>>,
    payload_completed: Arc<AtomicBool>,
    closed: Arc<AtomicUsize>,
    lease_closed: Arc<AtomicBool>,
    peers: Vec<JoinHandle<()>>,
}
impl Controller for Frontend {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        assert!(
            !self.output.exists(),
            "controller cleanup followed publication"
        );
        match call.operation {
            Operation::Status => assert_eq!(call.slot, Some(0)),
            Operation::ShareExportBegin => {
                assert_eq!(call.slot, Some(0));
                assert!(call.session.is_none() && call.expected_session.is_none());
                assert_eq!(
                    serde_json::from_slice::<Value>(call.secret)?,
                    json!({"kind":"safe","safe_id":ID})
                );
            }
            Operation::ShareExportSourceOpen => {
                assert_eq!(call.slot, Some(3));
                assert_eq!(call.session, Some(ID));
                assert_eq!(call.expected_session, Some(ID));
                assert_eq!(
                    serde_json::from_slice::<Value>(call.secret)?,
                    json!({"export_id":EXPORT,"password":null})
                );
            }
            _ => panic!("cleanup operations must use the cleanup authority"),
        }
        self.rpc.request(call)
    }
}
impl Runtime for Frontend {
    type Mark = ();
    fn slots(&self) -> Vec<u8> {
        vec![3]
    }
    fn password(&mut self, _: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        panic!("the scripted source is already authorized")
    }
    fn new_password(&mut self, label: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        assert_eq!(label, "Separate Share password");
        assert!(self.confirmed);
        Ok(Zeroizing::new(b"synthetic Share password only".to_vec()))
    }
    fn confirm(&mut self, word: &'static str) -> Result<bool> {
        assert_eq!(word, "SHARE");
        assert_eq!(self.attached, 1);
        assert_eq!(self.closed.load(Ordering::SeqCst), 1);
        assert!(!self.payload_completed.load(Ordering::SeqCst));
        assert!(!self.output.exists());
        self.confirmed = true;
        Ok(true)
    }
    fn now(&self) {}
    fn elapsed(&self, _: &()) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> Result<()> {
        panic!("no gateway retry in Share")
    }
    fn notice(&mut self, _: Notice<'_>) -> Result<()> {
        panic!("no agent notices in Share")
    }
    fn attach(&mut self, _: u8, _: &str, _: &str, _: &[String]) -> Result<i32> {
        panic!("no agent attachment in Share")
    }
    fn attach_workspace(&mut self, _: u8, _: &str) -> Result<i32> {
        panic!("no Workspace attachment in Share")
    }
}
impl Native for Frontend {
    type Attachment = Attached;
    type ExportLease = ExportLease;
    fn lease_share_export(&mut self, export: &str) -> Result<ExportLease> {
        assert_eq!(export, EXPORT);
        Ok(ExportLease {
            output: self.output.clone(),
            closed: Arc::clone(&self.lease_closed),
        })
    }
    fn attach_share_source(
        &mut self,
        opening: &Opening<u8>,
        lease: &mut ExportLease,
    ) -> Result<Attached> {
        lease.check()?;
        assert_eq!(opening.slot, 3);
        assert_eq!(opening.safe_id, ID);
        assert_eq!(opening.nonce, (self.attached + 1).to_string().repeat(32));
        assert_eq!(self.confirmed, self.attached == 1);
        self.attached += 1;
        let second = self.attached == 2;
        let changed = self.changed && second;
        let first_plan = Arc::clone(&self.first_plan);
        let completed = Arc::clone(&self.payload_completed);
        let root = self.root.clone();
        let (client, mut peer) = UnixStream::pair()?;
        for stream in [&client, &peer] {
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        }
        self.peers.push(std::thread::spawn(move || {
            let mut source = Selection::prepare(
                &root,
                &["workspace".into()],
                oblivion_transfer::share::LIMITS,
            )
            .unwrap();
            peer.write_all(b"OBSH1\n").unwrap();
            let request: Value = read_message(&mut peer, 4096).unwrap();
            assert_eq!(request["operation"], "plan");
            assert_eq!(request["paths"], json!(["workspace"]));
            assert_eq!(request["chat_ids"], json!([]));
            if second {
                assert_eq!(first_plan.lock().unwrap().as_ref().unwrap(), &request);
            } else {
                *first_plan.lock().unwrap() = Some(request.clone());
            }
            let digest = if changed { "3" } else { "2" }.repeat(64);
            let manifest = source.manifest();
            write_message(&mut peer, &json!({"version":1,"request_id":request["request_id"],
                "manifest":manifest.entries(),"manifest_sha256":manifest.sha256(),
                "plan_sha256":digest,"bytes":manifest.bytes(),"chats":[],"omitted":{},
                "warnings":[],"warning_count":0,
                "scan":{"files_bytes":CONTENT.len(),"history_bytes":0,"limit_per_kind":16777216,"best_effort":true}})).unwrap();
            let decision: Value = read_message(&mut peer, 4096).unwrap();
            assert_eq!(decision["request_id"], request["request_id"]);
            if !second || changed {
                assert_eq!(decision["operation"], "cancel");
                write_message(&mut peer, &json!({"version":1,"request_id":request["request_id"],"ok":true,"cancelled":true})).unwrap();
            } else {
                assert_eq!(decision["operation"], "confirm");
                assert_eq!(decision["plan_sha256"], digest);
                manifest.write(&mut peer).unwrap();
                source.send_data(&mut peer).unwrap();
                let receipt: Receipt = read_message(&mut peer, 4096).unwrap();
                assert_eq!(receipt.id, request["request_id"].as_str().unwrap());
                assert_eq!(receipt.manifest_sha256, source.manifest().sha256());
                assert_eq!(receipt.entries, 2);
                assert_eq!(receipt.bytes, CONTENT.len() as u64);
                completed.store(true, Ordering::SeqCst);
                peer.write_all(b"copied\n").unwrap();
            }
            assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        }));
        Ok(Attached {
            socket: Socket(client),
            output: self.output.clone(),
            closed: Arc::clone(&self.closed),
        })
    }
    fn attach_share_import(&mut self, _: &Opening<u8>) -> Result<Attached> {
        panic!("export cannot attach an import")
    }
    fn cleanup(&mut self, call: Call<'_, u8>) -> Result<String> {
        assert!(
            !self.output.exists(),
            "publication preceded controller cleanup"
        );
        match call.operation {
            Operation::ShareRelease => {
                assert_eq!(call.slot, Some(3));
                assert_eq!(call.session, Some(CLIENT));
                assert_eq!(call.expected_session, Some(ID));
                let opening: Opening<u8> = serde_json::from_slice(call.secret)?;
                assert_eq!(opening.slot, 3);
                assert_eq!(opening.safe_id, ID);
                assert_eq!(opening.nonce, self.attached.to_string().repeat(32));
                assert_eq!(
                    self.payload_completed.load(Ordering::SeqCst),
                    self.attached == 2
                );
            }
            Operation::ShareExportEnd => {
                assert_eq!(call.slot, Some(0));
                assert!(call.session.is_none() && call.expected_session.is_none());
                assert_eq!(
                    serde_json::from_slice::<Value>(call.secret)?,
                    json!({"export_id":EXPORT})
                );
                assert_eq!(self.payload_completed.load(Ordering::SeqCst), !self.changed);
            }
            _ => panic!("unexpected cleanup"),
        }
        self.rpc.request(call)
    }
}

#[test]
fn reviewed_export_reopens_the_same_plan_and_publishes_only_after_all_releases() {
    for changed in [false, true] {
        let scope = Scope::new();
        let output = scope.0.join("research.oblivion-share");
        let mut state = state("persistent");
        state["sessions"] = json!([ID]);
        state["session_titles"] = json!({ID:"GB"});
        let metadata = |nonce: &str| {
            json!({"opening":{"slot":3,"safe_id":ID,"nonce":nonce.repeat(32)},
            "title":"GB","created_by_agent":false,"requested_agent":null,"parent_not_included":false,
            "policy":"open-internet","required_proxy":null})
        };
        let mut steps = vec![
            status(&state),
            response(
                Operation::ShareExportBegin,
                json!({"export_id":EXPORT,"sources":[{"id":ID,"parent":null}],"settings":null})
                    .to_string(),
            ),
            status(&state),
            response(Operation::ShareExportSourceOpen, metadata("1").to_string()),
            response(Operation::ShareRelease, ""),
            status(&state),
            response(Operation::ShareExportSourceOpen, metadata("2").to_string()),
        ];
        if !changed {
            steps.push(response(Operation::ShareRelease, ""));
        }
        steps.push(response(Operation::ShareExportEnd, ""));
        let mut frontend = Frontend {
            rpc: support::Runtime::new(steps),
            root: scope.0.clone(),
            output: output.clone(),
            changed,
            attached: 0,
            confirmed: false,
            first_plan: Arc::new(Mutex::new(None)),
            payload_completed: Arc::new(AtomicBool::new(false)),
            closed: Arc::new(AtomicUsize::new(0)),
            lease_closed: Arc::new(AtomicBool::new(false)),
            peers: vec![],
        };
        let command = share::parse(&[
            "export".into(),
            "--safe".into(),
            "GB".into(),
            output.to_str().unwrap().into(),
            "--path".into(),
            "workspace".into(),
            "--no-chats".into(),
        ])
        .unwrap();
        let mut diagnostics = Vec::new();
        let result = share::run(&mut frontend, command, &mut Vec::new(), &mut diagnostics);
        for peer in frontend.peers.drain(..) {
            peer.join().unwrap();
        }
        frontend.rpc.finished();
        assert_eq!(frontend.attached, 2);
        assert_eq!(frontend.closed.load(Ordering::SeqCst), 2);
        assert!(frontend.lease_closed.load(Ordering::SeqCst));
        assert!(String::from_utf8(diagnostics).unwrap().contains("note.txt"));
        if changed {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("source changed after review")
            );
            assert!(!output.exists());
        } else {
            assert_eq!(result.unwrap(), 0);
            let ciphertext = std::fs::read(output).unwrap();
            assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
            assert!(
                !ciphertext
                    .windows(CONTENT.len())
                    .any(|bytes| bytes == CONTENT)
            );
        }
        assert_eq!(
            std::fs::read_dir(&scope.0).unwrap().count(),
            if changed { 1 } else { 2 }
        );
    }
}
