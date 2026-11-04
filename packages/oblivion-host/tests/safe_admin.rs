use oblivion_host::safe_admin::{self, Command, Metadata, Request, Response};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::Duration;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut id = [0; 16];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut id)
            .unwrap();
        let path = PathBuf::from("/tmp").join(format!(
            "oblivion-admin-{}",
            id.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        for name in ["state", "workspace", "home/.oblivion-history"] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path.join(name))
                .unwrap();
        }
        Self(path)
    }
    fn call(&self, command: Command) -> oblivion_host::control::Result<Response> {
        let (mut local, remote) = UnixStream::pair().unwrap();
        local
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        local
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let descriptor = remote.into_raw_fd();
        let script = r#"
import importlib.util, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
spec=importlib.util.spec_from_file_location('safe_admin', sys.argv[3])
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with os.fdopen(0,'r+b',buffering=0) as channel:
    module.serve_channel(channel, vault=Path(sys.argv[1]), owner='oblivion.admin.'+'a'*32)
"#;
        let mut process = std::process::Command::new("python3");
        process
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()))
            .env("HOME", self.0.join("home"))
            .args(["-B", "-c", script])
            .arg(&self.0)
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oblivion-history"))
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest/safe-admin.py"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            process.pre_exec(move || {
                if libc::dup2(descriptor, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(descriptor);
                Ok(())
            });
        }
        let mut child = process.spawn().unwrap();
        unsafe {
            libc::close(descriptor);
        }
        let response = safe_admin::exchange(&mut local, &Request::new(command));
        drop(local);
        assert!(child.wait().unwrap().success());
        response
    }
    fn catalog_writer(&self) -> Writer {
        let script = r#"
import os, sys
os.umask(0o077)
sys.path.insert(0,sys.argv[2])
from pathlib import Path
from oblivion_history.catalog import Catalog
catalog=Catalog(Path(sys.argv[1])/'home/.oblivion-history')
catalog.db.execute('PRAGMA wal_autocheckpoint=0')
with catalog.db:
    for index in range(62):
        identifier='00000000-0000-4000-8000-'+format(index,'012x')
        catalog.db.execute('INSERT INTO chat VALUES (?,?,?,?,?)',(identifier,'/vault/workspace','Chat città '+str(index)+'\x1b\u202e',1,index))
        catalog.db.execute('INSERT INTO native VALUES (?,?,?,?,?,?)',('codex','native-'+str(index),identifier,'','',''))
    catalog.db.execute("INSERT INTO deleted_chat VALUES (?,1,'explicit_confirmation')",('00000000-0000-4000-8000-000000000000',))
print('ready',flush=True)
sys.stdin.buffer.read(1)
catalog.close()
"#;
        let mut child = std::process::Command::new("python3")
            .args(["-B", "-u", "-c", script])
            .arg(&self.0)
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oblivion-history"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        Writer(child)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Writer(Child);
impl Drop for Writer {
    fn drop(&mut self) {
        self.0.stdin.take();
        let _ = self.0.wait();
    }
}
fn metadata() -> Metadata {
    Metadata {
        format: "oblivion-safe".into(),
        version: 1,
        safe_id: "b".repeat(32),
        title: Some("Città".into()),
        history_version: 1,
        origin: oblivion_host::safe_origin::Origin::Local {},
    }
}

#[test]
fn schema_accepts_only_current_neutral_safe_metadata() {
    assert!(metadata().valid());
    let mut value = serde_json::to_value(metadata()).unwrap();
    value["original_id"] = "b".repeat(32).into();
    assert!(serde_json::from_value::<Metadata>(value).is_err());
    for invalid in [
        r#"{"version":1,"command":{"operation":"usage","path":"/etc/passwd"}}"#,
        r#"{"version":1,"command":{"operation":"archive-state","cursor":"../escape"}}"#,
        r#"{"version":0,"command":{"operation":"usage"}}"#,
        r#"{"version":1,"command":{"operation":"checkpoint","metadata":{"format":"oblivion-session","version":1,"original_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","title":null}}}"#,
    ] {
        assert!(!serde_json::from_str::<Request>(invalid).is_ok_and(|value| value.valid()));
    }
}

#[test]
fn real_guest_checkpoint_and_inspect_need_no_native_database_or_agent() {
    let fixture = Fixture::new();
    let value = metadata();
    assert!(
        matches!(fixture.call(Command::Checkpoint { metadata: value.clone() }).unwrap(), Response::Metadata { metadata } if metadata == value)
    );
    assert!(
        matches!(fixture.call(Command::Inspect {}).unwrap(), Response::Metadata { metadata } if metadata == value)
    );
    assert!(
        !fixture
            .0
            .join("home/.oblivion-history/history.sqlite")
            .exists()
    );
    assert!(!fixture.0.join("state/opencode").exists());
    let target = fixture.0.join("state/oblivion/safe.json");
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut future = serde_json::to_value(value).unwrap();
    future["version"] = 2.into();
    fs::write(&target, serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(matches!(
        fixture
            .call(Command::Checkpoint {
                metadata: metadata()
            })
            .unwrap(),
        Response::Rejected { .. }
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(target).unwrap()).unwrap()["version"],
        2
    );
}

#[test]
fn standalone_agent_snapshot_preserves_sealed_context_and_attempts_without_general_or_mother() {
    let source = Fixture::new();
    let target = Fixture::new();
    let capability = oblivion_host::family::Capability::from_root_secret(&"1".repeat(32), zeroize::Zeroizing::new([7; 32])).unwrap();
    let mut origin = oblivion_host::safe_origin::AgentCreated {
        safe_id: "b".repeat(32), parent_id: "c".repeat(32), request_id: "d".repeat(32), agent: "codex".into(),
        creator_chat_id: Some("reported-native-chat".into()),
        sealed_task: oblivion_host::family::SealedTask::seal(&capability, &oblivion_host::family::TaskContext {
            safe_id: &"b".repeat(32), parent_id: &"c".repeat(32), request_id: &"d".repeat(32), agent: "codex",
        }, &"private-task-canary ".repeat(800)).unwrap(),
        attempts: vec!["d".repeat(32), "e".repeat(32)],
    };
    origin.creator_chat_id = Some("z".repeat(256));
    let mut value = metadata();
    value.origin = oblivion_host::safe_origin::Origin::AgentCreated { record: origin };
    assert!(value.valid());
    assert!(matches!(source.call(Command::Checkpoint { metadata: value.clone() }).unwrap(), Response::Metadata { .. }));
    let bytes = fs::read(source.0.join("state/oblivion/safe.json")).unwrap();
    assert!(bytes.len() > 4096 && bytes.len() < safe_admin::REQUEST_LIMIT);
    assert!(!String::from_utf8_lossy(&bytes).contains("private-task-canary"));
    fs::DirBuilder::new().mode(0o700).create(target.0.join("state/oblivion")).unwrap();
    fs::write(target.0.join("state/oblivion/safe.json"), bytes).unwrap();
    fs::set_permissions(target.0.join("state/oblivion/safe.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let Response::Metadata { metadata } = target.call(Command::Inspect {}).unwrap() else { panic!("metadata unavailable") };
    let oblivion_host::safe_origin::Origin::AgentCreated { record } = metadata.origin else { panic!("origin lost") };
    assert_eq!(record.parent_id, "c".repeat(32));
    assert_eq!(record.attempts, ["d".repeat(32), "e".repeat(32)]);
    assert!(record.sealed_task.open(&capability, &record.context()).unwrap().starts_with("private-task-canary"));
    assert!(!target.0.join("general").exists() && !target.0.join("mother").exists());
}

#[test]
fn offline_job_observation_reads_only_bounded_status_and_reconciles_a_dead_runner() {
    let fixture = Fixture::new();
    let id = "1".repeat(32);
    assert!(matches!(fixture.call(Command::Job { job_id: id.clone() }).unwrap(), Response::Job { info: None }));
    assert!(!fixture.0.join("home/.oblivion-jobs").exists());
    let path = fixture.0.join("home/.oblivion-jobs").join(&id);
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&path).unwrap();
    fs::write(path.join("task.txt"), "private-job-task-canary").unwrap();
    fs::write(path.join("stdout.jsonl"), "private-output-canary").unwrap();
    fs::write(path.join("status.json"), serde_json::to_vec(&serde_json::json!({"version":1,"output_bytes":0,
        "info":{"job_id":id,"request_id":"2".repeat(32),"agent":"codex","state":"running","native_chat_id":null,"reason":null}})).unwrap()).unwrap();
    fs::set_permissions(path.join("status.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let response = fixture.call(Command::Job { job_id: id }).unwrap();
    assert!(matches!(&response, Response::Job { info: Some(info) }
        if info.state == oblivion_host::managed::State::Failed && info.reason == Some(oblivion_host::managed::Reason::Interrupted)));
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains("private-job-task-canary") && !encoded.contains("private-output-canary"));
    assert!(!fixture.0.join("home/.codex").exists());
}

#[test]
fn paged_real_readonly_sqlite_snapshot_includes_committed_wal_and_omits_tombstones() {
    let fixture = Fixture::new();
    let _writer = fixture.catalog_writer();
    assert!(
        fixture
            .0
            .join("home/.oblivion-history/history.sqlite-wal")
            .exists()
    );
    let first = match fixture
        .call(Command::ArchiveState { cursor: None })
        .unwrap()
    {
        Response::ArchiveState { state } => state,
        _ => panic!("not archive state"),
    };
    assert_eq!(first.entries.len(), 50);
    assert!(
        first
            .entries
            .iter()
            .all(|entry| entry.title.starts_with("Chat città")
                && !entry.title.contains('\x1b')
                && !entry.title.contains('\u{202e}'))
    );
    assert!(
        first
            .entries
            .iter()
            .all(|entry| !entry.chat_id.ends_with("000000000000"))
    );
    let second = match fixture
        .call(Command::ArchiveState {
            cursor: first.next.clone(),
        })
        .unwrap()
    {
        Response::ArchiveState { state } => state,
        _ => panic!("not archive state"),
    };
    assert_eq!(second.entries.len(), 11);
    assert!(second.next.is_none());
    assert!(second.entries[0].chat_id > first.entries.last().unwrap().chat_id);
}

#[test]
fn invalid_present_catalog_is_not_reset_or_treated_as_empty() {
    let fixture = Fixture::new();
    let path = fixture.0.join("home/.oblivion-history/history.sqlite");
    fs::write(&path, b"malformed private data").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        fixture
            .call(Command::ArchiveState { cursor: None })
            .unwrap(),
        Response::Rejected { .. }
    ));
    assert_eq!(fs::read(path).unwrap(), b"malformed private data");
}

#[test]
fn diagnostics_use_allowlist_and_cannot_follow_workspace_symlinks() {
    let fixture = Fixture::new();
    let report = || {
        serde_json::from_value(serde_json::json!({
        "version":1,"controller_version":env!("CARGO_PKG_VERSION"),"architecture":"aarch64","cpu_cores":4,"memory_mib":4096,
        "ephemeral":false,"general_open":true,"session":"documents","transport":"offline","direct_access_blocked":true,
        "observation_age_ms":0,"tor_bootstrap":null,"laboratory":false
    })).unwrap()
    };
    let response = fixture
        .call(Command::Diagnostics { report: report() })
        .unwrap();
    let path = match response {
        Response::Exported { path, .. } => path,
        _ => panic!("not exported"),
    };
    assert_eq!(
        fs::metadata(fixture.0.join(&path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        serde_json::from_slice::<oblivion_host::diagnostics::Report>(
            &fs::read(fixture.0.join(path)).unwrap()
        )
        .unwrap()
        .valid()
    );
    fs::remove_dir_all(fixture.0.join("workspace/diagnostics")).unwrap();
    std::os::unix::fs::symlink(
        fixture.0.join("home"),
        fixture.0.join("workspace/diagnostics"),
    )
    .unwrap();
    assert!(
        fixture
            .call(Command::Diagnostics { report: report() })
            .is_err()
    );
    assert_eq!(fs::read_dir(fixture.0.join("home")).unwrap().count(), 1);
}

#[test]
fn native_frame_reader_refuses_oversized_and_cross_operation_replies() {
    for response in [None, Some(br#"{"version":1,"response":{"result":"metadata","metadata":{"format":"oblivion-safe","version":1,"safe_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","title":null,"history_version":1}}}"#.as_slice())] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let payload = response.map(Vec::from);
        let worker = std::thread::spawn(move || {
            server.write_all(safe_admin::READY).unwrap();
            let mut gate = [0]; server.read_exact(&mut gate).unwrap();
            assert_eq!(gate[0], b'G');
            let mut size = [0; 4]; server.read_exact(&mut size).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(size) as usize]; server.read_exact(&mut bytes).unwrap();
            if let Some(payload) = payload { server.write_all(&(payload.len() as u32).to_be_bytes()).unwrap(); server.write_all(&payload).unwrap(); }
            else { server.write_all(&65537u32.to_be_bytes()).unwrap(); }
        });
        assert!(safe_admin::exchange(&mut client, &Request::new(Command::Usage {})).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn real_private_guest_handoff_installs_only_the_requested_native_identity() {
    let source = Fixture::new();
    let child = Fixture::new();
    let directory = source.0.join("home/.codex");
    fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    fs::write(directory.join("auth.json"), br#"{"auth_mode":"apikey","OPENAI_API_KEY":"synthetic-safe-identity-canary"}"#).unwrap();
    fs::set_permissions(directory.join("auth.json"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(directory.join("config.toml"), "[mcp_servers.untrusted]\ncommand='must-not-copy'\n").unwrap();
    fs::write(directory.join("history.jsonl"), "source-chat-must-not-copy").unwrap();
    let Response::Credential { credential: Some(credential), reason: None } = source.call(Command::CredentialExport { agent: safe_admin::Agent::Codex }).unwrap() else { panic!("credential unavailable") };
    assert!(matches!(child.call(Command::CredentialInstall { credential }).unwrap(), Response::CredentialInstalled {}));
    assert!(!child.0.join("home/.codex/config.toml").exists());
    assert!(!child.0.join("home/.codex/history.jsonl").exists());
    assert!(!child.0.join("home/.claude").exists());
    assert!(!child.0.join("state/opencode").exists());
    let installed = fs::read(child.0.join("home/.codex/auth.json")).unwrap();
    assert!(String::from_utf8_lossy(&installed).contains("synthetic-safe-identity-canary"));
    assert!(matches!(source.call(Command::CredentialExport { agent: safe_admin::Agent::Claude }).unwrap(), Response::Credential { credential: None, reason: Some(safe_admin::CredentialReason::NeedsAuth) }));
    fs::write(directory.join("auth.json"), br#"{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-oauth-must-not-clone","refresh_token":"synthetic-refresh"}}"#).unwrap();
    assert!(matches!(source.call(Command::CredentialExport { agent: safe_admin::Agent::Codex }).unwrap(), Response::Credential { credential: None, reason: Some(safe_admin::CredentialReason::UnsupportedOauth) }));
}
