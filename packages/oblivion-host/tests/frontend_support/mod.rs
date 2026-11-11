// Each integration binary uses its own subset of this real Unix fixture.
#![allow(dead_code)]
use oblivion_cli::{controller, run};
use oblivion_host::{control, scope};
use oblivion_wire::control::{HEADER_LIMIT, RESPONSE_LIMIT, Request, Response};
use oblivion_wire::frame;
use std::collections::VecDeque;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) const SAFE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) struct Fixture {
    directory: PathBuf,
    pub(crate) path: PathBuf,
}
impl Fixture {
    pub(crate) fn new() -> (Self, UnixListener) {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        let directory =
            PathBuf::from("/tmp").join(format!("ob-frontend-{:016x}", u64::from_be_bytes(bytes)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (Self { directory, path }, listener)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
pub(crate) fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(3) =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("frontend connection failed: {error}"),
        }
    }
}
pub(crate) fn read(stream: &mut UnixStream) -> Request<scope::Slot> {
    let (request, secret) = receive(stream);
    assert!(secret.is_empty());
    request
}
pub(crate) fn receive(stream: &mut UnixStream) -> (Request<scope::Slot>, Zeroizing<Vec<u8>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header: serde_json::Value =
        serde_json::from_slice(&frame::read(stream, 1..=HEADER_LIMIT).unwrap()).unwrap();
    assert_eq!(
        header.as_object_mut().unwrap().remove("version"),
        Some(serde_json::json!(1))
    );
    let request: Request<scope::Slot> = serde_json::from_value(header).unwrap();
    assert!(request.secret_len <= 4096);
    let mut secret = Zeroizing::new(vec![0; request.secret_len as usize]);
    stream.read_exact(&mut secret).unwrap();
    (request, secret)
}
pub(crate) fn reply(stream: &mut UnixStream, output: &str, error: Option<&str>) {
    frame::write(
        stream,
        &serde_json::to_vec(&Response {
            ok: error.is_none(),
            output,
            error,
        })
        .unwrap(),
        1..=RESPONSE_LIMIT,
    )
    .unwrap();
}
pub(crate) fn state() -> serde_json::Value {
    serde_json::json!({
        "app_open":true,"app_mode":"persistent","general_present":true,
        "general_incomplete":false,"backing_recovery_required":false,"general_bytes":8589934592_u64,"recovery_required":false,
        "sessions":[SAFE],"session_titles":{SAFE:"GB"},
        "open_sessions":[{"slot":4,"id":SAFE,"mode":"documents","recovery_required":false}],
        "agent_safes":[],"platform_details":{"preserve_this_field":true}
    })
}
pub(crate) fn missing_storage(incomplete: bool) -> serde_json::Value {
    let mut source = state();
    source["app_open"] = serde_json::json!(false);
    source["app_mode"] = serde_json::json!("locked");
    source["general_present"] = serde_json::json!(false);
    source["general_incomplete"] = serde_json::json!(incomplete);
    source["sessions"] = serde_json::json!([]);
    source["open_sessions"] = serde_json::json!([]);
    source
}

// Only terminal interaction and time are substituted. Controller requests use
// the production Unix adapter, codec, socket authentication and slot scoping.
pub(crate) struct RunTerminal {
    controller: control::Client,
    pub(crate) prompts: Vec<&'static str>,
    pub(crate) answers: VecDeque<Zeroizing<Vec<u8>>>,
    pub(crate) confirmations: Vec<&'static str>,
    pub(crate) confirmed: bool,
    pub(crate) now: Duration,
    pub(crate) notices: Vec<String>,
    pub(crate) attached: Vec<(u8, String, String, Vec<String>)>,
    pub(crate) fail_attach: bool,
}
impl RunTerminal {
    pub(crate) fn new(path: &std::path::Path) -> Self {
        Self {
            controller: control::Client::remote(path),
            prompts: vec![],
            answers: VecDeque::new(),
            confirmations: vec![],
            confirmed: false,
            now: Duration::ZERO,
            notices: vec![],
            attached: vec![],
            fail_attach: false,
        }
    }
}
impl controller::Controller for RunTerminal {
    type Slot = scope::Slot;
    fn request(&mut self, call: controller::Call<'_, Self::Slot>) -> controller::Result<String> {
        self.controller.request(call)
    }
}
impl run::Runtime for RunTerminal {
    type Mark = Duration;
    fn slots(&self) -> Vec<scope::Slot> {
        (0..scope::LIMIT)
            .map(|index| scope::Slot::try_from(index).unwrap())
            .collect()
    }
    fn password(&mut self, label: &'static str) -> controller::Result<Zeroizing<Vec<u8>>> {
        self.prompts.push(label);
        Ok(self
            .answers
            .pop_front()
            .unwrap_or_else(|| Zeroizing::new(b"SYNTHETIC_PASSWORD_CANARY".to_vec())))
    }
    fn new_password(&mut self, label: &'static str) -> controller::Result<Zeroizing<Vec<u8>>> {
        self.password(label)
    }
    fn confirm(&mut self, word: &'static str) -> controller::Result<bool> {
        self.confirmations.push(word);
        Ok(self.confirmed)
    }
    fn now(&self) -> Self::Mark {
        self.now
    }
    fn elapsed(&self, mark: &Self::Mark) -> Duration {
        self.now - *mark
    }
    fn wait(&mut self, duration: Duration) -> controller::Result<()> {
        self.now += duration;
        Ok(())
    }
    fn notice(&mut self, notice: run::Notice<'_>) -> controller::Result<()> {
        self.notices.push(match notice {
            run::Notice::WaitingForConnection => "waiting".into(),
            run::Notice::SafeOpened(id) => format!("opened {id}"),
            run::Notice::StorageCapacity(bytes) => format!("capacity {bytes}"),
            run::Notice::StorageCreated => "storage-created".into(),
            run::Notice::IncompleteStorageReview => "review-incomplete".into(),
            run::Notice::IncompleteStorageDiscarded => "discarded-incomplete".into(),
            run::Notice::BackingRepairReview => "backing-review".into(),
            run::Notice::BackingRepaired => "backing-repaired".into(),
        });
        Ok(())
    }
    fn attach(
        &mut self,
        slot: scope::Slot,
        id: &str,
        agent: &str,
        argv: &[String],
    ) -> controller::Result<i32> {
        scope::within(slot, || {
            self.attached.push((
                scope::current().index(),
                id.into(),
                agent.into(),
                argv.to_vec(),
            ));
        });
        if self.fail_attach {
            return Err("attachment_failed".into());
        }
        Ok(19)
    }
    fn attach_workspace(&mut self, slot: scope::Slot, id: &str) -> controller::Result<i32> {
        self.attach(slot, id, "workspace", &[])
    }
}
pub(crate) fn run_options(args: &[&str]) -> run::Options<oblivion_transport::Transport> {
    run::parse(&args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>())
        .unwrap()
        .resolve_transport(|request| match request {
            oblivion_cli::proxy::Request::Ready(transport) => Ok(transport),
            _ => Err("Expected a complete numeric proxy"),
        })
        .unwrap()
}
