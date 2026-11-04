mod frontend_support;
use frontend_support::{accept, read, receive, reply, state, Fixture, SAFE};
use oblivion_cli::controller::{Call, Controller, Result};
use oblivion_cli::files::{self, Backend};
use oblivion_host::{control, scope};
use oblivion_transfer::native_files::{Action, Status, TransfersPage, TransfersQuery};
use oblivion_wire::control::Operation;
use oblivion_wire::idle::Opening;
use serde_json::{json, Value};

// Listings use the real controller adapter. The receiver I/O methods are not
// involved and would make this fixture fail if routing crossed that boundary.
struct Files(control::Client);
impl Controller for Files {
    type Slot = scope::Slot;
    fn request(&mut self, call: Call<'_, Self::Slot>) -> Result<String> {
        self.0.request(call)
    }
}
impl Backend for Files {
    fn transfers(
        &mut self,
        _: &Opening<Self::Slot>,
        _: &TransfersQuery,
        _: Option<&str>,
    ) -> Result<TransfersPage> {
        panic!("a directory listing cannot inspect an operation receiver")
    }
    fn manage(
        &mut self,
        _: &Opening<Self::Slot>,
        _: &str,
        _: Action,
        _: Option<&str>,
    ) -> Result<Status> {
        panic!("a directory listing cannot mutate an operation receiver")
    }
}

#[test]
fn shared_files_listing_uses_the_real_private_unix_adapter_and_safe_scope() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::Status);
        assert!(request.expected_session.is_none());
        reply(&mut stream, &state().to_string(), None);
        let mut stream = accept(&listener);
        let (request, body) = receive(&mut stream);
        assert_eq!(request.operation, Operation::Browse);
        assert_eq!(request.slot.index(), 4);
        assert_eq!(request.expected_session.as_deref(), Some(SAFE));
        assert!(request.session.is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"path":"workspace/project","after":"alpha","limit":100})
        );
        reply(&mut stream,&json!({"path":"workspace/project","entries":[{"name":"beta","directory":true,"bytes":0}],"next":null,"skipped":0}).to_string(),None);
    });
    let mut backend = Files(control::Client::remote(&fixture.path));
    let command = files::parse(
        &[
            "list",
            "workspace/project",
            "--safe",
            "GB",
            "--cursor",
            "alpha",
            "--json",
        ]
        .map(str::to_owned),
    )
    .unwrap()
    .unwrap();
    let mut output = vec![];
    let mut diagnostics = vec![];
    assert_eq!(
        files::execute(&mut backend, command, &mut output, &mut diagnostics).unwrap(),
        0
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"path":"workspace/project","entries":[{"name":"beta","path":"workspace/project/beta","kind":"directory","bytes":0}],"next_cursor":null,"skipped":0})
    );
    assert!(diagnostics.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}
