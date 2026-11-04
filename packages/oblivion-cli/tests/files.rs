mod support;
use oblivion_cli::controller::{Call, Controller, Result};
use oblivion_cli::files::{self, Backend};
use oblivion_transfer::native_files::{
    Action, Direction, State, Status, TransferEntry, TransfersPage, TransfersQuery,
};
use oblivion_transfer::Receipt;
use oblivion_wire::control::Operation;
use oblivion_wire::idle::Opening;
use serde_json::{json, Value};
use support::{active, response, status, Runtime, ID};

const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OP: &str = "cccccccccccccccccccccccccccccccc";
const OLD: &str = "dddddddddddddddddddddddddddddddd";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn command(values: &[&str]) -> files::Command {
    files::parse(&args(values)).unwrap().unwrap()
}
fn current() -> Value {
    let mut value = active();
    value["idle_lock"] = json!({"preferences":{"version":1,"safe_minutes":15,"host_minutes":30},
        "host":{"nonce":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","remaining_seconds":30,"closing":false},
        "safes":[{"opening":{"slot":1,"safe_id":ID,"nonce":NONCE},"remaining_seconds":20,"closing":false}],
        "last_error":null,"storage":"saved-encrypted","writable":true});
    value
}
fn outcome(state: State) -> Status {
    Status {
        operation_id: OP.into(),
        safe_id: ID.into(),
        opening: NONCE.into(),
        source_opening: (state != State::Unknown).then(|| OLD.into()),
        state,
        receipt: (state == State::Published).then(|| Receipt {
            id: OP.into(),
            manifest_sha256: "1".repeat(64),
            entries: 1,
            bytes: 17,
        }),
        can_recover: false,
        can_discard: state == State::Incomplete,
    }
}
fn page(direction: Direction) -> TransfersPage {
    TransfersPage {
        safe_id: ID.into(),
        opening: NONCE.into(),
        direction,
        entries: vec![],
        next_cursor: None,
        skipped: 0,
    }
}

struct Files {
    controller: Runtime,
    page: Option<TransfersPage>,
    outcome: Option<std::result::Result<Status, &'static str>>,
    reached: Vec<Value>,
}
impl Files {
    fn new(steps: Vec<support::Step>) -> Self {
        Self {
            controller: Runtime::new(steps),
            page: None,
            outcome: None,
            reached: vec![],
        }
    }
}
impl Controller for Files {
    type Slot = u8;
    fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
        self.controller.request(call)
    }
}
impl Backend for Files {
    fn transfers(
        &mut self,
        opening: &Opening<u8>,
        query: &TransfersQuery,
        destination: Option<&str>,
    ) -> Result<TransfersPage> {
        self.reached.push(json!({"slot":opening.slot,"safe":opening.safe_id,"opening":opening.nonce,"query":query,"destination":destination}));
        Ok(self.page.take().expect("unexpected inventory"))
    }
    fn manage(
        &mut self,
        opening: &Opening<u8>,
        operation: &str,
        action: Action,
        destination: Option<&str>,
    ) -> Result<Status> {
        self.reached.push(json!({"slot":opening.slot,"safe":opening.safe_id,"opening":opening.nonce,"operation":operation,
            "action":action,"destination":destination}));
        self.outcome
            .take()
            .expect("unexpected operation")
            .map_err(Into::into)
    }
}

#[test]
fn grammar_owns_all_inspection_actions_and_leaves_only_copies_to_native_adapter() {
    for action in ["import", "export"] {
        assert!(files::parse(&args(&[action])).unwrap().is_none());
    }
    for values in [
        vec!["list", "--safe", "GB"],
        vec![
            "list",
            "workspace/project",
            "--safe",
            "GB",
            "--cursor",
            "note",
            "--json",
        ],
        vec![
            "transfers",
            "--safe",
            "GB",
            "--limit",
            "8",
            "--opening",
            NONCE,
        ],
        vec!["status", "--safe", "GB", "--operation", OP],
        vec!["recover", "--safe", "GB", "--operation", OP],
        vec![
            "discard",
            "--safe",
            "GB",
            "--operation",
            OP,
            "--destination",
            "/chosen",
        ],
    ] {
        assert!(files::parse(&args(&values)).unwrap().is_some());
    }
    for values in [
        vec![],
        vec!["unknown"],
        vec!["list"],
        vec!["list", "--safe", "GB", "--safe", "GB"],
        vec!["list", "--safe", "GB", "--path", "workspace/file"],
        vec!["list", "one", "two", "--safe", "GB"],
        vec!["list", "--safe", "GB", "--opening", NONCE],
        vec!["list", "--safe", "GB", "../escape"],
        vec!["transfers", "--safe", "GB", "--source", "/file"],
        vec!["transfers", "--safe", "GB", "--name", "copy"],
        vec!["transfers", "--safe", "GB", "--operation", OP],
        vec!["transfers", "--safe", "GB", "--cursor", "invalid"],
        vec!["status", "--safe", "GB"],
        vec!["recover", "--safe", "GB", "--operation", "invalid"],
        vec![
            "discard",
            "--safe",
            "GB",
            "--operation",
            OP,
            "--opening",
            "invalid",
        ],
    ] {
        assert!(files::parse(&args(&values)).is_err());
    }
    for action in ["list", "transfers", "status", "recover", "discard"] {
        for flag in ["--yes", "--events"] {
            assert_eq!(
                files::parse(&args(&[action, "--safe", "GB", flag]))
                    .err()
                    .unwrap()
                    .to_string(),
                "--events and --yes apply only to file import or export"
            );
        }
    }
    for limit in ["0", "9", "-1", "invalid"] {
        assert_eq!(
            files::parse(&args(&["transfers", "--safe", "GB", "--limit", limit]))
                .err()
                .unwrap()
                .to_string(),
            "Choose a page limit from 1 to 8"
        );
    }
}

#[test]
fn listing_fences_the_actual_safe_slot_and_preserves_the_manager_json_shape() {
    let mut backend=Files::new(vec![status(&active()),response(Operation::Browse,
        json!({"path":"workspace/project","entries":[{"name":"file.txt","directory":false,"bytes":17}],"next":null,"skipped":0}).to_string())]);
    let mut output = vec![];
    files::execute(
        &mut backend,
        command(&["list", "workspace/project", "--safe", "GB", "--json"]),
        &mut output,
        &mut vec![],
    )
    .unwrap();
    backend.controller.finished();
    assert!(backend.reached.is_empty());
    assert_eq!(backend.controller.sent[1].slot, Some(1));
    assert_eq!(backend.controller.sent[1].expected.as_deref(), Some(ID));
    assert_eq!(
        serde_json::from_slice::<Value>(&backend.controller.sent[1].body).unwrap(),
        json!({"path":"workspace/project","after":null,"limit":100})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"path":"workspace/project","entries":[{"name":"file.txt","path":"workspace/project/file.txt","kind":"file","bytes":17}],"next_cursor":null,"skipped":0})
    );
}

#[test]
fn untrusted_directory_replies_cannot_print_raw_parse_errors_or_wrong_directory_entries() {
    for (reply, expected) in [
        (
            r#"{"path":"workspace","entries":[{"name":"file","directory":"secret-canary","bytes":0}],"next":null,"skipped":0}"#,
            "invalid_directory_response",
        ),
        (
            r#"{"path":"imports","entries":[],"next":null,"skipped":0}"#,
            "invalid_directory_page",
        ),
    ] {
        let mut backend = Files::new(vec![status(&active()), response(Operation::Browse, reply)]);
        let mut output = vec![];
        let error = files::execute(
            &mut backend,
            command(&["list", "workspace", "--safe", "GB", "--json"]),
            &mut output,
            &mut vec![],
        )
        .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(!format!("{error:?}").contains("canary"));
        assert!(output.is_empty());
        backend.controller.finished();
    }
}

#[test]
fn inventory_is_only_a_bounded_listing_and_keeps_old_source_opening_and_native_names() {
    let mut backend = Files::new(vec![status(&active()), status(&current())]);
    let mut inventory = page(Direction::Import);
    inventory.entries.push(TransferEntry {
        operation_id: OP.into(),
        source_opening: OLD.into(),
        name: "cafe\u{301}".into(),
    });
    inventory.next_cursor = Some("f".repeat(32));
    inventory.skipped = 1;
    backend.page = Some(inventory);
    let mut output = vec![];
    let mut diagnostics = vec![];
    files::execute(
        &mut backend,
        command(&[
            "transfers",
            "--safe",
            "GB",
            "--cursor",
            "11111111111111111111111111111111",
            "--limit",
            "1",
            "--json",
        ]),
        &mut output,
        &mut diagnostics,
    )
    .unwrap();
    backend.controller.finished();
    assert_eq!(backend.reached.len(), 1);
    assert_eq!(backend.reached[0]["query"]["limit"], 1);
    assert_eq!(backend.reached[0]["query"]["direction"], "import");
    assert_eq!(backend.reached[0]["opening"], NONCE);
    assert_eq!(backend.reached[0]["slot"], 1);
    let result: TransfersPage = serde_json::from_slice(&output).unwrap();
    assert_eq!(result.entries[0].name.as_bytes(), "cafe\u{301}".as_bytes());
    assert_eq!(result.entries[0].source_opening, OLD);
    assert_eq!(
        result.next_cursor.as_deref(),
        Some("ffffffffffffffffffffffffffffffff")
    );
    assert_eq!(result.skipped, 1);
    assert!(diagnostics.is_empty());
}

#[test]
fn text_inventory_explains_pagination_without_authorizing_recovery() {
    let mut backend = Files::new(vec![status(&active()), status(&current())]);
    let mut inventory = page(Direction::Import);
    inventory.next_cursor = Some(OP.into());
    inventory.skipped = 1;
    backend.page = Some(inventory);
    let mut output = vec![];
    let mut diagnostics = vec![];
    files::execute(
        &mut backend,
        command(&["transfers", "--safe", "GB"]),
        &mut output,
        &mut diagnostics,
    )
    .unwrap();
    backend.controller.finished();
    assert_eq!(backend.reached.len(), 1);
    assert!(output.is_empty());
    let diagnostics = String::from_utf8(diagnostics).unwrap();
    assert!(
        diagnostics.contains("More recorded operations")
            && diagnostics.contains("Listing does not authorize recovery or discard")
    );
}

#[test]
fn local_destination_is_opaque_to_core_and_never_enters_controller_requests() {
    let mut backend = Files::new(vec![status(&active()), status(&current())]);
    backend.page = Some(page(Direction::Export));
    let destination = r"C:\Users\Owner\Export";
    let mut output = vec![];
    files::execute(
        &mut backend,
        command(&[
            "transfers",
            "--safe",
            "GB",
            "--destination",
            destination,
            "--json",
        ]),
        &mut output,
        &mut vec![],
    )
    .unwrap();
    backend.controller.finished();
    assert_eq!(backend.reached[0]["destination"], destination);
    assert_eq!(backend.reached[0]["query"]["direction"], "export");
    assert!(backend
        .controller
        .sent
        .iter()
        .all(|call| call.body.is_empty()));
    assert_eq!(backend.controller.sent[1].slot, Some(1));
    assert_eq!(backend.controller.sent[1].expected.as_deref(), Some(ID));
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap()["direction"],
        "export"
    );
}

#[test]
fn status_recovery_and_discard_print_only_validated_receiver_outcomes() {
    for (action, state) in [
        ("status", State::Unknown),
        ("recover", State::Published),
        ("discard", State::Discarded),
    ] {
        let mut backend = Files::new(vec![status(&active()), status(&current())]);
        backend.outcome = Some(Ok(outcome(state)));
        let mut output = vec![];
        files::execute(
            &mut backend,
            command(&[
                action,
                "--safe",
                "GB",
                "--operation",
                OP,
                "--opening",
                NONCE,
            ]),
            &mut output,
            &mut vec![],
        )
        .unwrap();
        backend.controller.finished();
        assert_eq!(backend.reached.len(), 1);
        assert_eq!(backend.reached[0]["action"], action);
        assert_eq!(backend.reached[0]["operation"], OP);
        let result: Status = serde_json::from_slice(&output).unwrap();
        assert_eq!(result.state, state);
    }
}

#[test]
fn fresh_opening_host_and_safe_fences_reject_before_adapter_recovery() {
    for changed in [
        "nonce",
        "host-closing",
        "safe-closing",
        "safe-id",
        "slot",
        "invalid-nonce",
    ] {
        let mut value = current();
        match changed {
            "nonce" => value["idle_lock"]["safes"][0]["opening"]["nonce"] = json!(OLD),
            "host-closing" => value["idle_lock"]["host"]["closing"] = json!(true),
            "safe-closing" => value["idle_lock"]["safes"][0]["closing"] = json!(true),
            "safe-id" => value["idle_lock"]["safes"][0]["opening"]["safe_id"] = json!(OLD),
            "slot" => value["idle_lock"]["safes"][0]["opening"]["slot"] = json!(0),
            _ => value["idle_lock"]["safes"][0]["opening"]["nonce"] = json!("secret-canary"),
        }
        let mut backend = Files::new(vec![status(&active()), status(&value)]);
        let mut output = vec![];
        let error = files::execute(
            &mut backend,
            command(&[
                "recover",
                "--safe",
                "GB",
                "--operation",
                OP,
                "--opening",
                NONCE,
            ]),
            &mut output,
            &mut vec![],
        )
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(backend.reached.is_empty() && output.is_empty());
        backend.controller.finished();
    }
}

#[test]
fn interruptions_and_unconfirmed_or_wrong_receipts_never_become_success_output() {
    for case in [
        "interrupted",
        "missing-receipt",
        "wrong-safe",
        "wrong-opening",
    ] {
        let mut backend = Files::new(vec![status(&active()), status(&current())]);
        let mut result = outcome(State::Published);
        match case {
            "missing-receipt" => result.receipt = None,
            "wrong-safe" => result.safe_id = OLD.into(),
            "wrong-opening" => result.opening = OLD.into(),
            _ => {}
        }
        backend.outcome = Some(if case == "interrupted" {
            Err("transfer_disconnected")
        } else {
            Ok(result)
        });
        let mut output = vec![];
        assert!(files::execute(
            &mut backend,
            command(&["recover", "--safe", "GB", "--operation", OP]),
            &mut output,
            &mut vec![]
        )
        .is_err());
        assert!(output.is_empty());
        assert_eq!(backend.reached.len(), 1);
        backend.controller.finished();
    }
}
