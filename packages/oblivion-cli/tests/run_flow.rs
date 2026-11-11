mod support;
use oblivion_cli::run;
use oblivion_wire::control::Operation;
use serde_json::json;
use std::time::Duration;
use support::{CREATED, ID, Runtime, active, options, rejected, response, state, status};

#[test]
fn first_new_launch_guides_setup_unlock_and_creation_and_keeps_native_arguments() {
    let mut missing = state("locked");
    missing["general_present"] = json!(false);
    let locked = state("locked");
    let opened = state("persistent");
    let mut runtime = Runtime::new(vec![
        status(&missing),
        status(&missing),
        response(Operation::InitGeneral, ""),
        status(&locked),
        response(Operation::Unlock, ""),
        status(&opened),
        response(Operation::CreatePrepareAgent, format!("{CREATED}\n")),
        response(Operation::RenameSession, ""),
        response(Operation::StartAgent, ""),
    ]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&[
                "codex",
                "--resume",
                "native-id",
                "--safe",
                "opaque",
                "",
                "$(not a shell)",
                "città"
            ]),
            run::Context::default()
        )
        .unwrap(),
        7
    );
    runtime.finished();
    assert_eq!(
        runtime.events,
        [
            "capacity:8589934592",
            "new-password:Oblivion password",
            "storage-created",
            "password:Oblivion password",
            "new-password:New Safe password",
            &format!("opened:{CREATED}")
        ]
    );
    let renamed = runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::RenameSession)
        .unwrap();
    let rename: oblivion_wire::session_title::Rename =
        serde_json::from_slice(&renamed.body).unwrap();
    assert_eq!(rename.id, CREATED);
    assert_eq!(rename.title, "Safe cccccccc");
    assert_eq!(renamed.slot, Some(0));
    assert_eq!(renamed.expected.as_deref(), Some(CREATED));
    let prepared = runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::CreatePrepareAgent)
        .unwrap();
    assert_eq!(prepared.body.as_slice(), b"synthetic new password");
    assert_eq!(prepared.slot, Some(0));
    assert!(prepared.session.is_none());
    assert!(prepared.expected.is_none());
    let attached = runtime.attached.unwrap();
    assert_eq!(
        (attached.0, attached.1.as_str(), attached.2.as_str()),
        (0, CREATED, "codex")
    );
    assert_eq!(
        attached.3,
        [
            "--resume",
            "native-id",
            "--safe",
            "opaque",
            "",
            "$(not a shell)",
            "città"
        ]
    );
}

#[test]
fn read_only_unnamed_launch_creates_ram_safe_and_applies_temporary_network() {
    let readonly = state("read-only");
    let mut runtime = Runtime::new(vec![
        status(&readonly),
        status(&readonly),
        response(Operation::PrepareAgentEphemeral, format!("{CREATED}\n")),
        response(Operation::Egress, ""),
        response(Operation::SafeAccess, ""),
        response(Operation::StartAgent, ""),
    ]);
    run::execute(
        &mut runtime,
        options(&["--tor", "--policy", "strict", "claude"]),
        run::Context::default(),
    )
    .unwrap();
    runtime.finished();
    assert!(runtime.events.is_empty());
    for sent in runtime.sent.iter().filter(|sent| {
        matches!(
            sent.operation,
            Operation::Egress | Operation::SafeAccess | Operation::StartAgent
        )
    }) {
        assert_eq!(sent.slot, Some(0));
        assert_eq!(sent.expected.as_deref(), Some(CREATED));
    }
    let egress = &runtime
        .sent
        .iter()
        .find(|sent| sent.operation == Operation::Egress)
        .unwrap()
        .body;
    assert!(matches!(
        serde_json::from_slice::<oblivion_transport::egress::Command>(egress).unwrap(),
        oblivion_transport::egress::Command::Select { .. }
    ));
    let policy: oblivion_transport::policy::Command = serde_json::from_slice(
        &runtime
            .sent
            .iter()
            .find(|sent| sent.operation == Operation::SafeAccess)
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(!policy.save);
    assert_eq!(policy.mode, oblivion_transport::policy::Access::Strict);
}

#[test]
fn new_launch_retries_an_occupied_slot_and_cleans_only_its_own_preparation() {
    let initial = state("persistent");
    let mut current = initial.clone();
    current["sessions"] = json!([ID]);
    current["open_sessions"] = json!([{"slot":0,"id":ID,"mode":"starting","recovery_required":false}]);
    let mut runtime = Runtime::new(vec![
        status(&initial),
        status(&initial),
        rejected(Operation::CreatePrepareAgent, "vm_already_running"),
        status(&current),
        response(Operation::CreatePrepareAgent, CREATED),
        response(Operation::RenameSession, ""),
        rejected(Operation::SafeAccess, "policy_failed"),
        response(Operation::CloseIdle, ""),
    ]);
    let error = run::execute(
        &mut runtime,
        options(&["--policy", "offline", "codex"]),
        run::Context::default(),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "policy_failed");
    runtime.finished();
    assert!(runtime.attached.is_none());
    assert_eq!(runtime.sent[2].slot, Some(0));
    assert_eq!(runtime.sent[4].slot, Some(1));
    assert!(runtime.sent[2].session.is_none());
    assert!(runtime.sent[4].session.is_none());
    assert_eq!(runtime.sent[2].body.as_slice(), runtime.sent[4].body.as_slice());
    assert_eq!(runtime.sent[7].slot, Some(1));
    assert_eq!(runtime.sent[7].expected.as_deref(), Some(CREATED));
}

#[test]
fn an_existing_safe_request_never_initializes_missing_encrypted_storage() {
    let mut missing = state("locked");
    missing["general_present"] = json!(false);
    let mut runtime = Runtime::new(vec![status(&missing), status(&missing)]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "Encrypted storage is missing. Run oblivion init."
    );
    runtime.finished();
    assert!(runtime.events.is_empty() && runtime.attached.is_none());
}

#[test]
fn run_prepares_a_closed_root_safe_and_keeps_its_identity_when_retrying_a_slot() {
    let mut closed = active();
    closed["open_sessions"] = json!([]);
    let mut occupied = closed.clone();
    occupied["sessions"] = json!([ID, CREATED]);
    occupied["open_sessions"] = json!([{"slot":0,"id":CREATED,"mode":"starting","recovery_required":false}]);
    let mut runtime = Runtime::new(vec![
        status(&closed),
        status(&closed),
        rejected(Operation::PrepareAgent, "vm_already_running"),
        status(&occupied),
        response(Operation::PrepareAgent, ""),
        response(Operation::SafeAccess, ""),
        response(Operation::StartAgent, ""),
    ]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "--policy", "offline", "codex", "resume", "--last"]),
            run::Context::default(),
        )
        .unwrap(),
        7
    );
    runtime.finished();
    assert_eq!(runtime.events, ["password:Safe password"]);
    assert_eq!(runtime.sent[2].slot, Some(0));
    assert_eq!(runtime.sent[4].slot, Some(1));
    assert_eq!(runtime.sent[2].session.as_deref(), Some(ID));
    assert_eq!(runtime.sent[4].session.as_deref(), Some(ID));
    assert_eq!(runtime.sent[2].body.as_slice(), runtime.sent[4].body.as_slice());
    assert_eq!(runtime.sent[5].expected.as_deref(), Some(ID));
    assert_eq!(runtime.sent[6].expected.as_deref(), Some(ID));
    let attached = runtime.attached.unwrap();
    assert_eq!((attached.0, attached.1.as_str(), attached.2.as_str()), (1, ID, "codex"));
    assert_eq!(attached.3, ["resume", "--last"]);
}

#[test]
fn run_keeps_documents_opening_for_child_safes() {
    for (mode, ephemeral, operation) in [
        ("persistent", false, Operation::OpenDocuments),
        ("ram-only", true, Operation::OpenChildDocuments),
    ] {
        let mut child = state(mode);
        child["sessions"] = json!([ID]);
        child["agent_safes"] = json!([{"id":ID,"ephemeral":ephemeral,"state":"awaiting-start"}]);
        let mut runtime = Runtime::new(vec![
            status(&child),
            status(&child),
            response(operation, ""),
            response(Operation::StartAgent, ""),
        ]);
        run::execute(
            &mut runtime,
            options(&["--safe", ID, "codex"]),
            run::Context::default(),
        )
        .unwrap();
        runtime.finished();
        assert_eq!(runtime.sent[2].session.as_deref(), Some(ID));
        assert_eq!(runtime.sent[2].expected.as_deref(), ephemeral.then_some(ID));
    }
}

#[test]
fn storage_mode_guards_and_active_network_override_refuse_before_mutation() {
    let mut starting = active();
    starting["open_sessions"][0]["mode"] = json!("starting");
    for (value, args, message) in [
        (
            state("persistent"),
            vec!["--ephemeral", "codex"],
            "Lock Oblivion, then enter Ephemeral mode before creating a RAM-only Safe.",
        ),
        (
            state("read-only"),
            vec!["--name", "New", "codex"],
            "Named persistent Safes require persistent mode. Lock and unlock encrypted storage first.",
        ),
        (
            active(),
            vec!["--safe", "GB", "--tor", "codex"],
            "Safe is active. Change its network through the trusted network controls.",
        ),
        (
            starting,
            vec!["--safe", "GB", "codex"],
            "Safe is still starting. Wait for it to finish, or close it and retry.",
        ),
    ] {
        let mut runtime = Runtime::new(vec![status(&value), status(&value)]);
        assert_eq!(
            run::execute(&mut runtime, options(&args), run::Context::default())
                .unwrap_err()
                .to_string(),
            message
        );
        runtime.finished();
        assert!(runtime.events.is_empty() && runtime.attached.is_none());
    }
}

#[test]
fn protected_start_uses_the_monotonic_retry_window_without_waiting_in_the_test() {
    let active = active();
    let mut runtime = Runtime::new(vec![
        status(&active),
        status(&active),
        rejected(Operation::StartAgent, "gateway_not_ready"),
        rejected(Operation::StartAgent, "gateway_not_ready"),
    ]);
    runtime.advance = Some(Duration::from_secs(240));
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "gateway_not_ready"
    );
    runtime.finished();
    assert_eq!(runtime.events, ["waiting", "wait:500"]);
    assert!(runtime.attached.is_none());
    assert!(
        runtime
            .sent
            .iter()
            .filter(|sent| sent.operation == Operation::StartAgent)
            .all(|sent| sent.slot == Some(1) && sent.expected.as_deref() == Some(ID))
    );
    let mut runtime = Runtime::new(vec![
        status(&active),
        status(&active),
        rejected(Operation::StartAgent, "transport_failed"),
    ]);
    assert_eq!(
        run::execute(
            &mut runtime,
            options(&["--safe", "GB", "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string(),
        "transport_failed"
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
}

#[test]
fn protected_start_retries_short_contention_on_the_same_safe() {
    let mut runtime = Runtime::new(vec![
        rejected(Operation::StartAgent, "gateway_not_ready"),
        rejected(Operation::StartAgent, "controller_busy"),
        response(Operation::StartAgent, ""),
    ]);
    run::start_agent(&mut runtime, 1, ID).unwrap();
    runtime.finished();
    assert_eq!(runtime.events, ["waiting", "wait:500", "wait:500"]);
    assert!(runtime.sent.iter().all(|sent| sent.slot == Some(1) && sent.expected.as_deref() == Some(ID)));

    let mut runtime = Runtime::new(vec![
        rejected(Operation::StartAgent, "controller_busy"),
        rejected(Operation::StartAgent, "controller_busy"),
    ]);
    runtime.advance = Some(Duration::from_secs(3));
    assert_eq!(run::start_agent(&mut runtime, 1, ID).unwrap_err().to_string(), "controller_busy");
    runtime.finished();
    assert_eq!(runtime.events, ["wait:500"]);
}

#[test]
fn occupied_slots_and_failed_ram_children_never_create_an_unrelated_safe() {
    let mut full = state("ram-only");
    full["open_sessions"] =
        json!([{"slot":0,"id":null,"mode":"starting","recovery_required":false},{"slot":1,"id":null,"mode":"recovery","recovery_required":false}]);
    let mut runtime = Runtime::new(vec![status(&full), status(&full)]);
    assert_eq!(
        run::execute(&mut runtime, options(&["codex"]), run::Context::default())
            .unwrap_err()
            .to_string(),
        "No Safe slots available"
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
    let mut failed = state("ram-only");
    failed["agent_safes"] = json!([{"id":ID,"ephemeral":true,"state":"failed"}]);
    let mut runtime = Runtime::new(vec![status(&failed), status(&failed)]);
    assert!(
        run::execute(
            &mut runtime,
            options(&["--safe", ID, "codex"]),
            run::Context::default()
        )
        .unwrap_err()
        .to_string()
        .contains("not created successfully")
    );
    runtime.finished();
    assert!(runtime.events.is_empty());
}
