mod support;
use oblivion_cli::storage::{self, Command};
use oblivion_wire::control::Operation;
use serde_json::json;
use support::{Runtime, active, rejected, response, state, status};

fn command(values: &[&str]) -> Command {
    Command::parse(
        &values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .unwrap()
}
fn absent() -> serde_json::Value {
    let mut value = state("locked");
    value["general_present"] = json!(false);
    value
}
fn unfinished() -> serde_json::Value {
    let mut value = absent();
    value["general_incomplete"] = json!(true);
    value
}
fn global(runtime: &Runtime) {
    assert!(
        runtime
            .sent
            .iter()
            .all(|sent| sent.slot.is_none() && sent.session.is_none() && sent.expected.is_none())
    );
}

#[test]
fn lifecycle_grammar_is_complete_and_rejects_invalid_flags_before_runtime() {
    assert_eq!(
        command(&["init"]),
        Command::Init {
            reset_incomplete: false,
            confirmed_reset: false
        }
    );
    assert_eq!(
        command(&["init", "--reset-incomplete"]),
        Command::Init {
            reset_incomplete: true,
            confirmed_reset: false
        }
    );
    assert_eq!(
        command(&["init", "--confirmed-reset", "--reset-incomplete"]),
        Command::Init {
            reset_incomplete: true,
            confirmed_reset: true
        }
    );
    assert_eq!(command(&["unlock"]), Command::Unlock { read_only: false });
    assert_eq!(
        command(&["unlock", "--read-only"]),
        Command::Unlock { read_only: true }
    );
    assert_eq!(command(&["ephemeral"]), Command::Ephemeral);
    assert_eq!(command(&["lock"]), Command::Lock);
    for values in [
        vec!["init", "--confirmed-reset"],
        vec!["init", "--reset-incomplete", "--reset-incomplete"],
        vec![
            "init",
            "--reset-incomplete",
            "--confirmed-reset",
            "--confirmed-reset",
        ],
        vec!["init", "extra"],
        vec!["unlock", "--read-only", "extra"],
        vec!["unlock", "--password", "secret"],
        vec!["ephemeral", "--yes"],
        vec!["lock", "extra"],
    ] {
        assert!(
            Command::parse(
                &values
                    .iter()
                    .map(|value| (*value).into())
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    for values in [vec![], vec!["run", "codex"], vec!["status", "--json"]] {
        assert!(
            Command::parse(
                &values
                    .iter()
                    .map(|value| (*value).into())
                    .collect::<Vec<_>>()
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn a_direct_invalid_init_command_cannot_bypass_its_reset_requirement() {
    let mut runtime = Runtime::new(Vec::new());
    assert_eq!(
        storage::execute(
            &mut runtime,
            Command::Init {
                reset_incomplete: false,
                confirmed_reset: true
            }
        )
        .unwrap_err()
        .to_string(),
        "--confirmed-reset requires --reset-incomplete"
    );
    runtime.finished();
    assert!(runtime.sent.is_empty() && runtime.events.is_empty());
}

#[test]
fn initialization_creates_once_with_reviewed_capacity_and_stays_locked() {
    let mut runtime = Runtime::new(vec![
        status(&absent()),
        response(Operation::InitGeneral, ""),
    ]);
    assert_eq!(
        storage::execute(&mut runtime, command(&["init"])).unwrap(),
        0
    );
    runtime.finished();
    global(&runtime);
    assert_eq!(
        runtime.events,
        [
            "capacity:8589934592",
            "new-password:Oblivion password",
            "storage-created"
        ]
    );
    assert_eq!(&*runtime.sent[1].body, b"synthetic new password");
    assert!(runtime.attached.is_none());
}

#[test]
fn interrupted_review_or_secret_entry_never_initializes_storage() {
    for reject_notice in [false, true] {
        let mut runtime = Runtime::new(vec![status(&absent())]);
        if reject_notice {
            runtime.reject_notice = Some("capacity:8589934592");
        } else {
            runtime.prompt_error = Some("password_cancelled");
        }
        assert_eq!(
            storage::execute(&mut runtime, command(&["init"]))
                .unwrap_err()
                .to_string(),
            if reject_notice {
                "notice_unavailable"
            } else {
                "password_cancelled"
            }
        );
        runtime.finished();
        global(&runtime);
        assert_eq!(runtime.sent.len(), 1);
        assert!(!runtime.events.contains(&"storage-created".into()));
    }
}

#[test]
fn a_failed_create_or_notice_never_reports_success_or_discards_published_storage() {
    for fail_notice in [false, true] {
        let step = if fail_notice {
            response(Operation::InitGeneral, "")
        } else {
            rejected(Operation::InitGeneral, "storage_unavailable")
        };
        let mut runtime = Runtime::new(vec![status(&absent()), step]);
        if fail_notice {
            runtime.reject_notice = Some("storage-created");
        }
        assert_eq!(
            storage::execute(&mut runtime, command(&["init"]))
                .unwrap_err()
                .to_string(),
            if fail_notice {
                "notice_unavailable"
            } else {
                "storage_unavailable"
            }
        );
        runtime.finished();
        global(&runtime);
        assert_eq!(runtime.sent.len(), 2);
    }
}

#[test]
fn reset_is_explicit_and_ends_after_discard_without_recreation_or_unlock() {
    let mut cancelled = Runtime::new(vec![status(&unfinished())]);
    assert_eq!(
        storage::execute(&mut cancelled, command(&["init", "--reset-incomplete"]))
            .unwrap_err()
            .to_string(),
        "Storage reset cancelled. Nothing was changed."
    );
    cancelled.finished();
    assert_eq!(cancelled.events, ["storage-review", "confirm:RESET"]);
    for confirmed_flag in [false, true] {
        let mut runtime = Runtime::new(vec![
            status(&unfinished()),
            response(Operation::DiscardGeneralPending, ""),
        ]);
        runtime.confirmation = true;
        let args = if confirmed_flag {
            vec!["init", "--reset-incomplete", "--confirmed-reset"]
        } else {
            vec!["init", "--reset-incomplete"]
        };
        storage::execute(&mut runtime, command(&args)).unwrap();
        runtime.finished();
        global(&runtime);
        assert_eq!(
            runtime.events,
            if confirmed_flag {
                vec!["storage-review", "storage-discarded"]
            } else {
                vec!["storage-review", "confirm:RESET", "storage-discarded"]
            }
        );
        assert!(runtime.sent[1].body.is_empty());
    }
}

#[test]
fn storage_admission_preserves_published_or_incomplete_archives_without_mutation() {
    let cases = [
        (
            active(),
            vec!["init"],
            "Lock Oblivion before creating or resetting encrypted storage.",
        ),
        (
            state("locked"),
            vec!["init"],
            "Encrypted storage already exists. Run oblivion unlock.",
        ),
        (
            unfinished(),
            vec!["init"],
            "An incomplete storage setup exists. Review it with oblivion init --reset-incomplete.",
        ),
        (
            absent(),
            vec!["init", "--reset-incomplete"],
            "There is no incomplete storage setup to reset.",
        ),
        (
            state("locked"),
            vec!["init", "--reset-incomplete", "--confirmed-reset"],
            "Encrypted storage already exists. Run oblivion unlock.",
        ),
    ];
    for (value, args, message) in cases {
        let mut runtime = Runtime::new(vec![status(&value)]);
        assert_eq!(
            storage::execute(&mut runtime, command(&args))
                .unwrap_err()
                .to_string(),
            message
        );
        runtime.finished();
        global(&runtime);
        assert!(runtime.events.is_empty());
    }
}

#[test]
fn unlock_is_idempotent_only_in_the_requested_mode_and_never_creates_storage() {
    for (mode, readonly) in [("persistent", false), ("read-only", true)] {
        let mut runtime = Runtime::new(vec![status(&state(mode))]);
        storage::execute(
            &mut runtime,
            Command::Unlock {
                read_only: readonly,
            },
        )
        .unwrap();
        runtime.finished();
        assert!(runtime.events.is_empty());
    }
    for (mode, readonly) in [
        ("persistent", true),
        ("read-only", false),
        ("ram-only", false),
        ("ram-only", true),
    ] {
        let mut runtime = Runtime::new(vec![status(&state(mode))]);
        assert_eq!(
            storage::execute(
                &mut runtime,
                Command::Unlock {
                    read_only: readonly
                }
            )
            .unwrap_err()
            .to_string(),
            "Lock Oblivion before changing its storage mode"
        );
        runtime.finished();
        assert!(runtime.events.is_empty());
    }
    let mut missing = Runtime::new(vec![status(&absent())]);
    assert_eq!(
        storage::execute(&mut missing, command(&["unlock"]))
            .unwrap_err()
            .to_string(),
        "Encrypted storage is missing. Run oblivion init."
    );
    missing.finished();
    assert!(missing.events.is_empty());
    for (readonly, operation) in [
        (false, Operation::Unlock),
        (true, Operation::UnlockReadOnly),
    ] {
        let mut runtime = Runtime::new(vec![status(&state("locked")), response(operation, "")]);
        storage::execute(
            &mut runtime,
            Command::Unlock {
                read_only: readonly,
            },
        )
        .unwrap();
        runtime.finished();
        global(&runtime);
        assert_eq!(runtime.events, ["password:Oblivion password"]);
        assert_eq!(&*runtime.sent[1].body, b"synthetic unlock password");
    }
}

#[test]
fn ephemeral_refuses_live_mode_changes_and_global_lock_needs_no_unlock() {
    let mut already = Runtime::new(vec![status(&state("ram-only"))]);
    storage::execute(&mut already, command(&["ephemeral"])).unwrap();
    already.finished();
    assert!(already.events.is_empty());
    for mode in ["persistent", "read-only"] {
        let mut runtime = Runtime::new(vec![status(&state(mode))]);
        assert_eq!(
            storage::execute(&mut runtime, command(&["ephemeral"]))
                .unwrap_err()
                .to_string(),
            "Lock Oblivion, then enter Ephemeral mode. Active work must close before changing storage modes."
        );
        runtime.finished();
        assert!(runtime.events.is_empty());
    }
    let mut runtime = Runtime::new(vec![
        status(&state("locked")),
        response(Operation::EnterRam, ""),
    ]);
    storage::execute(&mut runtime, command(&["ephemeral"])).unwrap();
    runtime.finished();
    global(&runtime);
    assert!(runtime.events.is_empty());
    assert!(runtime.sent[1].body.is_empty());
    let mut runtime = Runtime::new(vec![response(Operation::Lock, "")]);
    storage::execute(&mut runtime, command(&["lock"])).unwrap();
    runtime.finished();
    global(&runtime);
    assert!(runtime.events.is_empty());
    assert!(runtime.sent[0].body.is_empty());
}
