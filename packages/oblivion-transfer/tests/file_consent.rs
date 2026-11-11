use oblivion_transfer::Receipt;
use oblivion_transfer::file_consent::{Admission, Flow, Review, Stage};
use oblivion_transfer::native_file_events::{Event, Identity, Input, Outcome, Phase, Summary};
use oblivion_transfer::native_files::Direction;
use oblivion_transfer::selection::{self, Plan};
use std::time::{Duration, Instant};

fn fixture() -> (Flow, Admission, Plan, Summary) {
    let identity = Identity {
        operation_id: "a".repeat(32),
        safe_id: "b".repeat(32),
        opening: "c".repeat(32),
    };
    let (flow, admission) = Flow::new(identity, Direction::Import, "note".into()).unwrap();
    let plan = Plan::new(&[selection::Input {
        path: "/private/note".into(),
        directory: false,
    }])
    .unwrap();
    let summary = Summary {
        manifest_sha256: "d".repeat(64),
        mapping_sha256: plan.sha256().unwrap(),
        entries: 1,
        files: 1,
        directories: 0,
        bytes: 8,
    };
    (flow, admission, plan, summary)
}
fn input(value: Input) -> Vec<u8> {
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    line
}
fn approve() -> Vec<u8> {
    input(Input::Approve {
        operation_id: "a".repeat(32),
        manifest_sha256: "d".repeat(64),
    })
}
fn cancel() -> Vec<u8> {
    input(Input::Cancel {
        operation_id: "a".repeat(32),
    })
}
fn receipt() -> Receipt {
    Receipt {
        id: "a".repeat(32),
        manifest_sha256: "d".repeat(64),
        entries: 1,
        bytes: 8,
    }
}
fn reviewed() -> (Flow, Admission) {
    let (mut flow, mut admission, plan, summary) = fixture();
    let mapping = flow.plan(&admission, &plan).unwrap();
    assert_eq!(mapping.events().len(), 1);
    flow.mapped(&admission, mapping).unwrap();
    assert!(matches!(
        flow.review(&mut admission, &summary, false).unwrap(),
        Review::Ready(Event::Review { .. })
    ));
    (flow, admission)
}

#[test]
fn prebuffered_and_partial_approval_cannot_cross_the_review_boundary() {
    let (mut flow, mut admission, plan, summary) = fixture();
    let mapping = flow.plan(&admission, &plan).unwrap();
    flow.mapped(&admission, mapping).unwrap();
    assert!(matches!(
        flow.review(&mut admission, &summary, true).unwrap(),
        Review::Waiting
    ));
    assert_eq!(admission.stage(), &Stage::Preparing);
    let line = approve();
    assert!(!admission.feed(&line[..line.len() - 1]).unwrap());
    assert_eq!(admission.pending(), line.len() - 1);
    assert!(matches!(
        flow.review(&mut admission, &summary, false).unwrap(),
        Review::Waiting
    ));
    assert!(admission.feed(b"\n").is_err());
    assert_eq!(admission.stage(), &Stage::Failed);
}

#[test]
fn approval_requires_exact_scope_digest_and_is_single_use() {
    let (mut flow, mut admission) = reviewed();
    let wrong = input(Input::Approve {
        operation_id: "a".repeat(32),
        manifest_sha256: "e".repeat(64),
    });
    assert!(admission.feed(&wrong).is_err());
    assert!(
        flow.finish(&admission, Outcome::Completed, Some(receipt()))
            .is_err()
    );
    let (_, mut admission) = reviewed();
    let wrong = input(Input::Approve {
        operation_id: "e".repeat(32),
        manifest_sha256: "d".repeat(64),
    });
    assert!(admission.feed(&wrong).is_err());
    let (mut flow, mut admission) = reviewed();
    assert!(!admission.feed(&approve()).unwrap());
    assert_eq!(admission.stage(), &Stage::Approved);
    assert!(admission.feed(&approve()).is_err());
    assert!(
        flow.progress(&admission, Phase::Copying, 0, Instant::now())
            .is_err()
    );
    let (mut flow, mut other, plan, _) = fixture();
    let mapping = flow.plan(&other, &plan).unwrap();
    let (_, mut unrelated) = Flow::new(
        Identity {
            operation_id: "a".repeat(32),
            safe_id: "b".repeat(32),
            opening: "f".repeat(32),
        },
        Direction::Import,
        "note".into(),
    )
    .unwrap();
    assert!(flow.mapped(&unrelated, mapping).is_err());
    assert!(flow.review(&mut unrelated, &fixture().3, false).is_err());
    assert!(other.eof().is_err());
}

#[test]
fn incomplete_mapping_delivery_never_arms_approval_and_a_changed_map_is_refused() {
    let (mut flow, mut admission, plan, summary) = fixture();
    let mapping = flow.plan(&admission, &plan).unwrap();
    assert!(flow.review(&mut admission, &summary, false).is_err());
    flow.mapped(&admission, mapping).unwrap();
    let mut changed = summary.clone();
    changed.mapping_sha256 = "e".repeat(64);
    assert!(flow.review(&mut admission, &changed, false).is_err());
    assert!(matches!(
        flow.review(&mut admission, &summary, false).unwrap(),
        Review::Ready(_)
    ));
}

#[test]
fn only_explicit_preapproval_cancel_proves_no_copy_while_eof_always_revokes() {
    let (mut flow, mut admission, _, summary) = fixture();
    assert!(admission.feed(&cancel()).unwrap());
    assert_eq!(admission.stage(), &Stage::CancelledBeforeCopy);
    assert!(matches!(
        flow.review(&mut admission, &summary, true).unwrap(),
        Review::CancelledBeforeCopy
    ));
    assert!(matches!(
        flow.finish(&admission, Outcome::CancelledBeforeCopy, None)
            .unwrap(),
        Event::Finished {
            outcome: Outcome::CancelledBeforeCopy,
            ..
        }
    ));
    let (mut flow, mut admission) = reviewed();
    admission.feed(&approve()).unwrap();
    assert!(admission.feed(&cancel()).unwrap());
    assert_eq!(admission.stage(), &Stage::Cancelled);
    assert!(
        flow.finish(&admission, Outcome::CancelledBeforeCopy, None)
            .is_err()
    );
    assert!(matches!(
        flow.finish(&admission, Outcome::Interrupted, None).unwrap(),
        Event::Finished {
            outcome: Outcome::Interrupted,
            ..
        }
    ));
    for approved in [false, true] {
        let (mut flow, mut admission) = reviewed();
        if approved {
            admission.feed(&approve()).unwrap();
        }
        assert!(admission.eof().is_err());
        assert_eq!(admission.stage(), &Stage::Failed);
        assert!(
            flow.finish(&admission, Outcome::Completed, Some(receipt()))
                .is_err()
        );
    }
}

#[test]
fn suppressed_progress_is_monotonic_finalization_is_exact_and_receipt_controls_completion() {
    let (mut flow, mut admission) = reviewed();
    let now = Instant::now();
    assert!(flow.progress(&admission, Phase::Copying, 0, now).is_err());
    admission.feed(&approve()).unwrap();
    assert!(
        flow.progress(&admission, Phase::Copying, 0, now)
            .unwrap()
            .is_some()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Copying,
            2,
            now + Duration::from_millis(1)
        )
        .unwrap()
        .is_none()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Copying,
            1,
            now + Duration::from_millis(2)
        )
        .is_err()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Finalizing,
            2,
            now + Duration::from_millis(3)
        )
        .is_err()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Copying,
            8,
            now + Duration::from_millis(4)
        )
        .unwrap()
        .is_some()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Finalizing,
            8,
            now + Duration::from_millis(5)
        )
        .unwrap()
        .is_some()
    );
    assert!(
        flow.progress(
            &admission,
            Phase::Copying,
            8,
            now + Duration::from_millis(6)
        )
        .is_err()
    );
    let mut wrong = receipt();
    wrong.bytes = 7;
    assert!(
        flow.finish(&admission, Outcome::Completed, Some(wrong))
            .is_err()
    );
    assert!(matches!(
        flow.finish(&admission, Outcome::Completed, Some(receipt()))
            .unwrap(),
        Event::Finished {
            outcome: Outcome::Completed,
            ..
        }
    ));
    assert!(flow.finish(&admission, Outcome::Interrupted, None).is_err());
}

#[test]
fn incremental_input_is_bounded_and_malformed_batches_revoke_approval() {
    let (_, mut admission) = reviewed();
    assert!(admission.feed(&[0xff, b'\n']).is_err());
    let (_, mut admission) = reviewed();
    assert!(admission.feed(&vec![b'x'; 4097]).is_err());
    assert_eq!(admission.pending(), 4096);
    let (_, mut admission) = reviewed();
    let mut duplicate = approve();
    duplicate.extend(approve());
    assert!(admission.feed(&duplicate).is_err());
    assert_eq!(admission.stage(), &Stage::Failed);
}
