use oblivion_cli::share::review::{Review, SourceMetadata, show_review, validate_review};
use oblivion_share::Manifest;
use oblivion_transfer::Entry;
use serde_json::{Value, json};

#[cfg(unix)]
#[test]
fn review_accepts_the_real_guest_plan_and_keeps_secret_candidates_out() {
    let root = std::env::temp_dir().join(format!(
        "oblivion-share-review-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let output = std::process::Command::new("python3").args(["-I", "-B", "-c", r#"
import json,pathlib,sys
repo,vault=map(pathlib.Path,sys.argv[1:])
sys.path[:0]=[str(repo/'guest'),str(repo.parent/'oblivion-history')]
from share_plan import Plan
(vault/'workspace'/'project').mkdir(parents=True)
(vault/'imports').mkdir()
(vault/'workspace'/'project'/'caffè.txt').write_text('public synthetic fixture')
(vault/'workspace'/'project'/'.env').write_text('PUBLIC_TEST_ONLY=not-a-real-secret')
request={'version':1,'operation':'plan','request_id':'1'*32,'paths':['workspace','imports'],'chat_ids':[],
'exclude_paths':[],'exclude_chats':[],'include_sensitive_paths':[],'include_sensitive_chats':[]}
plan=Plan(vault,request)
try: print(json.dumps(plan.public,ensure_ascii=False))
finally: plan.close()
"#]).arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).with_file_name("oblivion-host")).arg(&root).output().unwrap();
    let result = (|| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut review: Review = serde_json::from_slice(&output.stdout).unwrap();
        let manifest = validate_review(&mut review, &"1".repeat(32)).unwrap();
        assert!(
            manifest
                .entries()
                .iter()
                .any(|entry| entry.path() == "workspace/project/caffè.txt")
        );
        assert!(
            !manifest
                .entries()
                .iter()
                .any(|entry| entry.path().ends_with("/.env"))
        );
        assert!(review.warnings.iter().any(|warning| warning.path.as_deref()
            == Some("workspace/project/.env")
            && !warning.included));
        let mut escaped: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        escaped["warnings"][0]["path"] = json!("workspace/../outside");
        assert!(
            validate_review(
                &mut serde_json::from_value(escaped).unwrap(),
                &"1".repeat(32)
            )
            .is_err()
        );
        let mut dependency: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        dependency["warnings"][0] = json!({
            "reason": "native_history_dependency_included",
            "chat_id": "11111111-1111-4111-8111-111111111111",
            "included": true,
        });
        assert!(
            validate_review(
                &mut serde_json::from_value(dependency.clone()).unwrap(),
                &"1".repeat(32)
            )
            .is_ok()
        );
        for invalid in [
            json!({"included": false}),
            json!({"default_excluded": true}),
            json!({"chat_id": null, "path": "workspace/project"}),
        ] {
            let mut value = dependency.clone();
            value["warnings"][0]
                .as_object_mut()
                .unwrap()
                .extend(invalid.as_object().unwrap().clone());
            assert!(
                validate_review(&mut serde_json::from_value(value).unwrap(), &"1".repeat(32))
                    .is_err()
            );
        }
    })();
    std::fs::remove_dir_all(&root).unwrap();
    result
}
fn fixture() -> Value {
    let entries = vec![
        Entry::Directory {
            path: "workspace".into(),
        },
        Entry::File {
            path: "workspace/caffè.txt".into(),
            size: 7,
            sha256: "a".repeat(64),
        },
    ];
    let manifest = Manifest::new(entries, oblivion_transfer::share::LIMITS).unwrap();
    json!({"version":1,"request_id":"1".repeat(32),"manifest":manifest.entries(),"manifest_sha256":manifest.sha256(),"plan_sha256":"2".repeat(64),"bytes":7,"chats":[],"omitted":{"credentials":1},"warnings":[{"reason":"potential_secret","path":"workspace/caffè.txt","included":false,"default_excluded":true}],"warning_count":1,"scan":{"files_bytes":7,"history_bytes":0,"limit_per_kind":16777216,"best_effort":true}})
}
fn validate(value: Value) -> std::io::Result<(Review, Manifest)> {
    let mut review = serde_json::from_value(value).unwrap();
    let manifest = validate_review(&mut review, &"1".repeat(32))?;
    Ok((review, manifest))
}

#[test]
fn reviewed_output_is_portable_and_escapes_terminal_controls_in_untrusted_titles() {
    let (review, manifest) = validate(fixture()).unwrap();
    let mut output = Vec::new();
    show_review(&mut output, "GB\u{1b}[2J\nforged", &review, &manifest).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\\u{1b}[2J\\nforged"));
    assert!(!output.contains('\u{1b}'));
    assert!(
        output.contains("caffè.txt")
            && output.contains("potential_secret")
            && output.contains("excluded")
    );
    assert!(output.contains("Omitted credentials: 1"));
    assert!(
        show_review(
            &mut std::io::Cursor::new(&mut [0u8; 0][..]),
            "GB",
            &review,
            &manifest
        )
        .is_err()
    );
    let mut value = fixture();
    value["warning_count"] = json!(2);
    let (review, manifest) = validate(value).unwrap();
    assert!(show_review(&mut Vec::new(), "GB", &review, &manifest).is_err());
}

#[test]
fn review_binds_manifest_digest_size_request_and_best_effort_scan_limits() {
    for (field, value) in [
        ("version", json!(2)),
        ("request_id", json!("3".repeat(32))),
        ("plan_sha256", json!("PRIVATE_PEER_CANARY")),
        (
            "chats",
            json!([
                "11111111-1111-4111-8111-111111111111",
                "11111111-1111-4111-8111-111111111111"
            ]),
        ),
        ("omitted", json!({"PRIVATE_PEER_CANARY":1})),
    ] {
        let mut changed = fixture();
        changed[field] = value;
        let error = validate(changed).err().unwrap();
        assert_eq!(error.to_string(), "invalid_share_review");
        assert!(!format!("{error:?}").contains("CANARY"));
    }
    for (field, value) in [
        ("manifest_sha256", json!("3".repeat(64))),
        ("bytes", json!(8)),
    ] {
        let mut changed = fixture();
        changed[field] = value;
        assert_eq!(
            validate(changed).err().unwrap().to_string(),
            "share_review_changed"
        );
    }
    for (field, value) in [
        ("best_effort", json!(false)),
        ("limit_per_kind", json!(16777217)),
        ("files_bytes", json!(16777217)),
        ("history_bytes", json!(16777217)),
    ] {
        let mut changed = fixture();
        changed["scan"][field] = value;
        assert_eq!(
            validate(changed).err().unwrap().to_string(),
            "invalid_share_review"
        );
    }
}

#[test]
fn native_dependency_warnings_require_included_conversation_context_and_never_allow_paths() {
    let mut dependency = fixture();
    dependency["warnings"][0] = json!({"reason":"native_history_dependency_included","chat_id":"11111111-1111-4111-8111-111111111111","included":true});
    let (review, manifest) = validate(dependency.clone()).unwrap();
    let mut output = Vec::new();
    show_review(&mut output, "GB", &review, &manifest).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("Required saved context from a parent conversation")
    );
    for invalid in [
        json!({"included":false}),
        json!({"default_excluded":true}),
        json!({"chat_id":null,"path":"workspace/note"}),
        json!({"reason":"PRIVATE_PEER_CANARY"}),
    ] {
        let mut changed = dependency.clone();
        changed["warnings"][0]
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        let error = validate(changed).err().unwrap();
        assert_eq!(error.to_string(), "invalid_share_warning");
        assert!(!format!("{error:?}").contains("CANARY"));
    }
}

#[test]
fn metadata_uses_the_same_validated_slot_and_rejects_unknown_credentials_or_agent_types() {
    let value = json!({"opening":{"slot":3,"safe_id":"a".repeat(32),"nonce":"b".repeat(32)},"title":"GB","created_by_agent":false,"requested_agent":null,"parent_not_included":false,"policy":"open-internet","required_proxy":null});
    let metadata: SourceMetadata<oblivion_wire::slot::Slot> =
        serde_json::from_value(value.clone()).unwrap();
    assert_eq!(metadata.opening.slot.index(), 3);
    let mut invalid = value.clone();
    invalid["password"] = json!("PRIVATE_PEER_CANARY");
    assert!(serde_json::from_value::<SourceMetadata<oblivion_wire::slot::Slot>>(invalid).is_err());
    let mut invalid = value.clone();
    invalid["opening"]["slot"] = json!(256);
    assert!(serde_json::from_value::<SourceMetadata<oblivion_wire::slot::Slot>>(invalid).is_err());
    let mut invalid = value;
    invalid["requested_agent"] = json!("unknown-agent");
    assert!(serde_json::from_value::<SourceMetadata<oblivion_wire::slot::Slot>>(invalid).is_err());
}
