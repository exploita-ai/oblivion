use oblivion_share::control::{
    ExportOpen, ExportSelection, ExportStarted, Open, SourceMetadata, Status,
};
use oblivion_wire::slot::Slot;
use serde_json::json;

#[test]
fn import_status_and_openings_keep_one_current_generic_slot_wire_shape() {
    let value = json!({"transaction":"a".repeat(32),"package_id":"b".repeat(32),"metadata_sha256":"c".repeat(64),"outcome":"pending","safes":2,"ready":1,"openings":[{"slot":3,"safe_id":"d".repeat(32),"nonce":"e".repeat(32)}]});
    let status: Status<Slot> = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(status).unwrap(), value);
    let mut invalid = value.clone();
    invalid["openings"][0]["slot"] = json!(256);
    assert!(serde_json::from_value::<Status<Slot>>(invalid).is_err());
    let mut invalid = value;
    invalid["credential"] = json!("PRIVATE_CANARY");
    assert!(serde_json::from_value::<Status<Slot>>(invalid).is_err());
}

#[test]
fn export_control_and_source_metadata_are_the_exact_producer_consumer_types() {
    let selector = json!({"kind":"safe","safe_id":"a".repeat(32)});
    let decoded: ExportSelection = serde_json::from_value(selector.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), selector);
    let started = json!({"export_id":"b".repeat(32),"sources":[{"id":"a".repeat(32),"parent":null}],"settings":null});
    let decoded: ExportStarted = serde_json::from_value(started.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), started);
    let metadata = json!({"opening":{"slot":3,"safe_id":"a".repeat(32),"nonce":"b".repeat(32)},"title":"GB","created_by_agent":true,"requested_agent":"codex","parent_not_included":true,"policy":"strict","required_proxy":null});
    let decoded: SourceMetadata<Slot> = serde_json::from_value(metadata.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), metadata);
    for (field, value) in [
        ("requested_agent", json!("unknown")),
        ("policy", json!("direct")),
        ("password", json!("PRIVATE_CANARY")),
    ] {
        let mut invalid = metadata.clone();
        invalid[field] = value;
        assert!(serde_json::from_value::<SourceMetadata<Slot>>(invalid).is_err());
    }
}

#[test]
fn only_the_all_export_can_request_portable_settings() {
    for include_settings in [false, true] {
        let value = json!({"kind":"all","include_settings":include_settings});
        let decoded: ExportSelection = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }
    for invalid in [
        json!({"kind":"all"}),
        json!({"kind":"all","include_settings":"true"}),
        json!({"kind":"safe","safe_id":"a".repeat(32),"include_settings":true}),
        json!({"kind":"branch","safe_id":"a".repeat(32),"include_settings":true}),
    ] {
        assert!(serde_json::from_value::<ExportSelection>(invalid).is_err());
    }
}

#[test]
fn private_open_passwords_accept_only_the_current_scoped_request_fields() {
    let import = json!({"transaction":"a".repeat(32),"nonce":"b".repeat(32),"package_id":"c".repeat(32),"request_id":"d".repeat(32),"password":"SYNTHETIC_TEST_SECRET"});
    assert!(serde_json::from_value::<Open>(import.clone()).is_ok());
    let export = json!({"export_id":"a".repeat(32),"password":"SYNTHETIC_TEST_SECRET"});
    assert!(serde_json::from_value::<ExportOpen>(export.clone()).is_ok());
    for field in ["path", "slot", "runtime", "safe_id", "credentials"] {
        let mut invalid = import.clone();
        invalid[field] = json!("PRIVATE_CANARY");
        assert!(serde_json::from_value::<Open>(invalid).is_err());
        let mut invalid = export.clone();
        invalid[field] = json!("PRIVATE_CANARY");
        assert!(serde_json::from_value::<ExportOpen>(invalid).is_err());
    }
}
