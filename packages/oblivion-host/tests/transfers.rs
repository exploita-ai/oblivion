use oblivion_host::transfers::{Source, SourceKind};

#[test]
fn only_usb_or_explicitly_named_virtio_media_are_eligible() {
    assert!(matches!(
        SourceKind::detect(true, false, "disk"),
        Some(SourceKind::Usb)
    ));
    for serial in ["oblivion-import", "oblivion-export"] {
        assert!(matches!(
            SourceKind::detect(false, true, serial),
            Some(SourceKind::Virtual)
        ));
        assert!(SourceKind::detect(false, false, serial).is_none());
    }
    for serial in [
        "",
        "oblivion-vault",
        "oblivion-root",
        "other-user-disk",
        "oblivion-import-extra",
    ] {
        assert!(SourceKind::detect(false, true, serial).is_none());
    }
}

#[test]
fn media_metadata_is_compatible_and_preserves_read_only_status() {
    let previous: Source =
        serde_json::from_str(r#"{"id":"8:16","name":"sdb","bytes":1048576}"#).unwrap();
    assert!(matches!(previous.kind, SourceKind::Usb));
    assert!(!previous.read_only);
    let source: Source = serde_json::from_str(
        r#"{"id":"252:32","name":"vdc","bytes":1048576,"kind":"virtual","read_only":true}"#,
    )
    .unwrap();
    assert!(source.read_only);
    assert!(matches!(source.kind, SourceKind::Virtual));
    assert!(
        serde_json::from_str::<Source>(r#"{"id":"1:1","name":"disk","bytes":1,"kind":"internal"}"#)
            .is_err()
    );
}
