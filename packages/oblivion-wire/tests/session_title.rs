use oblivion_wire::session_title::{Rename, validate};

#[test]
fn safe_rename_roundtrips_the_existing_display_title_contract() {
    for title in ["Research", "Progetto città", "計画", "Session / notes"] {
        validate(title).unwrap();
        let command = Rename {
            id: "1".repeat(32),
            title: title.into(),
        };
        let json = serde_json::to_value(command).unwrap();
        assert_eq!(json, serde_json::json!({"id":"1".repeat(32),"title":title}));
        let decoded: Rename = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.title, title);
    }
    for title in [
        "",
        " ",
        " trailing ",
        "new\nline",
        "\x1b[31mhidden",
        "a\u{202e}b",
    ] {
        assert_eq!(validate(title), Err("invalid_session_title"));
    }
    assert!(validate(&"a".repeat(81)).is_err());
    assert!(validate(&"a".repeat(80)).is_ok());
    assert!(
        serde_json::from_str::<Rename>(r#"{"id":"abc","title":"Research","path":"/tmp"}"#).is_err()
    );
}
