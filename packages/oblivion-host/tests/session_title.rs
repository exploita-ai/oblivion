use oblivion_host::session_title::{Rename, validate};

#[test]
fn session_titles_are_unicode_display_text_not_terminal_controls() {
    for title in ["Research", "Progetto città", "計画", "Session / notes"] {
        assert!(validate(title).is_ok());
    }
    for title in ["", " ", " trailing ", "new\nline", "\x1b[31mhidden", "a\u{202e}b"] {
        assert!(validate(title).is_err());
    }
    assert!(validate(&"a".repeat(81)).is_err());
    assert!(validate(&"a".repeat(80)).is_ok());
    assert!(serde_json::from_str::<Rename>(r#"{"id":"abc","title":"Research","path":"/tmp"}"#).is_err());
}
