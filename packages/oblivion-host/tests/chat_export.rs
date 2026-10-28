use oblivion_host::chat_export::{Request, Response};

#[test]
fn private_backup_metadata_cannot_be_changed_via_chat_export() {
    let value = serde_json::json!({"format": "oblivion-session", "version": 1, "original_id": "a".repeat(32), "title": "Sessione città"});
    let request: Request =
        serde_json::from_value(serde_json::json!({"action": "checkpoint", "metadata": value}))
            .unwrap();
    assert!(request.valid());
    assert!(!request.is_chat_export());
    assert!(!Request::Inspect.is_chat_export());
    let metadata = match &request {
        Request::Checkpoint { metadata } => metadata.clone(),
        _ => unreachable!(),
    };
    assert!(
        Response::Metadata {
            metadata: metadata.clone()
        }
        .valid(&request)
    );
    let mut changed = metadata.clone();
    changed.title = Some("Another session".into());
    assert!(!Response::Metadata { metadata: changed }.valid(&request));
    assert!(
        !Response::Metadata {
            metadata: metadata.clone()
        }
        .valid(&Request::List { cursor: None })
    );
    assert!(Response::Metadata { metadata }.valid(&Request::Inspect));
    for (key, replacement) in [
        ("format", serde_json::json!("unknown")),
        ("version", serde_json::json!(2)),
        ("original_id", serde_json::json!("../escape")),
        ("title", serde_json::json!("\u{1b}[2J")),
        ("title", serde_json::json!("a".repeat(81))),
    ] {
        let mut changed = value.clone();
        changed[key] = replacement;
        assert!(
            !serde_json::from_value::<oblivion_host::backup::Metadata>(changed)
                .is_ok_and(|metadata| metadata.valid())
        );
    }
    let mut changed = value;
    changed["api_key"] = serde_json::json!("not-allowed");
    assert!(serde_json::from_value::<oblivion_host::backup::Metadata>(changed).is_err());
}

#[test]
fn requests_cannot_select_paths_or_engine_options() {
    for value in [
        r#"{"action":"list","cursor":"page"}"#,
        r#"{"action":"export","id":"ses_example","format":"json"}"#,
        r#"{"action":"export","id":"ses_example","format":"markdown"}"#,
    ] {
        assert!(serde_json::from_str::<Request>(value).unwrap().valid());
    }
    for value in [
        r#"{"action":"list","path":"/etc/passwd"}"#,
        r#"{"action":"export","id":"ses_../../escape","format":"json"}"#,
        r#"{"action":"export","id":"ses_example","format":"html"}"#,
        r#"{"action":"list","cursor":"\u001b[2J"}"#,
    ] {
        assert!(!serde_json::from_str::<Request>(value).is_ok_and(|request| request.valid()));
    }
}

#[test]
fn responses_must_match_requested_format_and_fixed_roots() {
    let request = serde_json::from_str::<Request>(
        r#"{"action":"export","id":"ses_example","format":"json"}"#,
    )
    .unwrap();
    for (path, expected) in [
        (
            format!("workspace/chat-exports/{}.json", "a".repeat(32)),
            true,
        ),
        (
            format!("workspace/chat-exports/{}.md", "a".repeat(32)),
            false,
        ),
        ("workspace/chat-exports/../secrets.json".into(), false),
        ("/vault/state/opencode/oblivion.db".into(), false),
    ] {
        assert_eq!(
            Response::Exported { path, bytes: 100 }.valid(&request),
            expected
        );
    }
    let request = serde_json::from_str::<Request>(r#"{"action":"list"}"#).unwrap();
    assert!(
        !Response::Exported {
            path: "workspace/escape".into(),
            bytes: 100
        }
        .valid(&request)
    );
    assert!(
        !serde_json::from_str::<Response>(
            r#"{"result":"chats","entries":[{"id":"ses_example","title":"\u001b[2J"}],"next":null}"#
        )
        .unwrap()
        .valid(&request)
    );
}

#[test]
fn diagnostic_schema_rejects_free_text_and_unknown_sensitive_fields() {
    let value = serde_json::json!({
        "version": 1, "controller_version": "0.1.0", "architecture": "aarch64", "cpu_cores": 4, "memory_mib": 4096,
        "ephemeral": false, "general_open": true, "session": "documents", "transport": "offline",
        "direct_access_blocked": true, "observation_age_ms": 0, "tor_bootstrap": null, "laboratory": false,
    });
    assert!(
        serde_json::from_value::<oblivion_host::diagnostics::Report>(value.clone())
            .unwrap()
            .valid()
    );
    for key in [
        "api_key",
        "session_title",
        "onion_url",
        "filename",
        "error",
        "logs",
    ] {
        let mut changed = value.clone();
        changed[key] = "private data".into();
        assert!(serde_json::from_value::<oblivion_host::diagnostics::Report>(changed).is_err());
    }
    let mut changed = value;
    changed["transport"] = "private proxy address".into();
    assert!(serde_json::from_value::<oblivion_host::diagnostics::Report>(changed).is_err());
}
