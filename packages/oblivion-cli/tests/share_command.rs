use oblivion_cli::share::command::{Action, Selector, parse};

#[test]
fn share_parser_preserves_review_selection_without_opening_files() {
    let args = [
        "export",
        "--safe",
        "GB",
        "missing/output",
        "--path",
        "workspace/project",
        "--exclude",
        "workspace/project/.env",
        "--no-chats",
    ]
    .map(str::to_owned);
    let command = parse(&args).unwrap();
    let Action::Export {
        selector,
        output,
        selection,
    } = command.into_action()
    else {
        panic!("expected export")
    };
    assert!(matches!(selector, Selector::Safe(name) if name == "GB"));
    assert_eq!(output, "missing/output");
    assert_eq!(selection.paths, ["workspace/project"]);
    assert_eq!(selection.exclude_paths, ["workspace/project/.env"]);
    assert_eq!(selection.chat_ids, Some(vec![]));
    let command = parse(&["export", "--all", "missing/output"].map(str::to_owned)).unwrap();
    let Action::Export {
        selector,
        selection,
        ..
    } = command.into_action()
    else {
        panic!("expected all")
    };
    assert!(matches!(selector, Selector::All));
    assert_eq!(selection.paths, ["workspace", "imports"]);
}

#[test]
fn import_and_recovery_grammar_is_typed_before_any_file_or_controller_access() {
    let command =
        parse(&["import", "missing/file", "--apply-settings"].map(str::to_owned)).unwrap();
    assert!(
        matches!(command.into_action(), Action::Import { file, settings: true } if file == "missing/file")
    );
    assert!(matches!(
        parse(&["imports", "--json"].map(str::to_owned))
            .unwrap()
            .into_action(),
        Action::Imports { json: true }
    ));
    let transaction = "a".repeat(32);
    assert!(
        matches!(parse(&["discard".into(), transaction.clone()]).unwrap().into_action(), Action::Discard { transaction: id } if id == transaction)
    );
    for values in [
        vec!["import"],
        vec!["import", "file", "--apply-settings", "--apply-settings"],
        vec!["imports", "unexpected"],
        vec!["discard", "PRIVATE_CANARY"],
        vec!["export", "--safe", "GB"],
        vec!["export", "--all", "file", "--path", "workspace/../outside"],
    ] {
        let error = parse(&values.into_iter().map(str::to_owned).collect::<Vec<_>>())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("PRIVATE_CANARY"));
    }
}
#[test]
fn only_the_single_safe_selector_accepts_explicit_conversation_ids() {
    let chat = "11111111-1111-4111-8111-111111111111";
    let args = [
        "export",
        "--safe",
        "GB",
        "output",
        "--chat",
        chat,
        "--exclude-chat",
        chat,
        "--include-sensitive",
        "workspace/note",
        "--include-sensitive-chat",
        chat,
    ]
    .map(str::to_owned);
    let Action::Export { selection, .. } = parse(&args).unwrap().into_action() else {
        panic!("export")
    };
    assert_eq!(selection.chat_ids.unwrap(), [chat]);
    assert_eq!(selection.exclude_chats, [chat]);
    assert_eq!(selection.include_sensitive_paths, ["workspace/note"]);
    assert_eq!(selection.include_sensitive_chats, [chat]);
    for selector in ["--branch", "--all"] {
        let args = if selector == "--all" {
            vec!["export", selector, "output", "--chat", chat]
        } else {
            vec!["export", selector, "GB", "output", "--chat", chat]
        };
        assert!(parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
    }
    for path in [
        "/workspace/note",
        "workspace/../note",
        "home/profile",
        "workspace/a\\b",
        "imports/\u{202e}evil",
    ] {
        assert!(
            parse(&["export", "--safe", "GB", "output", "--path", path].map(str::to_owned))
                .is_err()
        );
    }
    for chat in [
        "PRIVATE_CANARY",
        "11111111-1111-4111-8111-11111111111A",
        "../../outside",
    ] {
        let error = parse(&["export", "--safe", "GB", "output", "--chat", chat].map(str::to_owned))
            .err()
            .unwrap();
        assert!(!format!("{error:?}").contains("CANARY"));
    }
}
