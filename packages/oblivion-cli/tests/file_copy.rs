use oblivion_cli::file_copy::{CopyInput, parse};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn event_copies_cannot_bypass_their_manifest_approval_with_yes() {
    let args = [
        "import",
        "--safe",
        "research",
        "--source",
        "/selected",
        "--events",
        "--yes",
    ]
    .map(str::to_owned);
    assert_eq!(
        parse(&args).err().unwrap().to_string(),
        "Event copies require their reviewed approval; --yes cannot be combined with --events"
    );
}

#[test]
fn copy_selectors_are_explicit_and_never_reuse_the_positional_grammar() {
    for args in [
        vec!["import", "--safe", "research", "/selected"],
        vec![
            "export",
            "--safe",
            "research",
            "workspace/project",
            "/destination",
        ],
        vec![
            "import",
            "--safe",
            "research",
            "--path",
            "workspace/project",
        ],
    ] {
        assert!(
            parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .err()
                .unwrap()
                .to_string()
                .starts_with("Use files import --safe SAFE --source PATH")
        );
    }
}

#[test]
fn copy_grammar_keeps_selection_order_and_does_not_open_paths() {
    let args = [
        "import",
        "--safe",
        "GB",
        "--source",
        "relative/missing",
        "--source",
        "/also-missing",
        "--name",
        "collection",
        "--events",
        "--operation",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--opening",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    .map(str::to_owned);
    let command = parse(&args).unwrap();
    assert_eq!(command.safe, "GB");
    assert_eq!(command.name.as_deref(), Some("collection"));
    assert!(command.events_output && !command.confirmed);
    assert_eq!(
        command.operation_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        command.expected_opening.as_deref(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    let CopyInput::Upload(sources) = command.selection else {
        panic!("expected import")
    };
    assert_eq!(sources, ["relative/missing", "/also-missing"]);
    let command = parse(
        &[
            "export",
            "--safe",
            "GB",
            "--path",
            "workspace/project",
            "--destination",
            "/missing",
            "--yes",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    assert!(command.confirmed && !command.events_output);
    let CopyInput::Download {
        selected,
        destination,
    } = command.selection
    else {
        panic!("expected export")
    };
    assert_eq!(selected, ["workspace/project"]);
    assert_eq!(destination, "/missing");
}

#[test]
fn export_paths_require_safe_roots_before_shared_shape_validation() {
    for (path, message) in [
        (
            "outside/secret",
            "Export paths must be under workspace or imports",
        ),
        (
            "/workspace/secret",
            "Export paths must be under workspace or imports",
        ),
        (
            "C:/workspace/secret",
            "Export paths must be under workspace or imports",
        ),
        ("workspace/../secret", "invalid_selection_path"),
        ("imports//secret", "invalid_selection_path"),
    ] {
        let error = parse(&args(&[
            "export",
            "--safe",
            "GB",
            "--path",
            path,
            "--destination",
            "unopened",
        ]))
        .err()
        .unwrap();
        assert_eq!(error.to_string(), message, "{path}");
    }
    for path in ["workspace/project", "imports/note"] {
        let command = parse(&args(&[
            "export",
            "--safe",
            "GB",
            "--path",
            path,
            "--destination",
            "unopened",
        ]))
        .unwrap();
        assert!(
            matches!(command.selection, CopyInput::Download { selected, .. } if selected == [path])
        );
    }
}

#[test]
fn native_windows_and_unix_paths_are_literal_until_the_endpoint_resolves_them() {
    let source = r"C:\Users\alice\project $HOME 'quoted'";
    let command = parse(&args(&["import", "--safe", "GB", "--source", source])).unwrap();
    assert!(matches!(command.selection, CopyInput::Upload(paths) if paths == [source]));
    let destination = r"D:\private exports";
    let command = parse(&args(&[
        "export",
        "--safe",
        "GB",
        "--path",
        "workspace/project",
        "--path",
        "imports/note",
        "--destination",
        destination,
        "--name",
        "collection",
    ]))
    .unwrap();
    assert!(
        matches!(command.selection, CopyInput::Download { selected, destination: path }
        if selected == ["workspace/project", "imports/note"] && path == destination)
    );
}

#[test]
fn shared_selection_budgets_and_opening_ids_fail_before_a_platform_is_needed() {
    let mut values = args(&["import", "--safe", "GB", "--name", "collection"]);
    for _ in 0..128 {
        values.extend(args(&["--source", "/selected"]));
    }
    assert!(parse(&values).is_ok());
    values.extend(args(&["--source", "/last"]));
    assert_eq!(parse(&values).err().unwrap().to_string(), "selection_limit");
    let mut values = args(&["import", "--safe", "GB", "--name", "collection"]);
    for _ in 0..128 {
        values.extend(["--source".into(), format!("/{}", "é".repeat(256))]);
    }
    assert_eq!(
        parse(&values).err().unwrap().to_string(),
        "selection_byte_limit"
    );
    for flag in ["--operation", "--opening"] {
        let error = parse(&args(&[
            "import",
            "--safe",
            "GB",
            "--source",
            "/selected",
            flag,
            "PRIVATE_CANARY",
        ]))
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "Invalid operation or opening ID");
        assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
    }
}

#[test]
fn top_level_selection_uses_the_same_real_copy_parser() {
    let command = oblivion_cli::command::parse(
        &args(&[
            "files",
            "import",
            "--safe",
            "GB",
            "--source",
            r"C:\private\input",
            "--events",
        ]),
        parse,
        |_| -> oblivion_cli::controller::Result<()> { panic!("not Share") },
    )
    .unwrap();
    let oblivion_cli::command::Command::Files(oblivion_cli::command::Files::Copy(copy)) = command
    else {
        panic!("expected typed Files copy")
    };
    assert_eq!(copy.safe, "GB");
    assert!(copy.events_output && !copy.confirmed);
    assert!(matches!(copy.selection, CopyInput::Upload(paths) if paths == [r"C:\private\input"]));
}
