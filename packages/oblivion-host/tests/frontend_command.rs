#[test]
fn typed_top_level_and_platform_copy_grammar_fail_before_runtime_startup() {
    for (args, error) in [
        (
            vec!["UNKNOWN_PRIVATE_CANARY"],
            "Unknown command. Run oblivion --help.",
        ),
        (vec!["logs"], "Unknown command. Run oblivion --help."),
        (
            vec!["runtime", "atomic", "--yes"],
            "Use oblivion runtime atomic for an interactive review",
        ),
        (
            vec!["activity", "extra"],
            "Unknown command. Run oblivion --help.",
        ),
        (
            vec!["files", "import", "--source", "/missing-source"],
            "Choose a Safe with --safe NAME",
        ),
        (
            vec![
                "files",
                "export",
                "--safe",
                "GB",
                "--path",
                "workspace/a",
                "--destination",
                "/missing",
                "--unknown",
            ],
            "Unknown file option",
        ),
        (
            vec![
                "files", "import", "--safe", "GB", "--source", "/a", "--source", "/b",
            ],
            "Choose a collection name with --name when selecting multiple paths",
        ),
        (vec!["share", "import"], "Choose an encrypted Share file"),
        (
            vec!["share", "imports", "--unknown"],
            "Use share imports [--json]",
        ),
        (
            vec!["share", "export", "--safe", "GB"],
            "Choose an output Share file",
        ),
        (
            vec![
                "share",
                "export",
                "--all",
                "out",
                "--chat",
                "11111111-1111-4111-8111-111111111111",
            ],
            "Use --chat with a single --safe export. --exclude-chat applies to branches and all Safes.",
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
            .args(args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("Oblivion: {error}\n")
        );
    }
}

#[test]
fn compiled_help_uses_the_same_portable_text_without_a_runtime() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_oblivion"))
        .arg("--help")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        oblivion_cli::command::help(oblivion_cli::command::HelpProfile::Desktop)
    );
}
