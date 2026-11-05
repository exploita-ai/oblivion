use oblivion_cli::command::{self, Command, Files, RuntimeCommand};
use oblivion_cli::controller::{self, Result};
use oblivion_cli::{proxy, storage};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn parse(values: &[&str]) -> Result<Command<(), ()>> {
    command::parse(
        &args(values),
        |_| panic!("not a platform copy command"),
        |_| panic!("not a platform Share command"),
    )
}

#[test]
fn entrypoints_and_runtime_grammar_are_shared_without_platform_effects() {
    assert!(matches!(parse(&[]).unwrap(), Command::Manager));
    assert!(matches!(parse(&["help"]).unwrap(), Command::Help));
    assert!(matches!(parse(&["--help"]).unwrap(), Command::Help));
    assert!(matches!(parse(&["-h"]).unwrap(), Command::Help));
    assert!(matches!(parse(&["--version"]).unwrap(), Command::Version));
    assert!(matches!(parse(&["activity"]).unwrap(), Command::Activity));
    assert!(matches!(
        parse(&["runtime", "start"]).unwrap(),
        Command::Runtime(RuntimeCommand::Start)
    ));
    assert!(matches!(
        parse(&["runtime", "live-media", "--json"]).unwrap(),
        Command::Runtime(RuntimeCommand::LiveMedia)
    ));
    assert!(
        matches!(parse(&["runtime", "install-bundle", "C:\\native bundle"]).unwrap(), Command::Runtime(RuntimeCommand::InstallBundle(path)) if path == "C:\\native bundle")
    );
    assert!(
        matches!(parse(&["runtime", "supervise", "native-generation"]).unwrap(), Command::Runtime(RuntimeCommand::Supervise(generation)) if generation == "native-generation")
    );
    for values in [
        vec!["unknown"],
        vec!["activity", "extra"],
        vec!["runtime"],
        vec!["runtime", "start", "extra"],
        vec!["runtime", "install-bundle"],
        vec!["runtime", "live-media", "/dev/sda"],
    ] {
        assert!(parse(&values).is_err());
    }
}

#[test]
fn usb_transfer_grammar_accepts_only_a_device_identity_and_relative_sources() {
    let device = "a".repeat(64);
    let opening = "b".repeat(32);
    assert!(matches!(parse(&["files", "usb-browse", "--safe", "GB", "--usb", &device, "--opening", &opening]).unwrap(),
        Command::Files(Files::MediaBrowse(command)) if command.device == device && command.opening == opening));
    let parse_copy = |values: &[&str]| oblivion_cli::file_copy::parse(&args(values));
    assert!(matches!(parse_copy(&["import", "--safe", "GB", "--usb", &device, "--source", "notes/report.md"]).unwrap().selection,
        oblivion_cli::file_copy::CopyInput::MediaImport { device: id, sources } if id == device && sources == ["notes/report.md"]));
    for path in ["/etc/passwd", "../secret", ""] {
        assert!(parse_copy(&["import", "--safe", "GB", "--usb", &device, "--source", path]).is_err());
    }
    assert!(parse_copy(&["import", "--safe", "GB", "--usb", "/dev/sdb1", "--source", "file"]).is_err());
    assert!(parse_copy(&["export", "--safe", "GB", "--usb", &device, "--path", "workspace/file", "--destination", "/tmp"]).is_err());
    assert!(matches!(parse_copy(&["export", "--safe", "GB", "--usb", &device, "--path", "workspace/file", "--path", "imports/notes"]).unwrap().selection,
        oblivion_cli::file_copy::CopyInput::MediaExport { device: id, selected } if id == device && selected == ["workspace/file", "imports/notes"]));
    for option in [vec!["--yes"], vec!["--name", "Folder"]] {
        let mut command = vec!["export", "--safe", "GB", "--usb", &device, "--path", "workspace/file"];
        command.extend(option);
        assert!(parse_copy(&command).is_err());
    }
}

#[test]
fn all_control_families_dispatch_to_their_existing_typed_grammar() {
    assert!(matches!(
        parse(&["status", "--json"]).unwrap(),
        Command::Controller(controller::Command::StatusJson)
    ));
    assert!(matches!(
        parse(&["unlock", "--read-only"]).unwrap(),
        Command::Storage(storage::Command::Unlock { read_only: true })
    ));
    assert!(matches!(
        parse(&["shell", "--safe", "GB"]).unwrap(),
        Command::Shell(_)
    ));
    assert!(matches!(
        parse(&["network", "status", "--safe", "GB", "--json"]).unwrap(),
        Command::Network(_)
    ));
    assert!(matches!(
        parse(&["proxy", "list", "--json"]).unwrap(),
        Command::Proxy(_)
    ));
    assert!(matches!(
        parse(&["settings", "idle", "--json"]).unwrap(),
        Command::Settings(_)
    ));
    assert!(matches!(
        parse(&["safe", "open", "GB"]).unwrap(),
        Command::Safe(_)
    ));
    assert!(matches!(
        parse(&["safe", "password", "status", "--json"]).unwrap(),
        Command::FamilyPassword(_)
    ));
    assert!(matches!(
        parse(&["safe", "task", "status", "GB", "--json"]).unwrap(),
        Command::ChildTask(_)
    ));
    assert!(matches!(
        parse(&["backup", "status", "--json"]).unwrap(),
        Command::Backup(_)
    ));
    assert!(matches!(
        parse(&["files", "list", "--safe", "GB", "--json"]).unwrap(),
        Command::Files(Files::Inspect(_))
    ));
    for values in [
        vec!["status"],
        vec!["safe"],
        vec!["safe", "task"],
        vec!["safe", "password", "preview", "GB"],
        vec!["backup", "finish"],
        vec!["files", "list"],
        vec!["network", "status"],
        vec!["settings", "idle", "--host-minutes", "1441"],
    ] {
        assert!(parse(&values).is_err());
    }
}

#[test]
fn native_argv_and_private_proxy_prompt_request_survive_top_level_selection() {
    let values = [
        "run",
        "--safe",
        "GB",
        "-x",
        "socks5h://alice@192.0.2.1:1080",
        "codex",
        "--help",
        "--safe",
        "other",
        "",
        "a b",
        "città",
        "$(never)",
    ];
    let Command::Run(options) = parse(&values).unwrap() else {
        panic!("expected run")
    };
    assert_eq!(options.safe.as_deref(), Some("GB"));
    assert_eq!(options.agent, "codex");
    assert_eq!(options.argv, values[6..]);
    assert!(matches!(
        options.transport,
        Some(proxy::Request::NeedsPassword(_))
    ));
    for values in [
        vec!["run", "--safe", "GB", "--name", "Other", "codex"],
        vec!["run", "unknown-agent"],
        vec![
            "run",
            "-x",
            "socks5h://PRIVATE_CANARY@invalid:1080",
            "codex",
        ],
    ] {
        let error = parse(&values).err().unwrap();
        assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
    }
}

struct CopySelection(usize);
struct ShareSelection(bool);

#[test]
fn platform_copy_parsers_return_typed_commands_and_cannot_fall_back_to_raw_argv() {
    let command = command::parse(
        &args(&["files", "import", "--source", "chosen"]),
        |values| {
            assert_eq!(values, args(&["import", "--source", "chosen"]));
            Ok(CopySelection(values.len()))
        },
        |_| -> Result<ShareSelection> { panic!("wrong parser") },
    )
    .unwrap();
    assert!(matches!(
        command,
        Command::Files(Files::Copy(CopySelection(3)))
    ));
    let command = command::parse(
        &args(&["share", "imports", "--json"]),
        |_| -> Result<CopySelection> { panic!("wrong parser") },
        |values| {
            assert_eq!(values, args(&["imports", "--json"]));
            Ok(ShareSelection(true))
        },
    )
    .unwrap();
    assert!(matches!(command, Command::Share(ShareSelection(true))));
    let result = command::parse::<(), ()>(
        &args(&["files", "import"]),
        |_| Err("native_file_copy_unsupported".into()),
        |_| panic!("wrong parser"),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "native_file_copy_unsupported"
    );
    let result = command::parse::<(), ()>(
        &args(&["share", "export"]),
        |_| panic!("wrong parser"),
        |_| Err("native_share_copy_unsupported".into()),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "native_share_copy_unsupported"
    );
}

#[test]
fn storage_selection_is_derived_from_the_typed_command_only() {
    assert_eq!(parse(&[]).unwrap().live_storage(), None);
    assert_eq!(parse(&["init"]).unwrap().live_storage(), Some(false));
    assert_eq!(
        parse(&["unlock", "--read-only"]).unwrap().live_storage(),
        Some(false)
    );
    assert_eq!(parse(&["ephemeral"]).unwrap().live_storage(), Some(true));
    assert_eq!(
        parse(&["run", "--ephemeral", "claude"])
            .unwrap()
            .live_storage(),
        Some(true)
    );
    assert_eq!(
        parse(&["run", "--name", "new", "opencode2"])
            .unwrap()
            .live_storage(),
        Some(false)
    );
    assert_eq!(
        parse(&["run", "--safe", "GB", "codex"])
            .unwrap()
            .live_storage(),
        None
    );
}

#[test]
fn local_filesystem_requirement_is_available_before_runtime_discovery() {
    for (values, expected) in [
        (vec!["files", "list", "--safe", "GB", "--json"], false),
        (vec!["files", "transfers", "--safe", "GB", "--json"], false),
        (
            vec![
                "files",
                "transfers",
                "--safe",
                "GB",
                "--destination",
                "C:\\exports",
                "--json",
            ],
            true,
        ),
        (
            vec![
                "files",
                "status",
                "--safe",
                "GB",
                "--operation",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--json",
            ],
            false,
        ),
        (
            vec![
                "files",
                "recover",
                "--safe",
                "GB",
                "--operation",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--destination",
                "C:\\exports",
            ],
            true,
        ),
    ] {
        let Command::Files(Files::Inspect(command)) = parse(&values).unwrap() else {
            panic!("expected Files metadata")
        };
        assert_eq!(command.needs_local_filesystem(), expected);
    }
}
