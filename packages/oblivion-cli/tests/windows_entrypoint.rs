#![cfg(all(windows, feature = "windows-launcher"))]
use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn invoke(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(65536).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(65536).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    Output {
        status: status.expect("frontend did not reject syntax before runtime startup"),
        stdout,
        stderr,
    }
}

#[test]
fn actual_windows_executable_serves_shared_help_and_version_without_installation() {
    let output = invoke(&["--help"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, oblivion_cli::command::HELP.as_bytes());
    assert!(output.stderr.is_empty());
    let output = invoke(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("oblivion {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn syntax_and_unimplemented_endpoints_fail_before_hyperv_or_installation_discovery() {
    for (args, message) in [
        (vec!["unknown"], "Unknown command. Run oblivion --help."),
        (vec!["run", "--safe"], "Missing Safe name"),
        (vec!["files", "list"], "Choose a Safe with --safe NAME"),
        (
            vec!["files", "import", "--safe", "GB", "--source", "unopened"],
            "A file copy needs review in a terminal, --yes for an explicit unattended copy, or --events for the manager",
        ),
        (
            vec![
                "files",
                "export",
                "--safe",
                "GB",
                "--path",
                "outside/secret",
                "--destination",
                "unopened",
            ],
            "Export paths must be under workspace or imports",
        ),
        (
            vec![
                "files", "import", "--safe", "GB", "--source", "unopened", "--events", "--yes",
            ],
            "Event copies require their reviewed approval; --yes cannot be combined with --events",
        ),
        (
            vec!["backup", "import"],
            "Use backup export --safe SAFE FILE, backup import FILE, backup finish TRANSACTION, backup status [--json] or backup discard TRANSACTION",
        ),
        (vec!["share", "import"], "Choose an encrypted Share file"),
        (
            vec!["runtime", "deploy", "unopened"],
            "windows_runtime_operation_not_implemented",
        ),
        (
            vec!["shell", "--safe", "GB"],
            "Workspace requires an interactive terminal",
        ),
    ] {
        let output = invoke(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            format!("Oblivion: {message}")
        );
    }
}
