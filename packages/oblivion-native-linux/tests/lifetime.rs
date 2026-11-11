use std::os::unix::process::CommandExt;
use std::process::Command;

#[test]
fn runtime_requires_the_exact_supervisor_invocation_before_reading_configuration() {
    for arguments in [
        vec!["run", "--config", "/not-a-runtime-config"],
        vec![
            "run",
            "--config",
            "/not-a-runtime-config",
            "--lifetime-fd",
            "4",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_oblivion-vm"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("invalid_arguments")
        );
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-vm"));
    command.args([
        "run",
        "--config",
        "/not-a-runtime-config",
        "--lifetime-fd",
        "3",
    ]);
    unsafe {
        command.pre_exec(|| {
            libc::close(3);
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("supervisor_lifetime_required")
    );
}
