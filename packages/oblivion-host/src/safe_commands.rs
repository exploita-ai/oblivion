use oblivion_host::control;

pub fn run(command: oblivion_cli::safe::Command) -> control::Result<i32> {
    oblivion_cli::safe::execute(
        &mut super::UnixRuntime::new(),
        command,
        &mut std::io::stderr().lock(),
    )
}
