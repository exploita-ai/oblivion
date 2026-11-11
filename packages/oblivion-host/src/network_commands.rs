use oblivion_host::control;

pub fn run(command: oblivion_cli::network::Command) -> control::Result<i32> {
    oblivion_cli::network::execute(
        &mut super::UnixRuntime::new(),
        command,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}
