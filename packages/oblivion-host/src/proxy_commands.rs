use oblivion_host::control;

pub fn run(command: oblivion_cli::proxy_profiles::Command) -> control::Result<i32> {
    oblivion_cli::proxy_profiles::execute(
        &mut super::UnixRuntime::new(),
        command,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}
