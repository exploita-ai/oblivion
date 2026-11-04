use oblivion_host::control;

pub fn run(command: oblivion_cli::settings::Command) -> control::Result<i32> {
    oblivion_cli::settings::execute(&mut control::Client::new(), command, &mut std::io::stdout())
}
