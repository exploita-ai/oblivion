use oblivion_cli::child_task::{self, Command};
use oblivion_host::control;

pub fn run(command: Command) -> control::Result<i32> {
    child_task::execute(
        &mut super::UnixRuntime::new(),
        command,
        &mut std::io::stdout().lock(),
    )
}
