use oblivion_host::{control, scope};

pub fn run(command: oblivion_cli::family_password::Command) -> control::Result<i32> {
    scope::within(Default::default(), || {
        oblivion_cli::family_password::execute(
            &mut super::UnixRuntime::new(),
            command,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )
    })
}
