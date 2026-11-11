use oblivion_cli::shell;
use oblivion_host::control;

pub fn run(options: shell::Options) -> control::Result<i32> {
    shell::execute(&mut super::UnixRuntime::new(), options, unsafe {
        libc::isatty(0) == 1 && libc::isatty(1) == 1
    })
}
