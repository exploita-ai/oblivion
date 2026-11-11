#[cfg(not(windows))]
compile_error!(
    "The windows-launcher target is built for Windows; Unix uses oblivion-host's launcher"
);

#[cfg(windows)]
fn main() {
    match oblivion_cli::windows_entrypoint::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Oblivion: {error}");
            std::process::exit(1);
        }
    }
}
