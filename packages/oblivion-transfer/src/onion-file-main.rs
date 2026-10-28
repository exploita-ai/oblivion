mod runtime;

fn main() {
    #[cfg(target_os = "linux")]
    if runtime::harden()
        .and_then(|_| oblivion_transfer::onion_file::run())
        .is_ok()
    {
        return;
    }
    eprintln!("oblivion-onion-file: failed");
    std::process::exit(1);
}
