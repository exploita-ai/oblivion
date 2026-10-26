fn main() {
    #[cfg(target_os = "linux")]
    if oblivion_host::display::run().is_ok() {
        return;
    }
    eprintln!("display_connection_failed");
    std::process::exit(1);
}
