fn main() {
    #[cfg(windows)]
    {
        if let Err(error) = oblivion_native_windows::runtime::main() {
            eprintln!("{}", serde_json::json!({"event":error.0}));
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("{}", serde_json::json!({"event":"windows_x86_64_required"}));
        std::process::exit(1);
    }
}
