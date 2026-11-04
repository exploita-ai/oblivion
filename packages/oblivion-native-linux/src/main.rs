use oblivion_native_linux::{Error, config::RuntimeConfig, kvm, runtime};
use std::path::Path;

fn main() {
    unsafe {
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            runtime::report("core_dump_protection_failed");
            std::process::exit(1);
        }
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "capabilities" {
        match serde_json::to_string(&kvm::capabilities()) {
            Ok(value) => println!("{value}"),
            Err(_) => {
                runtime::report("capability_encoding_failed");
                std::process::exit(1);
            }
        }
        return;
    }
    let result = match args.as_slice() {
        [operation, flag, path] if operation == "run" && flag == "--config" => {
            RuntimeConfig::read(Path::new(path)).and_then(runtime::run)
        }
        _ => Err(Error("invalid_arguments")),
    };
    match result {
        Ok(()) => runtime::report("runtime_stopped"),
        Err(error) => {
            runtime::report(error.0);
            std::process::exit(1);
        }
    }
}
