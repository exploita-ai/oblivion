use oblivion_native_linux::{Error, config::RuntimeConfig, kvm, lifetime::Lifetime, runtime};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
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
    #[cfg(target_os = "linux")]
    if args.len() == 1 && args[0] == "pick-files" {
        // Exec preserves the manager's owned process and its stdin lifetime.
        let _ = std::process::Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-B",
                "-X",
                "utf8",
                "-c",
                include_str!("pick_files.py"),
            ])
            .env("GIO_USE_VFS", "local")
            .env("GSETTINGS_BACKEND", "memory")
            .exec();
        runtime::report("desktop_file_picker_unavailable");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    if args.len() == 1 && args[0] == "enroll" {
        if let Err(error) = oblivion_native_linux::enrollment::enroll() {
            runtime::report(error.0);
            std::process::exit(1);
        }
        return;
    }
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
        [operation, flag, path, lifetime, descriptor]
            if operation == "run"
                && flag == "--config"
                && lifetime == "--lifetime-fd"
                && descriptor == "3" =>
        {
            Lifetime::inherited().and_then(|lifetime| {
                RuntimeConfig::read(Path::new(path))
                    .and_then(|config| runtime::run(config, lifetime))
            })
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
