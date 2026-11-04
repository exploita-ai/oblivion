#[cfg(target_os = "linux")]
mod debug;
#[cfg(target_os = "linux")]
mod backup_host;
#[cfg(target_os = "linux")]
mod family_rotation_host;
#[cfg(target_os = "linux")]
mod gateway;
#[cfg(target_os = "linux")]
mod safe_access_store;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod safe_tools;
#[cfg(target_os = "linux")]
mod chat_jobs;
#[cfg(target_os = "linux")]
mod child_tasks;
#[cfg(target_os = "linux")]
mod child_runner;
#[cfg(target_os = "linux")]
mod idle_controller;
#[cfg(target_os = "linux")]
mod share_host;
#[cfg(target_os = "linux")]
mod share_import;
#[cfg(target_os = "linux")]
mod raw_restore;
#[cfg(target_os = "linux")]
mod share_export;
#[cfg(target_os = "linux")]
mod onion_host;
#[cfg(target_os = "linux")]
mod storage;
#[cfg(target_os = "linux")]
mod system_info;
#[cfg(target_os = "linux")]
mod transfer_host;
#[cfg(target_os = "linux")]
mod usb;
#[cfg(target_os = "linux")]
mod vm;

#[cfg(target_os = "linux")]
fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|argument| argument == "--backup-copy") {
        if backup_host::copy_worker(&arguments).is_err() { std::process::exit(1); }
        return;
    }
    if let Err(error) = ipc::init_worker_channel() {
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
    if let Err(error) = storage::main() {
        // Never print subprocess output, request bodies, passwords or decrypted paths.
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux_required");
    std::process::exit(1);
}
