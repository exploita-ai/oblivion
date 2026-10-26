#[cfg(target_os = "linux")]
mod gateway;
#[cfg(target_os = "linux")]
mod debug;
#[cfg(target_os = "linux")]
mod host_network;
#[cfg(target_os = "linux")]
mod system_info;
#[cfg(target_os = "linux")]
mod host_settings;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod storage;
#[cfg(target_os = "linux")]
mod transfer_host;
#[cfg(target_os = "linux")]
mod usb;
#[cfg(target_os = "linux")]
mod vm;

#[cfg(target_os = "linux")]
fn main() {
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
