#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod supervisor;
#[cfg(target_os = "linux")]
mod tor;

fn main() {
    #[cfg(target_os = "linux")]
    if supervisor::run().is_ok() {
        return;
    }
    // Never include requests, credentials, subprocess output or parser errors.
    eprintln!("oblivion-gateway-control: service_failed");
    std::process::exit(1);
}
