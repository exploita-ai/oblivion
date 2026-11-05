pub mod auth;
pub mod bridge;
pub mod config;
#[cfg(target_os = "linux")]
pub mod enrollment;
pub mod kvm;
pub mod lifetime;
pub mod private;
pub mod qemu;
pub mod runtime;

#[derive(Debug)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
