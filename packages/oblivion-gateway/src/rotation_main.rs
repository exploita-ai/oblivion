mod activation;

use std::{io, os::fd::FromRawFd, time::Duration};
use serde::Deserialize;
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::{TcpListener, UnixStream}, time::timeout};
use zeroize::Zeroizing;

fn main() {
    let result = activation::harden().and_then(|()| {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run())
    });
    if result.is_err() {
        eprintln!("oblivion-rotation: service_failed");
        std::process::exit(1);
    }
}

async fn run() -> io::Result<()> {
    let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    control.set_nonblocking(true)?;
    let listener = unsafe { std::net::TcpListener::from_raw_fd(4) };
    listener.set_nonblocking(true)?;
    let mut control = BufReader::new(UnixStream::from_std(control)?);
    let mut bytes = Zeroizing::new(Vec::new());
    timeout(Duration::from_secs(5), (&mut control).take(257).read_until(b'\n', &mut bytes)).await??;
    if bytes.len() > 256 || !bytes.ends_with(b"\n") { return Err(io::Error::other("invalid_control")); }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credentials { session_token: Zeroizing<String> }
    let credentials: Credentials = serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid_control"))?;
    drop(bytes);
    control.get_mut().write_all(b"{\"ready\":true}\n").await?;
    oblivion_gateway::rotation_api::serve(TcpListener::from_std(listener)?, control.into_inner(), credentials.session_token).await
}
