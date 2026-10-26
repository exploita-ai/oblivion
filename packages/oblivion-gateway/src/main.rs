mod activation;

use oblivion_gateway::{Broker, Credentials};
use std::{io, os::fd::FromRawFd, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixStream},
    signal::unix::{SignalKind, signal},
    time::timeout,
};
use zeroize::Zeroizing;

fn main() {
    // No configurable URL, command-line secret, environment credential or file.
    // FD 3 is a private controller stream; FD 4 is an already bound listener.
    let result = activation::harden().and_then(|()| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(run())
    });
    if result.is_err() {
        eprintln!("oblivion-api: service_failed");
        std::process::exit(1);
    }
}

async fn run() -> io::Result<()> {
    let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    control.peer_addr()?;
    control.set_nonblocking(true)?;
    let listener = unsafe { std::net::TcpListener::from_raw_fd(4) };
    listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let mut control = BufReader::new(UnixStream::from_std(control)?);
    let mut input = Zeroizing::new(Vec::new());
    timeout(
        Duration::from_secs(5),
        (&mut control).take(8193).read_until(b'\n', &mut input),
    )
    .await??;
    if input.len() > 8192 || !input.ends_with(b"\n") {
        return Err(io::Error::other("invalid_control"));
    }
    let credentials: Credentials =
        serde_json::from_slice(&input).map_err(|_| io::Error::other("invalid_control"))?;
    drop(input);
    let broker = Arc::new(Broker::new(credentials).map_err(io::Error::other)?);
    let mut termination = signal(SignalKind::terminate())?;
    let mut interruption = signal(SignalKind::interrupt())?;
    control.get_mut().write_all(b"{\"ready\":true}\n").await?;
    let service = broker.clone().serve(listener);
    tokio::pin!(service);
    tokio::select! {
        biased;
        _ = control.read_u8() => {}, // EOF, error, or any byte revokes the grant.
        _ = termination.recv() => {},
        _ = interruption.recv() => {},
        result = &mut service => return result,
    }
    broker.revoke();
    service.await
}
