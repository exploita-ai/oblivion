mod activation;

use oblivion_gateway::egress::{Credentials, Egress};
use std::{io, os::fd::FromRawFd, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixStream},
    signal::unix::{SignalKind, signal},
    time::timeout,
};
use zeroize::Zeroizing;

// Includes the bounded destination policy, supplied only on the private FD.
const FRAME_LIMIT: u64 = 128 * 1024;

fn main() {
    let result = activation::harden().and_then(|()| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(run())
    });
    if result.is_err() {
        eprintln!("oblivion-egress: service_failed");
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
    let mut bytes = Zeroizing::new(Vec::new());
    timeout(
        Duration::from_secs(5),
        (&mut control)
            .take(FRAME_LIMIT + 1)
            .read_until(b'\n', &mut bytes),
    )
    .await??;
    if bytes.len() as u64 > FRAME_LIMIT || !bytes.ends_with(b"\n") {
        return Err(io::Error::other("invalid_control"));
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged, deny_unknown_fields)]
    enum Activation {
        Probe {
            probe: oblivion_transport::Transport,
        },
        Serve(Credentials),
    }
    let activation: Activation =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid_control"))?;
    let credentials = match activation {
        Activation::Probe { probe } => {
            oblivion_gateway::egress::probe(&probe).await?;
            control.get_mut().write_all(b"{\"ready\":true}\n").await?;
            return Ok(());
        }
        Activation::Serve(credentials) => credentials,
    };
    drop(bytes);
    let egress = Arc::new(Egress::new(credentials).map_err(io::Error::other)?);
    let mut termination = signal(SignalKind::terminate())?;
    let mut interruption = signal(SignalKind::interrupt())?;
    // Validate listener placement before acknowledging startup.
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::other("loopback_required"));
    }
    control.get_mut().write_all(b"{\"ready\":true}\n").await?;
    let service = egress.clone().serve(listener);
    tokio::pin!(service);
    tokio::select! {
        biased;
        _ = control.read_u8() => {},
        _ = termination.recv() => {},
        _ = interruption.recv() => {},
        result = &mut service => return result,
    }
    egress.revoke();
    service.await
}
