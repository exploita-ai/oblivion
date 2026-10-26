use oblivion_transport::Transport;
pub use oblivion_transport::policy::Tools;
use oblivion_transport::policy::{Action, Destination};
use serde::Deserialize;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const USER: &[u8] = b"oblivion-api";
const TOOLS_USER: &[u8] = b"oblivion-tools";
const HOST: &[u8] = b"api.abliteration.ai";
const HANDSHAKE: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub transport: Transport,
    pub session_token: Zeroizing<String>,
    #[serde(default)]
    pub tools: Option<Tools>,
}

// One connector per grant. Tools admission requires explicit trusted
// configuration; absent it, only the fixed API origin is available. This
// loopback listener is never exposed to the session guest.
pub struct Egress {
    credentials: Credentials,
    cancelled: CancellationToken,
}

impl Egress {
    pub fn new(credentials: Credentials) -> Result<Self, &'static str> {
        credentials.transport.validate()?;
        if credentials.session_token.len() != 64
            || !credentials
                .session_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid_session_token");
        }
        Ok(Self {
            credentials,
            cancelled: CancellationToken::new(),
        })
    }

    pub fn revoke(&self) {
        self.cancelled.cancel();
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(io::Error::other("loopback_required"));
        }
        let mut tasks = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = self.cancelled.cancelled() => break Ok(()),
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = listener.accept() => {
                    let (mut client, _) = match incoming {
                        Ok(value) => value,
                        Err(error) => break Err(error),
                    };
                    if tasks.len() >= 64 { continue; }
                    let egress = self.clone();
                    tasks.spawn(async move {
                        // One absolute budget covers fragmented local input,
                        // proxy connect and authentication, with no retry.
                        let Ok(Ok(mut upstream)) = timeout(
                            HANDSHAKE,
                            egress.handshake(&mut client),
                        ).await else { return; };
                        let _ = copy_bidirectional(&mut client, &mut upstream).await;
                    });
                },
            }
        };
        drop(listener);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }

    async fn handshake(&self, client: &mut TcpStream) -> io::Result<TcpStream> {
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await?;
        if greeting[0] != 5 || greeting[1] == 0 {
            return Err(io::Error::other("invalid_socks_greeting"));
        }
        let mut methods = vec![0; greeting[1] as usize];
        client.read_exact(&mut methods).await?;
        if !methods.contains(&2) {
            client.write_all(&[5, 255]).await?;
            return Err(io::Error::other("authentication_required"));
        }
        client.write_all(&[5, 2]).await?;
        let mut auth = [0; 2];
        client.read_exact(&mut auth).await?;
        if auth[0] != 1 || auth[1] == 0 {
            return Err(io::Error::other("invalid_socks_authentication"));
        }
        let mut username = Zeroizing::new(vec![0; auth[1] as usize]);
        client.read_exact(&mut username).await?;
        let size = client.read_u8().await? as usize;
        let mut password = Zeroizing::new(vec![0; size]);
        client.read_exact(&mut password).await?;
        let tools = username.as_slice() == TOOLS_USER && self.credentials.tools.is_some();
        if (!tools && username.as_slice() != USER)
            || !bool::from(
                password
                    .as_slice()
                    .ct_eq(self.credentials.session_token.as_bytes()),
            )
        {
            client.write_all(&[1, 1]).await?;
            return Err(io::Error::other("authentication_failed"));
        }
        drop(username);
        drop(password);
        client.write_all(&[1, 0]).await?;
        let mut request = [0; 4];
        client.read_exact(&mut request).await?;
        if request[..3] != [5, 1, 0]
            || !matches!(request[3], 1 | 3 | 4)
            || (!tools && request[3] != 3)
        {
            client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::other("request_denied"));
        }
        let host = match request[3] {
            1 => {
                let mut bytes = [0; 4];
                client.read_exact(&mut bytes).await?;
                Ipv4Addr::from(bytes).to_string()
            }
            4 => {
                let mut bytes = [0; 16];
                client.read_exact(&mut bytes).await?;
                Ipv6Addr::from(bytes).to_string()
            }
            _ => {
                let mut bytes = vec![0; client.read_u8().await? as usize];
                client.read_exact(&mut bytes).await?;
                String::from_utf8(bytes).map_err(|_| io::Error::other("invalid_destination"))?
            }
        };
        let port = client.read_u16().await?;
        let destination = Destination::new(&host, port).ok();
        let allowed = match (&destination, tools) {
            (Some(destination), true) => self.credentials.tools.as_ref().is_some_and(|tools| {
                tools.policy.decision(&tools.session, destination) == Action::Allow
            }),
            (Some(_), false) => host.as_bytes() == HOST && port == 443,
            _ => false,
        };
        // Ask is closed until the trusted manager approval channel is wired.
        // No DNS or upstream TCP connection precedes this decision.
        if !allowed {
            client.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::other("destination_denied"));
        }
        let destination = destination.ok_or_else(|| io::Error::other("invalid_destination"))?;
        // All local admission precedes even connecting to the upstream proxy.
        let mut upstream = TcpStream::connect(self.credentials.transport.endpoint()).await?;
        let authentication = match &self.credentials.transport {
            Transport::Tor {} => Some((
                if tools { TOOLS_USER } else { USER },
                self.credentials.session_token.as_bytes(),
            )),
            Transport::Socks5 { authentication, .. } => authentication
                .as_ref()
                .map(|auth| (auth.username.as_bytes(), auth.password.as_bytes())),
        };
        authenticate(&mut upstream, authentication).await?;
        let mut request = vec![5, 1, 0];
        match destination.host().parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                request.extend_from_slice(&[3, destination.host().len() as u8]);
                request.extend_from_slice(destination.host().as_bytes());
            }
        }
        request.extend_from_slice(&destination.port().to_be_bytes());
        upstream.write_all(&request).await?;
        let mut reply = [0; 4];
        upstream.read_exact(&mut reply).await?;
        if reply[..3] != [5, 0, 0] {
            return Err(io::Error::other("proxy_connect_failed"));
        }
        // BND.ADDR is the proxy's bound endpoint, not evidence of the resolved
        // destination. Never resolve the requested domain locally or retry it.
        let size = match reply[3] {
            1 => 4,
            3 => {
                let size = upstream.read_u8().await? as usize;
                if size == 0 {
                    return Err(io::Error::other("invalid_proxy_reply"));
                }
                size
            }
            4 => 16,
            _ => return Err(io::Error::other("invalid_proxy_reply")),
        };
        let mut bound = vec![0; size + 2];
        upstream.read_exact(&mut bound).await?;
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        Ok(upstream)
    }
}

#[cfg(test)]
mod tests;

/// Check only the configured proxy greeting/authentication. No CONNECT command,
/// provider call, DNS lookup or external IP-check service is involved.
pub async fn probe(transport: &Transport) -> io::Result<()> {
    transport.validate().map_err(io::Error::other)?;
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(transport.endpoint()).await?;
        let authentication = match transport {
            Transport::Socks5 { authentication, .. } => authentication
                .as_ref()
                .map(|value| (value.username.as_bytes(), value.password.as_bytes())),
            Transport::Tor {} => None,
        };
        authenticate(&mut stream, authentication).await
    })
    .await
    .map_err(|_| io::Error::other("proxy_probe_timeout"))?
}

async fn authenticate(
    upstream: &mut TcpStream,
    authentication: Option<(&[u8], &[u8])>,
) -> io::Result<()> {
    let method = if authentication.is_some() { 2 } else { 0 };
    upstream.write_all(&[5, 1, method]).await?;
    let mut selected = [0; 2];
    upstream.read_exact(&mut selected).await?;
    if selected != [5, method] {
        return Err(io::Error::other("proxy_authentication_method_rejected"));
    }
    if let Some((username, password)) = authentication {
        let mut bytes = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
        bytes.extend_from_slice(&[1, username.len() as u8]);
        bytes.extend_from_slice(username);
        bytes.push(password.len() as u8);
        bytes.extend_from_slice(password);
        upstream.write_all(&bytes).await?;
        drop(bytes);
        let mut reply = [0; 2];
        upstream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(io::Error::other("proxy_authentication_failed"));
        }
    }
    Ok(())
}
