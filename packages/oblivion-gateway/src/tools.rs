use crate::dns::NoDns;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Frame, Incoming},
    header::{CONNECTION, HOST, HeaderMap, HeaderName, PROXY_AUTHORIZATION},
    http::uri::Authority,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use oblivion_transport::policy::Destination;
use reqwest::{Client, Proxy};
use serde::Deserialize;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zeroize::Zeroizing;

type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;
const USER: &[u8] = b"oblivion-tools";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub session_token: Zeroizing<String>,
    pub socks: SocketAddr,
}

// The private connector owns destination policy and external credentials.
// This HTTP-facing process holds only the current local grant token.
pub struct ToolsProxy {
    credentials: Credentials,
    authorization: Zeroizing<String>,
    client: Client,
    cancelled: CancellationToken,
    tunnels: TaskTracker,
    slots: Arc<Semaphore>,
}

impl ToolsProxy {
    pub fn new(credentials: Credentials) -> Result<Self, &'static str> {
        if !credentials.socks.ip().is_loopback()
            || credentials.socks.port() == 0
            || credentials.session_token.len() != 64
            || !credentials
                .session_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid_credentials");
        }
        let proxy = Proxy::all(format!("socks5h://{}", credentials.socks))
            .map_err(|_| "invalid_proxy")?
            .basic_auth("oblivion-tools", &credentials.session_token);
        let client = Client::builder()
            .no_proxy()
            .proxy(proxy)
            .dns_resolver(Arc::new(NoDns))
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| "client_failed")?;
        let raw = Zeroizing::new(format!(
            "oblivion-tools:{}",
            credentials.session_token.as_str()
        ));
        Ok(Self {
            authorization: Zeroizing::new(STANDARD.encode(raw.as_bytes())),
            credentials,
            client,
            cancelled: CancellationToken::new(),
            tunnels: TaskTracker::new(),
            slots: Arc::new(Semaphore::new(64)),
        })
    }

    pub fn revoke(&self) {
        self.cancelled.cancel();
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        let _revocation = self.cancelled.clone().drop_guard();
        let mut connections = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = self.cancelled.cancelled() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {},
                incoming = listener.accept() => {
                    let (socket, _) = match incoming {
                        Ok(value) => value,
                        Err(error) => break Err(error),
                    };
                    let Ok(permit) = self.slots.clone().try_acquire_owned() else { continue; };
                    let permit = Arc::new(permit);
                    let proxy = self.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let proxy = proxy.clone();
                            let permit = permit.clone();
                            async move { Ok::<_, Infallible>(proxy.handle(request, permit).await) }
                        });
                        let _ = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(10))
                            .max_headers(64)
                            .max_buf_size(32768)
                            .keep_alive(false)
                            .serve_connection(TokioIo::new(socket), service)
                            .with_upgrades().await;
                    });
                },
            }
        };
        self.revoke();
        drop(listener);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        // Upgraded CONNECT tunnels outlive their HTTP connection tasks. Stop
        // all producers before waiting, and retain their admission permits.
        self.tunnels.close();
        self.tunnels.wait().await;
        result
    }

    async fn handle(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<ResponseBody> {
        let headers = request.headers().get_all(PROXY_AUTHORIZATION);
        let mut headers = headers.iter();
        let auth = headers
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '));
        if headers.next().is_some()
            || !auth.is_some_and(|(scheme, value)| {
                scheme.eq_ignore_ascii_case("basic")
                    && bool::from(value.as_bytes().ct_eq(self.authorization.as_bytes()))
            })
        {
            return error(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        }
        let Ok(destination) = target(&request) else {
            return error(StatusCode::BAD_REQUEST);
        };
        if request.method() == Method::CONNECT {
            let upstream = timeout(Duration::from_secs(15), self.connect(&destination)).await;
            let mut upstream = match upstream {
                Ok(Ok(socket)) => socket,
                Ok(Err(status)) => return error(status),
                Err(_) => return error(StatusCode::GATEWAY_TIMEOUT),
            };
            let upgrade = hyper::upgrade::on(&mut request);
            let cancelled = self.cancelled.clone();
            self.tunnels.spawn(async move {
                let _permit = permit;
                tokio::select! {
                    biased;
                    _ = cancelled.cancelled() => {},
                    _ = async {
                        let Ok(client) = upgrade.await else { return; };
                        let _ = copy_bidirectional(&mut TokioIo::new(client), &mut upstream).await;
                    } => {},
                }
            });
            return Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            );
        }
        let host = if destination.host().contains(':') {
            format!("[{}]", destination.host())
        } else {
            destination.host().to_owned()
        };
        let url = format!(
            "http://{host}:{}{}",
            destination.port(),
            request
                .uri()
                .path_and_query()
                .map(|path| path.as_str())
                .unwrap_or("/")
        );
        if strip_hop_headers(request.headers_mut()).is_err() {
            return error(StatusCode::BAD_REQUEST);
        }
        // reqwest builds Host from the already validated, canonical authority.
        request.headers_mut().remove(HOST);
        let empty = request.body().is_end_stream();
        let (parts, body) = request.into_parts();
        let outgoing = self
            .client
            .request(parts.method, url)
            .headers(parts.headers);
        let outgoing = if empty {
            outgoing
        } else {
            outgoing.body(reqwest::Body::wrap_stream(body.into_data_stream()))
        };
        let Ok(mut upstream) = outgoing.send().await else {
            return error(StatusCode::BAD_GATEWAY);
        };
        if strip_hop_headers(upstream.headers_mut()).is_err() {
            return error(StatusCode::BAD_GATEWAY);
        }
        let status = upstream.status();
        if status == StatusCode::SWITCHING_PROTOCOLS {
            return error(StatusCode::BAD_GATEWAY);
        }
        let headers = upstream.headers().clone();
        let stream = stream::try_unfold(upstream, |mut upstream| async move {
            let chunk = upstream
                .chunk()
                .await
                .map_err(|_| io::Error::other("upstream_closed"))?;
            Ok::<_, io::Error>(chunk.map(|bytes| (Frame::data(bytes), upstream)))
        });
        let mut response = Response::new(StreamBody::new(stream).boxed_unsync());
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }

    async fn connect(&self, destination: &Destination) -> Result<TcpStream, StatusCode> {
        let mut socket = TcpStream::connect(self.credentials.socks)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        socket
            .write_all(&[5, 1, 2])
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let mut reply = [0; 2];
        socket
            .read_exact(&mut reply)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if reply != [5, 2] {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let mut auth = Zeroizing::new(vec![1, USER.len() as u8]);
        auth.extend_from_slice(USER);
        auth.push(self.credentials.session_token.len() as u8);
        auth.extend_from_slice(self.credentials.session_token.as_bytes());
        socket
            .write_all(&auth)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        drop(auth);
        socket
            .read_exact(&mut reply)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if reply != [1, 0] {
            return Err(StatusCode::BAD_GATEWAY);
        }
        // The connector canonicalizes literal IPs and encodes their actual
        // SOCKS address type after policy admission. No local DNS is used.
        let mut bytes = vec![5, 1, 0, 3, destination.host().len() as u8];
        bytes.extend_from_slice(destination.host().as_bytes());
        bytes.extend_from_slice(&destination.port().to_be_bytes());
        socket
            .write_all(&bytes)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let mut reply = [0; 4];
        socket
            .read_exact(&mut reply)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if reply[..3] == [5, 2, 0] {
            return Err(StatusCode::FORBIDDEN);
        }
        if reply[..3] != [5, 0, 0] {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let size = match reply[3] {
            1 => 4,
            4 => 16,
            3 => socket
                .read_u8()
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)? as usize,
            _ => return Err(StatusCode::BAD_GATEWAY),
        };
        if size == 0 {
            return Err(StatusCode::BAD_GATEWAY);
        }
        socket
            .read_exact(&mut vec![0; size + 2])
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        Ok(socket)
    }
}

fn target<T>(request: &Request<T>) -> Result<Destination, ()> {
    let connect = request.method() == Method::CONNECT;
    if request.headers().contains_key("upgrade") || request.uri().to_string().contains('#') {
        return Err(());
    }
    if connect {
        if request.uri().scheme().is_some()
            || request.uri().path_and_query().is_some()
            || request.headers().contains_key("transfer-encoding")
            || request
                .headers()
                .get("content-length")
                .is_some_and(|value| value != "0")
        {
            return Err(());
        }
    } else if request.uri().scheme_str() != Some("http") {
        return Err(());
    }
    let target = authority(request.uri().authority().ok_or(())?, connect)?;
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts.next().ok_or(())?.to_str().map_err(|_| ())?;
    if hosts.next().is_some()
        || authority(&host.parse::<Authority>().map_err(|_| ())?, connect)? != target
    {
        return Err(());
    }
    Ok(target)
}

fn authority(value: &Authority, connect: bool) -> Result<Destination, ()> {
    if value.as_str().contains('@') || value.as_str().ends_with(':') {
        return Err(());
    }
    let port = match value.port_u16() {
        Some(port) => port,
        None if !connect && value.as_str() == value.host() => 80,
        _ => return Err(()),
    };
    let host = value.host();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    Destination::new(host, port).map_err(|_| ())
}

fn strip_hop_headers(headers: &mut HeaderMap) -> Result<(), ()> {
    let names = headers
        .get_all(CONNECTION)
        .iter()
        .map(|value| value.to_str().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .flat_map(|value| value.split(','))
        .map(|name| HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    for name in names {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    Ok(())
}

fn error(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("connection", "close");
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response = response.header("proxy-authenticate", "Basic realm=\"oblivion\"");
    }
    response
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests;
