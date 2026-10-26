use crate::dns::NoDns;
use crate::request;
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use reqwest::{
    Client, ClientBuilder, Proxy,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::Deserialize;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const ORIGIN: &str = "https://api.abliteration.ai/v1/chat/completions";
const REQUEST_LIMIT: usize = 16 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 64 * 1024 * 1024;
type Body = UnsyncBoxBody<Bytes, io::Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub api_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    pub socks: SocketAddr,
}

// One process/instance per grant; it cannot be rearmed for a different session.
// Revocation drops the listener, every HTTP task, and their upstream streams.
pub struct Broker {
    client: Client,
    authorization: Zeroizing<String>,
    slots: Arc<Semaphore>,
    cancelled: CancellationToken,
}

impl Broker {
    pub fn new(credentials: Credentials) -> Result<Self, &'static str> {
        let client = Self::client(&credentials)?
            .build()
            .map_err(|_| "client_failed")?;
        Ok(Self::with_client(credentials, client))
    }

    fn client(credentials: &Credentials) -> Result<ClientBuilder, &'static str> {
        if !credentials.socks.ip().is_loopback()
            || credentials.socks.port() == 0
            || credentials.session_token.len() != 64
            || !credentials
                .session_token
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || !(16..=4096).contains(&credentials.api_key.len())
            || !credentials.api_key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("invalid_credentials");
        }
        let proxy = Proxy::all(format!("socks5h://{}", credentials.socks))
            .map_err(|_| "invalid_proxy")?
            .basic_auth("oblivion-api", &credentials.session_token);
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", credentials.api_key.as_str()))
                .map_err(|_| "invalid_credentials")?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        Ok(Client::builder()
            .no_proxy()
            .proxy(proxy)
            .dns_resolver(Arc::new(NoDns))
            .https_only(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(120))
            .timeout(Duration::from_secs(600))
            .default_headers(headers))
    }

    fn with_client(credentials: Credentials, client: Client) -> Self {
        Self {
            client,
            authorization: Zeroizing::new(format!("Bearer {}", credentials.session_token.as_str())),
            slots: Arc::new(Semaphore::new(4)),
            cancelled: CancellationToken::new(),
        }
    }

    pub fn revoke(&self) {
        self.cancelled.cancel();
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        let mut connections = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = self.cancelled.cancelled() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {},
                incoming = listener.accept() => {
                    let (socket, _) = match incoming {
                        Ok(incoming) => incoming,
                        Err(error) => break Err(error),
                    };
                    if connections.len() >= 64 {
                        continue;
                    }
                    let broker = self.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let broker = broker.clone();
                            async move { Ok::<_, Infallible>(broker.handle(request).await) }
                        });
                        let _ = timeout(Duration::from_secs(650), http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(10))
                            .max_headers(32)
                            .max_buf_size(32768)
                            .keep_alive(false)
                            .serve_connection(TokioIo::new(socket), service)).await;
                    });
                }
            }
        };
        // Abort even clients blocked reading/writing a body. Awaiting all joins
        // is the completion boundary, not merely setting a revocation flag.
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        result
    }

    async fn handle(self: Arc<Self>, incoming: Request<Incoming>) -> Response<Body> {
        let authorized = incoming
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        if authorized.len() != 1
            || !bool::from(
                authorized[0]
                    .as_bytes()
                    .ct_eq(self.authorization.as_bytes()),
            )
        {
            return error(StatusCode::UNAUTHORIZED, "invalid_session");
        }
        if incoming.method() != hyper::Method::POST
            || incoming.uri().path_and_query().map(|uri| uri.as_str())
                != Some("/v1/chat/completions")
            || incoming.uri().authority().is_some()
        {
            return error(StatusCode::NOT_FOUND, "endpoint_denied");
        }
        if incoming.headers().get_all(CONTENT_TYPE).iter().count() != 1
            || incoming
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|value| {
                    !["application/json", "application/json; charset=utf-8"].contains(&value)
                })
            || incoming.headers().contains_key("content-encoding")
        {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoding_denied");
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return error(StatusCode::TOO_MANY_REQUESTS, "request_limit");
        };
        let body = tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => return error(StatusCode::FORBIDDEN, "session_closed"),
            body = timeout(Duration::from_secs(30), Limited::new(incoming.into_body(), REQUEST_LIMIT).collect()) => body,
        };
        let Ok(Ok(body)) = body else {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "body_limit");
        };
        let Ok(body) = request::validate(&body.to_bytes()) else {
            return error(StatusCode::BAD_REQUEST, "request_denied");
        };
        let upstream = tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => return error(StatusCode::FORBIDDEN, "session_closed"),
            response = self.client.post(ORIGIN)
                .header(CONTENT_TYPE, "application/json")
                .header("accept", "text/event-stream")
                .body(body).send() => response,
        };
        let Ok(upstream) = upstream else {
            return error(StatusCode::BAD_GATEWAY, "provider_unavailable");
        };
        if upstream.status() == StatusCode::TOO_MANY_REQUESTS {
            return error(StatusCode::TOO_MANY_REQUESTS, "provider_limit");
        }
        if upstream.status() != StatusCode::OK
            || upstream
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|value| value.split(';').next() != Some("text/event-stream"))
        {
            // Do not forward error bodies, Location, cookies, diagnostics, or
            // echoed request credentials. Only the successful SSE body crosses.
            return error(StatusCode::BAD_GATEWAY, "provider_response_denied");
        }
        let state = StreamState {
            upstream,
            cancelled: self.cancelled.clone(),
            bytes: 0,
            _permit: permit,
        };
        let body = stream::try_unfold(state, |mut state| async move {
            let chunk = tokio::select! {
                biased;
                _ = state.cancelled.cancelled() => return Err(io::Error::other("session_closed")),
                chunk = state.upstream.chunk() => chunk.map_err(|_| io::Error::other("provider_unavailable"))?,
            };
            let Some(chunk) = chunk else { return Ok(None) };
            state.bytes += chunk.len();
            if state.bytes > RESPONSE_LIMIT {
                return Err(io::Error::other("response_limit"));
            }
            Ok(Some((Frame::data(chunk), state)))
        });
        Response::builder()
            .header(CONTENT_TYPE, "text/event-stream")
            .header("cache-control", "no-store")
            .header("connection", "close")
            .body(StreamBody::new(body).boxed_unsync())
            .expect("fixed response")
    }
}

struct StreamState {
    upstream: reqwest::Response,
    cancelled: CancellationToken,
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

fn error(status: StatusCode, code: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "no-store")
        .header("connection", "close")
        .body(
            Full::new(Bytes::from(format!(
                "{{\"error\":{{\"message\":\"{code}\",\"type\":\"oblivion_gateway\"}}}}"
            )))
            .map_err(|never| match never {})
            .boxed_unsync(),
        )
        .expect("fixed response")
}

#[cfg(test)]
mod tests;
