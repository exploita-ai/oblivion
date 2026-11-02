use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, Limited, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{AUTHORIZATION, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use oblivion_transport::policy::Destination;
use serde::Deserialize;
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;
use wreq::{Client, Proxy, Uri};
use wreq_util::Emulation;
use zeroize::Zeroizing;

type Body = UnsyncBoxBody<Bytes, io::Error>;
const REQUEST_LIMIT: usize = 4096;
const RESPONSE_LIMIT: usize = 5 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub session_token: Zeroizing<String>,
    pub socks: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetch {
    url: String,
}

// PrivacyWeb is intentionally narrower than the tools proxy: one authenticated
// HTTPS GET, bounded response, no caller-controlled headers, cookies, body or
// retry. A profile is selected once per session grant so a single browsing
// session stays coherent instead of changing fingerprints on every request.
pub struct PrivacyWeb {
    client: Client,
    authorization: Zeroizing<String>,
    cancelled: CancellationToken,
    slots: Arc<Semaphore>,
}

impl PrivacyWeb {
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
            .basic_auth("oblivion-web", &credentials.session_token);
        let client = Client::builder()
            .no_proxy()
            .proxy(proxy)
            .emulation(Emulation::weighted_random())
            .redirect(wreq::redirect::Policy::limited(10))
            .retry(wreq::retry::Policy::never())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(120))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| "client_failed")?;
        Ok(Self {
            client,
            authorization: Zeroizing::new(format!("Bearer {}", credentials.session_token.as_str())),
            cancelled: CancellationToken::new(),
            slots: Arc::new(Semaphore::new(4)),
        })
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
                        Ok(value) => value,
                        Err(error) => break Err(error),
                    };
                    if connections.len() >= 32 { continue; }
                    let web = self.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let web = web.clone();
                            async move { Ok::<_, Infallible>(web.handle(request).await) }
                        });
                        let _ = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(10))
                            .max_headers(16)
                            .max_buf_size(16384)
                            .keep_alive(false)
                            .serve_connection(TokioIo::new(socket), service)
                            .await;
                    });
                }
            }
        };
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        result
    }

    async fn handle(self: Arc<Self>, incoming: Request<Incoming>) -> Response<Body> {
        let authorization = incoming
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        if authorization.len() != 1
            || !bool::from(
                authorization[0]
                    .as_bytes()
                    .ct_eq(self.authorization.as_bytes()),
            )
        {
            return error(StatusCode::UNAUTHORIZED, "invalid_session");
        }
        if incoming.method() != Method::POST
            || incoming.uri().path_and_query().map(|value| value.as_str()) != Some("/fetch")
            || incoming.uri().authority().is_some()
        {
            return error(StatusCode::NOT_FOUND, "endpoint_denied");
        }
        if incoming.headers().get_all(CONTENT_TYPE).iter().count() != 1
            || incoming
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| {
                    !["application/json", "application/json; charset=utf-8"].contains(&value)
                })
            || incoming.headers().contains_key("content-encoding")
        {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoding_denied");
        }
        let Ok(_permit) = self.slots.clone().try_acquire_owned() else {
            return error(StatusCode::TOO_MANY_REQUESTS, "request_limit");
        };
        let body = timeout(
            Duration::from_secs(5),
            Limited::new(incoming.into_body(), REQUEST_LIMIT).collect(),
        )
        .await;
        let Ok(Ok(body)) = body else {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "body_limit");
        };
        let Ok(input) = serde_json::from_slice::<Fetch>(&body.to_bytes()) else {
            return error(StatusCode::BAD_REQUEST, "request_denied");
        };
        let Ok(url) = target(&input.url) else {
            return error(StatusCode::BAD_REQUEST, "destination_denied");
        };
        let upstream = tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => return error(StatusCode::FORBIDDEN, "session_closed"),
            response = self.client.get(url.to_string()).send() => response,
        };
        let Ok(upstream) = upstream else {
            return error(StatusCode::BAD_GATEWAY, "upstream_unavailable");
        };
        if !upstream.status().is_success() {
            return error(upstream.status(), "upstream_rejected");
        }
        if upstream
            .content_length()
            .is_some_and(|length| length > RESPONSE_LIMIT as u64)
        {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "response_limit");
        }
        let status = upstream.status();
        let content_type = upstream
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let final_url = upstream.uri().to_string();
        let mut stream = upstream.bytes_stream();
        let mut bytes = Vec::new();
        loop {
            let chunk = tokio::select! {
                biased;
                _ = self.cancelled.cancelled() => return error(StatusCode::FORBIDDEN, "session_closed"),
                chunk = stream.next() => chunk,
            };
            let Some(chunk) = chunk else { break };
            let Ok(chunk) = chunk else {
                return error(StatusCode::BAD_GATEWAY, "upstream_unavailable");
            };
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
                return error(StatusCode::PAYLOAD_TOO_LARGE, "response_limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut response = Response::builder()
            .status(status)
            .header("cache-control", "no-store")
            .header("connection", "close")
            .header("x-oblivion-final-url", final_url);
        if let Some(content_type) = content_type {
            response = response.header(CONTENT_TYPE, content_type);
        }
        response
            .body(
                Full::new(Bytes::from(bytes))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .expect("validated response")
    }
}

fn target(value: &str) -> Result<Uri, ()> {
    let uri = value.parse::<Uri>().map_err(|_| ())?;
    if uri.scheme_str() != Some("https") || uri.path_and_query().is_none() {
        return Err(());
    }
    let authority = uri.authority().ok_or(())?;
    if authority.as_str().contains('@') || authority.port_u16().is_some_and(|port| port != 443) {
        return Err(());
    }
    let destination = Destination::new(authority.host(), 443).map_err(|_| ())?;
    if destination.host().parse::<std::net::IpAddr>().is_ok() {
        return Err(());
    }
    Ok(uri)
}

fn error(status: StatusCode, code: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "no-store")
        .header("connection", "close")
        .body(
            Full::new(Bytes::from(format!("{{\"error\":\"{code}\"}}")))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("fixed response")
}

#[cfg(test)]
mod tests {
    use super::{Credentials, PrivacyWeb, target};
    use futures_util::FutureExt;
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };
    use zeroize::Zeroizing;

    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn accepts_only_public_https_domains() {
        assert!(target("https://example.org/path?q=1").is_ok());
        for value in [
            "http://example.org/",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://user:pass@example.org/",
            "https://example.org:8443/",
            "https://service.internal/",
        ] {
            assert!(target(value).is_err(), "accepted {value}");
        }
    }

    #[tokio::test]
    async fn authentication_and_destination_validation_precede_proxy_contact() {
        timeout(Duration::from_secs(5), async {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let web = Arc::new(
                PrivacyWeb::new(Credentials {
                    session_token: Zeroizing::new(TOKEN.into()),
                    socks: proxy.local_addr().unwrap(),
                })
                .unwrap(),
            );
            let server = tokio::spawn(web.clone().serve(listener));
            for (authorization, url, expected) in [
                ("Bearer invalid", "https://example.org/", "401 Unauthorized"),
                (TOKEN, "http://example.org/", "400 Bad Request"),
                (TOKEN, "https://127.0.0.1/", "400 Bad Request"),
                (TOKEN, "https://service.internal/", "400 Bad Request"),
            ] {
                let authorization = if authorization == TOKEN {
                    format!("Bearer {TOKEN}")
                } else {
                    authorization.to_owned()
                };
                let body = format!(r#"{{"url":"{url}"}}"#);
                let mut client = TcpStream::connect(address).await.unwrap();
                client
                    .write_all(
                        format!(
                            "POST /fetch HTTP/1.1\r\nHost: web\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut response = String::new();
                client.read_to_string(&mut response).await.unwrap();
                assert!(response.starts_with(&format!("HTTP/1.1 {expected}")), "{response}");
                assert!(proxy.accept().now_or_never().is_none());
            }
            web.revoke();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}
