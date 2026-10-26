use super::{Body, Broker, Credentials};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

mod adapter;

const KEY: &str = "synthetic-provider-key-never-in-guest";
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Observed {
    headers: hyper::HeaderMap,
    uri: String,
    body: Value,
    reply: oneshot::Sender<Reply>,
    ended: CancellationToken,
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    chunks: mpsc::Receiver<Bytes>,
}

struct Fixture {
    broker: Arc<Broker>,
    address: SocketAddr,
    service: JoinHandle<io::Result<()>>,
    socks: JoinHandle<()>,
    observed: mpsc::Receiver<Observed>,
    closed: mpsc::Receiver<()>,
    attempts: Arc<AtomicUsize>,
    sockets: mpsc::Receiver<(String, u16, String, String)>,
}

impl Fixture {
    async fn new(trust_fixture: bool, token: &str) -> Self {
        let certificate = generate_simple_self_signed(vec!["api.abliteration.ai".into()]).unwrap();
        let tls = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        certificate.key_pair.serialize_der(),
                    )),
                )
                .unwrap(),
        ));
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let credentials = Credentials {
            api_key: KEY.to_owned().into(),
            session_token: token.to_owned().into(),
            socks: socks.local_addr().unwrap(),
        };
        // Only this in-crate test can install the fixture CA. The production
        // constructor has a fixed origin and uses the public web PKI roots.
        let broker = if trust_fixture {
            let client = Broker::client(&credentials)
                .unwrap()
                .add_root_certificate(
                    reqwest::Certificate::from_der(certificate.cert.der()).unwrap(),
                )
                .build()
                .unwrap();
            Broker::with_client(credentials, client)
        } else {
            Broker::new(credentials).unwrap()
        };
        let broker = Arc::new(broker);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = tokio::spawn(broker.clone().serve(listener));
        let (observed, receive) = mpsc::channel(32);
        let (closed, receive_closed) = mpsc::channel(32);
        let (sockets, receive_sockets) = mpsc::channel(32);
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let socks = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    socket = socks.accept() => {
                        let (mut socket, _) = socket.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let tls = tls.clone();
                        let observed = observed.clone();
                        let sockets = sockets.clone();
                        let closed = closed.clone();
                        tasks.spawn(async move {
                            assert_eq!(socket.read_u8().await.unwrap(), 5);
                            let mut methods = vec![0; socket.read_u8().await.unwrap() as usize];
                            socket.read_exact(&mut methods).await.unwrap();
                            assert!(methods.contains(&2));
                            socket.write_all(&[5, 2]).await.unwrap();
                            assert_eq!(socket.read_u8().await.unwrap(), 1);
                            let mut user = vec![0; socket.read_u8().await.unwrap() as usize];
                            socket.read_exact(&mut user).await.unwrap();
                            let mut password = vec![0; socket.read_u8().await.unwrap() as usize];
                            socket.read_exact(&mut password).await.unwrap();
                            socket.write_all(&[1, 0]).await.unwrap();
                            let mut header = [0; 4];
                            socket.read_exact(&mut header).await.unwrap();
                            assert_eq!(header, [5, 1, 0, 3], "SOCKS must carry a domain, not a locally resolved IP");
                            let mut domain = vec![0; socket.read_u8().await.unwrap() as usize];
                            socket.read_exact(&mut domain).await.unwrap();
                            let port = socket.read_u16().await.unwrap();
                            sockets.send((String::from_utf8(domain).unwrap(), port, String::from_utf8(user).unwrap(), String::from_utf8(password).unwrap())).await.unwrap();
                            socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
                            if let Ok(socket) = tls.accept(socket).await {
                                let ended = CancellationToken::new();
                                let _ended = ended.clone().drop_guard();
                                let service = service_fn(move |request: Request<Incoming>| {
                                    let observed = observed.clone();
                                    let ended = ended.clone();
                                    async move {
                                        let (parts, body) = request.into_parts();
                                        let body = body.collect().await.unwrap().to_bytes();
                                        let (reply, receive) = oneshot::channel();
                                        observed.send(Observed { headers: parts.headers, uri: parts.uri.to_string(), body: serde_json::from_slice(&body).unwrap(), reply, ended }).await.unwrap();
                                        let reply = receive.await.unwrap();
                                        let body = stream::unfold(reply.chunks, |mut chunks| async move {
                                            chunks.recv().await.map(|chunk| (Ok::<_, io::Error>(Frame::data(chunk)), chunks))
                                        });
                                        let mut response = Response::builder().status(reply.status);
                                        for (name, value) in reply.headers { response = response.header(name, value); }
                                        Ok::<Response<Body>, Infallible>(response.body(StreamBody::new(body).boxed_unsync()).unwrap())
                                    }
                                });
                                let _ = http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(socket), service).await;
                            }
                            let _ = closed.send(()).await;
                        });
                    }
                }
            }
        });
        Self {
            broker,
            address,
            service,
            socks,
            observed: receive,
            closed: receive_closed,
            attempts,
            sockets: receive_sockets,
        }
    }

    fn request(&self, body: Value) -> reqwest::RequestBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{}/v1/chat/completions", self.address))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .body(body.to_string())
    }

    async fn next(&mut self) -> Observed {
        timeout(Duration::from_secs(10), self.observed.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn stop(&mut self) {
        self.broker.revoke();
        timeout(Duration::from_secs(10), &mut self.service)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.broker.revoke();
        self.service.abort();
        self.socks.abort();
    }
}

fn chat() -> Value {
    json!({"model":"abliterated-model", "messages":[{"role":"user","content":"synthetic prompt"}], "stream":true, "stream_options":{"include_usage":true}})
}

fn reply(
    observed: Observed,
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
) -> mpsc::Sender<Bytes> {
    let (send, chunks) = mpsc::channel(8);
    assert!(
        observed
            .reply
            .send(Reply {
                status,
                headers,
                chunks
            })
            .is_ok()
    );
    send
}

#[tokio::test]
async fn streams_native_tool_history_through_remote_dns_and_replaces_credentials() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut body = chat();
    body["tools"] = json!([{"type":"function","function":{"name":"shell","description":"local shell","parameters":{"type":"object","properties":{"command":{"type":"string"}}}}}]);
    body["messages"].as_array_mut().unwrap().extend([
        json!({"role":"assistant","content":null,"reasoning_content":"synthetic reasoning", "tool_calls":[{"id":"call_a","type":"function","function":{"name":"shell","arguments":"{\"command\":\"pwd\"}"}}]}),
        json!({"role":"tool","tool_call_id":"call_a","content":"/vault/workspace"}),
    ]);
    let pending = tokio::spawn(
        fixture
            .request(body.clone())
            .header("cookie", "guest-secret")
            .header("x-api-key", "guest-key")
            .header("x-forwarded-for", "192.0.2.1")
            .send(),
    );
    let observed = fixture.next().await;
    assert_eq!(observed.uri, "/v1/chat/completions");
    assert_eq!(observed.body, body);
    assert_eq!(observed.headers["authorization"], format!("Bearer {KEY}"));
    assert_eq!(observed.headers["host"], "api.abliteration.ai");
    for key in [
        "cookie",
        "x-api-key",
        "x-forwarded-for",
        "proxy-authorization",
    ] {
        assert!(!observed.headers.contains_key(key));
    }
    let socket = fixture.sockets.recv().await.unwrap();
    assert_eq!(
        socket,
        (
            "api.abliteration.ai".into(),
            443,
            "oblivion-api".into(),
            TOKEN.into()
        )
    );
    let chunks = reply(
        observed,
        200,
        vec![
            ("content-type", "text/event-stream"),
            ("set-cookie", "secret=provider"),
            ("x-provider-debug", KEY),
        ],
    );
    chunks
        .send(Bytes::from_static(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n",
        ))
        .await
        .unwrap();
    let mut response = timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(!response.headers().contains_key("x-provider-debug"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        String::from_utf8(response.chunk().await.unwrap().unwrap().to_vec())
            .unwrap()
            .contains("first")
    );
    // The first chunk is delivered while the provider stream is still open.
    chunks
        .send(Bytes::from_static(b"data: [DONE]\n\n"))
        .await
        .unwrap();
    drop(chunks);
    assert_eq!(response.text().await.unwrap(), "data: [DONE]\n\n");
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejects_provider_features_and_remote_media_before_contacting_socks() {
    let fixture = Fixture::new(true, TOKEN).await;
    let denied = [
        ("model", json!("other-provider")),
        ("stream", json!(false)),
        ("store", json!(true)),
        ("web_search_options", json!({})),
        ("web_fetch", json!(true)),
        ("extra_body", json!({})),
        ("metadata", json!({"web_search":true})),
        ("tools", json!([{"type":"web_search"}])),
        (
            "tools",
            json!([{"type":"function","function":{"name":"shell","parameters":{"$ref":"https://example.com/schema"}}}]),
        ),
        (
            "tools",
            json!([{"type":"function","function":{"name":"shell","parameters":{},"url":"https://example.com"}}]),
        ),
        ("tool_choice", json!({"type":"web_search"})),
        (
            "stream_options",
            json!({"include_usage":true,"web_fetch":true}),
        ),
        (
            "messages",
            json!([{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/private"}}]}]),
        ),
        (
            "messages",
            json!([{"role":"user","content":[{"type":"file","file":{"filename":"x.pdf","file_data":"file:///secret"}}]}]),
        ),
        (
            "messages",
            json!([{"role":"user","content":"x","web_search":true}]),
        ),
        (
            "messages",
            json!([{"role":"assistant","content":null,"tool_calls":[{"id":"x","type":"web_search","function":{"name":"x","arguments":"{}"}}]}]),
        ),
        ("temperature", json!(3)),
        ("max_tokens", json!(-1)),
        ("stop", json!("not-an-array")),
    ];
    for (field, value) in denied {
        let mut body = chat();
        body[field] = value;
        let response = fixture.request(body).send().await.unwrap();
        assert_eq!(response.status(), 400, "{field}");
        assert!(!response.text().await.unwrap().contains(KEY));
    }
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepts_inline_images_pdf_and_normalizes_duplicate_keys() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut body = chat();
    body["messages"][0]["content"] = json!([
        {"type":"text","text":"context"},
        {"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw=="}},
        {"type":"file","file":{"filename":"document.pdf","file_data":"data:application/pdf;base64,JVBERg=="}},
    ]);
    let encoded = body
        .to_string()
        .replacen('{', "{\"store\":true,\"store\":false,", 1);
    let pending = tokio::spawn(fixture.request(body).body(encoded).send());
    let observed = fixture.next().await;
    assert_eq!(observed.body["store"], false);
    drop(reply(
        observed,
        200,
        vec![("content-type", "text/event-stream")],
    ));
    assert_eq!(pending.await.unwrap().unwrap().status(), 200);
}

#[tokio::test]
async fn denies_auth_endpoints_and_encoding_without_network() {
    let fixture = Fixture::new(true, TOKEN).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for path in [
        "/v1/models",
        "/v1/responses",
        "/v1/chat/completions?url=https://example.com",
        "/v1/chat/completions/",
    ] {
        assert_eq!(
            client
                .post(format!("http://{}{path}", fixture.address))
                .bearer_auth(TOKEN)
                .header("content-type", "application/json")
                .body(chat().to_string())
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    assert_eq!(
        fixture
            .request(chat())
            .bearer_auth("bad-token")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        fixture
            .request(chat())
            .header("authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        fixture
            .request(chat())
            .header("content-encoding", "gzip")
            .send()
            .await
            .unwrap()
            .status(),
        415
    );
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_untrusted_tls_and_does_not_fall_back_when_proxy_is_down() {
    let mut fixture = Fixture::new(false, TOKEN).await;
    let response = fixture.request(chat()).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert!(!response.text().await.unwrap().contains(KEY));
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
    assert!(fixture.observed.try_recv().is_err());
    fixture.socks.abort();
    let _ = (&mut fixture.socks).await;
    let response = fixture.request(chat()).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refuses_redirects_and_sanitizes_provider_errors() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    for (status, expected) in [
        (302, 502),
        (307, 502),
        (400, 502),
        (401, 502),
        (429, 429),
        (500, 502),
        (200, 502),
    ] {
        let pending = tokio::spawn(fixture.request(chat()).send());
        let observed = fixture.next().await;
        let chunks = reply(
            observed,
            status,
            vec![
                ("content-type", "application/json"),
                ("location", "https://example.com/exfiltrate"),
                ("set-cookie", "secret=provider"),
            ],
        );
        let _ = chunks.send(Bytes::from_static(KEY.as_bytes())).await;
        drop(chunks);
        let response = pending.await.unwrap().unwrap();
        assert_eq!(response.status(), expected);
        assert!(!response.headers().contains_key("location"));
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(!response.text().await.unwrap().contains(KEY));
    }
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn revocation_closes_streams_and_old_token_is_rejected_by_next_grant() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    let pending = tokio::spawn(fixture.request(chat()).send());
    let observed = fixture.next().await;
    let chunks = reply(observed, 200, vec![("content-type", "text/event-stream")]);
    chunks
        .send(Bytes::from_static(b"data: first\n\n"))
        .await
        .unwrap();
    let mut response = pending.await.unwrap().unwrap();
    assert!(response.chunk().await.unwrap().is_some());
    fixture.stop().await;
    assert!(
        timeout(Duration::from_secs(10), response.chunk())
            .await
            .unwrap()
            .is_err()
    );
    timeout(Duration::from_secs(10), fixture.closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(fixture.request(chat()).send().await.is_err());
    let next = Fixture::new(true, NEXT_TOKEN).await;
    assert_eq!(next.request(chat()).send().await.unwrap().status(), 401);
    assert_eq!(next.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn limits_concurrency_and_revokes_requests_waiting_for_response_headers() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut pending = Vec::new();
    let mut observed = Vec::new();
    for _ in 0..4 {
        pending.push(tokio::spawn(fixture.request(chat()).send()));
        observed.push(fixture.next().await);
    }
    assert_eq!(fixture.request(chat()).send().await.unwrap().status(), 429);
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 4);
    fixture.stop().await;
    for task in pending {
        if let Ok(response) = task.await.unwrap() {
            assert_eq!(response.status(), 403);
        }
    }
    for _ in 0..4 {
        timeout(Duration::from_secs(10), fixture.closed.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        observed
            .into_iter()
            .all(|request| request.reply.is_closed())
    );
}

#[tokio::test]
async fn client_disconnect_cancels_upstream_inference() {
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut socket = TcpStream::connect(fixture.address).await.unwrap();
    let body = chat().to_string();
    socket.write_all(format!("POST /v1/chat/completions HTTP/1.1\r\nHost: gateway\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let observed = fixture.next().await;
    drop(socket);
    timeout(Duration::from_secs(10), fixture.closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(observed.reply.is_closed());
}

#[tokio::test]
async fn refuses_oversized_and_malformed_requests_before_socks() {
    let fixture = Fixture::new(true, TOKEN).await;
    for body in ["x".repeat(super::REQUEST_LIMIT + 1), "{invalid-json".into()] {
        let response = fixture.request(chat()).body(body).send().await.unwrap();
        assert!([400, 413].contains(&response.status().as_u16()));
    }
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
}
