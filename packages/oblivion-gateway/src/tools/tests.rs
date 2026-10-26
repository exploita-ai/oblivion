use super::*;
use futures_util::FutureExt;
use tokio::sync::oneshot;

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn fixture() -> (
    Arc<ToolsProxy>,
    TcpStream,
    TcpListener,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let connector = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Arc::new(
        ToolsProxy::new(Credentials {
            session_token: Zeroizing::new(TOKEN.into()),
            socks: connector.local_addr().unwrap(),
        })
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(proxy.clone().serve(listener));
    let client = TcpStream::connect(address).await.unwrap();
    (proxy, client, connector, server)
}

fn authorization() -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        STANDARD.encode(format!("oblivion-tools:{TOKEN}"))
    )
}

async fn headers(socket: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await.unwrap());
        assert!(bytes.len() < 32768);
    }
    String::from_utf8(bytes).unwrap()
}

async fn connector(listener: TcpListener, port: u16, status: u8) -> TcpStream {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = [0; 3];
    socket.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [5, 1, 2]);
    socket.write_all(&[5, 2]).await.unwrap();
    assert_eq!(socket.read_u8().await.unwrap(), 1);
    let mut user = vec![0; socket.read_u8().await.unwrap() as usize];
    socket.read_exact(&mut user).await.unwrap();
    assert_eq!(user, b"oblivion-tools");
    let mut token = vec![0; socket.read_u8().await.unwrap() as usize];
    socket.read_exact(&mut token).await.unwrap();
    assert_eq!(token, TOKEN.as_bytes());
    socket.write_all(&[1, 0]).await.unwrap();
    let mut bytes = [0; 5];
    socket.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [5, 1, 0, 3, 11]);
    let mut host = [0; 11];
    socket.read_exact(&mut host).await.unwrap();
    assert_eq!(&host, b"example.com");
    assert_eq!(socket.read_u16().await.unwrap(), port);
    socket
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    socket
}

#[test]
fn private_configuration_cannot_select_an_external_connector() {
    for (socks, token) in [
        ("192.0.2.1:9051", TOKEN),
        ("127.0.0.1:0", TOKEN),
        ("127.0.0.1:9051", "bad"),
    ] {
        assert!(
            ToolsProxy::new(Credentials {
                session_token: Zeroizing::new(token.into()),
                socks: socks.parse().unwrap()
            })
            .is_err()
        );
    }
}

#[test]
fn authorities_are_canonical_and_host_agrees_with_the_requested_target() {
    for (method, uri, host, expected, port) in [
        (
            Method::GET,
            "http://EXAMPLE.com./path?q=1",
            "example.com:80",
            "example.com",
            80,
        ),
        (
            Method::CONNECT,
            "example.com:443",
            "EXAMPLE.COM.:443",
            "example.com",
            443,
        ),
        (
            Method::GET,
            "http://[2001:4860:4860::8888]/",
            "[2001:4860:4860::8888]",
            "2001:4860:4860::8888",
            80,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, host)
            .body(())
            .unwrap();
        let parsed = target(&request).unwrap();
        assert_eq!(parsed.host(), expected);
        assert_eq!(parsed.port(), port);
    }
    for (method, uri, host) in [
        (Method::GET, "/path", "example.com"),
        (Method::GET, "https://example.com/", "example.com"),
        (Method::GET, "http://user@example.com/", "example.com"),
        (Method::GET, "http://example.com/", "different.com"),
        (Method::GET, "http://example.com:/", "example.com"),
        (Method::GET, "http://example.com:99999/", "example.com"),
        (Method::GET, "http://127.0.0.1/", "127.0.0.1"),
        (Method::GET, "http://127.1/", "127.1"),
        (Method::CONNECT, "example.com", "example.com"),
        (Method::CONNECT, "example.com:443", "example.com:80"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, host)
            .body(());
        assert!(request.is_err() || request.is_ok_and(|request| target(&request).is_err()));
    }
    for (name, value) in [
        ("content-length", "1"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "websocket"),
    ] {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header(HOST, "example.com:443")
            .header(name, value)
            .body(())
            .unwrap();
        assert!(target(&request).is_err());
    }
    let request = Request::builder()
        .uri("http://example.com/")
        .header(HOST, "example.com")
        .header(HOST, "example.com")
        .body(())
        .unwrap();
    assert!(target(&request).is_err());
}

#[test]
fn hop_headers_and_proxy_credentials_do_not_cross_either_direction() {
    let mut request = Request::builder()
        .header(CONNECTION, "X-Private, keep-alive")
        .header("x-private", "secret")
        .header("keep-alive", "timeout=10")
        .header(PROXY_AUTHORIZATION, "secret")
        .header("proxy-authenticate", "secret")
        .header("proxy-connection", "close")
        .header("transfer-encoding", "chunked")
        .header("trailer", "secret")
        .header("te", "trailers")
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    strip_hop_headers(request.headers_mut()).unwrap();
    assert_eq!(request.headers().len(), 1);
    assert_eq!(request.headers()["content-type"], "text/plain");
}

#[tokio::test]
async fn invalid_authentication_and_targets_never_contact_the_connector() {
    timeout(Duration::from_secs(5), async {
        for request in [
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_owned(),
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{}{}\r\n",
                authorization(),
                authorization()
            ),
            format!(
                "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n{}\r\n",
                authorization()
            ),
            format!(
                "GET http://example.com/ HTTP/1.1\r\nHost: other.com\r\n{}\r\n",
                authorization()
            ),
        ] {
            let (proxy, mut client, upstream, server) = fixture().await;
            client.write_all(request.as_bytes()).await.unwrap();
            let response = headers(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 407") || response.starts_with("HTTP/1.1 400"));
            assert!(!response.contains(TOKEN));
            assert!(upstream.accept().now_or_never().is_none());
            proxy.revoke();
            server.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_preserves_buffered_bytes_and_revoke_joins_the_upgraded_tunnel() {
    timeout(Duration::from_secs(5), async {
        let (proxy, mut client, upstream, server) = fixture().await;
        let upstream = tokio::spawn(async move {
            let mut socket = connector(upstream, 443, 0).await;
            let mut bytes = [0; 6];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"opaque");
            socket.write_all(b"answer").await.unwrap();
            assert_eq!(socket.read(&mut bytes).await.unwrap(), 0);
        });
        client
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{}\r\nopaque",
                    authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = headers(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.to_ascii_lowercase().contains("content-length"));
        let mut bytes = [0; 6];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"answer");
        assert_eq!(proxy.slots.available_permits(), 63);
        proxy.revoke();
        server.await.unwrap().unwrap();
        assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
        upstream.await.unwrap();
        assert_eq!(proxy.slots.available_permits(), 64);
        assert!(proxy.tunnels.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_denied_connect_never_upgrades_or_retries() {
    timeout(Duration::from_secs(5), async {
        let (proxy, mut client, upstream, server) = fixture().await;
        let upstream = tokio::spawn(async move {
            let mut socket = connector(upstream, 443, 2).await;
            // The proxy may close with the remainder of the rejection unread.
            let result = socket.read(&mut [0]).await;
            assert!(
                matches!(result, Ok(0))
                    || result.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset)
            );
        });
        client
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{}\r\n",
                    authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(headers(&mut client).await.starts_with("HTTP/1.1 403"));
        upstream.await.unwrap();
        proxy.revoke();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_forwards_the_body_and_redirect_without_proxy_credentials_or_automatic_follow() {
    timeout(Duration::from_secs(5), async {
        let (proxy, mut client, upstream, server) = fixture().await;
        let upstream = tokio::spawn(async move {
            let mut socket = connector(upstream, 80, 0).await;
            let request = headers(&mut socket).await.to_ascii_lowercase();
            assert!(request.starts_with("post /document?q=1 http/1.1\r\n"));
            assert!(request.contains("host: example.com\r\n"));
            assert!(!request.contains("proxy-authorization") && !request.contains(TOKEN));
            assert!(!request.contains("x-private") && !request.contains("proxy-connection"));
            let mut body = [0; 5];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello");
            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://other.com/\r\nContent-Length: 5\r\nConnection: x-private\r\nX-Private: secret\r\nProxy-Authenticate: secret\r\n\r\nworld").await.unwrap();
            assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
        });
        client.write_all(format!("POST http://EXAMPLE.COM./document?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: x-private\r\nX-Private: secret\r\nProxy-Connection: keep-alive\r\n{}\r\nhello", authorization()).as_bytes()).await.unwrap();
        let response = headers(&mut client).await.to_ascii_lowercase();
        assert!(response.starts_with("http/1.1 302"));
        assert!(response.contains("location: http://other.com/\r\n"));
        assert!(!response.contains("x-private") && !response.contains("proxy-authenticate"));
        let mut body = [0; 5];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"world");
        upstream.await.unwrap();
        proxy.revoke();
        server.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn revoke_closes_an_http_body_still_streaming_from_the_connector() {
    timeout(Duration::from_secs(5), async {
        let (proxy, mut client, upstream, server) = fixture().await;
        let (sent, observed) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let mut socket = connector(upstream, 80, 0).await;
            headers(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nfirst")
                .await
                .unwrap();
            sent.send(()).unwrap();
            assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
        });
        client
            .write_all(
                format!(
                    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n{}\r\n",
                    authorization()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(headers(&mut client).await.starts_with("HTTP/1.1 200"));
        let mut body = [0; 5];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"first");
        observed.await.unwrap();
        proxy.revoke();
        server.await.unwrap().unwrap();
        assert_eq!(client.read(&mut body).await.unwrap(), 0);
        upstream.await.unwrap();
    })
    .await
    .unwrap();
}
