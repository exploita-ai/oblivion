use super::*;
use oblivion_transport::{Authentication, Metadata, provider::Provider};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::oneshot;

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOST: &[u8] = b"api.abliteration.ai";

fn configuration(endpoint: SocketAddrV4, authenticated: bool) -> Credentials {
    provider_configuration(Provider::AbliterationAi, endpoint, authenticated)
}

fn provider_configuration(
    provider: Provider,
    endpoint: SocketAddrV4,
    authenticated: bool,
) -> Credentials {
    Credentials {
        provider,
        session_token: Zeroizing::new(TOKEN.into()),
        tools: None,
        transport: Transport::Socks5 {
            endpoint,
            authentication: authenticated.then(|| Authentication {
                username: Zeroizing::new("external-user".into()),
                password: Zeroizing::new("external-password".into()),
            }),
        },
    }
}

async fn fixture(
    authenticated: bool,
) -> (
    Arc<Egress>,
    TcpStream,
    TcpListener,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    configured_fixture(authenticated, None).await
}

async fn configured_fixture(
    authenticated: bool,
    tools: Option<Tools>,
) -> (
    Arc<Egress>,
    TcpStream,
    TcpListener,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    configured_provider_fixture(authenticated, tools, Provider::AbliterationAi).await
}

async fn configured_provider_fixture(
    authenticated: bool,
    tools: Option<Tools>,
    provider: Provider,
) -> (
    Arc<Egress>,
    TcpStream,
    TcpListener,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // The unit fixture supplies a prevalidated internal configuration so its
    // real proxy can use a dynamic loopback port. Egress::new rejects this
    // endpoint in production; validation has independent coverage below.
    let egress = Arc::new(Egress {
        credentials: Credentials {
            tools,
            ..provider_configuration(
                provider,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, upstream.local_addr().unwrap().port()),
                authenticated,
            )
        },
        cancelled: CancellationToken::new(),
    });
    let server = tokio::spawn(egress.clone().serve(listener));
    let client = TcpStream::connect(address).await.unwrap();
    (egress, client, upstream, server)
}

#[tokio::test]
async fn api_role_is_pinned_to_the_selected_provider_hostname() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        for provider in [
            Provider::AbliterationAi,
            Provider::Refuseless,
            Provider::Openrouter,
        ] {
            let (egress, mut client, upstream, server) =
                configured_provider_fixture(false, None, provider).await;
            assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
            request(&mut client, b"example.com", 443).await;
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 2);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();

            let (egress, mut client, upstream, server) =
                configured_provider_fixture(false, None, provider).await;
            assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
            request(&mut client, provider.host().as_bytes(), 443).await;
            let _ = upstream.accept().await.unwrap();
            egress.revoke();
            server.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

async fn authenticate(client: &mut TcpStream, token: &[u8]) -> [u8; 2] {
    authenticate_as(client, USER, token).await
}

async fn authenticate_as(client: &mut TcpStream, user: &[u8], token: &[u8]) -> [u8; 2] {
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    let mut auth = vec![1, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(token.len() as u8);
    auth.extend_from_slice(token);
    client.write_all(&auth).await.unwrap();
    client.read_exact(&mut reply).await.unwrap();
    reply
}

async fn request(client: &mut TcpStream, host: &[u8], port: u16) {
    let mut bytes = vec![5, 1, 0, 3, host.len() as u8];
    bytes.extend_from_slice(host);
    bytes.extend_from_slice(&port.to_be_bytes());
    client.write_all(&bytes).await.unwrap();
}

async fn external(listener: TcpListener, authenticated: bool) -> TcpStream {
    let mut request = vec![5, 1, 0, 3, HOST.len() as u8];
    request.extend_from_slice(HOST);
    request.extend_from_slice(&443u16.to_be_bytes());
    external_request(listener, authenticated, &request).await
}

async fn external_request(listener: TcpListener, authenticated: bool, request: &[u8]) -> TcpStream {
    let (mut proxy, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    proxy.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, if authenticated { 2 } else { 0 }]);
    proxy.write_all(&[5, greeting[2]]).await.unwrap();
    if authenticated {
        assert_eq!(proxy.read_u8().await.unwrap(), 1);
        let mut user = vec![0; proxy.read_u8().await.unwrap() as usize];
        proxy.read_exact(&mut user).await.unwrap();
        let mut password = vec![0; proxy.read_u8().await.unwrap() as usize];
        proxy.read_exact(&mut password).await.unwrap();
        assert_eq!(user, b"external-user");
        assert_eq!(password, b"external-password");
        assert_ne!(password, TOKEN.as_bytes());
        proxy.write_all(&[1, 0]).await.unwrap();
    }
    let mut bytes = vec![0; request.len()];
    proxy.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, request);
    proxy
        .write_all(&[5, 0, 0, 1, 192, 0, 2, 9, 23, 45])
        .await
        .unwrap();
    proxy
}

#[test]
fn transport_validation_and_metadata_never_expose_proxy_secrets() {
    let good = configuration("192.168.1.7:1080".parse().unwrap(), true);
    assert!(Egress::new(good).is_ok());
    assert!(matches!(Transport::default(), Transport::Tor {}));
    for endpoint in [
        "0.0.0.0:1080",
        "0.1.2.3:1080",
        "127.0.0.1:9050",
        "10.88.0.1:1080",
        "10.88.0.2:1080",
        "224.0.0.1:1080",
        "255.255.255.255:1080",
        "192.0.2.1:0",
    ] {
        assert!(Egress::new(configuration(endpoint.parse().unwrap(), false)).is_err());
    }
    for bytes in [
        r#"{"mode":"direct"}"#,
        r#"{"mode":"socks5","endpoint":"proxy.example:1080"}"#,
        r#"{"mode":"socks5","endpoint":"[::1]:1080"}"#,
        r#"{"mode":"tor","endpoint":"192.0.2.1:1080"}"#,
    ] {
        assert!(serde_json::from_str::<Transport>(bytes).is_err());
    }
    for password in [String::new(), "x".repeat(256), "unsafe\ncontrol".into()] {
        let transport = Transport::Socks5 {
            endpoint: "192.0.2.1:1080".parse().unwrap(),
            authentication: Some(Authentication {
                username: Zeroizing::new("name".into()),
                password: Zeroizing::new(password),
            }),
        };
        assert!(transport.validate().is_err());
    }
    let config = configuration("192.0.2.7:1080".parse().unwrap(), true);
    let metadata = serde_json::to_string(&config.transport.metadata()).unwrap();
    assert!(!metadata.contains("external-user") && !metadata.contains("external-password"));
    assert!(matches!(
        serde_json::from_str::<Metadata>(&metadata).unwrap(),
        Metadata::Socks5 {
            authenticated: true,
            ..
        }
    ));
}

#[tokio::test]
async fn remote_dns_and_distinct_proxy_authentication_relay_and_revoke() {
    for authenticated in [false, true] {
        timeout(Duration::from_secs(5), async {
            let (egress, mut client, upstream, server) = fixture(authenticated).await;
            assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
            let (ready, observed) = oneshot::channel();
            let proxy = tokio::spawn(async move {
                let mut proxy = external(upstream, authenticated).await;
                let mut bytes = [0; 7];
                proxy.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"opaque!");
                proxy.write_all(b"reply!").await.unwrap();
                ready.send(()).unwrap();
                assert_eq!(proxy.read(&mut bytes).await.unwrap(), 0);
            });
            request(&mut client, HOST, 443).await;
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            client.write_all(b"opaque!").await.unwrap();
            let mut bytes = [0; 6];
            client.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"reply!");
            observed.await.unwrap();
            egress.revoke();
            server.await.unwrap().unwrap();
            assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
            proxy.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn local_admission_rejects_before_any_proxy_connection() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        for denied in [0, 1, 2, 3, 4] {
            let (egress, mut client, upstream, server) = fixture(false).await;
            if denied == 0 {
                assert_eq!(authenticate(&mut client, b"wrong").await, [1, 1]);
            } else {
                assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
                if denied == 1 {
                    request(&mut client, b"example.com", 443).await;
                }
                if denied == 2 {
                    request(&mut client, HOST, 80).await;
                }
                if denied == 3 {
                    client.write_all(&[5, 1, 0, 1]).await.unwrap();
                }
                if denied == 4 {
                    client.write_all(&[5, 3, 0, 3]).await.unwrap();
                }
                let mut reply = [0; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_ne!(reply[1], 0);
            }
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn proxy_downgrade_bad_password_and_connect_failure_do_not_retry() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        for failure in [0, 1, 2] {
            let (egress, mut client, upstream, server) = fixture(true).await;
            assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
            request(&mut client, HOST, 443).await;
            let (mut proxy, _) = upstream.accept().await.unwrap();
            let mut greeting = [0; 3];
            proxy.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            proxy
                .write_all(&[5, if failure == 0 { 0 } else { 2 }])
                .await
                .unwrap();
            if failure > 0 {
                assert_eq!(proxy.read_u8().await.unwrap(), 1);
                let mut bytes = vec![0; proxy.read_u8().await.unwrap() as usize];
                proxy.read_exact(&mut bytes).await.unwrap();
                let mut bytes = vec![0; proxy.read_u8().await.unwrap() as usize];
                proxy.read_exact(&mut bytes).await.unwrap();
                proxy
                    .write_all(&[1, if failure == 1 { 1 } else { 0 }])
                    .await
                    .unwrap();
                if failure == 2 {
                    let mut request = vec![0; 7 + HOST.len()];
                    proxy.read_exact(&mut request).await.unwrap();
                    proxy.write_all(&[5, 5, 0, 1]).await.unwrap();
                }
            }
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert_eq!(proxy.read(&mut [0]).await.unwrap(), 0);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fragmented_handshake_has_an_absolute_deadline_and_listener_recovers() {
    timeout(Duration::from_secs(15), async {
        let (egress, client, upstream, server) = fixture(false).await;
        let address = client.peer_addr().unwrap();
        let (mut incoming, mut outgoing) = client.into_split();
        // Real I/O shares the production ten-second budget. Progress at three
        // and six seconds must not restart that budget for the next field.
        let drip = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            for byte in [5, 1, 2, 1, 12] {
                interval.tick().await;
                if outgoing.write_all(&[byte]).await.is_err() {
                    return;
                }
            }
        });
        let mut reply = Vec::new();
        incoming.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        drip.abort();
        let _ = drip.await;
        let mut next = TcpStream::connect(address).await.unwrap();
        assert_eq!(authenticate(&mut next, b"bad").await, [1, 1]);
        use futures_util::FutureExt;
        assert!(upstream.accept().now_or_never().is_none());
        egress.revoke();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

fn tools(rules: Value) -> Tools {
    serde_json::from_value(json!({
        "session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policy": {"version": 1, "rules": rules},
    }))
    .unwrap()
}

#[test]
fn tools_configuration_validates_session_and_policy_at_the_private_boundary() {
    for invalid in [
        json!({"session": "bad", "policy": {"version": 1, "rules": []}}),
        json!({"session": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "policy": {"version": 1, "rules": []}}),
        json!({"session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy": {"version": 2, "rules": []}}),
        json!({"session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy": {"version": 1, "rules": [{"destination": "127.0.0.1", "port": 80, "action": "allow"}]}}),
        json!({"session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy": {"version": 1, "rules": []}, "direct": true}),
    ] {
        assert!(
            serde_json::from_value::<Credentials>(json!({
                "provider": "abliteration-ai", "transport": {"mode": "tor"}, "session_token": TOKEN, "tools": invalid,
            }))
            .is_err()
        );
    }
    let credentials: Credentials = serde_json::from_value(json!({
        "provider": "abliteration-ai", "transport": {"mode": "tor"}, "session_token": TOKEN,
    }))
    .unwrap();
    assert!(credentials.tools.is_none());
    assert!(Egress::new(credentials).is_ok());
}

#[tokio::test]
async fn tools_role_needs_explicit_configuration_and_the_current_token() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        for (enabled, user, token) in [
            (false, TOOLS_USER, TOKEN.as_bytes()),
            (true, TOOLS_USER, b"wrong".as_slice()),
            (true, b"guest-selected-role".as_slice(), TOKEN.as_bytes()),
        ] {
            let (egress, mut client, upstream, server) =
                configured_fixture(false, enabled.then(|| tools(json!([])))).await;
            assert_eq!(authenticate_as(&mut client, user, token).await, [1, 1]);
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tools_policy_and_reserved_addresses_fail_before_contacting_the_proxy() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        let allow = json!({"destination": "example.com", "port": 443, "action": "allow"});
        for (rules, host, port) in [
            (json!([]), b"example.com".as_slice(), 443),
            (json!([{"destination": "example.com", "port": 443, "action": "ask"}]), b"example.com".as_slice(), 443),
            (json!([allow, {"destination": "example.com", "port": 443, "action": "deny"}]), b"example.com".as_slice(), 443),
            (json!([{"destination": "example.com", "port": 443, "action": "allow", "session": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]), b"example.com".as_slice(), 443),
            (json!([allow]), b"example.com".as_slice(), 80),
            (json!([{"destination": "*.example.com", "port": 443, "action": "allow"}]), b"example.com".as_slice(), 443),
            (json!([allow]), b"example.com.attacker.org".as_slice(), 443),
            (json!([allow]), b"127.0.0.1".as_slice(), 443),
            (json!([allow]), b"0177.0.0.1".as_slice(), 443),
            (json!([allow]), b"example.com:443".as_slice(), 443),
            (json!([allow]), b"example.com\n".as_slice(), 443),
            (json!([allow]), b"example.com".as_slice(), 0),
        ] {
            let (egress, mut client, upstream, server) =
                configured_fixture(true, Some(tools(rules))).await;
            assert_eq!(authenticate_as(&mut client, TOOLS_USER, TOKEN.as_bytes()).await, [1, 0]);
            request(&mut client, host, port).await;
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 2);
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();
        }
        for request in [
            vec![5, 1, 0, 1, 127, 0, 0, 1, 1, 187],
            vec![5, 1, 0, 1, 10, 88, 0, 1, 1, 187],
            vec![5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187],
            vec![5, 2, 0, 3], // BIND
            vec![5, 3, 0, 3], // UDP ASSOCIATE
            vec![5, 1, 1, 3], // Invalid reserved byte
            vec![5, 1, 0, 2], // Unsupported address type
        ] {
            let (egress, mut client, upstream, server) =
                configured_fixture(false, Some(tools(json!([])))).await;
            assert_eq!(authenticate_as(&mut client, TOOLS_USER, TOKEN.as_bytes()).await, [1, 0]);
            client.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_ne!(reply[1], 0);
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert!(upstream.accept().now_or_never().is_none());
            egress.revoke();
            server.await.unwrap().unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn allowed_tools_relay_canonical_destinations_with_external_credentials_and_revoke() {
    timeout(Duration::from_secs(5), async {
        // Literal wire frames make the address type, canonical name and port
        // observable at the actual upstream socket, without resolving them.
        for (host, incoming, outgoing) in [
            ("example.com", b"\x05\x01\x00\x03\x0cEXAMPLE.COM.\x01\xbb".as_slice(), b"\x05\x01\x00\x03\x0bexample.com\x01\xbb".as_slice()),
            ("8.8.8.8", b"\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb".as_slice(), b"\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb".as_slice()),
            ("8.8.8.8", b"\x05\x01\x00\x03\x078.8.8.8\x01\xbb".as_slice(), b"\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb".as_slice()),
            ("2001:4860:4860::8888", b"\x05\x01\x00\x04\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88\x01\xbb".as_slice(), b"\x05\x01\x00\x04\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88\x01\xbb".as_slice()),
        ] {
            for authenticated in [false, true] {
                let (egress, mut client, upstream, server) = configured_fixture(authenticated, Some(tools(json!([
                    {"destination": host, "port": 443, "action": "allow", "session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
                ])))).await;
                assert_eq!(authenticate_as(&mut client, TOOLS_USER, TOKEN.as_bytes()).await, [1, 0]);
                let proxy = tokio::spawn(async move {
                    let mut proxy = external_request(upstream, authenticated, outgoing).await;
                    let mut bytes = [0; 7];
                    proxy.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"opaque!");
                    proxy.write_all(b"reply!").await.unwrap();
                    assert_eq!(proxy.read(&mut bytes).await.unwrap(), 0);
                });
                client.write_all(incoming).await.unwrap();
                let mut reply = [0; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                client.write_all(b"opaque!").await.unwrap();
                let mut bytes = [0; 6];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"reply!");
                egress.revoke();
                server.await.unwrap().unwrap();
                assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
                proxy.await.unwrap();
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn tools_rules_cannot_expand_the_api_role() {
    use futures_util::FutureExt;
    timeout(Duration::from_secs(5), async {
        let (egress, mut client, upstream, server) = configured_fixture(
            false,
            Some(tools(json!([
                {"destination": "example.com", "port": 443, "action": "allow"}
            ]))),
        )
        .await;
        assert_eq!(authenticate(&mut client, TOKEN.as_bytes()).await, [1, 0]);
        request(&mut client, b"example.com", 443).await;
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert!(upstream.accept().now_or_never().is_none());
        egress.revoke();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn readiness_negotiates_authentication_without_sending_connect_or_a_target() {
    for authenticated in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, if authenticated { 2 } else { 0 }]);
            stream.write_all(&[5, greeting[2]]).await.unwrap();
            if authenticated {
                let mut credentials = [0; 5];
                stream.read_exact(&mut credentials).await.unwrap();
                assert_eq!(&credentials, &[1, 1, b'u', 1, b'p']);
                stream.write_all(&[1, 0]).await.unwrap();
            }
            // Successful observation closes here, before any CONNECT or DNS target.
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let mut stream = TcpStream::connect(endpoint).await.unwrap();
        super::authenticate(
            &mut stream,
            authenticated.then_some((b"u".as_slice(), b"p".as_slice())),
        )
        .await
        .unwrap();
        drop(stream);
        peer.await.unwrap();
    }
}
