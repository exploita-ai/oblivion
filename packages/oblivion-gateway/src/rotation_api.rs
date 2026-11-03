//! Unprivileged, session-authenticated bridge for one fixed controller action.
//! It has no Tor cookie, provider key, destination parameter or external route.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header::AUTHORIZATION,
    server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, io, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, UnixStream},
    sync::{Semaphore, mpsc, oneshot}, task::JoinSet, time::timeout};
use zeroize::Zeroizing;

pub async fn serve(listener: TcpListener, mut control: UnixStream, token: Zeroizing<String>) -> io::Result<()> {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid_capability"));
    }
    let authorization = Arc::new(Zeroizing::new(format!("Bearer {}", token.as_str())));
    let slots = Arc::new(Semaphore::new(1));
    let (requests, mut incoming) = mpsc::channel::<oneshot::Sender<u8>>(1);
    let controller = async move {
        loop {
            let reply = tokio::select! {
                request = incoming.recv() => match request {
                    Some(reply) => reply,
                    None => return Ok::<_, io::Error>(()),
                },
                closed = control.read_u8() => return match closed {
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
                    Err(error) => Err(error),
                    Ok(_) => Err(io::Error::other("unexpected_rotation_reply")),
                },
            };
            control.write_all(b"R").await?;
            // The trusted controller has a shorter deadline. Losing this channel
            // exits the process; its supervisor then revokes the entire grant.
            let result = timeout(Duration::from_secs(150), control.read_u8()).await??;
            if !b"SNFUCTPDBXOIVEHRL".contains(&result) { return Err(io::Error::other("invalid_rotation_reply")); }
            let _ = reply.send(result);
        }
    };
    tokio::pin!(controller);
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            result = &mut controller => break result,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                if connections.len() >= 8 { continue; }
                let authorization = authorization.clone();
                let slots = slots.clone();
                let requests = requests.clone();
                connections.spawn(async move {
                    let service = service_fn(move |request| handle(request, authorization.clone(), slots.clone(), requests.clone()));
                    let _ = http1::Builder::new().timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(3)).max_headers(12)
                        .max_buf_size(8192).keep_alive(false)
                        .serve_connection(TokioIo::new(socket), service).await;
                });
            }
        }
    };
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

async fn handle(request: Request<Incoming>, authorization: Arc<Zeroizing<String>>, slots: Arc<Semaphore>, requests: mpsc::Sender<oneshot::Sender<u8>>) -> Result<Response<Full<Bytes>>, Infallible> {
    let headers = request.headers().get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    if headers.len() != 1 || !bool::from(headers[0].as_bytes().ct_eq(authorization.as_bytes())) {
        return Ok(reply(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if request.method() != Method::POST || request.uri().path_and_query().map(|v| v.as_str()) != Some("/tor/rotate") {
        return Ok(reply(StatusCode::NOT_FOUND, "unsupported_operation"));
    }
    // No request-controlled Tor options, addresses, timeouts or test switches.
    match timeout(Duration::from_secs(3), Limited::new(request.into_body(), 0).collect()).await {
        Ok(Ok(_)) => {},
        _ => return Ok(reply(StatusCode::BAD_REQUEST, "empty_body_required")),
    }
    let Ok(_permit) = slots.try_acquire_owned() else {
        return Ok(reply(StatusCode::CONFLICT, "rotation_in_progress"));
    };
    let (send, receive) = oneshot::channel();
    if requests.send(send).await.is_err() {
        return Ok(reply(StatusCode::SERVICE_UNAVAILABLE, "controller_unavailable"));
    }
    Ok(match receive.await {
        Ok(b'S') => reply(StatusCode::OK, "rotated"),
        Ok(b'N') => reply(StatusCode::OK, "renewed"),
        Ok(b'F') => reply(StatusCode::SERVICE_UNAVAILABLE, "blocked"),
        Ok(reason @ (b'P' | b'D' | b'B' | b'X' | b'O' | b'I' | b'V' | b'E' | b'H' | b'R' | b'L')) => {
            // Closed diagnostic vocabulary only: no raw Tor replies, paths,
            // endpoints, credentials or logs cross this boundary.
            let phase = match reason {
                b'P' => "preparing",
                b'D' => "draining",
                b'B' => "circuit_build",
                b'X' => "previous_exit",
                b'O' => "deadline",
                b'I' => "isolation",
                b'E' => "circuit_status",
                b'H' => "tor_information",
                b'R' => "tor_reply",
                b'L' => "listener_in_use",
                _ => "verification",
            };
            let mut response = reply(StatusCode::SERVICE_UNAVAILABLE, "blocked");
            *response.body_mut() = Full::new(Bytes::from(format!("{{\"status\":\"blocked\",\"phase\":\"{phase}\"}}")));
            response
        },
        Ok(b'U') => reply(StatusCode::CONFLICT, "tor_required"),
        Ok(b'C') => reply(StatusCode::TOO_MANY_REQUESTS, "cooldown"),
        Ok(b'T') => reply(StatusCode::CONFLICT, "rotation_not_allowed"),
        _ => reply(StatusCode::SERVICE_UNAVAILABLE, "controller_unavailable"),
    })
}

fn reply(status: StatusCode, state: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(format!("{{\"status\":\"{state}\"}}"))));
    *response.status_mut() = status;
    response.headers_mut().insert("content-type", "application/json".parse().unwrap());
    response.headers_mut().insert("cache-control", "no-store".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_fixed_operation_waits_for_controller_and_reports_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/tor/rotate", listener.local_addr().unwrap());
        let (child, mut control) = UnixStream::pair().unwrap();
        let token = "a".repeat(64);
        let auth = format!("Bearer {token}");
        let server = tokio::spawn(serve(listener, child, Zeroizing::new(token)));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        assert_eq!(client.post(&url).send().await.unwrap().status(), 401);
        assert_eq!(client.get(&url).header("Authorization", &auth).send().await.unwrap().status(), 404);
        assert_eq!(client.post(&url).header("Authorization", &auth).body("{\"exit\":\"chosen\"}").send().await.unwrap().status(), 400);
        let mut unexpected = [0];
        assert_eq!(control.try_read(&mut unexpected).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        for (byte, expected, status, phase) in [
            (b'S', "rotated", 200, None), (b'N', "renewed", 200, None),
            (b'F', "blocked", 503, None), (b'U', "tor_required", 409, None),
            (b'C', "cooldown", 429, None), (b'T', "rotation_not_allowed", 409, None),
            (b'P', "blocked", 503, Some("preparing")),
            (b'D', "blocked", 503, Some("draining")),
            (b'B', "blocked", 503, Some("circuit_build")),
            (b'X', "blocked", 503, Some("previous_exit")),
            (b'O', "blocked", 503, Some("deadline")),
            (b'I', "blocked", 503, Some("isolation")),
            (b'V', "blocked", 503, Some("verification")),
            (b'E', "blocked", 503, Some("circuit_status")),
            (b'H', "blocked", 503, Some("tor_information")),
            (b'R', "blocked", 503, Some("tor_reply")),
            (b'L', "blocked", 503, Some("listener_in_use")),
        ] {
            let request = client.post(&url).header("Authorization", &auth).send();
            tokio::pin!(request);
            let controller = async {
                assert_eq!(control.read_u8().await.unwrap(), b'R');
                // A second request cannot trigger a second concurrent rotation.
                assert_eq!(client.post(&url).header("Authorization", &auth).send().await.unwrap().status(), 409);
                control.write_all(&[byte]).await.unwrap();
            };
            let (response, ()) = tokio::join!(request, controller);
            let response = response.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
            assert_eq!(body, match phase {
                Some(phase) => serde_json::json!({"status": expected, "phase": phase}),
                None => serde_json::json!({"status": expected}),
            });
        }
        drop(control);
        timeout(Duration::from_secs(2), server).await.unwrap().unwrap().unwrap();
    }
}
