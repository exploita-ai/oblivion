// Synthetic laboratory probe of the real Unix socket. Not installed in releases.
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn request(header: Value, secret: &[u8]) -> Value {
    let mut stream = UnixStream::connect("/run/oblivion-control.sock").unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let bytes = serde_json::to_vec(&header).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    stream.write_all(secret).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("unauthorized") {
        let mut stream = UnixStream::connect("/run/oblivion-control.sock").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["error"], "unauthorized_peer");
        return;
    }
    for (header, secret, error) in [
        (
            json!({"operation":"shell","secret_len":0}),
            &b""[..],
            "invalid_request",
        ),
        (
            json!({"operation":"status","secret_len":0,"path":"/etc/shadow"}),
            &b""[..],
            "invalid_request",
        ),
        (
            json!({"operation":"open","secret_len":0,"session":"../../profile"}),
            &b""[..],
            "invalid_session_id",
        ),
        (
            json!({"operation":"status","secret_len":1}),
            &b""[..],
            "unexpected_secret",
        ),
        (
            json!({"operation":"unlock","secret_len":1025}),
            &b""[..],
            "invalid_secret_length",
        ),
        (
            json!({"operation":"unlock","secret_len":16}),
            &b"short"[..],
            "incomplete_secret",
        ),
        (
            json!({"operation":"open","secret_len":16}),
            &b""[..],
            "invalid_session_argument",
        ),
    ] {
        let response = request(header, secret);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], error);
        assert_eq!(response["output"], "");
    }
    let mut stream = UnixStream::connect("/run/oblivion-control.sock").unwrap();
    stream.write_all(&1025u32.to_be_bytes()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["error"], "invalid_frame_length");
}
