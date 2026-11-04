//! Private runtime handshakes. OS adapters supply entropy and streams whose
//! individual I/O calls are bounded; tokens never enter diagnostic data.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const READY: &[u8; 8] = b"OBLVPRV2";
pub const SET: &[u8; 8] = b"OBLVSET2";
pub const HELLO: &[u8; 8] = b"OBLVCTL1";
pub const ACK: &[u8; 8] = b"OBLVAUT1";

pub const DATA_LIMIT: usize = 512;

/// The host may authorize initialization only while it owns the capability
/// returned by creating a fresh disk. Paths and device selectors are excluded.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Data {
    Existing,
    NewDisk { runtime_id: String, bytes: u64 },
}

impl Data {
    pub fn validate(&self) -> Result<()> {
        if let Self::NewDisk { runtime_id, bytes } = self {
            if !crate::control::valid_id(runtime_id)
                || runtime_id.bytes().all(|byte| byte == b'0')
                || !(4 * 1024 * 1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(bytes)
                || bytes % (1024 * 1024) != 0
            {
                return Err(Error("invalid_runtime_data_authority"));
            }
        }
        Ok(())
    }
}

pub struct Token(Zeroizing<[u8; 32]>);
impl Token {
    pub fn from_entropy(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub fn provision(
    stream: &mut (impl Read + Write),
    token: &Token,
    data: &Data,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    data.validate()?;
    let data = serde_json::to_vec(data).map_err(|_| Error("invalid_runtime_data_authority"))?;
    if data.len() > DATA_LIMIT {
        return Err(Error("invalid_runtime_data_authority"));
    }
    let mut ready = [0; 8];
    receive(stream, &mut ready, stop, deadline)?;
    if &ready != READY {
        return Err(Error("runtime_auth_provision_failed"));
    }
    send(
        stream,
        token.0.as_slice(),
        stop,
        deadline,
        "runtime_auth_provision_failed",
    )?;
    send(
        stream,
        &(data.len() as u32).to_be_bytes(),
        stop,
        deadline,
        "runtime_auth_provision_failed",
    )?;
    send(
        stream,
        &data,
        stop,
        deadline,
        "runtime_auth_provision_failed",
    )?;
    let mut acknowledged = [0; 8];
    receive(stream, &mut acknowledged, stop, deadline)?;
    if &acknowledged != SET {
        return Err(Error("runtime_auth_provision_failed"));
    }
    check(stop, deadline)
}

pub fn authenticate(
    stream: &mut (impl Read + Write),
    token: &Token,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    send(stream, HELLO, stop, deadline, "guest_control_unavailable")?;
    send(
        stream,
        token.0.as_slice(),
        stop,
        deadline,
        "guest_control_unavailable",
    )?;
    let mut acknowledged = [0; 8];
    receive(stream, &mut acknowledged, stop, deadline)?;
    if &acknowledged != ACK {
        return Err(Error("runtime_control_authentication_failed"));
    }
    check(stop, deadline)
}

fn receive(
    stream: &mut impl Read,
    mut output: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    while !output.is_empty() {
        check(stop, deadline)?;
        match stream.read(output) {
            Ok(0) => return Err(Error("guest_control_unavailable")),
            Ok(length) => output = &mut output[length..],
            Err(error) if retryable(&error) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return Err(Error("guest_control_unavailable")),
        }
    }
    Ok(())
}

fn send(
    stream: &mut impl Write,
    mut input: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
    failure: &'static str,
) -> Result<()> {
    while !input.is_empty() {
        check(stop, deadline)?;
        match stream.write(input) {
            Ok(0) => return Err(Error(failure)),
            Ok(length) => input = &input[length..],
            Err(error) if retryable(&error) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return Err(Error(failure)),
        }
    }
    loop {
        check(stop, deadline)?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) if retryable(&error) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return Err(Error(failure)),
        }
    }
}

fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
    if stop.load(Ordering::Relaxed) {
        return Err(Error("runtime_auth_cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error("runtime_auth_timeout"));
    }
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::{ACK, Data, Error, HELLO, READY, SET, Token, authenticate, provision};
    use std::io::{self, Cursor, Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;
    struct Stream {
        input: Cursor<Vec<u8>>,
        output: Zeroizing<Vec<u8>>,
        chunk: usize,
        retry_read: bool,
        retry_write: bool,
        retry_flush: bool,
        flushed: usize,
        fail_write: bool,
    }
    impl Read for Stream {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.retry_read) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let length = output.len().min(self.chunk);
            self.input.read(&mut output[..length])
        }
    }
    impl Write for Stream {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::other("secret-canary"));
            }
            if std::mem::take(&mut self.retry_write) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let length = input.len().min(self.chunk);
            self.output.extend_from_slice(&input[..length]);
            Ok(length)
        }
        fn flush(&mut self) -> io::Result<()> {
            if std::mem::take(&mut self.retry_flush) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.flushed += 1;
            Ok(())
        }
    }
    fn stream(input: &[u8]) -> Stream {
        Stream {
            input: Cursor::new(input.to_vec()),
            output: Zeroizing::new(vec![]),
            chunk: usize::MAX,
            retry_read: false,
            retry_write: false,
            retry_flush: false,
            flushed: 0,
            fail_write: false,
        }
    }
    fn token() -> Token {
        Token::from_entropy(Zeroizing::new([7; 32]))
    }

    #[test]
    fn ready_gates_token_and_authority_before_current_control_authentication() {
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut bootstrap = stream(&[READY.as_slice(), SET.as_slice()].concat());
        provision(&mut bootstrap, &token(), &Data::Existing, &stop, deadline).unwrap();
        assert_eq!(&bootstrap.output[..32], &[7; 32]);
        assert_eq!(&bootstrap.output[32..36], &19u32.to_be_bytes());
        assert_eq!(&bootstrap.output[36..], br#"{"kind":"existing"}"#);
        assert_eq!(bootstrap.flushed, 3);
        let mut connection = stream(ACK);
        authenticate(&mut connection, &token(), &stop, deadline).unwrap();
        assert_eq!(&connection.output[..8], HELLO);
        assert_eq!(&connection.output[8..], &[7; 32]);
        assert_eq!(connection.flushed, 2);
    }

    #[test]
    fn fragmented_retryable_read_write_and_flush_use_the_same_protocol() {
        let mut stream = stream(&[READY.as_slice(), SET.as_slice()].concat());
        stream.chunk = 3;
        stream.retry_read = true;
        stream.retry_write = true;
        stream.retry_flush = true;
        provision(
            &mut stream,
            &token(),
            &Data::Existing,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(&stream.output[..32], &[7; 32]);
        assert_eq!(&stream.output[36..], br#"{"kind":"existing"}"#);
        assert_eq!(stream.flushed, 3);
    }

    #[test]
    fn wrong_ready_cancellation_and_expiry_never_send_token() {
        let stop = AtomicBool::new(false);
        let mut wrong = stream(b"PRIVATE!");
        assert_eq!(
            provision(
                &mut wrong,
                &token(),
                &Data::Existing,
                &stop,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error("runtime_auth_provision_failed"))
        );
        assert!(wrong.output.is_empty());
        stop.store(true, Ordering::Relaxed);
        let mut cancelled = stream(READY);
        assert_eq!(
            provision(
                &mut cancelled,
                &token(),
                &Data::Existing,
                &stop,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error("runtime_auth_cancelled"))
        );
        assert!(cancelled.output.is_empty());
        stop.store(false, Ordering::Relaxed);
        assert_eq!(
            provision(
                &mut cancelled,
                &token(),
                &Data::Existing,
                &stop,
                Instant::now()
            ),
            Err(Error("runtime_auth_timeout"))
        );
        assert!(cancelled.output.is_empty());
    }

    #[test]
    fn rejections_and_io_errors_preserve_linux_fatal_classification_without_raw_error() {
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut wrong = stream(b"REJECTED");
        assert_eq!(
            authenticate(&mut wrong, &token(), &stop, deadline),
            Err(Error("runtime_control_authentication_failed"))
        );
        let mut closed = stream(&[]);
        assert_eq!(
            authenticate(&mut closed, &token(), &stop, deadline),
            Err(Error("guest_control_unavailable"))
        );
        let mut failing = stream(READY);
        failing.fail_write = true;
        let error =
            provision(&mut failing, &token(), &Data::Existing, &stop, deadline).unwrap_err();
        assert_eq!(error, Error("runtime_auth_provision_failed"));
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn fresh_disk_authority_has_only_bounded_identity_and_capacity() {
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut bootstrap = stream(&[READY.as_slice(), SET.as_slice()].concat());
        provision(
            &mut bootstrap,
            &token(),
            &Data::NewDisk {
                runtime_id: "a".repeat(32),
                bytes: 8 * 1024 * 1024 * 1024,
            },
            &stop,
            deadline,
        )
        .unwrap();
        let data: Data = serde_json::from_slice(&bootstrap.output[36..]).unwrap();
        data.validate().unwrap();
        for data in [
            Data::NewDisk {
                runtime_id: "0".repeat(32),
                bytes: 8 * 1024 * 1024 * 1024,
            },
            Data::NewDisk {
                runtime_id: "a".repeat(32),
                bytes: 1,
            },
            Data::NewDisk {
                runtime_id: "a".repeat(32),
                bytes: 4 * 1024 * 1024 * 1024 + 1,
            },
        ] {
            let mut bootstrap = stream(READY);
            assert_eq!(
                provision(&mut bootstrap, &token(), &data, &stop, deadline),
                Err(Error("invalid_runtime_data_authority"))
            );
            assert!(bootstrap.output.is_empty());
        }
        assert!(serde_json::from_str::<Data>(r#"{"kind":"new-disk","runtime_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":8589934592,"path":"/dev/sda"}"#).is_err());
    }
}
