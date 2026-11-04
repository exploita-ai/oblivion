//! Pure control-client serialization over caller-owned byte streams.
//! Peer authentication, secret budgets, deadlines and lease ownership remain
//! in each operating-system adapter. Neither framing mode guesses the other.
use crate::control::{HEADER_LIMIT, NativeRequest, RESPONSE_LIMIT, Request, Response};
use crate::frame;
use serde::Serialize;
use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    Local,
    Native,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidRequest,
    InvalidResponse,
    HeaderTooLarge,
    SecretLengthMismatch,
    InvalidFrameLength,
    InvalidResponseLength,
    ResponseTooLarge,
    Rejected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(output),
            Self::InvalidRequest => output.write_str("invalid_control_request"),
            Self::InvalidResponse => output.write_str("invalid_control_response"),
            Self::HeaderTooLarge => output.write_str("header_too_large"),
            Self::SecretLengthMismatch => output.write_str("secret_length_mismatch"),
            Self::InvalidFrameLength => output.write_str("invalid_frame_length"),
            Self::InvalidResponseLength => output.write_str("invalid_response_length"),
            Self::ResponseTooLarge => output.write_str("response_too_large"),
            Self::Rejected(error) => output.write_str(error),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    /// OS adapters retain their existing timeout/transport error classification.
    pub fn into_boxed(self) -> Box<dyn std::error::Error> {
        match self {
            Self::Io(error) => Box::new(error),
            error => Box::new(error),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn write_request<S: Serialize>(
    writer: &mut impl Write,
    request: &Request<S>,
    secret: &[u8],
    framing: Framing,
) -> Result<()> {
    if request.secret_len as usize != secret.len() {
        return Err(Error::SecretLengthMismatch);
    }
    let header = match framing {
        Framing::Local => serde_json::to_vec(request),
        Framing::Native => serde_json::to_vec(&NativeRequest::new(request)),
    }
    .map_err(|_| Error::InvalidRequest)?;
    if header.len() > HEADER_LIMIT {
        return Err(match framing {
            Framing::Local => Error::InvalidFrameLength,
            Framing::Native => Error::HeaderTooLarge,
        });
    }
    frame::write(writer, &header, 1..=HEADER_LIMIT).map_err(|error| match error {
        frame::Error::Io(error) => Error::Io(error),
        frame::Error::InvalidLength => Error::InvalidFrameLength,
    })?;
    writer.write_all(secret).map_err(Error::Io)
}

pub fn read_response(reader: &mut impl Read, framing: Framing) -> Result<String> {
    let bytes = match framing {
        Framing::Local => {
            let mut bytes = Vec::new();
            reader
                .take(RESPONSE_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(Error::Io)?;
            if bytes.len() > RESPONSE_LIMIT {
                return Err(Error::ResponseTooLarge);
            }
            bytes
        }
        Framing::Native => {
            frame::read(reader, 1..=RESPONSE_LIMIT).map_err(|error| match error {
                frame::Error::Io(error) => Error::Io(error),
                frame::Error::InvalidLength => Error::InvalidResponseLength,
            })?
        }
    };
    let response: Response = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
    if !response.ok {
        // Preserve the server's static-identifier contract. Never surface its
        // arbitrary response output or rejected diagnostic text as an error.
        let error = response.error.filter(|value| {
            value.len() <= 80
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
        return Err(Error::Rejected(
            error.unwrap_or_else(|| "operation_rejected".into()),
        ));
    }
    Ok(response.output)
}
