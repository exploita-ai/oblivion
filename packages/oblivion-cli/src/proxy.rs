//! Literal proxy syntax shared by run, network changes and saved profiles.
use oblivion_transport::{Authentication, Transport};
use std::net::SocketAddrV4;
use zeroize::Zeroizing;

// These contain credentials: deliberately no Debug implementation.
pub enum Request {
    Ready(Transport),
    NeedsPassword(PasswordRequest),
}

pub struct PasswordRequest {
    endpoint: SocketAddrV4,
    username: Zeroizing<String>,
}

impl PasswordRequest {
    /// The OS frontend obtains a password privately, then completes the request.
    /// Prompting and terminal handling do not belong to the portable parser.
    pub fn complete(self, password: Zeroizing<String>) -> Result<Transport, &'static str> {
        let transport = Transport::Socks5 {
            endpoint: self.endpoint,
            authentication: Some(Authentication {
                username: self.username,
                password,
            }),
        };
        transport.validate()?;
        Ok(transport)
    }
}

pub fn parse(url: &str) -> Result<Request, &'static str> {
    let value = url
        .strip_prefix("socks5h://")
        .or_else(|| url.strip_prefix("socks5://"))
        .ok_or("Expected socks5h://[USER:PASS@]IP:PORT")?;
    let Some((credentials, address)) = value.rsplit_once('@') else {
        let transport = Transport::Socks5 {
            endpoint: endpoint(value)?,
            authentication: None,
        };
        transport.validate()?;
        return Ok(Request::Ready(transport));
    };
    let Some((user, pass)) = credentials.split_once(':') else {
        let endpoint = endpoint(address)?;
        Transport::Socks5 {
            endpoint,
            authentication: None,
        }
        .validate()?;
        return Ok(Request::NeedsPassword(PasswordRequest {
            endpoint,
            username: decode(credentials)?,
        }));
    };
    let transport = Transport::Socks5 {
        endpoint: endpoint(address)?,
        authentication: Some(Authentication {
            username: decode(user)?,
            password: decode(pass)?,
        }),
    };
    transport.validate()?;
    Ok(Request::Ready(transport))
}

fn endpoint(value: &str) -> Result<SocketAddrV4, &'static str> {
    value
        .parse()
        .map_err(|_| "Proxy endpoint must be an IPv4 address and port")
}

fn decode(value: &str) -> Result<Zeroizing<String>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let digit = |byte: u8| {
            (byte as char)
                .to_digit(16)
                .map(|n| n as u8)
                .ok_or("Invalid proxy URL encoding")
        };
        bytes.push(
            digit(input.next().ok_or("Invalid proxy URL encoding")?)? * 16
                + digit(input.next().ok_or("Invalid proxy URL encoding")?)?,
        );
    }
    std::str::from_utf8(&bytes)
        .map(|value| Zeroizing::new(value.to_owned()))
        .map_err(|_| "Invalid proxy URL encoding")
}
