//! Proxy input shared by run, network changes and saved profiles.
use oblivion_transport::policy::Destination;
use oblivion_transport::{Authentication, Transport};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use zeroize::Zeroizing;

// These contain credentials: deliberately no Debug implementation.
pub enum Request {
    Ready(Transport),
    NeedsPassword(PasswordRequest),
    NeedsResolution(HostnameRequest),
}

pub struct PasswordRequest {
    endpoint: Endpoint,
    username: Zeroizing<String>,
}

pub struct HostnameRequest {
    endpoint: Destination,
    authentication: Option<Authentication>,
}

enum Endpoint {
    Ip(SocketAddrV4),
    Hostname(Destination),
}

impl PasswordRequest {
    /// The OS frontend obtains a password privately, then completes the request.
    /// Prompting and terminal handling do not belong to the portable parser.
    pub fn complete(self, password: Zeroizing<String>) -> Result<Transport, &'static str> {
        let authentication = Authentication {
            username: self.username,
            password,
        };
        authentication.validate()?;
        let authentication = Some(authentication);
        match self.endpoint {
            Endpoint::Ip(endpoint) => Ok(Transport::Socks5 {
                endpoint,
                authentication,
            }),
            Endpoint::Hostname(endpoint) => HostnameRequest {
                endpoint,
                authentication,
            }
            .resolve(),
        }
    }
}

impl HostnameRequest {
    fn resolve(self) -> Result<Transport, &'static str> {
        self.resolve_with(|host, port| (host, port).to_socket_addrs())
    }

    fn resolve_with<I: Iterator<Item = SocketAddr>>(
        self,
        lookup: impl FnOnce(&str, u16) -> std::io::Result<I>,
    ) -> Result<Transport, &'static str> {
        let port = self.endpoint.port();
        // An absolute lookup keeps the host resolver from appending search domains.
        let name = format!("{}.", self.endpoint.host());
        let endpoint = lookup(&name, port)
            .map_err(|_| "Could not resolve SOCKS5 proxy hostname")?
            .find_map(|address| match address {
                SocketAddr::V4(address)
                    if Destination::new(&address.ip().to_string(), port).is_ok() =>
                {
                    Some(SocketAddrV4::new(*address.ip(), port))
                }
                _ => None,
            })
            .ok_or("SOCKS5 proxy hostname has no public IPv4 address")?;
        Ok(Transport::Socks5 {
            endpoint,
            authentication: self.authentication,
        })
    }
}

impl Endpoint {
    const INVALID: &str = "Proxy endpoint must be an IPv4 address or hostname and port";

    fn authority(value: &str) -> Result<Self, &'static str> {
        let (host, port) = value.split_once(':').ok_or(Self::INVALID)?;
        Self::parse(host, port)
    }

    fn parse(host: &str, port: &str) -> Result<Self, &'static str> {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Self::INVALID);
        }
        let port = port.parse::<u16>().map_err(|_| Self::INVALID)?;
        if let Ok(ip) = host.parse() {
            let endpoint = SocketAddrV4::new(ip, port);
            Transport::Socks5 {
                endpoint,
                authentication: None,
            }
            .validate()?;
            return Ok(Self::Ip(endpoint));
        }
        Ok(Self::Hostname(
            Destination::new(host, port).map_err(|_| Self::INVALID)?,
        ))
    }

    fn request(self, authentication: Option<Authentication>) -> Result<Request, &'static str> {
        if let Some(authentication) = &authentication {
            authentication.validate()?;
        }
        Ok(match self {
            Self::Ip(endpoint) => Request::Ready(Transport::Socks5 {
                endpoint,
                authentication,
            }),
            Self::Hostname(endpoint) => Request::NeedsResolution(HostnameRequest {
                endpoint,
                authentication,
            }),
        })
    }
}

pub fn complete(
    request: Request,
    runtime: &mut impl crate::run::Runtime,
) -> crate::controller::Result<Transport> {
    match request {
        Request::Ready(transport) => Ok(transport),
        Request::NeedsResolution(request) => Ok(request.resolve()?),
        Request::NeedsPassword(request) => {
            let password = runtime.password("Proxy password")?;
            let password =
                std::str::from_utf8(&password).map_err(|_| "invalid_proxy_authentication")?;
            Ok(request.complete(Zeroizing::new(password.to_owned()))?)
        }
    }
}

pub fn read_hidden(runtime: &mut impl crate::run::Runtime) -> crate::controller::Result<Transport> {
    let entered = runtime.password("SOCKS5 endpoint (hidden)")?;
    let request = parse(std::str::from_utf8(&entered).map_err(|_| "invalid_proxy_url")?)?;
    drop(entered);
    complete(request, runtime)
}

pub fn parse(url: &str) -> Result<Request, &'static str> {
    let Some(value) = url
        .strip_prefix("socks5h://")
        .or_else(|| url.strip_prefix("socks5://"))
    else {
        let mut parts = url.splitn(4, ':');
        let host = parts.next().ok_or("Expected a SOCKS5 endpoint")?;
        let port = parts.next().ok_or("Expected a SOCKS5 endpoint")?;
        // Provider strings carry literal credentials. Only URI userinfo is decoded.
        let authentication = match (parts.next(), parts.next()) {
            (None, None) => None,
            (Some(username), Some(password)) => Some(Authentication {
                username: Zeroizing::new(username.to_owned()),
                password: Zeroizing::new(password.to_owned()),
            }),
            _ => return Err("Expected HOST:PORT or HOST:PORT:USER:PASS"),
        };
        return Endpoint::parse(host, port)?.request(authentication);
    };
    let Some((credentials, address)) = value.rsplit_once('@') else {
        return Endpoint::authority(value)?.request(None);
    };
    let endpoint = Endpoint::authority(address)?;
    let Some((user, pass)) = credentials.split_once(':') else {
        return Ok(Request::NeedsPassword(PasswordRequest {
            endpoint,
            username: decode(credentials)?,
        }));
    };
    endpoint.request(Some(Authentication {
        username: decode(user)?,
        password: decode(pass)?,
    }))
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

#[cfg(test)]
mod tests {
    use super::{Request, parse};
    use oblivion_transport::Transport;
    use std::net::SocketAddr;

    #[test]
    fn provider_entry_resolves_only_the_proxy_and_pins_a_public_ipv4() {
        let Request::NeedsResolution(request) =
            parse("Proxy.Example.COM.:5000:fixture-user:p%40ss:word@").unwrap()
        else {
            panic!("expected hostname resolution");
        };
        let answers = [
            "[::1]:5000",
            "169.254.169.254:5000",
            "192.168.1.2:5000",
            "93.184.216.34:5000",
        ]
        .map(|address| address.parse::<SocketAddr>().unwrap());
        let transport = request
            .resolve_with(|host, port| {
                assert_eq!((host, port), ("proxy.example.com.", 5000));
                Ok(answers.into_iter())
            })
            .unwrap();
        let Transport::Socks5 {
            endpoint,
            authentication,
        } = transport
        else {
            panic!()
        };
        assert_eq!(endpoint.to_string(), "93.184.216.34:5000");
        let authentication = authentication.unwrap();
        assert_eq!(authentication.username.as_str(), "fixture-user");
        assert_eq!(authentication.password.as_str(), "p%40ss:word@");
    }

    #[test]
    fn hostname_resolution_rejects_private_answers_and_hides_resolver_errors() {
        let hostname =
            || match parse("socks5h://fixture-user:fixture-pass@proxy.example.com:5000").unwrap() {
                Request::NeedsResolution(request) => request,
                _ => panic!("expected hostname resolution"),
            };
        let answer = "10.88.0.2:5000".parse().unwrap();
        assert_eq!(
            hostname()
                .resolve_with(|_, _| Ok(std::iter::once(answer)))
                .err(),
            Some("SOCKS5 proxy hostname has no public IPv4 address"),
        );
        assert_eq!(
            hostname()
                .resolve_with::<std::iter::Empty<SocketAddr>>(|_, _| {
                    Err(std::io::Error::other("resolver included proxy.example.com"))
                })
                .err(),
            Some("Could not resolve SOCKS5 proxy hostname"),
        );
        assert!(matches!(
            parse("socks5://fixture-user@proxy.example.com:5000"),
            Ok(Request::NeedsPassword(_))
        ));
        for invalid in [
            "proxy.example.com:0:user:pass",
            "proxy.example.com:5000:user",
            "proxy.example.com:5000:user:",
            "proxy.example.com:5000::pass",
            "proxy..example.com:5000:user:pass",
        ] {
            assert!(parse(invalid).is_err());
        }
    }
}
