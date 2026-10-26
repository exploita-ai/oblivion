pub mod policy;

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
use zeroize::Zeroizing;

// This type contains secrets: deliberately no Debug implementation. Only the
// trusted host and gateway receive it; manager status uses Metadata instead.
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Transport {
    Tor {},
    Socks5 {
        endpoint: SocketAddrV4,
        authentication: Option<Authentication>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Metadata {
    Tor {},
    Socks5 {
        endpoint: SocketAddrV4,
        authenticated: bool,
    },
}

impl Default for Transport {
    fn default() -> Self {
        Self::Tor {}
    }
}

impl Transport {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::Socks5 {
            endpoint,
            authentication,
        } = self
        {
            // The first transport supports literal IPv4 only. It cannot target
            // local Tor, the inside link, multicast or an unspecified address.
            let octets = endpoint.ip().octets();
            if endpoint.port() == 0
                || octets[0] == 0
                || octets[0] == 127
                || octets[0] >= 224
                || (octets[..3] == [10, 88, 0] && octets[3] < 4)
            {
                return Err("invalid_proxy_endpoint");
            }
            if let Some(authentication) = authentication {
                for secret in [&authentication.username, &authentication.password] {
                    if !(1..=255).contains(&secret.len()) || secret.chars().any(char::is_control) {
                        return Err("invalid_proxy_authentication");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn metadata(&self) -> Metadata {
        match self {
            Self::Tor {} => Metadata::Tor {},
            Self::Socks5 {
                endpoint,
                authentication,
            } => Metadata::Socks5 {
                endpoint: *endpoint,
                authenticated: authentication.is_some(),
            },
        }
    }

    pub fn endpoint(&self) -> SocketAddrV4 {
        match self {
            Self::Tor {} => SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9050),
            Self::Socks5 { endpoint, .. } => *endpoint,
        }
    }
}
