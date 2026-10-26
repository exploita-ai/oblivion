use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const RULE_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

// No Debug: destinations and session identities are not diagnostic output.
#[derive(Clone, PartialEq, Eq)]
pub struct Destination {
    host: String,
    port: u16,
}

impl Destination {
    pub fn new(host: &str, port: u16) -> Result<Self, &'static str> {
        if port == 0 {
            return Err("invalid_destination_port");
        }
        Ok(Self {
            host: hostname(host)?,
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct Session(String);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    pub session: Session,
    pub policy: Policy,
}

impl Session {
    pub fn new(id: &str) -> Result<Self, &'static str> {
        session(id)?;
        Ok(Self(id.to_owned()))
    }
}

impl TryFrom<String> for Session {
    type Error = &'static str;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        session(&id)?;
        Ok(Self(id))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(try_from = "Input")]
pub struct Policy {
    version: u8,
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    rules: Vec<Rule>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RuleInput")]
pub struct Rule {
    destination: String,
    port: u16,
    action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    destination: String,
    port: u16,
    action: Action,
    #[serde(default)]
    session: Option<String>,
}

impl Rule {
    pub fn new(
        destination: String,
        port: u16,
        action: Action,
        session: Option<String>,
    ) -> Result<Self, &'static str> {
        RuleInput {
            destination,
            port,
            action,
            session,
        }
        .try_into()
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn action(&self) -> Action {
        self.action
    }
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }
}

impl TryFrom<RuleInput> for Rule {
    type Error = &'static str;

    fn try_from(input: RuleInput) -> Result<Self, Self::Error> {
        if let Some(id) = &input.session {
            session(id)?;
        }
        let wildcard = input.destination.starts_with("*.");
        let target = Destination::new(
            input
                .destination
                .strip_prefix("*.")
                .unwrap_or(&input.destination),
            input.port,
        )?;
        if wildcard && target.host.parse::<IpAddr>().is_ok() {
            return Err("invalid_destination_pattern");
        }
        Ok(Self {
            destination: if wildcard {
                format!("*.{}", target.host)
            } else {
                target.host
            },
            port: input.port,
            action: input.action,
            session: input.session,
        })
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
        }
    }
}

impl TryFrom<Input> for Policy {
    type Error = &'static str;

    fn try_from(input: Input) -> Result<Self, Self::Error> {
        if input.version != 1 || input.rules.len() > RULE_LIMIT {
            return Err("invalid_network_policy");
        }
        Ok(Self {
            version: 1,
            rules: input.rules,
        })
    }
}

impl Policy {
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn put(&mut self, rule: Rule) -> Result<(), &'static str> {
        let matches = |existing: &Rule| {
            existing.destination == rule.destination
                && existing.port == rule.port
                && existing.session == rule.session
        };
        if self.rules.len() == RULE_LIMIT && !self.rules.iter().any(matches) {
            return Err("too_many_network_rules");
        }
        self.rules.retain(|existing| !matches(existing));
        self.rules.push(rule);
        Ok(())
    }

    pub fn remove(&mut self, rule: &Rule) -> Result<(), &'static str> {
        let index = self
            .rules
            .iter()
            .position(|existing| existing == rule)
            .ok_or("network_rule_missing")?;
        self.rules.remove(index);
        Ok(())
    }

    // Order-independent and restrictive: any matching deny wins, then ask,
    // then allow. An unknown destination stays pending, never implicitly allowed.
    pub fn decision(&self, session: &Session, destination: &Destination) -> Action {
        self.rules
            .iter()
            .filter(|rule| {
                rule.port == destination.port
                    && rule.session.as_ref().is_none_or(|id| id == &session.0)
                    && if let Some(suffix) = rule.destination.strip_prefix('*') {
                        destination.host.ends_with(suffix)
                    } else {
                        rule.destination == destination.host
                    }
            })
            .map(|rule| rule.action)
            .max()
            .unwrap_or(Action::Ask)
    }
}

fn session(id: &str) -> Result<(), &'static str> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid_policy_session");
    }
    Ok(())
}

fn hostname(input: &str) -> Result<String, &'static str> {
    // The HTTP/SOCKS boundary supplies a host, not a URL or an authority.
    // IPv6 brackets, ports, userinfo, escaped labels and zone IDs are rejected.
    if let Ok(address) = input.parse::<IpAddr>() {
        if special(address) {
            return Err("reserved_destination");
        }
        return Ok(address.to_string());
    }
    let host = input.strip_suffix('.').unwrap_or(input);
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err("invalid_destination_host");
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || !labels
            .last()
            .unwrap()
            .bytes()
            .any(|byte| byte.is_ascii_alphabetic())
    {
        return Err("invalid_destination_host");
    }
    let host = host.to_ascii_lowercase();
    if [
        "localhost",
        "local",
        "internal",
        "home",
        "lan",
        "arpa",
        "invalid",
        "test",
        "example",
    ]
    .iter()
    .any(|suffix| host.ends_with(&format!(".{suffix}")))
    {
        return Err("reserved_destination");
    }
    Ok(host)
}

fn special(address: IpAddr) -> bool {
    // Internet tools cannot target IANA special-purpose space, including its
    // globally reachable infrastructure exceptions. This is stricter than an
    // is_global test. Also exclude multicast and IPv6 outside 2000::/3.
    // Sources: IANA IPv4/IPv6 Special-Purpose Address Registries, 2025-10-09.
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168
                        || matches!(
                            (b, c),
                            (0, 0 | 2) | (31, 196) | (52, 193) | (88, 99) | (175, 48)
                        )))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(0x2000..=0x3fff).contains(&segments[0])
                || (segments[0] == 0x2001 && (segments[1] <= 0x1ff || segments[1] == 0xdb8))
                || segments[0] == 0x2002
                || (segments[..3] == [0x2620, 0x4f, 0x8000])
                || (segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}
