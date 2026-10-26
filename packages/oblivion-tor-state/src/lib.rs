//! Version-pinned, selective Tor persistence. No filesystem or network access.
use std::collections::HashSet;

pub const VERSION: &str = "0.4.9.14";
pub const LIMIT: usize = 128 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidState;

#[derive(Debug, PartialEq, Eq)]
pub struct State(String);

impl State {
    /// A saved profile must already be selective. Never silently discard an
    /// unknown field or migrate state from an unreviewed Tor version.
    pub fn parse(text: &str) -> Result<Self, InvalidState> {
        let state = Self::select(text)?;
        if state.0 != text {
            return Err(InvalidState);
        }
        Ok(state)
    }

    /// Extract guard records from Tor's RAM-only full state file. The other
    /// sections include traffic counters and activity history and stay in RAM.
    pub fn select(text: &str) -> Result<Self, InvalidState> {
        if text.len() > LIMIT || !text.is_ascii() || text.contains('\0') {
            return Err(InvalidState);
        }
        let mut guards = Vec::new();
        let mut identities = HashSet::new();
        let mut version = None;
        let mut written = None;
        for line in text.lines() {
            if line.starts_with("Guard") && !line.starts_with("Guard ") {
                return Err(InvalidState);
            }
            if let Some(value) = line.strip_prefix("Guard ") {
                if guards.len() == 512 || value.len() > 2048 {
                    return Err(InvalidState);
                }
                let mut fields = HashSet::new();
                let mut selection = None;
                let mut identity = None;
                for part in value.split(' ') {
                    let (key, value) = part.split_once('=').ok_or(InvalidState)?;
                    if !fields.insert(key) || value.is_empty() {
                        return Err(InvalidState);
                    }
                    let valid = match key {
                        "in" => {
                            selection = Some(value);
                            matches!(value, "default" | "restricted" | "bridges")
                        }
                        "rsa_id" => {
                            identity = Some(value);
                            value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        }
                        "sampled_on" | "unlisted_since" | "confirmed_on" => timestamp(value, b'T'),
                        "sampled_idx" | "confirmed_idx" => {
                            value.parse::<i32>().is_ok_and(|value| value >= 0)
                        }
                        "listed" => matches!(value, "0" | "1"),
                        "sampled_by" => {
                            value.len() <= 128
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric() || b".-_()".contains(&byte)
                                })
                        }
                        "nickname" => {
                            value.len() <= 19
                                && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
                        }
                        "bridge_addr" => value
                            .parse::<std::net::SocketAddr>()
                            .is_ok_and(|address| address.port() != 0),
                        "pb_use_attempts"
                        | "pb_use_successes"
                        | "pb_circ_attempts"
                        | "pb_circ_successes"
                        | "pb_successful_circuits_closed"
                        | "pb_collapsed_circuits"
                        | "pb_unusable_circuits"
                        | "pb_timeouts" => value
                            .parse::<f64>()
                            .is_ok_and(|value| value.is_finite() && (0.0..=1e12).contains(&value)),
                        _ => false,
                    };
                    if !valid {
                        return Err(InvalidState);
                    }
                }
                if fields.contains("confirmed_idx") != fields.contains("confirmed_on")
                    || !["in", "rsa_id", "sampled_on", "sampled_idx", "listed"]
                        .iter()
                        .all(|key| fields.contains(key))
                    || !identities.insert((
                        selection.ok_or(InvalidState)?,
                        identity.ok_or(InvalidState)?.to_ascii_uppercase(),
                    ))
                {
                    return Err(InvalidState);
                }
                guards.push(line);
                continue;
            }
            if let Some(value) = line.strip_prefix("TorVersion ") {
                if version.replace(value).is_some() || value != format!("Tor {VERSION}") {
                    return Err(InvalidState);
                }
            }
            if let Some(value) = line.strip_prefix("LastWritten ") {
                if written.replace(value).is_some() || !timestamp(value, b' ') {
                    return Err(InvalidState);
                }
            }
        }
        let version = version.ok_or(InvalidState)?;
        let written = written.ok_or(InvalidState)?;
        let mut selected = guards.join("\n");
        if !selected.is_empty() {
            selected.push('\n');
        }
        selected.push_str(&format!("TorVersion {version}\nLastWritten {written}\n"));
        Ok(Self(selected))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn has_guards(&self) -> bool {
        self.0.starts_with("Guard ")
    }

    /// Avoid rewriting the USB only because unrelated counters changed the
    /// full state's LastWritten timestamp.
    pub fn same_guards(&self, other: &Self) -> bool {
        self.0
            .lines()
            .filter(|line| line.starts_with("Guard "))
            .eq(other.0.lines().filter(|line| line.starts_with("Guard ")))
    }
}

fn timestamp(value: &str, separator: u8) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != separator
        || bytes[13] != b':'
        || bytes[16] != b':'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [4, 7, 10, 13, 16].contains(&index) || byte.is_ascii_digit())
    {
        return false;
    }
    let number = |start: usize, end: usize| value[start..end].parse::<u32>().unwrap_or(0);
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    year >= 1970
        && day >= 1
        && day <= days
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}

#[cfg(test)]
mod tests {
    use super::State;

    const GUARD: &str = "Guard in=default rsa_id=0123456789ABCDEF0123456789ABCDEF01234567 nickname=TestGuard sampled_on=2026-10-24T01:02:03 sampled_idx=0 sampled_by=0.4.9.14 listed=1 confirmed_on=2026-10-24T01:03:04 confirmed_idx=0 pb_circ_attempts=4.000000 pb_circ_successes=3.000000\n";
    const META: &str = "TorVersion Tor 0.4.9.14\nLastWritten 2026-10-24 01:04:05\n";

    #[test]
    fn retains_guard_identity_order_and_path_bias_without_traffic_history() {
        let raw = format!(
            "# generated in RAM\nBWHistoryReadValues 100,200\n{GUARD}Dormant 0\nCircuitBuildTimeBin 50 3\n{META}"
        );
        let state = State::select(&raw).unwrap();
        assert_eq!(state.as_str(), format!("{GUARD}{META}"));
        assert!(state.has_guards());
        assert_eq!(State::parse(state.as_str()).unwrap(), state);
        assert!(State::parse(&raw).is_err());
    }

    #[test]
    fn rejects_unreviewed_or_invalid_state_instead_of_resetting_guards() {
        let input = format!("{GUARD}{META}");
        for invalid in [
            input.replace("Tor 0.4.9.14", "Tor 0.4.10.0"),
            input.replace("listed=1", "listed=2"),
            input.replace("sampled_idx=0", "sampled_idx=-1"),
            input.replace("sampled_idx=0", "sampled_idx=0 unknown=1"),
            input.replace("2026-10-24T", "2026-02-30T"),
            input.replace("4.000000", "NaN"),
            input.replace("in=default", "in=default in=bridges"),
            format!("{GUARD}{GUARD}{META}"),
            input.replace("Guard ", "Guard\t"),
            format!("{input}BWHistoryWriteValues 123\n"),
        ] {
            assert!(
                State::parse(&invalid).is_err(),
                "accepted malformed profile"
            );
        }
    }

    #[test]
    fn metadata_only_changes_do_not_require_another_usb_write() {
        let before = State::parse(&format!("{GUARD}{META}")).unwrap();
        let after =
            State::parse(&format!("{GUARD}{META}").replace("01:04:05", "01:04:06")).unwrap();
        assert!(before.same_guards(&after));
        assert!(!before.same_guards(&State::parse(META).unwrap()));
        assert!(!State::parse(META).unwrap().has_guards());
    }
}
