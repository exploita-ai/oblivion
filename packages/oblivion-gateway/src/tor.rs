use oblivion_tor_state::{LIMIT, State, VERSION};
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct Tor;

/// A recipient's canonical base32 X25519 public key, never its private key.
#[derive(Deserialize)]
#[serde(try_from = "String")]
pub struct ClientAuth(String);

impl TryFrom<String> for ClientAuth {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 52
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
            || !matches!(value.as_bytes().last(), Some(b'A' | b'Q'))
        {
            return Err("invalid_client_auth");
        }
        Ok(Self(value))
    }
}

/// Only for the dedicated transfer Tor instance. Never take ownership of the
/// model gateway's daemon: closing this connection intentionally terminates Tor.
pub struct OnionController(UnixStream);

pub struct OnionService {
    control: UnixStream,
    id: Zeroizing<String>,
}

impl OnionController {
    pub fn new() -> io::Result<Self> {
        let mut stream = connection()?;
        if request(&mut stream, "GETINFO version\r\n")? != [format!("250-version={VERSION}\r\n")] {
            return Err(io::Error::other("unsupported_tor_version"));
        }
        if !request(&mut stream, "TAKEOWNERSHIP\r\n")?.is_empty() {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(Self(stream))
    }

    /// Create exactly one private, ephemeral service with a fixed backend.
    /// The caller verifies bootstrap and firewall state before publication to
    /// the user. This primitive may prepare a service while Tor is disabled.
    pub fn publish(mut self, auth: &ClientAuth) -> io::Result<OnionService> {
        let lines = request(
            &mut self.0,
            &format!(
                "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,V3Auth,MaxStreamsCloseCircuit MaxStreams=8 Port=80,10.89.0.2:8080 ClientAuthV3={}\r\n",
                auth.0,
            ),
        )?;
        let mut id = None;
        let mut echoed = false;
        for line in lines {
            if let Some(value) = line
                .strip_prefix("250-ServiceID=")
                .and_then(|value| value.strip_suffix("\r\n"))
            {
                if id.is_some()
                    || value.len() != 56
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
                {
                    return Err(io::Error::other("unexpected_tor_reply"));
                }
                id = Some(Zeroizing::new(value.to_owned()));
                continue;
            }
            if !echoed && line == format!("250-ClientAuthV3={}\r\n", auth.0) {
                echoed = true;
                continue;
            }
            // DiscardPK must suppress private keys; never accept, retain or
            // forward a key, an arbitrary field or a duplicate from the daemon.
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(OnionService {
            control: self.0,
            id: id.ok_or_else(|| io::Error::other("missing_service_id"))?,
        })
    }
}

impl OnionService {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn revoke(mut self) -> io::Result<()> {
        if !request(
            &mut self.control,
            &format!("DEL_ONION {}\r\n", self.id.as_str()),
        )?
        .is_empty()
            || !request(&mut self.control, "SIGNAL SHUTDOWN\r\n")?.is_empty()
        {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        // This consumes the owner connection even on error. TAKEOWNERSHIP is
        // the crash fallback; the supervisor still confirms Tor's process exit
        // and reaps the file VM before acknowledging a completed close/lock.
        Ok(())
    }
}

impl Tor {
    pub fn initialize(state: Option<State>) -> io::Result<Self> {
        let had_guards = state.as_ref().is_some_and(State::has_guards);
        // Lazy startup: SOCKS mode must never launch Tor. Starting disabled
        // here initializes Tor's RAM state before import. Type=simple only
        // confirms process creation: wait for control before asking it to stop.
        service("start")?;
        ready()?;
        service("stop")?;
        // Tor has only run with DisableNetwork=1 in this fresh VM. Replace its
        // initial RAM state before permitting any external connection.
        if let Some(state) = state {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/var/lib/tor/state.oblivion")?;
            file.write_all(state.as_str().as_bytes())?;
            file.sync_all()?;
            if unsafe { libc::fchown(file.as_raw_fd(), 1200, 1200) } != 0 {
                return Err(io::Error::last_os_error());
            }
            fs::rename("/var/lib/tor/state.oblivion", "/var/lib/tor/state")?;
        }
        service("start")?;
        ready()?;
        let tor = Self;
        if had_guards && !tor.snapshot(false)?.has_guards() {
            return Err(io::Error::other("tor_state_rejected"));
        }
        Ok(tor)
    }

    pub fn enable(&self) -> io::Result<()> {
        let lines = control("SETCONF DisableNetwork=0\r\n")?;
        if !lines.is_empty() {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(())
    }

    pub fn disable(&self) -> io::Result<()> {
        if !control("SETCONF DisableNetwork=1\r\n")?.is_empty() {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(())
    }

    pub fn bootstrapped(&self) -> io::Result<bool> {
        Ok(self.progress()? == 100)
    }

    pub fn progress(&self) -> io::Result<u8> {
        bootstrap_progress(&control("GETINFO status/bootstrap-phase\r\n")?)
    }

    pub fn exits(&self) -> io::Result<std::collections::BTreeSet<String>> {
        Ok(circuits(&information("circuit-status")?)?.into_iter()
            .filter_map(|circuit| circuit.exit).collect())
    }

    pub fn prepare_rotation(&self, excluded: &std::collections::BTreeSet<String>) -> io::Result<()> {
        self.disable()?;
        let exits = excluded.iter().cloned().collect::<Vec<_>>().join(",");
        if !control(&format!("SETCONF ExcludeExitNodes={exits}\r\n"))?.is_empty() {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(())
    }

    pub fn drained(&self) -> io::Result<bool> {
        Ok(information("circuit-status")?.is_empty() && information("stream-status")?.is_empty())
    }

    pub fn build_circuit(&self) -> io::Result<u32> {
        let mut stream = connection()?;
        stream.write_all(b"EXTENDCIRCUIT 0 purpose=general\r\n")?;
        let line = read_line(&mut stream, Instant::now() + Duration::from_secs(5), &mut 4096)?;
        line.strip_prefix("250 EXTENDED ").and_then(|value| value.parse::<u32>().ok())
            .filter(|id| *id != 0).ok_or_else(|| io::Error::other("circuit_build_failed"))
    }

    pub fn circuit_ready(&self, id: u32, excluded: &std::collections::BTreeSet<String>) -> io::Result<bool> {
        let status = circuits(&information("circuit-status")?)?;
        if status.iter().any(|circuit| circuit.exit.as_ref().is_some_and(|exit| excluded.contains(exit))) {
            return Err(io::Error::other("previous_exit_reused"));
        }
        Ok(status.iter().any(|circuit| circuit.id == id && circuit.built && circuit.exit.is_some()))
    }

    pub fn snapshot(&self, stop: bool) -> io::Result<State> {
        if stop {
            service("stop")?;
        }
        let mut text = String::new();
        private_file("/var/lib/tor/state")?
            .take(LIMIT as u64 + 1)
            .read_to_string(&mut text)?;
        State::select(&text).map_err(|_| io::Error::other("invalid_tor_state"))
    }
}

struct Circuit { id: u32, built: bool, exit: Option<String> }

fn circuits(lines: &[String]) -> io::Result<Vec<Circuit>> {
    lines.iter().map(|line| {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let id = fields.first().and_then(|value| value.parse::<u32>().ok())
            .filter(|id| *id != 0).ok_or_else(|| io::Error::other("invalid_circuit_status"))?;
        let built = fields.get(1) == Some(&"BUILT");
        let hops = fields.get(2).map(|path| path.split(',').collect::<Vec<_>>()).unwrap_or_default();
        // Conflux circuits also carry application traffic and must not retain
        // an old exit when Tor links two paths for the same destination.
        let exit = if fields.iter().any(|field| matches!(*field, "PURPOSE=GENERAL" | "PURPOSE=CONFLUX_LINKED" | "PURPOSE=CONFLUX_UNLINKED")) && hops.len() >= 3 {
            let fingerprint = hops.last().unwrap().split(['~', '=']).next().unwrap();
            if fingerprint.len() != 41 || !fingerprint.starts_with('$') || !fingerprint[1..].bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(io::Error::other("invalid_exit_identity"));
            }
            Some(fingerprint.to_ascii_uppercase())
        } else { None };
        Ok(Circuit { id, built, exit })
    }).collect()
}

fn information(name: &str) -> io::Result<Vec<String>> {
    let mut stream = connection()?;
    stream.write_all(format!("GETINFO {name}\r\n").as_bytes())?;
    read_information(&mut stream, name)
}

fn read_information(stream: &mut UnixStream, name: &str) -> io::Result<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut remaining = 65536;
    let header = read_line(stream, deadline, &mut remaining)?;
    // GETINFO uses an inline value when exactly one circuit/stream remains.
    // That is common immediately after DisableNetwork or EXTENDCIRCUIT, not
    // an invalid response or an empty/drained state.
    if let Some(value) = header.strip_prefix(&format!("250-{name}=")) {
        if read_line(stream, deadline, &mut remaining)? != "250 OK" {
            return Err(io::Error::other("invalid_tor_information"));
        }
        return Ok(if value.is_empty() { Vec::new() } else { vec![value.to_owned()] });
    }
    if header != format!("250+{name}=") { return Err(io::Error::other("invalid_tor_information")); }
    let mut lines = Vec::new();
    loop {
        let line = read_line(stream, deadline, &mut remaining)?;
        if line == "." { break; }
        lines.push(line);
    }
    if read_line(stream, deadline, &mut remaining)? != "250 OK" {
        return Err(io::Error::other("invalid_tor_information"));
    }
    Ok(lines)
}

fn read_line(stream: &mut UnixStream, deadline: Instant, remaining: &mut usize) -> io::Result<String> {
    let mut line = Vec::new();
    while *remaining > 0 {
        *remaining -= 1;
        stream.set_read_timeout(Some(deadline.checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            if !line.ends_with(b"\r\n") { break; }
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|_| io::Error::other("invalid_tor_line"));
        }
    }
    Err(io::Error::other("invalid_tor_line"))
}

fn ready() -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match control("GETINFO version\r\n") {
            Ok(lines) if lines == [format!("250-version={VERSION}\r\n")] => return Ok(()),
            Ok(_) => return Err(io::Error::other("unsupported_tor_version")),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(error),
        }
    }
}

fn private_file(path: &str) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 1200
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::other("unsafe_tor_file"));
    }
    Ok(file)
}

fn service(operation: &str) -> io::Result<()> {
    let status = Command::new("/usr/bin/systemctl")
        .args([operation, "oblivion-tor.service"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("tor_service_failed"));
    }
    if operation == "stop" {
        let result = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "oblivion-tor.service",
                "--property=Result",
                "--value",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !result.status.success() || result.stdout != b"success\n" {
            return Err(io::Error::other("tor_stop_failed"));
        }
    }
    Ok(())
}

fn connection() -> io::Result<UnixStream> {
    let mut cookie = Zeroizing::new(Vec::new());
    private_file("/run/tor/control.authcookie")?
        .take(33)
        .read_to_end(&mut cookie)?;
    if cookie.len() != 32 {
        return Err(io::Error::other("invalid_tor_cookie"));
    }
    let mut stream = UnixStream::connect("/run/tor/control")?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || peer.uid != 1200
    {
        return Err(io::Error::other("invalid_tor_peer"));
    }
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let auth = Zeroizing::new(format!(
        "AUTHENTICATE {}\r\n",
        cookie
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    stream.write_all(auth.as_bytes())?;
    expect(&mut stream, "250 OK\r\n")?;
    Ok(stream)
}

fn control(command: &str) -> io::Result<Vec<String>> {
    request(&mut connection()?, command)
}

fn request(stream: &mut UnixStream, command: &str) -> io::Result<Vec<String>> {
    stream.write_all(command.as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut lines = Vec::new();
    let mut line = Vec::new();
    for _ in 0..4096 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if byte[0] != b'\n' {
            continue;
        }
        if line == b"250 OK\r\n" {
            return Ok(lines);
        }
        if !line.starts_with(b"250-") || !line.ends_with(b"\r\n") {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        lines.push(
            String::from_utf8(std::mem::take(&mut line))
                .map_err(|_| io::Error::other("unexpected_tor_reply"))?,
        );
    }
    Err(io::Error::other("tor_reply_too_large"))
}

fn expect(stream: &mut UnixStream, expected: &str) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    for byte in expected.bytes() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        stream.set_read_timeout(Some(remaining))?;
        let mut actual = [0];
        stream.read_exact(&mut actual)?;
        if actual[0] != byte {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
    }
    Ok(())
}

// Export only the bounded percentage, never Tor's free-form diagnostics.
fn bootstrap_progress(lines: &[String]) -> io::Result<u8> {
    if lines.len() != 1 || !lines[0].starts_with("250-status/bootstrap-phase=") {
        return Err(io::Error::other("unexpected_tor_reply"));
    }
    let fields: Vec<_> = lines[0]["250-status/bootstrap-phase=".len()..]
        .split_ascii_whitespace()
        .filter_map(|field| field.strip_prefix("PROGRESS="))
        .collect();
    if fields.len() != 1 {
        return Err(io::Error::other("unexpected_tor_reply"));
    }
    fields[0]
        .parse::<u8>()
        .ok()
        .filter(|value| *value <= 100)
        .ok_or_else(|| io::Error::other("unexpected_tor_reply"))
}

#[cfg(test)]
mod tests {
    use super::{ClientAuth, bootstrap_progress, circuits, read_information, read_line};

    #[test]
    fn information_accepts_inline_and_multiline_values_without_losing_a_single_circuit_or_stream() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        for name in ["circuit-status", "stream-status"] {
            for (wire, expected) in [
                (format!("250-{name}=\r\n250 OK\r\n"), vec![]),
                (format!("250-{name}=one\r\n250 OK\r\n"), vec!["one"]),
                (format!("250+{name}=\r\none\r\n.\r\n250 OK\r\n"), vec!["one"]),
                (format!("250+{name}=\r\none\r\ntwo\r\n.\r\n250 OK\r\n"), vec!["one", "two"]),
                (format!("250+{name}=\r\n.\r\n250 OK\r\n"), vec![]),
            ] {
                let (mut reader, mut writer) = UnixStream::pair().unwrap();
                writer.write_all(wire.as_bytes()).unwrap();
                drop(writer);
                assert_eq!(read_information(&mut reader, name).unwrap(), expected);
            }
            for wire in [
                "250-wrong-key=one\r\n250 OK\r\n".to_owned(),
                format!("250-{name}=one\r\n551 failed\r\n"),
                format!("250+{name}=\r\none\r\n.\r\n551 failed\r\n"),
                format!("250-{name}=one\r\n"),
            ] {
                let (mut reader, mut writer) = UnixStream::pair().unwrap();
                writer.write_all(wire.as_bytes()).unwrap();
                drop(writer);
                assert!(read_information(&mut reader, name).is_err());
            }
        }
    }

    #[test]
    fn circuit_verification_requires_a_full_general_path_and_valid_exit() {
        let path = format!("${}~guard,${}~middle,${}~exit", "A".repeat(40), "B".repeat(40), "c".repeat(40));
        let parsed = circuits(&[
            format!("42 BUILT {path} PURPOSE=GENERAL TIME_CREATED=now"),
            format!("43 BUILT {path} PURPOSE=HS_CLIENT_REND"),
            "44 LAUNCHED PURPOSE=GENERAL".to_owned(),
            format!("45 EXTENDED ${}~guard PURPOSE=GENERAL", "A".repeat(40)),
        ]).unwrap();
        assert!(parsed[0].built);
        assert_eq!(parsed[0].id, 42);
        assert_eq!(parsed[0].exit, Some(format!("${}", "C".repeat(40))));
        assert!(parsed[1..].iter().all(|circuit| circuit.exit.is_none()));
        assert!(circuits(&["1 BUILT $a,$b,$bad PURPOSE=GENERAL".into()]).is_err());
        assert!(circuits(&["invalid BUILT PURPOSE=GENERAL".into()]).is_err());
    }

    #[test]
    fn conflux_paths_are_included_in_the_exits_to_replace() {
        for purpose in ["CONFLUX_LINKED", "CONFLUX_UNLINKED"] {
            let line = format!("12 BUILT $A~guard,$B~middle,${}~exit PURPOSE={purpose}", "D".repeat(40));
            let parsed = circuits(&[line]).unwrap();
            assert_eq!(parsed[0].exit.as_deref(), Some(format!("${}", "D".repeat(40)).as_str()));
        }
    }

    #[test]
    fn control_line_reader_bounds_input_and_rejects_invalid_framing() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};
        for (bytes, limit, valid) in [(b"250 EXTENDED 42\r\n".as_slice(), 64, true), (b"bad\n", 64, false), (b"oversized\r\n", 4, false)] {
            let (mut read, mut write) = UnixStream::pair().unwrap();
            write.write_all(bytes).unwrap();
            drop(write);
            assert_eq!(read_line(&mut read, Instant::now() + Duration::from_secs(1), &mut {limit}).is_ok(), valid);
        }
    }

    #[test]
    fn client_auth_accepts_only_canonical_public_keys() {
        assert!(ClientAuth::try_from("A".repeat(52)).is_ok());
        assert!(ClientAuth::try_from(format!("{}Q", "7".repeat(51))).is_ok());
        for value in [
            "A".repeat(51),
            "A".repeat(53),
            "a".repeat(52),
            "8".repeat(52),
            format!("{}B", "A".repeat(51)),
            format!("{}\r\nSIGNAL SHUTDOWN", "A".repeat(52)),
        ] {
            assert!(ClientAuth::try_from(value).is_err());
        }
        assert!(serde_json::from_str::<ClientAuth>("true").is_err());
        assert!(serde_json::from_str::<ClientAuth>("{\"key\":\"wrong\"}").is_err());
    }

    #[test]
    fn progress_is_bounded_and_does_not_export_diagnostics() {
        for value in [0, 5, 50, 95, 100] {
            assert_eq!(bootstrap_progress(&[format!("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={value} TAG=conn SUMMARY=private")]).unwrap(), value);
        }
        for line in [
            "250-status/bootstrap-phase=PROGRESS=101",
            "250-status/bootstrap-phase=PROGRESS=50 PROGRESS=100",
            "250-status/bootstrap-phase=PROGRESS=bad",
            "250-other=PROGRESS=100",
        ] {
            assert!(bootstrap_progress(&[line.into()]).is_err());
        }
        assert!(bootstrap_progress(&[]).is_err());
    }
}
