use oblivion_tor_state::{LIMIT, State, VERSION};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct Tor;

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

    pub fn bootstrapped(&self) -> io::Result<bool> {
        let lines = control("GETINFO status/bootstrap-phase\r\n")?;
        if lines.len() != 1 || !lines[0].starts_with("250-status/bootstrap-phase=") {
            return Err(io::Error::other("unexpected_tor_reply"));
        }
        Ok(lines[0]
            .split_ascii_whitespace()
            .any(|field| field == "PROGRESS=100"))
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

fn control(command: &str) -> io::Result<Vec<String>> {
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
