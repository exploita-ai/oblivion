use crate::{Error, Result, config::RuntimeConfig, private};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub fn arguments(config: &RuntimeConfig) -> Result<Vec<OsString>> {
    config.validate()?;
    let mut args: Vec<OsString> = [
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-no-reboot",
        "-S",
        "-accel",
        "kvm",
        "-cpu",
        "host",
        "-machine",
        if cfg!(target_arch = "aarch64") {
            "virt,virtualization=on,gic-version=3,mem-merge=off,dump-guest-core=off"
        } else {
            "q35,vmport=off,mem-merge=off,dump-guest-core=off"
        },
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    for (option, value) in [
        ("-smp", OsString::from(config.cpu_count.to_string())),
        ("-m", OsString::from(config.memory_mi_b.to_string())),
        ("-kernel", config.kernel.as_os_str().to_owned()),
        ("-append", OsString::from(&config.command_line)),
    ] {
        args.extend([OsString::from(option), value]);
    }
    if let Some(initrd) = &config.initrd {
        args.extend([OsString::from("-initrd"), initrd.as_os_str().to_owned()]);
    }
    let qmp = private::sidecar(&config.control_socket, ".qmp");
    args.extend([
        OsString::from("-qmp"),
        OsString::from(format!(
            "unix:{},server=on,wait=off",
            qmp.to_string_lossy().replace(',', ",,")
        )),
    ]);
    let auth = private::sidecar(&config.control_socket, ".auth");
    args.extend([
        OsString::from("-chardev"),
        OsString::from(format!(
            "socket,id=runtime-auth,path={},server=on,wait=off",
            auth.to_string_lossy().replace(',', ",,")
        )),
    ]);
    for (index, disk) in config.disks.iter().enumerate() {
        // JSON keeps a filename containing commas or option-like text opaque.
        // directsync: direct I/O + honored flushes + device write cache off.
        let options = json!({
            "driver":"raw", "node-name":format!("disk{index}"), "read-only":disk.read_only,
            "file":{
                "driver": if std::fs::symlink_metadata(&disk.path).is_ok_and(|info| info.file_type().is_block_device()) { "host_device" } else { "file" }, "filename":disk.path, "locking":"on", "aio":"threads",
                "cache":{"direct":!disk.read_only,"no-flush":false},
            },
        });
        args.extend([
            OsString::from("-blockdev"),
            OsString::from(options.to_string()),
            OsString::from("-device"),
            OsString::from(format!("virtio-blk-pci,drive=disk{index},write-cache=off,config-wce=off,discard=off,write-zeroes=off,werror=stop,rerror=stop")),
        ]);
    }
    args.extend([
        OsString::from("-chardev"),
        OsString::from("stdio,id=console,signal=off"),
        OsString::from("-device"),
        OsString::from("virtio-serial-pci"),
        OsString::from("-device"),
        OsString::from("virtconsole,chardev=console"),
        OsString::from("-device"),
        OsString::from("virtserialport,chardev=runtime-auth,name=oblivion.runtime-auth"),
        OsString::from("-device"),
        OsString::from(format!("vhost-vsock-pci,guest-cid={}", config.guest_cid)),
        OsString::from("-object"),
        OsString::from("rng-random,id=rng,filename=/dev/urandom"),
        OsString::from("-device"),
        OsString::from("virtio-rng-pci,rng=rng"),
    ]);
    if config.network {
        args.extend([
            OsString::from("-netdev"),
            OsString::from("user,id=uplink,ipv6=off"),
            OsString::from("-device"),
            OsString::from("virtio-net-pci,netdev=uplink"),
        ]);
    }
    Ok(args)
}

pub fn connect_private(path: &Path, deadline: Instant) -> Result<UnixStream> {
    let stream = loop {
        match UnixStream::connect(path) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => return Err(Error("qmp_unavailable")),
        }
    };
    if private::peer_uid(&stream)? != unsafe { libc::getuid() } {
        return Err(Error("untrusted_qmp_peer"));
    }
    let info = std::fs::symlink_metadata(path).map_err(|_| Error("qmp_unavailable"))?;
    if !info.file_type().is_socket() || info.uid() != unsafe { libc::getuid() } {
        return Err(Error("untrusted_qmp_peer"));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| Error("qmp_unavailable"))?;
    Ok(stream)
}

const MAX_PENDING_EVENTS: usize = 32;

pub struct Qmp {
    stream: UnixStream,
    buffered: Vec<u8>,
    events: VecDeque<Value>,
    event_overflow: bool,
    sequence: u32,
    #[cfg(any(target_os = "linux", test))]
    pub(crate) media: Option<crate::media::Attachment>,
}
impl Qmp {
    pub fn connect(path: &Path, deadline: Instant) -> Result<Self> {
        let stream = connect_private(path, deadline)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| Error("qmp_unavailable"))?;
        let mut qmp = Self {
            stream,
            buffered: Vec::new(),
            events: VecDeque::new(),
            event_overflow: false,
            sequence: 0,
            #[cfg(any(target_os = "linux", test))]
            media: None,
        };
        let greeting = qmp.until_wire(deadline)?;
        if !greeting.get("QMP").is_some_and(Value::is_object) {
            return Err(Error("invalid_qmp_greeting"));
        }
        qmp.command("qmp_capabilities", deadline)?;
        Ok(qmp)
    }

    pub fn command(&mut self, name: &str, deadline: Instant) -> Result<Value> {
        self.request::<()>(name, None, None, deadline)
    }

    pub(crate) fn request<A: Serialize>(
        &mut self,
        name: &str,
        arguments: Option<A>,
        mut descriptor: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> Result<Value> {
        #[derive(Serialize)]
        struct Request<'a, A> {
            execute: &'a str,
            id: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            arguments: Option<A>,
        }
        if self.event_overflow {
            return Err(Error("qmp_event_queue_overflow"));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error("qmp_sequence_exhausted"))?;
        let mut data = serde_json::to_vec(&Request {
            execute: name,
            id: self.sequence,
            arguments,
        })
        .map_err(|_| Error("invalid_qmp_request"))?;
        if data.len() >= 4096 {
            return Err(Error("qmp_request_too_large"));
        }
        data.push(b'\n');
        let mut remaining = data.as_slice();
        while !remaining.is_empty() {
            if Instant::now() >= deadline {
                return Err(Error("qmp_timeout"));
            }
            let sent = match descriptor {
                Some(file) => send_descriptor(&self.stream, remaining, file),
                None => self.stream.write(remaining),
            };
            match sent {
                Ok(0) => return Err(Error("qmp_disconnected")),
                Ok(length) => {
                    // A partial send has already transferred the descriptor.
                    descriptor = None;
                    remaining = &remaining[length..];
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT, deadline)?
                }
                Err(_) => return Err(Error("qmp_failed")),
            }
        }
        loop {
            let mut value = self.until_wire(deadline)?;
            if value.get("event").is_some() {
                self.queue_event(value)?;
                continue;
            }
            if value.get("id").and_then(Value::as_u64) != Some(u64::from(self.sequence)) {
                continue;
            }
            if value.get("error").is_some() {
                return Err(Error("qmp_command_failed"));
            }
            return value
                .as_object_mut()
                .and_then(|reply| reply.remove("return"))
                .ok_or(Error("invalid_qmp_reply"));
        }
    }

    fn queue_event(&mut self, value: Value) -> Result<()> {
        if self.events.len() == MAX_PENDING_EVENTS {
            // Missing an event makes this monitor's state uncertain.
            self.events.clear();
            self.event_overflow = true;
            return Err(Error("qmp_event_queue_overflow"));
        }
        self.events.push_back(value);
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn wait_event(
        &mut self,
        matches: impl Fn(&Value) -> bool,
        deadline: Instant,
    ) -> Result<Value> {
        if self.event_overflow {
            return Err(Error("qmp_event_queue_overflow"));
        }
        if let Some(position) = self.events.iter().position(&matches) {
            return self
                .events
                .remove(position)
                .ok_or(Error("invalid_qmp_event"));
        }
        loop {
            let event = self.until_wire(deadline)?;
            if event.get("event").is_some() {
                if matches(&event) {
                    return Ok(event);
                }
                self.queue_event(event)?;
            }
        }
    }

    pub fn next(&mut self) -> Result<Option<Value>> {
        if self.event_overflow {
            return Err(Error("qmp_event_queue_overflow"));
        }
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        self.next_wire()
    }

    fn next_wire(&mut self) -> Result<Option<Value>> {
        if let Some(newline) = self.buffered.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = self.buffered.drain(..=newline).collect();
            return serde_json::from_slice(&line)
                .map(Some)
                .map_err(|_| Error("invalid_qmp_message"));
        }
        let mut chunk = [0; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err(Error("qmp_disconnected")),
            Ok(length) => {
                if self.buffered.len() + length > 65536 {
                    return Err(Error("qmp_message_too_large"));
                }
                self.buffered.extend_from_slice(&chunk[..length]);
                if self.buffered.contains(&b'\n') {
                    self.next_wire()
                } else {
                    Ok(None)
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(_) => Err(Error("qmp_failed")),
        }
    }

    fn until_wire(&mut self, deadline: Instant) -> Result<Value> {
        loop {
            if Instant::now() >= deadline {
                return Err(Error("qmp_timeout"));
            }
            if let Some(value) = self.next_wire()? {
                return Ok(value);
            }
            self.wait(libc::POLLIN, deadline)?;
        }
    }

    fn wait(&self, events: i16, deadline: Instant) -> Result<()> {
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events,
            revents: 0,
        };
        if millis == 0 || unsafe { libc::poll(&mut poll, 1, millis) } <= 0 {
            return Err(Error("qmp_timeout"));
        }
        Ok(())
    }
}

fn send_descriptor(
    stream: &UnixStream,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
) -> std::io::Result<usize> {
    let mut control = [0usize; 8];
    let mut data = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as _;
    let sent = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write_unaligned(descriptor.as_raw_fd());
        libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sent as usize)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{MAX_PENDING_EVENTS, Qmp};
    use std::collections::VecDeque;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    pub(crate) fn socket_pair() -> (Qmp, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        (
            Qmp {
                stream,
                buffered: Vec::new(),
                events: VecDeque::new(),
                event_overflow: false,
                sequence: 0,
                media: None,
            },
            peer,
        )
    }

    #[test]
    fn commands_preserve_event_order_across_replies() {
        let (mut qmp, mut peer) = socket_pair();
        peer.write_all(
            b"{\"event\":\"STOP\"}\n\
              {\"return\":1,\"id\":1}\n\
              {\"event\":\"RESUME\"}\n\
              {\"event\":\"DEVICE_DELETED\"}\n\
              {\"return\":2,\"id\":2}\n\
              {\"event\":\"SHUTDOWN\"}\n",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(qmp.command("query-status", deadline).unwrap(), 1);
        assert_eq!(qmp.command("system_powerdown", deadline).unwrap(), 2);
        for event in ["STOP", "RESUME", "DEVICE_DELETED", "SHUTDOWN"] {
            assert_eq!(qmp.next().unwrap().unwrap()["event"], event);
        }
        assert!(qmp.next().unwrap().is_none());
    }

    #[test]
    fn an_event_burst_cannot_leave_a_partial_monitor_usable() {
        let (mut qmp, mut peer) = socket_pair();
        for _ in 0..=MAX_PENDING_EVENTS {
            peer.write_all(b"{\"event\":\"STOP\"}\n").unwrap();
        }
        peer.write_all(b"{\"return\":{},\"id\":1}\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(
            qmp.command("query-status", deadline).unwrap_err().0,
            "qmp_event_queue_overflow"
        );
        assert_eq!(qmp.next().unwrap_err().0, "qmp_event_queue_overflow");
        assert_eq!(
            qmp.command("system_powerdown", deadline).unwrap_err().0,
            "qmp_event_queue_overflow"
        );
    }
}

#[derive(Default)]
pub struct SerialGuard {
    tail: Zeroizing<Vec<u8>>,
}
impl SerialGuard {
    pub fn observe(&mut self, bytes: &[u8]) -> Option<&'static str> {
        for chunk in bytes.chunks(4096) {
            self.tail.extend_from_slice(chunk);
            let contains = |marker: &[u8]| {
                self.tail
                    .windows(marker.len())
                    .any(|window| window == marker)
            };
            if [
                b"BUG: Bad rss-counter state".as_slice(),
                b"BUG: corrupted stack end",
                b"Internal error: Oops",
                b"Oops:",
                b"BUG: unable to handle page fault",
            ]
            .into_iter()
            .any(contains)
            {
                return Some("runtime_kernel_memory_failure");
            }
            if contains(b"Kernel panic - not syncing") {
                return Some("runtime_kernel_panic");
            }
            if self.tail.len() > 128 {
                let remove = self.tail.len() - 128;
                self.tail.drain(..remove);
            }
        }
        None
    }
}
