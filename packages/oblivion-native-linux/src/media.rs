//! One removable device, owned by the controller's QMP connection.
use crate::{Error, Result, qemu::Qmp};
use oblivion_wire::live_media::Direction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileTypeExt;
use std::time::Instant;

const PORT: &str = "oblivion-media-port";
const NODE: &str = "oblivion-media-node";
const DEVICE: &str = "oblivion-media";
const DEVICE_PATH: &str = "/machine/peripheral/oblivion-media";
const BACKEND_PATH: &str = "/machine/peripheral/oblivion-media/virtio-backend";

/// The Live launcher adds this port to q35 or virt before controller boot.
pub fn reserve_port(arguments: &mut Vec<OsString>) {
    arguments.extend([
        OsString::from("-device"),
        OsString::from(format!(
            "pcie-root-port,id={PORT},bus=pcie.0,chassis=1,slot=1"
        )),
    ]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaStatus {
    Empty,
    Attached,
    Uncertain,
}

pub(crate) struct Attachment {
    // Also retain the host's exclusive open after an ambiguous QMP result.
    _device: File,
    receipt: Option<FdSet>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct FdSet {
    fdset_id: u32,
    fd: u32,
}

#[derive(Serialize)]
struct AddFd<'a> {
    opaque: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BlockNode {
    driver: &'static str,
    node_name: &'static str,
    read_only: bool,
    file: BlockFile,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BlockFile {
    driver: &'static str,
    filename: String,
    read_only: bool,
    locking: &'static str,
    aio: &'static str,
    cache: Cache,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Cache {
    direct: bool,
    no_flush: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BlockDevice<'a> {
    driver: &'static str,
    id: &'static str,
    bus: &'static str,
    drive: &'static str,
    serial: &'a str,
    write_cache: &'static str,
    config_wce: bool,
    discard: bool,
    write_zeroes: bool,
    rerror: &'static str,
    werror: &'static str,
}

#[derive(Serialize)]
struct DeviceId {
    id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct NodeId {
    node_name: &'static str,
}

pub(crate) fn block_access_matches(media: &File, direction: Direction) -> bool {
    let access = match direction {
        Direction::Import => libc::O_RDONLY,
        Direction::Export => libc::O_RDWR,
    };
    let flags = unsafe { libc::fcntl(media.as_raw_fd(), libc::F_GETFL) };
    let invalid_access = flags < 0 || flags & libc::O_ACCMODE != access;
    #[cfg(target_os = "linux")]
    let invalid_access = invalid_access || flags & libc::O_PATH != 0;
    !invalid_access
        && media
            .metadata()
            .is_ok_and(|info| info.file_type().is_block_device())
}

impl Qmp {
    /// The caller must supply an already authorized and exclusively opened
    /// partition. The descriptor access must match the reservation direction.
    pub fn attach_media(
        &mut self,
        media: File,
        direction: Direction,
        serial: &str,
        deadline: Instant,
    ) -> Result<()> {
        if !serial.strip_prefix("obl-").is_some_and(|id| {
            id.len() == 16
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(Error("invalid_qmp_media_serial"));
        }
        if !block_access_matches(&media, direction) {
            return Err(Error("qmp_media_block_access_mismatch"));
        }
        self.attach_media_descriptor(media, direction, serial, deadline)
    }

    fn attach_media_descriptor(
        &mut self,
        media: File,
        direction: Direction,
        serial: &str,
        deadline: Instant,
    ) -> Result<()> {
        match self.media_status() {
            MediaStatus::Empty => {}
            MediaStatus::Attached => return Err(Error("qmp_media_already_attached")),
            MediaStatus::Uncertain => return Err(Error("qmp_media_ownership_uncertain")),
        }
        let read_only = direction == Direction::Import;
        let attached = (|| {
            let receipt: FdSet = serde_json::from_value(self.request(
                "add-fd",
                Some(AddFd { opaque: serial }),
                Some(media.as_fd()),
                deadline,
            )?)
            .map_err(|_| Error("invalid_qmp_fdset"))?;
            self.confirm_media_command(
                "blockdev-add",
                BlockNode {
                    driver: "raw",
                    node_name: NODE,
                    read_only,
                    file: BlockFile {
                        driver: "host_device",
                        filename: format!("/dev/fdset/{}", receipt.fdset_id),
                        read_only,
                        locking: "on",
                        aio: "threads",
                        cache: Cache {
                            direct: false,
                            no_flush: false,
                        },
                    },
                },
                deadline,
            )?;
            self.confirm_media_command(
                "device_add",
                BlockDevice {
                    driver: "virtio-blk-pci",
                    id: DEVICE,
                    bus: PORT,
                    drive: NODE,
                    serial,
                    write_cache: "off",
                    config_wce: false,
                    discard: false,
                    write_zeroes: false,
                    rerror: "report",
                    werror: "report",
                },
                deadline,
            )?;
            Ok(receipt)
        })();
        self.media = Some(Attachment {
            _device: media,
            receipt: attached.as_ref().ok().copied(),
        });
        attached.map(|_| ())
    }

    /// The caller first verifies the transfer VM stopped and unmapped the disk.
    pub fn detach_media(&mut self, deadline: Instant) -> Result<()> {
        let Some(media) = self.media.as_mut() else {
            return Ok(());
        };
        let receipt = media
            .receipt
            .take()
            .ok_or(Error("qmp_media_ownership_uncertain"))?;
        self.confirm_media_command("device_del", DeviceId { id: DEVICE }, deadline)?;
        let removed = self.wait_event(
            |event| {
                let data = &event["data"];
                data["path"] == DEVICE_PATH
                    && match event["event"].as_str() {
                        Some("DEVICE_DELETED") => data["device"] == DEVICE,
                        Some("DEVICE_UNPLUG_GUEST_ERROR") => {
                            data.get("device").is_none_or(|device| device == DEVICE)
                        }
                        _ => false,
                    }
            },
            deadline,
        )?;
        if removed["event"] != "DEVICE_DELETED" {
            return Err(Error("qmp_media_unplug_rejected"));
        }
        self.confirm_media_command("blockdev-del", NodeId { node_name: NODE }, deadline)?;
        self.confirm_media_command("remove-fd", receipt, deadline)?;
        self.media = None;
        Ok(())
    }

    pub fn media_status(&self) -> MediaStatus {
        match &self.media {
            None => MediaStatus::Empty,
            Some(media) if media.receipt.is_some() => MediaStatus::Attached,
            Some(_) => MediaStatus::Uncertain,
        }
    }

    pub fn owns_media_error(&self, event: &Value) -> bool {
        // A report can still be queued after a verified detach. Only these
        // reserved IDs identify a removable device; the data disks stay fatal.
        event["event"] == "BLOCK_IO_ERROR"
            && event["data"]["action"] == "report"
            && (event["data"]["node-name"] == NODE
                || event["data"]["qom-path"] == BACKEND_PATH
                || event["data"]["qom-path"] == DEVICE_PATH)
    }

    fn confirm_media_command(
        &mut self,
        command: &str,
        arguments: impl Serialize,
        deadline: Instant,
    ) -> Result<()> {
        if self
            .request(command, Some(arguments), None, deadline)?
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        {
            return Ok(());
        }
        Err(Error("invalid_qmp_media_reply"))
    }
}

#[cfg(test)]
mod tests {
    use super::{BACKEND_PATH, DEVICE, DEVICE_PATH, MediaStatus, NODE, PORT};
    use crate::qemu::tests::socket_pair;
    use oblivion_wire::live_media::Direction;
    use serde_json::{Value, json};
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    const SERIAL: &str = "obl-1234abcd5678ef90";

    fn request(peer: &mut BufReader<UnixStream>, command: &str, prefix: &[u8]) -> Value {
        let mut line = prefix.to_vec();
        assert_ne!(peer.read_until(b'\n', &mut line).unwrap(), 0);
        let request: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(request["execute"], command);
        request
    }

    fn send(peer: &mut BufReader<UnixStream>, message: Value) {
        writeln!(peer.get_mut(), "{message}").unwrap();
    }

    fn reply(peer: &mut BufReader<UnixStream>, request: &Value, result: Value) {
        send(peer, json!({"id": request["id"], "return": result}));
    }

    fn expect_attach(peer: &mut BufReader<UnixStream>, direction: Direction) {
        let read_only = direction == Direction::Import;
        let mut control = [0usize; 8];
        let mut first = [0u8; 1];
        let mut data = libc::iovec {
            iov_base: first.as_mut_ptr().cast(),
            iov_len: first.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control) as _;
        let fd = unsafe {
            assert_eq!(
                libc::recvmsg(peer.get_ref().as_raw_fd(), &mut message, 0),
                1
            );
            assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null());
            assert_eq!(
                ((*header).cmsg_level, (*header).cmsg_type),
                (libc::SOL_SOCKET, libc::SCM_RIGHTS)
            );
            assert_eq!(
                (*header).cmsg_len as usize,
                libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize
            );
            let fd = libc::CMSG_DATA(header).cast::<RawFd>().read_unaligned();
            assert_eq!(
                libc::fcntl(fd, libc::F_GETFL) & libc::O_ACCMODE,
                if read_only {
                    libc::O_RDONLY
                } else {
                    libc::O_RDWR
                },
            );
            assert_eq!(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            File::from_raw_fd(fd)
        };
        assert_eq!(
            fd.metadata().unwrap().rdev(),
            std::fs::metadata("/dev/null").unwrap().rdev()
        );
        let added = request(peer, "add-fd", &first);
        assert_eq!(added["arguments"], json!({"opaque":SERIAL}));
        reply(peer, &added, json!({"fdset-id":7,"fd":19}));

        let node = request(peer, "blockdev-add", &[]);
        assert_eq!(
            node["arguments"],
            json!({
                "driver":"raw", "node-name":NODE, "read-only":read_only,
                "file":{"driver":"host_device", "filename":"/dev/fdset/7", "read-only":read_only,
                        "locking":"on","aio":"threads","cache":{"direct":false,"no-flush":false}}
            })
        );
        reply(peer, &node, json!({}));

        let device = request(peer, "device_add", &[]);
        assert_eq!(
            device["arguments"],
            json!({
                "driver":"virtio-blk-pci","id":DEVICE,"bus":PORT,"drive":NODE,"serial":SERIAL,
                "write-cache":"off","config-wce":false,"discard":false,"write-zeroes":false,
                "rerror":"report","werror":"report"
            })
        );
        reply(peer, &device, json!({}));
    }

    #[test]
    fn removable_media_uses_the_exact_fd_and_waits_for_owned_eject() {
        for direction in [Direction::Import, Direction::Export] {
            check_owned_eject(direction);
        }
    }

    fn check_owned_eject(direction: Direction) {
        let (mut qmp, peer) = socket_pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            expect_attach(&mut peer, direction);
            let delete = request(&mut peer, "device_del", &[]);
            assert_eq!(delete["arguments"], json!({"id":DEVICE}));
            send(
                &mut peer,
                json!({"event":"DEVICE_DELETED","data":{"device":"foreign","path":"/foreign"}}),
            );
            send(&mut peer, json!({"event":"SHUTDOWN"}));
            reply(&mut peer, &delete, json!({}));
            // Prove the acknowledgement and a foreign event do not authorize teardown.
            peer.get_ref()
                .set_read_timeout(Some(Duration::from_millis(75)))
                .unwrap();
            assert!(matches!(
                peer.fill_buf().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            peer.get_ref()
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            send(
                &mut peer,
                json!({"event":"DEVICE_DELETED","data":{"device":DEVICE,"path":DEVICE_PATH}}),
            );
            let node = request(&mut peer, "blockdev-del", &[]);
            assert_eq!(node["arguments"], json!({"node-name":NODE}));
            reply(&mut peer, &node, json!({}));
            let removed = request(&mut peer, "remove-fd", &[]);
            assert_eq!(removed["arguments"], json!({"fdset-id":7,"fd":19}));
            reply(&mut peer, &removed, json!({}));
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        // The socket fixture verifies descriptor transport, while production
        // admission only accepts a real block descriptor with matching access.
        let descriptor = || {
            OpenOptions::new()
                .read(true)
                .write(direction == Direction::Export)
                .open("/dev/null")
                .unwrap()
        };
        assert_eq!(
            qmp.attach_media(descriptor(), direction, SERIAL, deadline)
                .unwrap_err()
                .0,
            "qmp_media_block_access_mismatch"
        );
        qmp.attach_media_descriptor(descriptor(), direction, SERIAL, deadline)
            .unwrap();
        assert_eq!(qmp.media_status(), MediaStatus::Attached);
        qmp.detach_media(deadline).unwrap();
        assert_eq!(qmp.media_status(), MediaStatus::Empty);
        assert_eq!(qmp.next().unwrap().unwrap()["data"]["device"], "foreign");
        assert_eq!(qmp.next().unwrap().unwrap()["event"], "SHUTDOWN");
        assert!(qmp.owns_media_error(
            &json!({"event":"BLOCK_IO_ERROR","data":{"action":"report","qom-path":BACKEND_PATH}})
        ));
        assert!(!qmp.owns_media_error(
            &json!({"event":"BLOCK_IO_ERROR","data":{"action":"stop","node-name":"disk1"}})
        ));
        worker.join().unwrap();
    }

    #[test]
    fn eject_failure_fences_the_slot_without_releasing_the_fdset() {
        let (mut qmp, peer) = socket_pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            expect_attach(&mut peer, Direction::Import);
            let delete = request(&mut peer, "device_del", &[]);
            // QEMU may deliver the event before its command response.
            send(
                &mut peer,
                json!({"event":"DEVICE_UNPLUG_GUEST_ERROR","data":{"path":DEVICE_PATH}}),
            );
            reply(&mut peer, &delete, json!({}));
            let mut trailing = String::new();
            assert_eq!(peer.read_line(&mut trailing).unwrap(), 0);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        qmp.attach_media_descriptor(
            File::open("/dev/null").unwrap(),
            Direction::Import,
            SERIAL,
            deadline,
        )
        .unwrap();
        assert_eq!(
            qmp.detach_media(deadline).unwrap_err().0,
            "qmp_media_unplug_rejected"
        );
        assert_eq!(qmp.media_status(), MediaStatus::Uncertain);
        assert_eq!(
            qmp.attach_media_descriptor(
                File::open("/dev/null").unwrap(),
                Direction::Import,
                SERIAL,
                deadline
            )
            .unwrap_err()
            .0,
            "qmp_media_ownership_uncertain"
        );
        assert_eq!(
            qmp.detach_media(deadline).unwrap_err().0,
            "qmp_media_ownership_uncertain"
        );
        drop(qmp);
        worker.join().unwrap();
    }
}
