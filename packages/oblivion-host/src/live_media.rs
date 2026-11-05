//! A read-only media reservation lives only while its controller attachment and
//! the exact Safe VM remain alive. This grants no device or guest file access.
use crate::storage::{Error, Result, random_id, require};
use oblivion_host::{autolock::Opening, scope::Slot};
use oblivion_wire::live_media::Reserve;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(15 * 60);

struct Reservation {
    id: String,
    host: String,
    opening: Opening,
    device_id: String,
    signal: UnixStream,
}

#[derive(Clone, Default)]
pub struct Registry(Arc<Mutex<Vec<Reservation>>>);

pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

pub fn require_live() -> Result<()> {
    let command_line =
        std::fs::read_to_string("/proc/cmdline").map_err(|_| Error("runtime_unavailable"))?;
    require(live_profile(&command_line), "live_media_unavailable")
}

fn live_profile(command_line: &str) -> bool {
    let parameters = command_line.split_whitespace().collect::<Vec<_>>();
    [
        ("oblivion.runtime=", "oblivion.runtime=1"),
        ("oblivion.runtime-live=", "oblivion.runtime-live=1"),
        (
            "oblivion.runtime-backend=",
            "oblivion.runtime-backend=qemu-kvm",
        ),
    ]
    .into_iter()
    .all(|(key, expected)| {
        parameters.contains(&expected)
            && parameters
                .iter()
                .filter(|value| value.starts_with(key))
                .count()
                == 1
    })
}

impl Registry {
    /// Caller holds storage.lock and has verified the live Safe and host openings.
    pub fn reserve(
        &self,
        request: Reserve<Slot>,
        host: String,
        owner: OwnedFd,
    ) -> Result<(UnixStream, Lease)> {
        let mut entries = self
            .0
            .lock()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        require(
            !entries.iter().any(|entry| {
                entry.device_id == request.device_id || entry.opening.slot == request.opening.slot
            }),
            "live_media_busy",
        )?;
        let id = random_id()?;
        let (controller, client) =
            UnixStream::pair().map_err(|_| Error("live_media_reservation_failed"))?;
        let signal = controller
            .try_clone()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        entries.push(Reservation {
            id: id.clone(),
            host,
            opening: request.opening,
            device_id: request.device_id,
            signal,
        });
        let lease = Lease {
            registry: self.clone(),
            id,
            controller,
            owner,
            deadline: Instant::now() + LIFETIME,
        };
        Ok((client, lease))
    }

    pub fn active(&self, slot: Slot) -> Result<bool> {
        let entries = self
            .0
            .lock()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        Ok(entries.iter().any(|entry| entry.opening.slot == slot))
    }

    pub fn revoke_slot(&self, slot: Slot) -> Result<()> {
        self.revoke(|entry| entry.opening.slot == slot)
    }

    pub fn revoke_opening(&self, opening: &Opening) -> Result<()> {
        self.revoke(|entry| entry.opening == *opening)
    }

    pub fn revoke_host(&self, host: Option<&str>) -> Result<()> {
        self.revoke(|entry| host.is_none_or(|host| entry.host == host))
    }

    fn revoke(&self, matches: impl Fn(&Reservation) -> bool) -> Result<()> {
        let mut entries = self
            .0
            .lock()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        let mut failed = false;
        entries.retain(|entry| {
            if !matches(entry) {
                return true;
            }
            if let Err(error) = entry.signal.shutdown(Shutdown::Both) {
                if error.kind() != std::io::ErrorKind::NotConnected {
                    failed = true;
                    return true;
                }
            }
            false
        });
        require(!failed, "live_media_revocation_failed")
    }
}

pub struct Lease {
    registry: Registry,
    id: String,
    controller: UnixStream,
    owner: OwnedFd,
    deadline: Instant,
}

impl Lease {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn wait(self, control: &UnixStream) {
        let mut descriptors = [
            control.as_raw_fd(),
            self.controller.as_raw_fd(),
            self.owner.as_raw_fd(),
        ]
        .map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        while let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) {
            let millis = remaining.as_millis().max(1) as i32;
            // The attachment carries no commands. Any bytes, EOF, process exit
            // or socket error end the grant. The deadline never renews.
            if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, millis) } >= 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.registry.revoke(|entry| entry.id == self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::{Lease, Registry, live_profile};
    use crate::storage::Result;
    use oblivion_host::autolock::Opening;
    use oblivion_wire::live_media::Reserve;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn reserve(
        registry: &Registry,
        slot: u8,
        device: &str,
    ) -> Result<(UnixStream, Lease, UnixStream)> {
        let (owner, alive) = UnixStream::pair().unwrap();
        let opening = Opening {
            slot: slot.try_into().unwrap(),
            safe_id: format!("{slot:032x}"),
            nonce: "a".repeat(32),
        };
        let (client, lease) = registry.reserve(
            Reserve {
                opening,
                device_id: device.repeat(64),
            },
            "b".repeat(32),
            owner.into(),
        )?;
        Ok((client, lease, alive))
    }

    #[test]
    fn desktop_and_conflicting_boot_profiles_cannot_reserve_live_media() {
        let desktop = "oblivion.runtime=1 oblivion.runtime-backend=qemu-kvm";
        assert!(!live_profile(desktop));
        assert!(!live_profile("oblivion.runtime-live=1"));
        assert!(live_profile(&format!("{desktop} oblivion.runtime-live=1")));
        assert!(!live_profile(&format!(
            "{desktop} oblivion.runtime-live=1 oblivion.runtime-live=0"
        )));
    }

    #[test]
    fn device_and_safe_slot_are_exclusive_and_stale_revocation_leaves_new_leases() {
        let registry = Registry::default();
        let (mut first, first_lease, _owner) =
            reserve(&registry, 0, "1").unwrap_or_else(|error| panic!("{}", error.0));
        assert!(reserve(&registry, 1, "1").is_err());
        assert!(reserve(&registry, 0, "2").is_err());
        let (mut second, _second_lease, _owner) =
            reserve(&registry, 1, "2").unwrap_or_else(|error| panic!("{}", error.0));
        let stale = Opening {
            slot: 0.try_into().unwrap(),
            safe_id: "0".repeat(32),
            nonce: "c".repeat(32),
        };
        assert!(registry.revoke_opening(&stale).is_ok());
        assert!(registry.revoke_host(Some(&"c".repeat(32))).is_ok());
        assert!(matches!(registry.active(0.try_into().unwrap()), Ok(true)));
        assert!(registry.revoke_slot(0.try_into().unwrap()).is_ok());
        assert_eq!(first.read(&mut [0]).unwrap(), 0);
        let (_next, next_lease, _owner) =
            reserve(&registry, 0, "1").unwrap_or_else(|error| panic!("{}", error.0));
        assert_ne!(first_lease.id(), next_lease.id());
        drop(first_lease);
        assert!(matches!(registry.active(0.try_into().unwrap()), Ok(true)));
        second.set_nonblocking(true).unwrap();
        assert_eq!(
            second.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(registry.revoke_host(None).is_ok());
        assert_eq!(second.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn client_eof_and_owner_loss_end_the_reservation() {
        let registry = Registry::default();
        for owner_exits in [false, true] {
            let (mut console, mut lease, owner) =
                reserve(&registry, 0, "1").unwrap_or_else(|error| panic!("{}", error.0));
            let (control, peer) = UnixStream::pair().unwrap();
            lease.deadline = Instant::now() + Duration::from_secs(2);
            let thread = std::thread::spawn(move || lease.wait(&control));
            if owner_exits {
                drop(owner)
            } else {
                drop(peer)
            }
            console
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(console.read(&mut [0]).unwrap(), 0);
            thread.join().unwrap();
            assert!(matches!(registry.active(0.try_into().unwrap()), Ok(false)));
        }
    }
}
