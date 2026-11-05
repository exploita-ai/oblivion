//! The native owner holds a reservation stream separately from the one source
//! attachment. The source can be revoked without losing the eject handshake.
use crate::storage::{self, Error, Result, random_id, require};
use oblivion_host::channel::Channel;
use oblivion_host::{autolock::Opening, scope::Slot};
use oblivion_wire::live_media::{DETACHED, Direction, Purpose, REVOKED, Reserve, STOP, Source};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(15 * 60);
const CLEANUP_BUDGET: Duration = Duration::from_secs(50);

struct Reservation {
    id: String,
    host: String,
    opening: Opening,
    device_id: String,
    direction: Direction,
    purpose: Purpose,
    signal: UnixStream,
    owner: Arc<OwnedFd>,
    deadline: Instant,
    claimed: bool,
    revoked: bool,
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
        require(
            request.purpose.valid_for(request.direction),
            "invalid_live_media_request",
        )?;
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
        let (watch, signal) =
            UnixStream::pair().map_err(|_| Error("live_media_reservation_failed"))?;
        let slot = request.opening.slot;
        let owner = Arc::new(owner);
        let deadline = Instant::now() + LIFETIME;
        entries.push(Reservation {
            id: id.clone(),
            host,
            opening: request.opening,
            device_id: request.device_id,
            direction: request.direction,
            purpose: request.purpose,
            signal,
            owner: owner.clone(),
            deadline,
            claimed: false,
            revoked: false,
        });
        let lease = Lease {
            registry: self.clone(),
            id,
            slot,
            direction: request.direction,
            controller,
            watch,
            owner,
            deadline,
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

    /// Caller holds storage.lock and has checked the current openings.
    pub fn claim(&self, request: &Source<Slot>, host: &str) -> Result<SourceLease> {
        let mut entries = self
            .0
            .lock()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        let entry = entries
            .iter_mut()
            .find(|entry| entry.id == request.lease_id)
            .ok_or(Error("live_media_reservation_changed"))?;
        require(
            !entry.revoked
                && !entry.claimed
                && Instant::now() < entry.deadline
                && entry.host == host
                && entry.opening == request.opening
                && entry.device_id == request.device_id
                && entry.direction == request.direction
                && entry.purpose == request.purpose,
            "live_media_reservation_changed",
        )?;
        let watch = entry
            .signal
            .try_clone()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        entry.claimed = true;
        Ok(SourceLease {
            registry: self.clone(),
            id: entry.id.clone(),
            watch,
            owner: entry.owner.clone(),
            deadline: entry.deadline,
        })
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
        for entry in entries.iter_mut().filter(|entry| matches(entry)) {
            entry.revoked = true;
            if let Err(error) = entry.signal.shutdown(Shutdown::Both) {
                require(
                    error.kind() == std::io::ErrorKind::NotConnected,
                    "live_media_revocation_failed",
                )?;
            }
        }
        Ok(())
    }

    fn claimed(&self, id: &str) -> Result<bool> {
        let entries = self
            .0
            .lock()
            .map_err(|_| Error("live_media_reservation_failed"))?;
        let entry = entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(Error("live_media_reservation_changed"))?;
        Ok(entry.claimed)
    }
}

pub struct Lease {
    registry: Registry,
    id: String,
    slot: Slot,
    direction: Direction,
    controller: UnixStream,
    watch: UnixStream,
    owner: Arc<OwnedFd>,
    deadline: Instant,
}

impl Lease {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn wait(self, control: &UnixStream, delivered: bool) {
        let stop = if delivered {
            match ready(
                [
                    control.as_raw_fd(),
                    self.controller.as_raw_fd(),
                    self.watch.as_raw_fd(),
                    self.owner.as_raw_fd(),
                ],
                self.deadline,
            ) {
                Ok([false, true, ..]) if self.stop_command() => Stop::Requested,
                Ok([false, false, ..]) => Stop::Revoked,
                _ => Stop::Lost,
            }
        } else {
            Stop::Lost
        };
        let until = Instant::now() + CLEANUP_BUDGET;
        if self.registry.revoke(|entry| entry.id == self.id).is_err() {
            return;
        }
        let sent_revoke = stop == Stop::Revoked && self.notify(REVOKED);
        let cleanup = self.registry.claimed(&self.id).and_then(|claimed| {
            if !claimed {
                return Ok(());
            }
            oblivion_host::scope::within(self.slot, || {
                let _lock = storage::recovery_lock()?;
                crate::transfer_host::stop_live_media(&self.id, self.direction)
            })
        });
        if cleanup.is_err() {
            return;
        }
        let acknowledged = stop == Stop::Requested
            || sent_revoke
                && matches!(
                    ready([control.as_raw_fd(), self.controller.as_raw_fd()], until),
                    Ok([false, true])
                )
                && self.stop_command();
        if acknowledged {
            self.notify(DETACHED);
        }
    }

    fn stop_command(&self) -> bool {
        let mut byte = [0];
        Channel::new(&self.controller, Duration::from_secs(2))
            .read_exact(&mut byte)
            .is_ok()
            && byte == [STOP]
    }

    fn notify(&self, bytes: &[u8]) -> bool {
        Channel::new(&self.controller, Duration::from_secs(2))
            .write_all(bytes)
            .is_ok()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.registry.revoke(|entry| entry.id == self.id);
        if let Ok(mut entries) = self.registry.0.lock() {
            entries.retain(|entry| entry.id != self.id);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Requested,
    Revoked,
    Lost,
}

pub struct SourceLease {
    registry: Registry,
    id: String,
    watch: UnixStream,
    owner: Arc<OwnedFd>,
    deadline: Instant,
}

impl SourceLease {
    pub fn check(&self, control: &UnixStream) -> Result<()> {
        require(
            Instant::now() < self.deadline
                && ready(
                    [
                        control.as_raw_fd(),
                        self.watch.as_raw_fd(),
                        self.owner.as_raw_fd(),
                    ],
                    Instant::now(),
                )? == [false, false, false],
            "live_media_revoked",
        )
    }

    pub fn wait(&self, control: &UnixStream) {
        let _ = ready(
            [
                control.as_raw_fd(),
                self.watch.as_raw_fd(),
                self.owner.as_raw_fd(),
            ],
            self.deadline,
        );
    }
}

impl Drop for SourceLease {
    fn drop(&mut self) {
        let _ = self.registry.revoke(|entry| entry.id == self.id);
    }
}

fn ready<const N: usize>(fds: [i32; N], deadline: Instant) -> Result<[bool; N]> {
    let mut descriptors = fds.map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    loop {
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as i32;
        if unsafe { libc::poll(descriptors.as_mut_ptr(), N as _, millis) } >= 0 {
            return Ok(descriptors.map(|entry| entry.revents != 0));
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(Error("live_media_watch_failed"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DETACHED, Lease, REVOKED, Registry, STOP, live_profile};
    use crate::storage::Result;
    use oblivion_host::autolock::Opening;
    use oblivion_wire::live_media::{Direction, Purpose, Reserve, Source};
    use std::io::{Read, Write};
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
                direction: Direction::Import,
                purpose: Purpose::Copy,
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
        assert!(reserve(&registry, 0, "1").is_err());
        drop(first_lease);
        assert_eq!(first.read(&mut [0]).unwrap(), 0);
        let (_next, _next_lease, _owner) =
            reserve(&registry, 0, "1").unwrap_or_else(|error| panic!("{}", error.0));
        assert!(matches!(registry.active(0.try_into().unwrap()), Ok(true)));
        second.set_nonblocking(true).unwrap();
        assert_eq!(
            second.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(registry.revoke_host(None).is_ok());
        assert!(matches!(registry.active(1.try_into().unwrap()), Ok(true)));
    }

    #[test]
    fn client_eof_ends_the_reservation_and_owner_loss_keeps_the_stop_handshake() {
        let registry = Registry::default();
        for owner_exits in [false, true] {
            let (mut console, mut lease, owner) =
                reserve(&registry, 0, "1").unwrap_or_else(|error| panic!("{}", error.0));
            let (control, peer) = UnixStream::pair().unwrap();
            lease.deadline = Instant::now() + Duration::from_secs(2);
            let thread = std::thread::spawn(move || lease.wait(&control, true));
            console
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if owner_exits {
                drop(owner);
                let mut revoked = [0; REVOKED.len()];
                console.read_exact(&mut revoked).unwrap();
                assert_eq!(&revoked, REVOKED);
                console.write_all(&[STOP]).unwrap();
                let mut detached = [0; DETACHED.len()];
                console.read_exact(&mut detached).unwrap();
                assert_eq!(&detached, DETACHED);
            } else {
                drop(peer);
            }
            assert_eq!(console.read(&mut [0]).unwrap(), 0);
            thread.join().unwrap();
            assert!(matches!(registry.active(0.try_into().unwrap()), Ok(false)));
        }
    }

    #[test]
    fn reservation_rejects_purposes_with_the_wrong_media_access() {
        let registry = Registry::default();
        for (purpose, direction) in [
            (Purpose::Inspect, Direction::Export),
            (Purpose::Recover, Direction::Import),
            (Purpose::Discard, Direction::Import),
        ] {
            let (owner, _alive) = UnixStream::pair().unwrap();
            let selected = Reserve {
                opening: Opening {
                    slot: 0.try_into().unwrap(),
                    safe_id: "a".repeat(32),
                    nonce: "b".repeat(32),
                },
                device_id: "c".repeat(64),
                direction,
                purpose,
            };
            assert!(matches!(
                registry.reserve(selected, "d".repeat(32), owner.into()),
                Err(crate::storage::Error("invalid_live_media_request"))
            ));
            assert!(matches!(registry.active(0.try_into().unwrap()), Ok(false)));
        }
    }

    #[test]
    fn source_claim_requires_the_exact_reservation_and_cannot_be_reused() {
        let registry = Registry::default();
        let (_client, lease, _owner) =
            reserve(&registry, 1, "1").unwrap_or_else(|error| panic!("{}", error.0));
        let host = "b".repeat(32);
        let mut request = Source {
            lease_id: lease.id().into(),
            opening: Opening {
                slot: 0.try_into().unwrap(),
                safe_id: format!("{:032x}", 1),
                nonce: "a".repeat(32),
            },
            device_id: "1".repeat(64),
            direction: Direction::Import,
            purpose: Purpose::Copy,
        };
        assert!(registry.claim(&request, &host).is_err());
        request.opening.slot = 1.try_into().unwrap();
        request.opening.nonce = "e".repeat(32);
        assert!(registry.claim(&request, &host).is_err());
        request.opening.nonce = "a".repeat(32);
        request.device_id = "2".repeat(64);
        assert!(registry.claim(&request, &host).is_err());
        request.device_id = "1".repeat(64);
        request.direction = Direction::Export;
        assert!(registry.claim(&request, &host).is_err());
        request.direction = Direction::Import;
        request.purpose = Purpose::Inspect;
        assert!(registry.claim(&request, &host).is_err());
        request.purpose = Purpose::Copy;
        assert!(registry.claim(&request, &"c".repeat(32)).is_err());
        let source = registry
            .claim(&request, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let (control, _peer) = UnixStream::pair().unwrap();
        assert!(source.check(&control).is_ok());
        assert!(registry.claim(&request, &host).is_err());
        registry
            .revoke_opening(&request.opening)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(source.check(&control).is_err());
    }
}
