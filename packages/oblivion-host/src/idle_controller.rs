//! Resident monotonic idle policy. Only authenticated frontend activity resets it.
use crate::storage::{Error, Result, require};
use oblivion_host::autolock::{Activity, Lock, Opening, Preferences, Tracker};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RUN: &str = "/run/oblivion";
const SAVED: &str = "/run/oblivion/general/profile/app-settings.json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "target", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Target {
    Host { nonce: String },
    Safe { opening: Opening },
}

impl Target {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Host { nonce } => crate::storage::validate_id(nonce),
            Self::Safe { opening } => {
                crate::storage::validate_id(&opening.safe_id)?;
                crate::storage::validate_id(&opening.nonce)
            }
        }
    }
    pub(crate) fn action(&self) -> Lock {
        match self {
            Self::Host { nonce } => Lock::Host(nonce.clone()),
            Self::Safe { opening } => Lock::Safe(opening.clone()),
        }
    }
    fn path(&self) -> PathBuf {
        Path::new(RUN).join("idle-locks").join(match self {
            Self::Host { nonce } => format!("host-{nonce}"),
            Self::Safe { opening } => format!("safe-{}-{}-{}", opening.slot.index(), opening.safe_id, opening.nonce),
        })
    }
}

impl From<Lock> for Target {
    fn from(action: Lock) -> Self {
        match action {
            Lock::Host(nonce) => Self::Host { nonce },
            Lock::Safe(opening) => Self::Safe { opening },
        }
    }
}

pub(crate) struct Snapshot {
    pub host: Option<String>,
    pub safes: Vec<Opening>,
    pub fences: Vec<Target>,
    pub general_open: bool,
    pub writable: bool,
}

#[derive(Serialize)]
pub(crate) struct Status {
    #[serde(flatten)]
    pub(crate) state: oblivion_host::autolock::Status,
    storage: &'static str,
    writable: bool,
}

struct State {
    tracker: Tracker,
    storage: &'static str,
    writable: bool,
    error: Option<&'static str>,
}

#[derive(Clone)]
pub(crate) struct Controller(Arc<Mutex<State>>);

impl Controller {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self(Arc::new(Mutex::new(State {
            tracker: Tracker::new(Preferences::default()).map_err(Error)?,
            storage: "defaults", writable: false, error: None,
        }))))
    }

    pub(crate) fn start(&self, dispatch: impl Fn(&Target) -> Result<()> + Send + Sync + 'static) {
        let controller = self.clone();
        let dispatch = Arc::new(dispatch);
        std::thread::spawn(move || loop {
            if let Err(error) = controller.refresh() {
                if error.0 != "controller_busy" {
                    if let Ok(mut state) = controller.0.lock() { state.error = Some(error.0); }
                }
            }
            let actions = controller.0.lock().map(|mut state| state.tracker.due(Instant::now())).unwrap_or_default();
            for action in actions {
                let target = Target::from(action.clone());
                let result = latch(&target);
                let controller = controller.clone();
                let dispatch = Arc::clone(&dispatch);
                std::thread::spawn(move || {
                    let result = result.and_then(|()| dispatch(&target));
                    if let Ok(mut state) = controller.0.lock() {
                        let result = result.map_err(|error| error.0);
                        let result = if result == Err("idle_opening_changed") { Ok(()) } else { result };
                        state.tracker.finished(&action, result, Instant::now());
                    }
                });
            }
            std::thread::sleep(Duration::from_secs(1));
        });
    }

    pub(crate) fn refresh(&self) -> Result<()> {
        let _lock = crate::storage::lock_named("storage.lock")?;
        self.observe(crate::storage::idle_snapshot()?)
    }

    pub(crate) fn observe(&self, snapshot: Snapshot) -> Result<()> {
        let preferences = read_preferences(snapshot.general_open);
        let mut state = self.0.lock().map_err(|_| Error("idle_controller_failed"))?;
        state.error = None;
        let (preferences, origin) = match preferences {
            Ok(value) => value,
            Err(error) => {
                state.error = Some(error.0);
                // An unreadable preference never silently disables protection.
                (Preferences::default(), "defaults")
            }
        };
        state.tracker.configure(preferences).map_err(Error)?;
        let now = Instant::now();
        state.tracker.observe(snapshot.host.as_deref(), &snapshot.safes, now);
        for target in &snapshot.fences { state.tracker.fence(&target.action(), now); }
        state.storage = origin;
        state.writable = snapshot.writable;
        Ok(())
    }

    pub(crate) fn activity(&self, activity: Activity) -> Result<()> {
        crate::storage::validate_id(&activity.host)?;
        if let Some(safe) = &activity.safe {
            crate::storage::validate_id(&safe.safe_id)?;
            crate::storage::validate_id(&safe.nonce)?;
        }
        match crate::storage::lock_named("storage.lock") {
            Ok(_lock) => {
                let snapshot = crate::storage::idle_snapshot()?;
                require(snapshot.host.as_deref() == Some(&activity.host), "idle_opening_changed")?;
                if let Some(safe) = &activity.safe {
                    require(snapshot.safes.contains(safe), "idle_opening_changed")?;
                }
                self.observe(snapshot)?;
            }
            Err(Error("controller_busy")) => {
                // Long VM/bootstrap workers retain the operation lock. Human
                // input can refresh only the generation already known here,
                // with its current private nonce and no teardown fence.
                crate::storage::require_current_idle_activity(&activity)?;
            }
            Err(error) => return Err(error),
        }
        self.0.lock().map_err(|_| Error("idle_controller_failed"))?
            .tracker.activity(&activity, Instant::now()).map_err(Error)
    }

    pub(crate) fn configure(&self, preferences: Preferences) -> Result<()> {
        preferences.validate().map_err(Error)?;
        let _lock = crate::storage::lock_named("storage.lock")?;
        let snapshot = crate::storage::idle_snapshot()?;
        let path = if snapshot.writable { PathBuf::from(SAVED) } else { Path::new(RUN).join("app-settings.json") };
        write_preferences(&path, preferences)?;
        if snapshot.writable { clear_temporary()?; }
        self.observe(snapshot)
    }

    pub(crate) fn status(&self) -> Result<Status> {
        if let Err(error) = self.refresh() {
            if error.0 != "controller_busy" {
                self.0.lock().map_err(|_| Error("idle_controller_failed"))?.error = Some(error.0);
            }
        }
        let state = self.0.lock().map_err(|_| Error("idle_controller_failed"))?;
        let mut view = state.tracker.status(Instant::now());
        if let Some(error) = state.error { view.last_error = Some(error.into()); }
        Ok(Status { state: view, storage: state.storage, writable: state.writable })
    }
}

fn read_preferences(general_open: bool) -> Result<(Preferences, &'static str)> {
    for (path, origin) in [(Path::new(RUN).join("app-settings.json"), "ram-only"), (PathBuf::from(SAVED), "saved-encrypted")] {
        if origin == "saved-encrypted" && !general_open { continue }
        if !path.try_exists().map_err(|_| Error("idle_preferences_unavailable"))? { continue }
        let mut bytes = Vec::new();
        crate::storage::trusted_file(&path)?.take(1025).read_to_end(&mut bytes)
            .map_err(|_| Error("idle_preferences_unavailable"))?;
        require(bytes.len() <= 1024, "invalid_idle_preferences")?;
        let preferences: Preferences = serde_json::from_slice(&bytes).map_err(|_| Error("invalid_idle_preferences"))?;
        preferences.validate().map_err(Error)?;
        return Ok((preferences, origin));
    }
    Ok((Preferences::default(), "defaults"))
}

fn write_preferences(path: &Path, preferences: Preferences) -> Result<()> {
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        if existing.try_exists().map_err(|_| Error("idle_preferences_unavailable"))? { crate::storage::trusted_file(existing)?; }
    }
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&pending)
        .map_err(|_| Error("idle_preferences_write_failed"))?;
    file.write_all(&serde_json::to_vec(&preferences).map_err(|_| Error("encode_failed"))?)
        .and_then(|()| file.sync_all()).map_err(|_| Error("idle_preferences_write_failed"))?;
    fs::rename(&pending, path).map_err(|_| Error("idle_preferences_write_failed"))?;
    OpenOptions::new().read(true).open(path.parent().ok_or(Error("invalid_path"))?)
        .map_err(|_| Error("idle_preferences_write_failed"))?
        .sync_all().map_err(|_| Error("idle_preferences_write_failed"))
}

pub(crate) fn clear_temporary() -> Result<()> {
    for name in ["app-settings.json", "app-settings.json.pending"] {
        let path = Path::new(RUN).join(name);
        if path.try_exists().map_err(|_| Error("idle_preferences_unavailable"))? {
            crate::storage::trusted_file(&path)?;
            fs::remove_file(path).map_err(|_| Error("idle_preferences_write_failed"))?;
        }
    }
    Ok(())
}

pub(crate) fn latch(target: &Target) -> Result<()> {
    target.validate()?;
    let directory = Path::new(RUN).join("idle-locks");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&directory)
        .map_err(|_| Error("idle_fence_failed"))?;
    let info = fs::symlink_metadata(&directory).map_err(|_| Error("idle_fence_failed"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "idle_fence_failed")?;
    if target.path().exists() { crate::storage::trusted_file(&target.path())?; return Ok(()) }
    OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(target.path())
        .map_err(|_| Error("idle_fence_failed"))?;
    Ok(())
}

pub(crate) fn fenced(target: &Target) -> Result<bool> {
    if !target.path().try_exists().map_err(|_| Error("idle_fence_failed"))? { return Ok(false) }
    crate::storage::trusted_file(&target.path())?;
    Ok(true)
}

pub(crate) fn clear_fence(target: &Target) -> Result<()> {
    if fenced(target)? { fs::remove_file(target.path()).map_err(|_| Error("idle_fence_failed"))?; }
    Ok(())
}

pub(crate) fn fences() -> Result<Vec<Target>> {
    let directory = Path::new(RUN).join("idle-locks");
    if !directory.try_exists().map_err(|_| Error("idle_fence_failed"))? { return Ok(Vec::new()) }
    let info = fs::symlink_metadata(&directory).map_err(|_| Error("idle_fence_failed"))?;
    require(info.is_dir() && info.uid() == 0 && info.mode() & 0o077 == 0, "idle_fence_failed")?;
    let mut targets = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| Error("idle_fence_failed"))? {
        require(targets.len() < 512, "idle_fence_failed")?;
        let entry = entry.map_err(|_| Error("idle_fence_failed"))?;
        let name = entry.file_name();
        let fields: Vec<_> = name.to_str().ok_or(Error("idle_fence_failed"))?.split('-').collect();
        let target = match fields.as_slice() {
            ["host", nonce] => Target::Host { nonce: nonce.to_string() },
            ["safe", slot, safe_id, nonce] => Target::Safe { opening: Opening {
                slot: slot.parse::<u8>().map_err(|_| Error("idle_fence_failed"))?.try_into().map_err(Error)?,
                safe_id: safe_id.to_string(), nonce: nonce.to_string(),
            } },
            _ => return Err(Error("idle_fence_failed")),
        };
        target.validate()?;
        crate::storage::trusted_file(&entry.path())?;
        targets.push(target);
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_targets_reject_unknown_fields_and_invalid_generations() {
        assert!(serde_json::from_str::<Target>(r#"{"target":"host","nonce":"00000000000000000000000000000001","safe_id":"chosen"}"#).is_err());
        assert!(Target::Host { nonce: "old-opening".into() }.validate().is_err());
        assert!(serde_json::from_str::<Activity>(r#"{"host":"00000000000000000000000000000001","safe":null,"text":"never accepted"}"#).is_err());
    }

    #[test]
    #[ignore = "requires an isolated root-owned tmpfs /run; no production state"]
    fn private_preferences_and_generation_fences() {
        assert_eq!(std::env::var("OBLIVION_IDLE_CONTROLLER_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fs::DirBuilder::new().recursive(true).mode(0o700).create(RUN).unwrap();
        assert!(fs::read_dir(RUN).unwrap().next().is_none());
        let path = Path::new(RUN).join("app-settings.json");
        let preferences = Preferences { version: 1, safe_minutes: 3, host_minutes: 7 };
        write_preferences(&path, preferences).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(read_preferences(false).unwrap_or_else(|error| panic!("{}", error.0)), (preferences, "ram-only"));
        assert!(!path.with_extension("json.pending").exists());
        let controller = Controller::new().unwrap_or_else(|error| panic!("{}", error.0));
        let nonce = "11111111111111111111111111111111";
        let opening = Opening { slot: Default::default(), safe_id: "22222222222222222222222222222222".into(), nonce: "33333333333333333333333333333333".into() };
        let target = Target::Safe { opening: opening.clone() };
        latch(&target).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(fenced(&target).unwrap_or_else(|error| panic!("{}", error.0)));
        assert_eq!(fences().unwrap_or_else(|error| panic!("{}", error.0)).len(), 1);
        let snapshot = || Snapshot { host: Some(nonce.into()), safes: vec![opening.clone()], fences: vec![target.clone()], general_open: false, writable: false };
        controller.observe(snapshot()).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(controller.0.lock().unwrap().tracker.status(Instant::now()).safes[0].closing);
        fs::write(&path, br#"{"version":1,"safe_minutes":0,"host_minutes":9999}"#).unwrap();
        controller.observe(snapshot()).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(controller.0.lock().unwrap().tracker.preferences(), Preferences::default());
        assert_eq!(controller.0.lock().unwrap().error, Some("invalid_idle_preferences"));
        write_preferences(&path, Preferences { version: 1, safe_minutes: 0, host_minutes: 0 }).unwrap_or_else(|error| panic!("{}", error.0));
        controller.observe(snapshot()).unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(controller.0.lock().unwrap().error, None);
        assert!(controller.0.lock().unwrap().tracker.status(Instant::now()).safes[0].closing);
        clear_fence(&target).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(!fenced(&target).unwrap_or_else(|error| panic!("{}", error.0)));
        clear_temporary().unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(read_preferences(false).unwrap_or_else(|error| panic!("{}", error.0)), (Preferences::default(), "defaults"));
    }
}
