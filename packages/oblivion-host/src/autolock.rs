//! Idle deadlines depend exclusively on trusted human activity. Callers supply
//! monotonic instants; status polls, model output and guest traffic have no hook.
use crate::scope::Slot;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub version: u8,
    pub safe_minutes: u16,
    pub host_minutes: u16,
}

impl Default for Preferences {
    fn default() -> Self { Self { version: 1, safe_minutes: 15, host_minutes: 30 } }
}

impl Preferences {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 || self.safe_minutes > 1440 || self.host_minutes > 1440 {
            return Err("invalid_idle_preferences");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub slot: Slot,
    pub safe_id: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub host: String,
    pub safe: Option<Opening>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lock {
    Host(String),
    Safe(Opening),
}

struct Clock {
    touched: Instant,
    closing: bool,
    pending: bool,
    retry: Instant,
}

impl Clock {
    fn new(now: Instant) -> Self { Self { touched: now, closing: false, pending: false, retry: now } }
    fn due(&mut self, minutes: u16, now: Instant) -> bool {
        if self.pending || now < self.retry || !self.closing && (minutes == 0
            || now.saturating_duration_since(self.touched) < Duration::from_secs(u64::from(minutes) * 60)) {
            return false;
        }
        self.closing = true;
        self.pending = true;
        true
    }
    fn remaining(&self, minutes: u16, now: Instant) -> Option<u64> {
        (minutes > 0).then(|| Duration::from_secs(u64::from(minutes) * 60)
            .saturating_sub(now.saturating_duration_since(self.touched)).as_secs())
    }
}

pub struct Tracker {
    preferences: Preferences,
    host: Option<(String, Clock)>,
    safes: Vec<(Opening, Clock)>,
    last_error: Option<&'static str>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Status {
    pub preferences: Preferences,
    pub host: Option<HostStatus>,
    pub safes: Vec<SafeStatus>,
    pub last_error: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HostStatus {
    pub nonce: String,
    pub remaining_seconds: Option<u64>,
    pub closing: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SafeStatus {
    pub opening: Opening,
    pub remaining_seconds: Option<u64>,
    pub closing: bool,
}

impl Tracker {
    pub fn new(preferences: Preferences) -> Result<Self, &'static str> {
        preferences.validate()?;
        Ok(Self { preferences, host: None, safes: Vec::new(), last_error: None })
    }

    pub fn preferences(&self) -> Preferences { self.preferences }

    pub fn configure(&mut self, preferences: Preferences) -> Result<(), &'static str> {
        preferences.validate()?;
        self.preferences = preferences;
        Ok(())
    }

    pub fn observe(&mut self, host: Option<&str>, safes: &[Opening], now: Instant) {
        if self.host.as_ref().map(|entry| entry.0.as_str()) != host {
            self.host = host.map(|nonce| (nonce.to_owned(), Clock::new(now)));
            self.safes.clear();
            self.last_error = None;
        }
        if host.is_none() { return }
        self.safes.retain(|entry| safes.contains(&entry.0));
        for opening in safes {
            if !self.safes.iter().any(|entry| entry.0 == *opening) {
                self.safes.push((opening.clone(), Clock::new(now)));
            }
        }
        if self.host.as_ref().is_some_and(|entry| !entry.1.closing)
            && !self.safes.iter().any(|entry| entry.1.closing) {
            self.last_error = None;
        }
    }

    pub fn activity(&mut self, activity: &Activity, now: Instant) -> Result<(), &'static str> {
        let host = self.host.as_mut().filter(|entry| entry.0 == activity.host && !entry.1.closing)
            .ok_or("idle_opening_changed")?;
        if let Some(opening) = &activity.safe {
            let safe = self.safes.iter_mut().find(|entry| entry.0 == *opening && !entry.1.closing)
                .ok_or("idle_opening_changed")?;
            safe.1.touched = now;
        }
        host.1.touched = now;
        Ok(())
    }

    pub fn due(&mut self, now: Instant) -> Vec<Lock> {
        let Some(host) = self.host.as_mut() else { return Vec::new() };
        if host.1.due(self.preferences.host_minutes, now) { return vec![Lock::Host(host.0.clone())] }
        if host.1.closing { return Vec::new() }
        self.safes.iter_mut().filter_map(|entry| entry.1.due(self.preferences.safe_minutes, now)
            .then(|| Lock::Safe(entry.0.clone()))).collect()
    }

    pub fn fence(&mut self, action: &Lock, now: Instant) -> bool {
        let clock = match action {
            Lock::Host(nonce) => self.host.as_mut().filter(|entry| entry.0 == *nonce).map(|entry| &mut entry.1),
            Lock::Safe(opening) => self.safes.iter_mut().find(|entry| entry.0 == *opening).map(|entry| &mut entry.1),
        };
        let Some(clock) = clock else { return false };
        if !clock.closing { clock.closing = true; clock.retry = now }
        true
    }

    pub fn finished(&mut self, action: &Lock, result: Result<(), &'static str>, now: Instant) {
        let clock = match action {
            Lock::Host(nonce) => self.host.as_mut().filter(|entry| entry.0 == *nonce).map(|entry| &mut entry.1),
            Lock::Safe(opening) => self.safes.iter_mut().find(|entry| entry.0 == *opening).map(|entry| &mut entry.1),
        };
        let Some(clock) = clock else { return };
        clock.pending = false;
        // Keep the opening fenced until a fresh observation confirms that its
        // actual volume closed. Cleanup failures never make activity reopen it.
        clock.retry = now + Duration::from_secs(30);
        if let Err(error) = result { self.last_error = Some(error) }
    }

    pub fn status(&self, now: Instant) -> Status {
        Status {
            preferences: self.preferences,
            host: self.host.as_ref().map(|entry| HostStatus {
                nonce: entry.0.clone(), remaining_seconds: entry.1.remaining(self.preferences.host_minutes, now), closing: entry.1.closing,
            }),
            safes: self.safes.iter().map(|entry| SafeStatus {
                opening: entry.0.clone(), remaining_seconds: entry.1.remaining(self.preferences.safe_minutes, now), closing: entry.1.closing,
            }).collect(),
            last_error: self.last_error.map(str::to_owned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn opening(slot: u8, nonce: &str) -> Opening {
        Opening { slot: Slot::try_from(slot).unwrap(), safe_id: format!("{slot:032x}"), nonce: nonce.into() }
    }

    #[test]
    fn independent_safe_and_host_deadlines_require_human_activity() {
        let now = Instant::now();
        let a = opening(0, "a");
        let b = opening(1, "b");
        let mut tracker = Tracker::new(Preferences::default()).unwrap();
        tracker.observe(Some("host"), &[a.clone(), b.clone()], now);
        tracker.activity(&Activity { host: "host".into(), safe: Some(b.clone()) }, now + Duration::from_secs(14 * 60)).unwrap();
        // Observations represent model output, polling and VM promotion. They
        // do not refresh either opening's timestamp.
        tracker.observe(Some("host"), &[a.clone(), b.clone()], now + Duration::from_secs(15 * 60));
        assert_eq!(tracker.due(now + Duration::from_secs(15 * 60)), vec![Lock::Safe(a.clone())]);
        assert!(tracker.due(now + Duration::from_secs(16 * 60)).is_empty());
        assert_eq!(tracker.due(now + Duration::from_secs(29 * 60)), vec![Lock::Safe(b)]);
        assert_eq!(tracker.due(now + Duration::from_secs(44 * 60)), vec![Lock::Host("host".into())]);
    }

    #[test]
    fn stale_openings_cannot_extend_reopened_safe_or_host() {
        let now = Instant::now();
        let old = opening(0, "old");
        let new = opening(0, "new");
        let mut tracker = Tracker::new(Preferences::default()).unwrap();
        tracker.observe(Some("host"), &[old.clone()], now);
        tracker.observe(Some("host"), &[new.clone()], now + Duration::from_secs(60));
        assert_eq!(tracker.activity(&Activity { host: "host".into(), safe: Some(old) }, now + Duration::from_secs(120)), Err("idle_opening_changed"));
        assert_eq!(tracker.status(now + Duration::from_secs(120)).host.unwrap().remaining_seconds, Some(28 * 60));
        tracker.observe(Some("new-host"), &[new.clone()], now + Duration::from_secs(180));
        assert!(tracker.activity(&Activity { host: "host".into(), safe: Some(new) }, now + Duration::from_secs(240)).is_err());
    }

    #[test]
    fn host_deadline_wins_and_failed_cleanup_remains_fenced() {
        let now = Instant::now();
        let safe = opening(0, "safe");
        let mut tracker = Tracker::new(Preferences { version: 1, safe_minutes: 15, host_minutes: 10 }).unwrap();
        tracker.observe(Some("host"), &[safe], now);
        let action = Lock::Host("host".into());
        assert_eq!(tracker.due(now + Duration::from_secs(600)), vec![action.clone()]);
        tracker.finished(&action, Err("cleanup_failed"), now + Duration::from_secs(600));
        assert!(tracker.activity(&Activity { host: "host".into(), safe: None }, now + Duration::from_secs(601)).is_err());
        assert!(tracker.due(now + Duration::from_secs(629)).is_empty());
        assert_eq!(tracker.due(now + Duration::from_secs(630)), vec![action]);
        assert_eq!(tracker.status(now).last_error.as_deref(), Some("cleanup_failed"));
        tracker.observe(None, &[], now + Duration::from_secs(631));
        assert!(tracker.status(now).host.is_none());
        assert!(tracker.due(now + Duration::from_secs(3600)).is_empty());
    }

    #[test]
    fn disabled_timers_require_explicit_zero_and_unknown_profiles_are_rejected() {
        let now = Instant::now();
        let mut tracker = Tracker::new(Preferences { version: 1, safe_minutes: 0, host_minutes: 0 }).unwrap();
        tracker.observe(Some("host"), &[opening(0, "safe")], now);
        assert!(tracker.due(now + Duration::from_secs(86400)).is_empty());
        assert_eq!(tracker.status(now).safes[0].remaining_seconds, None);
        assert!(serde_json::from_str::<Preferences>(r#"{"version":1,"safe_minutes":15}"#).is_err());
        assert!(Preferences { version: 2, ..Preferences::default() }.validate().is_err());
        assert!(Preferences { safe_minutes: 1441, ..Preferences::default() }.validate().is_err());
    }

    #[test]
    fn recovery_fences_cannot_be_cancelled_by_new_policy_or_observations() {
        let now = Instant::now();
        let safe = opening(0, "safe");
        let action = Lock::Safe(safe.clone());
        let mut tracker = Tracker::new(Preferences::default()).unwrap();
        tracker.observe(Some("host"), &[safe.clone()], now);
        assert!(tracker.fence(&action, now));
        assert_eq!(tracker.due(now), vec![action.clone()]);
        assert!(tracker.fence(&action, now));
        assert!(tracker.due(now).is_empty());
        tracker.finished(&action, Err("cleanup_failed"), now);
        tracker.configure(Preferences { version: 1, safe_minutes: 0, host_minutes: 0 }).unwrap();
        tracker.observe(Some("host"), &[safe.clone()], now + Duration::from_secs(20));
        assert!(tracker.fence(&action, now + Duration::from_secs(20)));
        assert!(tracker.due(now + Duration::from_secs(29)).is_empty());
        assert_eq!(tracker.due(now + Duration::from_secs(30)), vec![action]);
        assert!(tracker.activity(&Activity { host: "host".into(), safe: Some(safe) }, now + Duration::from_secs(31)).is_err());
    }
}
