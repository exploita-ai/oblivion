//! Process-local startup observations, never durable execution facts. The
//! sealed creation journal and the guest job remain the recovery authorities.
use crate::safe_tools::Context;
use crate::storage::{Error, Result, require};
use oblivion_host::autolock::Opening;
use oblivion_host::managed::Info;
use serde::Serialize;
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Queued, Preparing, NeedsAuth, Submitted, Finished, Unavailable }

#[derive(Clone, Serialize)]
pub(crate) struct Observation {
    pub phase: Phase,
    pub job: Option<Info>,
    pub reason: Option<&'static str>,
}

struct Record { parent: Opening, owner: Arc<OwnedFd>, observation: Observation }

#[derive(Default)]
pub(crate) struct Registry { records: Mutex<BTreeMap<String, Record>> }

pub(crate) fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

impl Registry {
    pub(crate) fn begin(&self, parent: &Context, child: &str) -> Result<bool> {
        require(oblivion_host::managed::id(child) && child != parent.safe_id, "invalid_child_task_request")?;
        let mut records = self.records.lock().map_err(|_| Error("child_start_unavailable"))?;
        // Closed parents no longer authorize startup observations. Reclaim
        // them so successive RAM-only workspaces do not exhaust this bound.
        records.retain(|_, record| crate::safe_tools::owner_alive(&record.owner).unwrap_or(true));
        if let Some(record) = records.get(child) {
            require(record.parent == parent.opening, "child_start_authority_changed")?;
            // Reconciliation cannot start another process, including after a
            // failed boot. A later explicit task Start owns that decision.
            return Ok(false);
        }
        require(records.len() < 128, "child_start_limit")?;
        records.insert(child.into(), Record { parent: parent.opening.clone(), owner: Arc::clone(&parent.owner),
            observation: Observation { phase: Phase::Queued, job: None, reason: None } });
        Ok(true)
    }

    pub(crate) fn set(&self, parent: &Context, child: &str, observation: Observation) -> Result<()> {
        require(observation.job.as_ref().is_none_or(Info::valid), "invalid_child_task_response")?;
        let mut records = self.records.lock().map_err(|_| Error("child_start_unavailable"))?;
        let record = records.get_mut(child).filter(|record| record.parent == parent.opening)
            .ok_or(Error("child_start_authority_changed"))?;
        record.observation = observation;
        Ok(())
    }

    pub(crate) fn get(&self, parent: &Context, child: &str) -> Result<Option<Observation>> {
        Ok(self.records.lock().map_err(|_| Error("child_start_unavailable"))?.get(child)
            .filter(|record| record.parent == parent.opening).map(|record| record.observation.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn a_creation_is_admitted_once_and_observations_never_cross_an_opening() {
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) as i32 };
        assert!(descriptor >= 0);
        let parent = Context { slot: Default::default(), safe_id: "1".repeat(32),
            opening: Opening { slot: Default::default(), safe_id: "1".repeat(32), nonce: "2".repeat(32) },
            owner: Arc::new(unsafe { OwnedFd::from_raw_fd(descriptor) }) };
        let child = "3".repeat(32);
        let registry = Registry::default();
        assert!(registry.begin(&parent, &child).unwrap_or_else(|error| panic!("{}", error.0)));
        assert!(!registry.begin(&parent, &child).unwrap_or_else(|error| panic!("{}", error.0)));
        registry.set(&parent, &child, Observation { phase: Phase::NeedsAuth, job: None,
            reason: Some("needs-auth") }).unwrap_or_else(|error| panic!("{}", error.0));
        assert!(!registry.begin(&parent, &child).unwrap_or_else(|error| panic!("{}", error.0)));
        let mut reopened = parent.clone();
        reopened.opening.nonce = "4".repeat(32);
        assert!(registry.get(&reopened, &child).unwrap_or_else(|error| panic!("{}", error.0)).is_none());
        assert!(registry.begin(&reopened, &child).is_err());
        assert!(registry.set(&reopened, &child, Observation { phase: Phase::Submitted, job: None, reason: None }).is_err());
        assert_eq!(serde_json::to_value(registry.get(&parent, &child).unwrap_or_else(|error| panic!("{}", error.0))).unwrap(),
            serde_json::json!({ "phase": "needs-auth", "job": null, "reason": "needs-auth" }));
    }
}
