//! User-directed delivery of an immutable, sealed child task. The creation
//! journal admits request IDs; the guest/managed registry owns execution facts.
use crate::chat_jobs::{Registry, Release};
use crate::safe_tools::Context;
use crate::storage::{Error, Result, require};
use oblivion_host::child_task::{Phase, Review, Status};
use oblivion_host::family::Capability;
use oblivion_host::managed::{Info, Reason, State};
use oblivion_host::{child_task, safe_admin, safe_origin, scope};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum Action { Status, Review, Start, Retry, Cancel }

enum Observation { Absent, Known(Info), Unavailable }

pub(crate) fn prepare(expected: &str) -> Result<Context> {
    let _lock = crate::storage::recovery_lock()?;
    require(!crate::storage::recovery_required()?, "recovery_required")?;
    let opening = crate::storage::idle_opening()?.filter(|opening| opening.safe_id == expected)
        .ok_or(Error("session_changed"))?;
    crate::storage::task_origin(&opening)?;
    let owner = Arc::new(crate::vm::session_owner()?);
    require(crate::safe_tools::owner_alive(&owner)?, "session_changed")?;
    Ok(Context { slot: scope::current(), safe_id: expected.into(), opening, owner })
}

pub(crate) fn call(jobs: &Arc<Registry>, context: &Context, capability: &Capability,
    action: Action, request: Option<&child_task::Request>, release: Release) -> Result<String> {
    let origin = source(context)?;
    if let Some(request) = request {
        require(request.request_id == origin.request_id, "child_task_changed")?;
    }
    let observation = observe(jobs, context, &origin, &release)?;
    match action {
        Action::Status => encode(status(&origin, observation)),
        Action::Review => {
            let task = origin.sealed_task.open(capability, &origin.context()).map_err(Error)?;
            source(context)?;
            encode(Review { status: status(&origin, observation), task })
        }
        Action::Start | Action::Retry => {
            require(request.is_some(), "invalid_child_task_request")?;
            let prior = match &observation { Observation::Known(info) => Some(info), _ => None };
            require(!matches!(observation, Observation::Unavailable), "task_status_unavailable")?;
            if let Some(info) = prior {
                // An ordinary Start reconciles the existing attempt. It never
                // repeats completed/failed work under a new request identity.
                if matches!(action, Action::Start) { return encode(status(&origin, Observation::Known(info.clone()))); }
            }
            let task = origin.sealed_task.open(capability, &origin.context()).map_err(Error)?;
            let attempt = {
                let _lock = crate::storage::recovery_lock()?;
                require_current(context)?;
                crate::storage::task_attempt(&context.opening, prior, matches!(action, Action::Retry))?
            };
            // The durable admission precedes model execution. Retrying Start
            // after an uncertain response uses this exact request identity.
            let info = jobs.create(context, &origin.agent, &task, &attempt, release)?;
            drop(task);
            let current = source(context)?;
            encode(status(&current, Observation::Known(info)))
        }
        Action::Cancel => {
            require(request.is_some(), "invalid_child_task_request")?;
            let Observation::Known(info) = observation else { return Err(Error("task_status_unavailable")) };
            if info.state.terminal() { return encode(status(&origin, Observation::Known(info))); }
            let info = jobs.cancel(context, &info.job_id)?;
            source(context)?;
            encode(status(&origin, Observation::Known(info)))
        }
    }
}

fn source(context: &Context) -> Result<safe_origin::AgentCreated> {
    let _lock = crate::storage::recovery_lock()?;
    require_current(context)?;
    crate::storage::task_origin(&context.opening)
}

fn require_current(context: &Context) -> Result<()> {
    require(!crate::storage::recovery_required()? && scope::current() == context.slot
        && crate::storage::idle_opening()?.as_ref() == Some(&context.opening)
        && crate::safe_tools::owner_alive(&context.owner)?, "session_changed")?;
    crate::storage::require_safe_branch_open(&context.safe_id)
}

fn observe(jobs: &Arc<Registry>, context: &Context, origin: &safe_origin::AgentCreated, release: &Release) -> Result<Observation> {
    let Some(attempt) = origin.attempts.last() else { return Ok(Observation::Absent) };
    let id = crate::chat_jobs::derive_id(&context.safe_id, attempt);
    let mode = {
        let _lock = crate::storage::recovery_lock()?;
        require_current(context)?;
        crate::storage::session_info()?.ok_or(Error("session_changed"))?.1
    };
    let observation = if mode == "agent" {
        match jobs.status(context, &id, Arc::clone(release)) {
            Ok(info) => Observation::Known(info),
            Err(Error("chat_job_not_found")) => Observation::Absent,
            Err(_) => Observation::Unavailable,
        }
    } else {
        let _lock = crate::storage::recovery_lock()?;
        require_current(context)?;
        match crate::storage::session_admin(safe_admin::Command::Job { job_id: id }) {
            Ok(safe_admin::Response::Job { info: Some(info) }) => Observation::Known(info),
            Ok(safe_admin::Response::Job { info: None }) => Observation::Absent,
            _ => Observation::Unavailable,
        }
    };
    if let Observation::Known(info) = &observation {
        require(info.valid() && info.request_id == *attempt && info.agent == origin.agent, "invalid_child_task_response")?;
    }
    source(context)?;
    Ok(observation)
}

fn status(origin: &safe_origin::AgentCreated, observation: Observation) -> Status {
    let unavailable = matches!(observation, Observation::Unavailable);
    let job = match observation { Observation::Known(info) => Some(info), _ => None };
    let cleanup = job.as_ref().is_some_and(|info| info.reason == Some(Reason::CleanupRequired));
    Status {
        version: 1, safe_id: origin.safe_id.clone(), agent: origin.agent.clone(), request_id: origin.request_id.clone(),
        attempt_request_id: origin.attempts.last().cloned(), attempts: origin.attempts.len(), attempt_limit: safe_origin::ATTEMPT_LIMIT,
        phase: if job.is_some() { Phase::Submitted } else if origin.attempts.is_empty() { Phase::NotStarted } else { Phase::Unknown },
        can_start: !unavailable && job.is_none(),
        can_retry: !cleanup && origin.attempts.len() < safe_origin::ATTEMPT_LIMIT
            && job.as_ref().is_some_and(|info| matches!(info.state, State::Failed | State::Cancelled)),
        can_cancel: job.as_ref().is_some_and(|info| !info.state.terminal()),
        blocked: if unavailable { Some("task_status_unavailable".into()) } else if cleanup { Some("recovery_required".into()) }
            else if origin.attempts.len() == safe_origin::ATTEMPT_LIMIT
                && job.as_ref().is_some_and(|info| matches!(info.state, State::Failed | State::Cancelled)) { Some("task_attempt_limit".into()) } else { None },
        job,
    }
}

fn encode(value: impl serde::Serialize) -> Result<String> {
    serde_json::to_string(&value).map_err(|_| Error("encode_failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oblivion_host::family::{SealedTask, TaskContext};
    use zeroize::Zeroizing;

    fn origin() -> safe_origin::AgentCreated {
        let capability = Capability::from_root_secret(&"1".repeat(32), Zeroizing::new([37; 32])).unwrap();
        let safe_id = "2".repeat(32);
        let parent_id = "3".repeat(32);
        let request_id = "4".repeat(32);
        let sealed_task = SealedTask::seal(&capability, &TaskContext { safe_id: &safe_id, parent_id: &parent_id, request_id: &request_id, agent: "codex" }, "private queued task canary").unwrap();
        safe_origin::AgentCreated { safe_id, parent_id, request_id, agent: "codex".into(), creator_chat_id: None, sealed_task, attempts: Vec::new() }
    }

    #[test]
    fn execution_facts_fit_the_client_contract_without_task_content() {
        let mut origin = origin();
        let pending = status(&origin, Observation::Absent);
        assert!(pending.valid() && pending.can_start && !pending.can_retry && !pending.can_cancel);
        origin.attempts.push(origin.request_id.clone());
        for state in [State::Queued, State::Running, State::Completed, State::Failed, State::Cancelled] {
            let value = status(&origin, Observation::Known(Info {
                job_id: crate::chat_jobs::derive_id(&origin.safe_id, &origin.request_id), request_id: origin.request_id.clone(),
                agent: origin.agent.clone(), state, native_chat_id: None, reason: if state == State::Failed { Some(Reason::NeedsAuth) } else { None },
            }));
            assert!(value.valid());
            assert!(!value.can_start);
            assert_eq!(value.can_cancel, !state.terminal());
            assert_eq!(value.can_retry, matches!(state, State::Failed | State::Cancelled));
            let encoded = serde_json::to_vec(&value).unwrap();
            assert!(!encoded.windows(7).any(|bytes| bytes == b"private"));
            let decoded: child_task::Status = serde_json::from_slice(&encoded).unwrap();
            assert!(decoded.valid());
        }
    }

    #[test]
    fn missing_observation_never_authorizes_a_new_attempt_or_claims_completion() {
        let mut origin = origin();
        origin.attempts.push(origin.request_id.clone());
        let missing = status(&origin, Observation::Absent);
        assert!(missing.valid() && missing.phase == Phase::Unknown && missing.can_start);
        assert!(!missing.can_retry && !missing.can_cancel && missing.job.is_none());
        let unavailable = status(&origin, Observation::Unavailable);
        assert!(unavailable.valid() && unavailable.phase == Phase::Unknown && !unavailable.can_start);
        assert!(!unavailable.can_retry && !unavailable.can_cancel && unavailable.job.is_none());
        assert_eq!(unavailable.blocked.as_deref(), Some("task_status_unavailable"));
    }
}
