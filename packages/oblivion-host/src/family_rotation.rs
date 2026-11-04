//! Current password-wrapper change protocol. This never replaces a data key.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Two 1024-byte passwords can each expand sixfold in JSON. This bound applies
/// only to the password-change body, not to other controller operations.
pub const CHANGE_LIMIT: usize = 16 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub safe_id: String,
    pub title: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub host_opening: String,
    pub family_id: String,
    pub members: Vec<Member>,
    pub sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub safe_id: String,
    pub host_opening: String,
    pub plan_sha256: String,
    pub current_password: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome { Pending, Complete, RolledBack }

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction { Complete, Rollback }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Recover {
    pub transaction: String,
    pub host_opening: String,
    pub direction: Direction,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub transaction: String,
    pub family_id: String,
    pub members: Vec<Member>,
    pub outcome: Outcome,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub host_opening: String,
    pub transactions: Vec<Entry>,
}

impl Plan {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::managed::id(&self.host_opening) || !crate::managed::id(&self.family_id)
            || self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err("invalid_family_password_response");
        }
        members(&self.members)
    }
}

impl Entry {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::managed::id(&self.transaction) || !crate::managed::id(&self.family_id) { return Err("invalid_family_password_response"); }
        members(&self.members)
    }
}

impl Status {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::managed::id(&self.host_opening) || self.transactions.len() > 128 { return Err("invalid_family_password_response"); }
        let mut ids = std::collections::BTreeSet::new();
        for entry in &self.transactions {
            entry.validate()?;
            if !ids.insert(&entry.transaction) { return Err("invalid_family_password_response"); }
        }
        Ok(())
    }
}

fn members(members: &[Member]) -> Result<(), &'static str> {
    if members.is_empty() || members.len() > 256 { return Err("invalid_family_password_response"); }
    let mut ids = std::collections::BTreeSet::new();
    for member in members {
        if !crate::managed::id(&member.safe_id) || !ids.insert(&member.safe_id) { return Err("invalid_family_password_response"); }
        crate::session_title::validate(&member.title)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_never_accept_a_host_path_or_family_capability() {
        let change = serde_json::json!({"safe_id":"a".repeat(32),"host_opening":"b".repeat(32),"plan_sha256":"c".repeat(64),
            "current_password":"synthetic-current","new_password":"synthetic-new-password"});
        assert!(serde_json::from_value::<Change>(change.clone()).is_ok());
        for field in ["path", "members", "capability", "family_id", "token", "command"] {
            let mut invalid = change.clone(); invalid.as_object_mut().unwrap().insert(field.into(), serde_json::json!("not caller authority"));
            assert!(serde_json::from_value::<Change>(invalid).is_err());
        }
        assert!(serde_json::from_value::<Recover>(serde_json::json!({"transaction":"a".repeat(32),"host_opening":"b".repeat(32),"direction":"auto"})).is_err());
    }

    #[test]
    fn response_boundary_rejects_terminal_controls_duplicate_members_and_unbounded_plans() {
        let mut plan = Plan { host_opening: "a".repeat(32), family_id: "b".repeat(32), sha256: "c".repeat(64),
            members: vec![Member { safe_id: "d".repeat(32), title: "Safe child".into() }] };
        assert!(plan.validate().is_ok());
        plan.members[0].title = "Safe\u{1b}[2J".into(); assert!(plan.validate().is_err());
        plan.members[0].title = "Safe child".into(); plan.members.push(plan.members[0].clone()); assert!(plan.validate().is_err());
        plan.members = vec![plan.members[0].clone(); 257]; assert!(plan.validate().is_err());
        plan.members.truncate(1); plan.host_opening = "not an opening".into(); assert!(plan.validate().is_err());
    }

    #[test]
    fn maximum_escaped_passwords_fit_the_dedicated_change_body() {
        let change = Change { safe_id: "a".repeat(32), host_opening: "b".repeat(32), plan_sha256: "c".repeat(64),
            current_password: Zeroizing::new("\u{1}".repeat(1024)), new_password: Zeroizing::new("\u{2}".repeat(1024)) };
        let body = Zeroizing::new(serde_json::to_vec(&change).unwrap());
        assert!(body.len() > 4096 && body.len() <= CHANGE_LIMIT);
        let decoded: Change = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.current_password.len(), 1024);
        assert_eq!(decoded.new_password.len(), 1024);
    }
}
