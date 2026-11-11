//! One controller-owned, export-only authorization. No passwords or transcripts.
use crate::storage::{Error, Result, require};
use oblivion_host::{autolock::Opening, family::Capability};
pub use oblivion_share::control::{ExportIdentity, ExportOpen, ExportSelection, ExportSource, ExportStarted};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const LIFETIME: Duration = Duration::from_secs(3600);

struct Export {
    id: String,
    host: String,
    sources: BTreeSet<String>,
    capabilities: BTreeMap<String, Capability>,
    opening: Option<Opening>,
    created: Instant,
    leased: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Registry, String, String, String, String) {
        let registry = Registry::default();
        let (id, host, first, second) = (
            "a".repeat(32),
            "b".repeat(32),
            "c".repeat(32),
            "d".repeat(32),
        );
        registry
            .begin(
                id.clone(),
                host.clone(),
                vec![
                    ExportSource {
                        id: first.clone(),
                        parent: None,
                    },
                    ExportSource {
                        id: second.clone(),
                        parent: Some(first.clone()),
                    },
                ],
            )
            .unwrap_or_else(|error| panic!("{}", error.0));
        (registry, id, host, first, second)
    }

    #[test]
    fn authority_requires_lease_host_generation_and_fixed_source_set() {
        let (registry, id, host, first, _) = fixture();
        assert!(
            registry
                .lookup(&id, &host, &first, &"e".repeat(32))
                .is_err()
        );
        registry
            .lease(&id, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(
            registry
                .lookup(&id, &"f".repeat(32), &first, &"e".repeat(32))
                .is_err()
        );
        assert!(
            registry
                .lookup(&id, &host, &"f".repeat(32), &"e".repeat(32))
                .is_err()
        );
        assert!(
            registry
                .lookup(&id, &host, &first, &"e".repeat(32))
                .unwrap_or_else(|error| panic!("{}", error.0))
                .is_none()
        );
        assert!(registry.lease(&id, &host).is_err());
    }

    #[test]
    fn family_reopens_selected_siblings_without_retaining_passwords() {
        let (registry, id, host, first, second) = fixture();
        registry
            .lease(&id, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let family = "e".repeat(32);
        let capability = Capability::from_root_secret(&family, Zeroizing::new([37; 32])).unwrap();
        let expected = oblivion_host::family::credential_for_safe(&capability, &second).unwrap();
        registry
            .retain(&id, &host, &first, capability)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let recovered = registry
            .lookup(&id, &host, &second, &family)
            .unwrap_or_else(|error| panic!("{}", error.0))
            .unwrap();
        assert_eq!(
            *oblivion_host::family::credential_for_safe(&recovered, &second).unwrap(),
            *expected
        );
        registry
            .end(Some(&id))
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(registry.lookup(&id, &host, &second, &family).is_err());
    }

    #[test]
    fn only_one_maintenance_opening_survives_until_confirmed_closed() {
        let (registry, id, host, first, second) = fixture();
        registry
            .lease(&id, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let first = Opening {
            slot: Default::default(),
            safe_id: first,
            nonce: "e".repeat(32),
        };
        let second = Opening {
            slot: 1.try_into().unwrap(),
            safe_id: second,
            nonce: "f".repeat(32),
        };
        registry
            .opened(&id, &host, first.clone())
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(registry.opened(&id, &host, second.clone()).is_err());
        registry
            .closed(&second)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(registry.opened(&id, &host, second.clone()).is_err());
        registry
            .closed(&first)
            .unwrap_or_else(|error| panic!("{}", error.0));
        registry
            .opened(&id, &host, second.clone())
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(
            registry
                .end(Some(&id))
                .unwrap_or_else(|error| panic!("{}", error.0)),
            Some(second)
        );
    }

    #[test]
    fn expiry_and_idle_revoke_without_waiting_for_physical_teardown() {
        let (registry, id, host, first, _) = fixture();
        registry
            .lease(&id, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        registry.0.lock().unwrap().as_mut().unwrap().created -= LIFETIME;
        assert!(
            registry
                .lookup(&id, &host, &first, &"e".repeat(32))
                .is_err()
        );
        registry
            .end(Some(&id))
            .unwrap_or_else(|error| panic!("{}", error.0));
        let (registry, id, host, first, _) = fixture();
        registry
            .lease(&id, &host)
            .unwrap_or_else(|error| panic!("{}", error.0));
        let opening = Opening {
            slot: Default::default(),
            safe_id: first,
            nonce: "e".repeat(32),
        };
        registry
            .opened(&id, &host, opening.clone())
            .unwrap_or_else(|error| panic!("{}", error.0));
        registry
            .revoke_opening(&opening)
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert!(registry.current(&id, &host, &opening.safe_id).is_err());
    }
}

#[derive(Default)]
pub struct Registry(Mutex<Option<Export>>);
static REGISTRY: OnceLock<Registry> = OnceLock::new();
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::default)
}

impl Registry {
    pub fn begin(&self, id: String, host: String, sources: Vec<ExportSource>) -> Result<ExportStarted> {
        crate::storage::validate_id(&id)?;
        crate::storage::validate_id(&host)?;
        require(
            !sources.is_empty() && sources.len() <= oblivion_share::manifest::MAX_SAFES,
            "share_safe_limit",
        )?;
        let mut set = BTreeSet::new();
        for source in &sources {
            crate::storage::validate_id(&source.id)?;
            require(set.insert(source.id.clone()), "duplicate_share_safe")?;
            if let Some(parent) = &source.parent {
                crate::storage::validate_id(parent)?;
            }
        }
        require(
            sources.iter().all(|source| {
                source
                    .parent
                    .as_ref()
                    .is_none_or(|parent| set.contains(parent) && parent != &source.id)
            }),
            "invalid_share_parent",
        )?;
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        if entry
            .as_ref()
            .is_some_and(|entry| !entry.leased && entry.created.elapsed() > Duration::from_secs(30))
        {
            *entry = None;
        }
        require(entry.is_none(), "share_export_active")?;
        *entry = Some(Export {
            id: id.clone(),
            host,
            sources: set,
            capabilities: BTreeMap::new(),
            opening: None,
            created: Instant::now(),
            leased: false,
        });
        Ok(ExportStarted {
            export_id: id,
            sources,
            settings: None,
        })
    }

    pub fn lease(&self, id: &str, host: &str) -> Result<Duration> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        let entry = entry.as_mut().ok_or(Error("share_export_not_found"))?;
        require(
            entry.id == id
                && entry.host == host
                && !entry.leased
                && entry.created.elapsed() < Duration::from_secs(30),
            "share_export_not_found",
        )?;
        entry.leased = true;
        Ok(LIFETIME.saturating_sub(entry.created.elapsed()))
    }

    fn active<'a>(
        entry: &'a mut Option<Export>,
        id: &str,
        host: &str,
        source: &str,
    ) -> Result<&'a mut Export> {
        let entry = entry.as_mut().ok_or(Error("share_export_not_found"))?;
        require(
            entry.id == id
                && entry.host == host
                && entry.leased
                && entry.created.elapsed() < LIFETIME,
            "share_export_expired",
        )?;
        require(
            entry.sources.contains(source),
            "share_source_not_authorized",
        )?;
        Ok(entry)
    }

    pub fn lookup(
        &self,
        id: &str,
        host: &str,
        source: &str,
        family: &str,
    ) -> Result<Option<Capability>> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        let entry = Self::active(&mut entry, id, host, source)?;
        entry
            .capabilities
            .get(family)
            .map(|capability| {
                Capability::from_root_secret(family, Zeroizing::new(*capability.root_secret()))
                    .map_err(Error)
            })
            .transpose()
    }

    pub fn retain(&self, id: &str, host: &str, source: &str, capability: Capability) -> Result<()> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        Self::active(&mut entry, id, host, source)?
            .capabilities
            .insert(capability.family_id().to_owned(), capability);
        Ok(())
    }

    pub fn current(&self, id: &str, host: &str, source: &str) -> Result<Option<Opening>> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        Ok(Self::active(&mut entry, id, host, source)?.opening.clone())
    }

    pub fn opened(&self, id: &str, host: &str, opening: Opening) -> Result<()> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        let entry = Self::active(&mut entry, id, host, &opening.safe_id)?;
        require(entry.opening.is_none(), "share_source_active")?;
        entry.opening = Some(opening);
        Ok(())
    }

    pub fn closed(&self, opening: &Opening) -> Result<()> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        if let Some(entry) = entry
            .as_mut()
            .filter(|entry| entry.opening.as_ref() == Some(opening))
        {
            entry.opening = None;
        }
        Ok(())
    }

    pub fn revoke_opening(&self, opening: &Opening) -> Result<()> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        if entry
            .as_ref()
            .is_some_and(|entry| entry.opening.as_ref() == Some(opening))
        {
            *entry = None;
        }
        Ok(())
    }

    /// Removes authority before any potentially slow physical cleanup.
    pub fn end(&self, id: Option<&str>) -> Result<Option<Opening>> {
        let mut entry = self.0.lock().map_err(|_| Error("share_export_failed"))?;
        if let Some(id) = id {
            if entry.is_none() {
                return Ok(None);
            }
            require(
                entry.as_ref().is_some_and(|entry| entry.id == id),
                "share_export_not_found",
            )?;
        }
        Ok(entry.take().and_then(|entry| entry.opening))
    }
}
