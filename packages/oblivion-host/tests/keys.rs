use oblivion_host::keys::{Archive, Command, Keyring, LEGACY};
use oblivion_transport::provider::Provider;
use zeroize::Zeroizing;

const FIRST: &str = "synthetic-first-api-key";
const SECOND: &str = "synthetic-second-api-key";

#[test]
fn ram_default_is_global_and_opening_override_does_not_change_it() {
    let mut temporary = Archive::empty();
    temporary
        .change(Command::Add {
            provider: Provider::Refuseless,
            name: "Temporary".into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    let id = temporary.status(None).entries[0].id.clone();
    let mut keyring = Keyring::new(
        Archive::legacy(Zeroizing::new(FIRST.into())).unwrap(),
        temporary,
    )
    .unwrap();
    keyring.default = Some(Some(id.clone()));
    assert_eq!(keyring.status(None).default, Some(id.clone()));
    assert_eq!(
        keyring
            .status(Some(Some(LEGACY.into())))
            .selected
            .as_deref(),
        Some(LEGACY)
    );
    assert_eq!(keyring.status(None).selected, Some(id.clone()));
    keyring.temporary.change(Command::Remove { id }).unwrap();
    assert!(keyring.status(None).default.is_none());
    assert!(keyring.status(None).selected.is_none());
    keyring.default = None;
    assert_eq!(keyring.status(None).default.as_deref(), Some(LEGACY));
}

#[test]
fn named_keys_roundtrip_without_disclosing_secrets_in_status() {
    let mut archive = Archive::empty();
    archive
        .change(Command::Add {
            provider: Provider::AbliterationAi,
            name: "Personale".into(),
            key: Zeroizing::new(FIRST.into()),
        })
        .unwrap();
    archive
        .change(Command::Add {
            provider: Provider::Refuseless,
            name: "Lavoro".into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    let archive = Archive::decode(&archive.encode().unwrap()).unwrap();
    let status = archive.status(None);
    assert_eq!(status.entries.len(), 2);
    assert_ne!(status.entries[0].id, status.entries[1].id);
    assert_eq!(status.entries[0].provider, Provider::AbliterationAi);
    assert_eq!(status.entries[1].provider, Provider::Refuseless);
    assert_eq!(status.selected.as_ref(), Some(&status.entries[0].id));
    assert_eq!(archive.key(&status.entries[1].id), Some(SECOND));
    let public = serde_json::to_string(&status).unwrap();
    assert!(public.contains("Personale") && public.contains("Lavoro"));
    assert!(!public.contains(FIRST) && !public.contains(SECOND));
}

#[test]
fn version_one_archives_migrate_to_abliteration_without_losing_the_key() {
    let archive = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&archive.encode().unwrap()).unwrap();
    legacy["version"] = serde_json::json!(1);
    legacy["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("provider");
    let migrated = Archive::decode(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_eq!(migrated.key(LEGACY), Some(FIRST));
    assert_eq!(
        migrated.status(None).entries[0].provider,
        Provider::AbliterationAi
    );
    let encoded: serde_json::Value = serde_json::from_slice(&migrated.encode().unwrap()).unwrap();
    assert_eq!(encoded["version"], 2);
    assert_eq!(encoded["entries"][0]["provider"], "abliteration-ai");
}

#[test]
fn selection_overrides_default_without_rotating_after_removal() {
    let mut archive = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    archive
        .change(Command::Add {
            provider: Provider::Refuseless,
            name: "Seconda".into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    let next = archive.status(None).entries[1].id.clone();
    archive
        .change(Command::Default { id: next.clone() })
        .unwrap();
    assert_eq!(archive.status(None).selected, Some(next.clone()));
    assert_eq!(
        archive
            .status(Some(Some(LEGACY.into())))
            .selected
            .as_deref(),
        Some(LEGACY)
    );
    assert!(archive.status(Some(None)).selected.is_none());
    archive
        .change(Command::Remove { id: LEGACY.into() })
        .unwrap();
    assert!(archive.status(Some(Some(LEGACY.into()))).selected.is_none());
    archive.change(Command::Remove { id: next }).unwrap();
    assert!(archive.status(None).default.is_none());
    assert!(archive.status(None).selected.is_none());
}

#[test]
fn replacement_and_rename_preserve_identity_and_invalid_changes_preserve_data() {
    let mut archive = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    archive
        .change(Command::Rename {
            id: LEGACY.into(),
            name: "Privata".into(),
        })
        .unwrap();
    archive
        .change(Command::Replace {
            id: LEGACY.into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    assert_eq!(archive.status(None).entries[0].name, "Privata");
    assert_eq!(archive.key(LEGACY), Some(SECOND));
    let before = archive.encode().unwrap();
    for name in ["", " spazio", "fine ", "escape\x1b[2J", "due\nrighe"] {
        assert!(
            archive
                .change(Command::Rename {
                    id: LEGACY.into(),
                    name: name.into()
                })
                .is_err()
        );
    }
    assert!(
        archive
            .change(Command::Replace {
                id: LEGACY.into(),
                key: Zeroizing::new("invalid key".into())
            })
            .is_err()
    );
    assert!(
        archive
            .change(Command::Default {
                id: "missing".into()
            })
            .is_err()
    );
    assert_eq!(*before, *archive.encode().unwrap());
}

#[test]
fn malformed_archives_never_fall_back_to_legacy_or_another_key() {
    let archive = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&archive.encode().unwrap()).unwrap();
    for field in ["version", "default", "entries", "extra"] {
        let mut invalid = original.clone();
        invalid[field] = serde_json::json!("invalid");
        assert!(Archive::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let mut duplicate = original.clone();
    duplicate["entries"]
        .as_array_mut()
        .unwrap()
        .push(original["entries"][0].clone());
    assert!(Archive::decode(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    assert!(Archive::decode(b"{}").is_err());
    assert!(
        serde_json::from_str::<Command>(r#"{"action":"select","id":"a","key":"not-allowed"}"#)
            .is_err()
    );
}

#[test]
fn temporary_keys_are_marked_and_never_encoded_into_the_saved_archive() {
    let saved = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    let before = saved.encode().unwrap();
    let mut temporary = Archive::empty();
    temporary
        .change(Command::Add {
            provider: Provider::Refuseless,
            name: "Temporanea".into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    let id = temporary.status(None).entries[0].id.clone();
    let keyring = Keyring::new(saved, temporary).unwrap();
    let status = keyring.status(Some(Some(id.clone())));
    assert_eq!(status.selected.as_deref(), Some(id.as_str()));
    assert_eq!(status.default.as_deref(), Some(LEGACY));
    assert!(!status.entries[0].temporary);
    assert!(status.entries[1].temporary);
    let public = serde_json::to_string(&status).unwrap();
    assert!(!public.contains(FIRST) && !public.contains(SECOND));
    assert_eq!(keyring.key(&id), Some(SECOND));
    assert_eq!(keyring.key(LEGACY), Some(FIRST));
    assert_eq!(*before, *keyring.saved.encode().unwrap());
    assert!(
        !std::str::from_utf8(&keyring.saved.encode().unwrap())
            .unwrap()
            .contains(SECOND)
    );
}

#[test]
fn removing_a_temporary_key_never_rotates_to_the_saved_account() {
    let mut temporary = Archive::empty();
    temporary
        .change(Command::Add {
            provider: Provider::Openrouter,
            name: "RAM".into(),
            key: Zeroizing::new(SECOND.into()),
        })
        .unwrap();
    let id = temporary.status(None).entries[0].id.clone();
    let mut keyring = Keyring::new(
        Archive::legacy(Zeroizing::new(FIRST.into())).unwrap(),
        temporary,
    )
    .unwrap();
    keyring
        .temporary
        .change(Command::Remove { id: id.clone() })
        .unwrap();
    assert!(keyring.status(Some(Some(id))).selected.is_none());
    assert!(keyring.status(Some(None)).selected.is_none());
    assert_eq!(keyring.status(None).selected.as_deref(), Some(LEGACY));
    assert!(
        keyring
            .saved
            .change(Command::Temporary {
                provider: Provider::Openrouter,
                name: "RAM".into(),
                key: Zeroizing::new(SECOND.into()),
            })
            .is_err()
    );
    assert!(
        Keyring::new(
            keyring.saved,
            Archive::legacy(Zeroizing::new(SECOND.into())).unwrap()
        )
        .is_err()
    );
}

#[test]
fn metadata_edits_preserve_the_gateway_but_effective_credentials_revoke_it() {
    let mut saved = Archive::legacy(Zeroizing::new(FIRST.into())).unwrap();
    saved.change(Command::Add { provider: Provider::Refuseless, name: "Other".into(), key: Zeroizing::new(SECOND.into()) }).unwrap();
    let other = saved.status(None).entries[1].id.clone();
    let ring = Keyring::new(saved, Archive::empty()).unwrap();
    assert!(!ring.requires_revocation(&Command::Rename { id: LEGACY.into(), name: "Renamed".into() }, None));
    assert!(!ring.requires_revocation(&Command::Remove { id: other.clone() }, None));
    assert!(!ring.requires_revocation(&Command::Replace { id: other.clone(), key: Zeroizing::new(FIRST.into()) }, None));
    assert!(!ring.requires_revocation(&Command::Replace { id: LEGACY.into(), key: Zeroizing::new(FIRST.into()) }, None));
    assert!(!ring.requires_revocation(&Command::Select { id: LEGACY.into() }, None));
    assert!(ring.requires_revocation(&Command::Replace { id: LEGACY.into(), key: Zeroizing::new(SECOND.into()) }, None));
    assert!(ring.requires_revocation(&Command::Remove { id: LEGACY.into() }, None));
    assert!(ring.requires_revocation(&Command::Select { id: other.clone() }, None));
    assert!(ring.requires_revocation(&Command::Default { id: other.clone() }, None));
    assert!(!ring.requires_revocation(&Command::Default { id: other }, Some(Some(LEGACY.into()))));
}
