use oblivion_host::volume::{MIB, Request, Usage, growth, resized, size};

#[test]
fn capacity_requires_reserved_replacement_space_and_never_shrinks() {
    assert_eq!(size(512).unwrap(), 512 * MIB);
    assert!(size(127).is_err());
    assert!(size(u64::MAX).is_err());
    assert!(growth(512 * MIB, 512, 10_000 * MIB).is_err());
    assert!(growth(512 * MIB, 256, 10_000 * MIB).is_err());
    assert!(growth(512 * MIB, 2048, 2048 * MIB).is_err());
    assert_eq!(growth(512 * MIB, 2048, 2112 * MIB).unwrap(), 2048 * MIB);
}

#[test]
fn storage_requests_reject_paths_and_never_expose_secrets_in_debug() {
    for json in [
        r#"{"action":"grow","id":"../vault","mib":2048,"password":"x"}"#,
        r#"{"action":"create","mib":512,"password":"short"}"#,
    ] {
        let request: Request = serde_json::from_str(json).unwrap();
        assert!(request.validate().is_err());
    }
    assert!(
        serde_json::from_str::<Request>(r#"{"action":"usage","path":"/vault/state"}"#).is_err()
    );
    let request: Request = serde_json::from_str(
        r#"{"action":"grow","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mib":2048,"password":"old"}"#,
    )
    .unwrap();
    assert!(request.validate().is_ok());
}

#[test]
fn maintenance_success_requires_the_filesystem_to_fill_the_expanded_mapping() {
    assert!(resized(2048 * MIB, 2032 * MIB, 2032 * MIB));
    assert!(!resized(2048 * MIB, 2032 * MIB, 496 * MIB));
    assert!(!resized(2048 * MIB, 496 * MIB, 496 * MIB));
    assert!(!resized(2048 * MIB, 0, 0));
    assert!(!resized(2048 * MIB, 2032 * MIB, 2032 * MIB + 1));
    assert!(
        Usage {
            capacity: 100,
            used: 10,
            available: 80
        }
        .valid()
    );
    assert!(
        !Usage {
            capacity: 100,
            used: 10,
            available: 100
        }
        .valid()
    );
}
