use oblivion_wire::volume::{size, Request, MAX_MIB, MIB};
use serde_json::json;
use zeroize::Zeroizing;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn native_volume_request_round_trips_the_single_controller_shape() {
    let raw = json!({"action":"grow","id":ID,"mib":2048,"password":"synthetic password"});
    let request: Request = serde_json::from_value(raw.clone()).unwrap();
    request.validate().unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), raw);
    assert!(serde_json::from_value::<Request>(json!({"action":"usage","extra":true})).is_err());
}

#[test]
fn capacity_and_secret_limits_are_shared_by_frontend_and_controller() {
    assert_eq!(size(128).unwrap(), 128 * MIB);
    assert_eq!(size(MAX_MIB).unwrap(), MAX_MIB * MIB);
    for mib in [0, 127, MAX_MIB + 1, u64::MAX] {
        assert_eq!(size(mib), Err("invalid_session_size"));
    }
    for (length, valid) in [
        (0, false),
        (1, false),
        (15, false),
        (16, true),
        (1024, true),
        (1025, false),
    ] {
        let request = Request::Create {
            mib: 128,
            password: Zeroizing::new("a".repeat(length)),
        };
        assert_eq!(request.validate().is_ok(), valid);
    }
    for (length, valid) in [(0, false), (1, true), (1024, true), (1025, false)] {
        let request = Request::Grow {
            id: ID.into(),
            mib: 128,
            password: Zeroizing::new("a".repeat(length)),
        };
        assert_eq!(request.validate().is_ok(), valid);
    }
    for id in [
        "",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "short",
        "unsafe-peer-canary",
    ] {
        assert_eq!(
            Request::Discard { id: id.into() }.validate(),
            Err("invalid_session_id")
        );
    }
}
