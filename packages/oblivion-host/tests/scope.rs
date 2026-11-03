use oblivion_host::scope::{self, Slot, LIMIT};
use std::collections::HashSet;

#[test]
fn identities_and_resources_are_disjoint_for_every_slot() {
    let mut users = HashSet::new();
    let mut paths = HashSet::new();
    for index in 0..LIMIT {
        let slot = Slot::try_from(index).unwrap();
        for base in [1100, 1101, 1102, 1103, 1105, 1106] {
            assert!(users.insert(slot.uid(base)));
            assert_ne!(slot.uid(base), 1000);
        }
        for path in ["/run/oblivion-session/console.sock", "/run/oblivion-gateway-vm/inside.sock",
            "/run/oblivion/ephemeral.luks", "/run/oblivion/gateway-control.sock",
            "/run/oblivion-transfer-host/control.sock", "/run/oblivion-onion-host/control.sock",
            "/run/oblivion/transfer.json", "/run/oblivion/onion.json", "/dev/mapper/oblivion-session"] {
            assert!(paths.insert(slot.path(path)));
        }
        assert_eq!(slot.path("/run/oblivion/general/profile"), "/run/oblivion/general/profile");
        assert_eq!(slot.path("/dev/oblivion-session"), "/dev/oblivion-session");
    }
}

#[test]
fn only_host_side_launch_paths_are_scoped_and_expansion_is_idempotent() {
    scope::within(Slot::try_from(3).unwrap(), || {
        for (input, expected) in [
            ("--property=BindPaths=/dev/mapper/oblivion-session:/dev/oblivion-session", "--property=BindPaths=/dev/mapper/oblivion-session-s3:/dev/oblivion-session"),
            ("--property=BindReadOnlyPaths=/run/oblivion-gateway-vm/inside.sock:/run/oblivion-session/network.sock", "--property=BindReadOnlyPaths=/run/oblivion-gateway-vm-s3/inside.sock:/run/oblivion-session-s3/network.sock"),
            ("socket,id=console,path=/run/oblivion-session/console.sock,server=on,wait=off", "socket,id=console,path=/run/oblivion-session-s3/console.sock,server=on,wait=off"),
            ("--property=BindsTo=oblivion-gateway-host.service", "--property=BindsTo=oblivion-gateway-host@3.service"),
            ("ReadWritePaths=/run/oblivion-session", "ReadWritePaths=/run/oblivion-session-s3"),
        ] {
            assert_eq!(scope::wire(input), expected);
            assert_eq!(scope::wire(&scope::wire(input)), expected);
        }
        assert_eq!(scope::path("/run/oblivion-session-s2/console.sock"), "/run/oblivion-session-s2/console.sock");
    });
}

#[test]
fn slots_are_validated_and_scoped_to_one_thread() {
    for invalid in ["-1", "32", "255", "\"1\"", "1.5"] {
        assert!(serde_json::from_str::<Slot>(invalid).is_err());
    }
    assert_eq!(scope::current().index(), 0);
    scope::within(Slot::try_from(4).unwrap(), || {
        assert_eq!(scope::current().index(), 4);
        assert!(std::panic::catch_unwind(|| scope::within(Slot::try_from(6).unwrap(), || panic!("synthetic"))).is_err());
        assert_eq!(scope::current().index(), 4);
        std::thread::spawn(|| assert_eq!(scope::current().index(), 0)).join().unwrap();
    });
    assert_eq!(scope::current().index(), 0);
}
