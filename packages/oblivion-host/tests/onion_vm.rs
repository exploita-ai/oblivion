use oblivion_host::onion_vm::{self, Kind};
use std::path::Path;

#[test]
fn file_guest_has_one_private_nic_and_only_the_three_fixed_ports() {
    let args = Kind::File
        .arguments(Path::new("/run/oblivion-onion-file-vm"))
        .unwrap();
    assert_eq!(args.iter().filter(|arg| *arg == "-netdev").count(), 1);
    assert_eq!(args.iter().filter(|arg| *arg == "-chardev").count(), 3);
    assert!(
        args.iter()
            .any(|arg| arg == "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:04,romfile=")
    );
    for name in [
        "oblivion.onion.file",
        "oblivion.onion.stage",
        "oblivion.onion.source",
    ] {
        assert!(
            args.iter()
                .any(|arg| arg.ends_with(&format!("name={name}")))
        );
    }
    assert!(args.iter().any(|arg| arg == "stream,id=inside,server=off,addr.type=unix,addr.path=/run/oblivion-onion-file-vm/network.sock,reconnect-ms=0"));
}

#[test]
fn transfer_gateway_has_no_user_nat_or_model_port_and_keeps_two_private_wires() {
    let args = Kind::Gateway
        .arguments(Path::new("/run/oblivion-onion-gateway-vm"))
        .unwrap();
    assert_eq!(args.iter().filter(|arg| *arg == "-netdev").count(), 2);
    assert_eq!(args.iter().filter(|arg| *arg == "-chardev").count(), 1);
    assert!(
        args.iter()
            .any(|arg| arg == "virtserialport,chardev=control,name=oblivion.onion-gateway")
    );
    assert!(args.iter().any(|arg| arg == "stream,id=outside,server=off,addr.type=unix,addr.path=/run/oblivion-onion-gateway-vm/uplink.sock,reconnect-ms=0"));
    assert!(args.iter().any(|arg| arg == "stream,id=inside,server=on,addr.type=unix,addr.path=/run/oblivion-onion-gateway-vm/inside.sock"));
    for kind in [Kind::Gateway, Kind::File] {
        let args = kind
            .arguments(Path::new("/run/oblivion-onion-guest"))
            .unwrap();
        assert_eq!(args.first().map(String::as_str), Some("-S"));
        for argument in &args {
            assert!(
                !argument.starts_with("user,")
                    && !argument.contains("hostfwd")
                    && !argument.contains("addr.type=inet")
            );
            assert!(
                !argument.contains("oblivion.session")
                    && !argument.contains("oblivion.gateway")
                    && !argument.contains("token")
            );
            assert!(!matches!(
                argument.as_str(),
                "-drive" | "-blockdev" | "-fsdev" | "-virtfs"
            ));
        }
    }
    assert_ne!(Kind::Gateway.uid(), Kind::File.uid());
    assert_eq!(Kind::Gateway.uid(), onion_vm::GATEWAY_UID);
    assert_eq!(Kind::File.uid(), onion_vm::FILE_UID);
    let identities = [
        1000,
        1100,
        1101,
        1102,
        1103,
        1104,
        Kind::Gateway.uid(),
        Kind::File.uid(),
    ];
    assert_eq!(
        identities
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        identities.len(),
        "VMs must not share the trusted display or another host identity"
    );
    for path in ["/run/x,server=on", "../tmp", "/run/x\n"] {
        assert!(Kind::Gateway.arguments(Path::new(path)).is_err());
        assert!(Kind::File.arguments(Path::new(path)).is_err());
    }
}
