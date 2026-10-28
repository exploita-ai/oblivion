//! Fixed private interfaces for the two transfer guests. Neither hypervisor
//! gets host Internet sockets, provider capabilities or a writable data disk.
use std::path::Path;

pub const OWNER: &str = "oblivion-onion-host.service";
// 1104 already belongs to the Live host's display/input boundary.
pub const GATEWAY_UID: u32 = 1105;
pub const FILE_UID: u32 = 1106;

#[derive(Clone, Copy)]
pub enum Kind {
    Gateway,
    File,
}

pub fn session_lifetime(runtime: &Path) -> Result<Vec<String>, &'static str> {
    crate::onion_uplink::require_runtime(runtime)?;
    Ok(vec![
        "-qmp".into(),
        format!(
            "unix:{}/lifetime.sock,server=on,wait=off",
            runtime.display()
        ),
    ])
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Gateway => "oblivion-onion-gateway-vm",
            Self::File => "oblivion-onion-file-vm",
        }
    }

    pub fn uid(self) -> u32 {
        match self {
            Self::Gateway => GATEWAY_UID,
            Self::File => FILE_UID,
        }
    }

    /// Base machine/kernel/read-only image options belong to the VM launcher.
    /// All devices added here have fixed names and private Unix backends.
    pub fn arguments(self, runtime: &Path) -> Result<Vec<String>, &'static str> {
        // Apply the same QEMU/Unix-path boundary as the network-only actor.
        crate::onion_uplink::require_runtime(runtime)?;
        let mut args = vec!["-S".into(), "-device".into(), "virtio-serial-pci".into()];
        let ports: &[(&str, &str)] = match self {
            Self::Gateway => &[("control", "oblivion.onion-gateway")],
            Self::File => &[
                ("control", "oblivion.onion.file"),
                ("stage", "oblivion.onion.stage"),
                ("source", "oblivion.onion.source"),
            ],
        };
        for (id, name) in ports {
            args.extend([
                "-chardev".into(),
                format!(
                    "socket,id={id},path={}/{id}.sock,server=on,wait=off",
                    runtime.display()
                ),
                "-device".into(),
                format!("virtserialport,chardev={id},name={name}"),
            ]);
        }
        if matches!(self, Self::Gateway) {
            args.extend([
                "-netdev".into(), format!("stream,id=inside,server=on,addr.type=unix,addr.path={}/inside.sock", runtime.display()),
                "-device".into(), "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:01,romfile=".into(),
                "-netdev".into(), format!("stream,id=outside,server=off,addr.type=unix,addr.path={}/uplink.sock,reconnect-ms=0", runtime.display()),
                "-device".into(), "virtio-net-pci,netdev=outside,mac=52:54:00:6f:00:02,romfile=".into(),
            ]);
            return Ok(args);
        }
        // ARM virt and x86 q35 root buses cannot hotplug a PCI endpoint.
        // Reserve one fixed port for an explicitly authorized ciphertext disk.
        args.extend([
            "-device".into(),
            "pcie-root-port,id=oblivion-backup-port".into(),
        ]);
        args.extend([
            "-netdev".into(), format!("stream,id=inside,server=off,addr.type=unix,addr.path={}/network.sock,reconnect-ms=0", runtime.display()),
            "-device".into(), "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:04,romfile=".into(),
        ]);
        Ok(args)
    }
}
