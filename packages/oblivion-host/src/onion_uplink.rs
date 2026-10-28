//! QEMU's existing userspace network stack, with no machine, CPU or disk.
//! The Linux owner will run this under the existing gateway uplink UID. Only
//! the dedicated Tor VM gets its private Ethernet socket; file/session VMs do
//! not receive a connection or a new host firewall exception.
use std::path::{Component, Path};

pub const UNIT: &str = "oblivion-onion-uplink.service";
pub const RUNTIME: &str = "/run/oblivion-onion-uplink";

/// `runtime` belongs to the trusted service launcher, never a client request.
/// It also supports disposable private directories in the actual QEMU fixture.
pub fn arguments(runtime: &Path) -> Result<Vec<String>, &'static str> {
    require_runtime(runtime)?;
    let args = vec![
        "-machine".into(),
        "none".into(),
        "-m".into(),
        "16".into(),
        "-nodefaults".into(),
        "-no-user-config".into(),
        "-no-reboot".into(),
        "-display".into(),
        "none".into(),
        "-serial".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-nic".into(),
        "none".into(),
        "-qmp".into(),
        format!("unix:{}/qmp.sock,server=on,wait=off", runtime.display()),
        "-netdev".into(),
        "user,id=uplink,ipv6=off".into(),
        "-netdev".into(),
        "hubport,id=uplink-port,hubid=0,netdev=uplink".into(),
        "-netdev".into(),
        format!(
            "stream,id=wire,server=on,addr.type=unix,addr.path={}/network.sock",
            runtime.display()
        ),
        "-netdev".into(),
        "hubport,id=wire-port,hubid=0,netdev=wire".into(),
    ];
    // The dedicated Tor guest applies its own Tor-only outbound policy. This
    // NAT process carries encrypted relay traffic, not provider/API payloads.
    if cfg!(target_os = "linux") {
        return Ok(args
            .into_iter()
            .chain([
                "-sandbox".into(),
                "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
            ])
            .collect());
    }
    Ok(args)
}

pub(crate) fn require_runtime(runtime: &Path) -> Result<(), &'static str> {
    let path = runtime.as_os_str().as_encoded_bytes();
    if !runtime.is_absolute()
        || path.len() + "/network.sock".len() > 100
        || runtime
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || !path
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.-".contains(byte))
    {
        return Err("invalid_uplink_runtime");
    }
    Ok(())
}
