use crate::storage::{Error, Result, require};
use oblivion_host::channel::{self, Channel};
use oblivion_transport::policy::Tools;
use oblivion_transport::provider::Provider;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEVICE: &str = "/dev/mapper/oblivion-session";
pub const VM_UID: u32 = 1100;
pub const GATEWAY_UID: u32 = 1101;
pub const IMPORT_UID: u32 = 1102;
pub const EXPORT_UID: u32 = 1103;
pub const EXPORT_DEVICE: &str = "/dev/mapper/oblivion-export";
pub const IMPORT_DEVICE: &str = "/dev/mapper/oblivion-import";

#[derive(Clone, Copy)]
pub enum Role {
    Session,
    Gateway,
    Import,
    Export,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Session => "oblivion-session",
            Self::Gateway => "oblivion-gateway-vm",
            Self::Import => "oblivion-import-vm",
            Self::Export => "oblivion-export-vm",
        }
    }

    fn uid(self) -> u32 {
        match self {
            Self::Session => VM_UID,
            Self::Gateway => GATEWAY_UID,
            Self::Import => IMPORT_UID,
            Self::Export => EXPORT_UID,
        }
    }

    pub fn runtime(self) -> String {
        format!("/run/{}", self.name())
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Accelerator {
    #[default]
    Kvm,
    #[cfg(feature = "lab-emulation")]
    Tcg,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    root: PathBuf,
    kernel: PathBuf,
    initrd: PathBuf,
    filesystem: PathBuf,
    memory_mib: u32,
    cpus: u8,
    #[serde(default)]
    accelerator: Accelerator,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require(
            (256..=32768).contains(&self.memory_mib),
            "invalid_vm_memory",
        )?;
        require((1..=16).contains(&self.cpus), "invalid_vm_cpus")?;
        for path in [&self.root, &self.kernel, &self.initrd, &self.filesystem] {
            require(
                path.is_absolute()
                    && !path
                        .as_os_str()
                        .as_encoded_bytes()
                        .iter()
                        .any(|byte| b",:%".contains(byte) || byte.is_ascii_whitespace()),
                "invalid_vm_path",
            )?;
            let meta = fs::symlink_metadata(path).map_err(|_| Error("vm_image_missing"))?;
            require(
                meta.uid() == 0 && meta.mode() & 0o022 == 0 && !meta.file_type().is_symlink(),
                "unsafe_vm_image",
            )?;
            require(
                if path == &self.root {
                    meta.is_dir()
                } else {
                    meta.is_file()
                },
                "invalid_vm_image",
            )?;
        }
        if matches!(self.accelerator, Accelerator::Kvm) {
            let device = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .map_err(|_| Error("kvm_required"))?;
            require(
                device
                    .metadata()
                    .map_err(|_| Error("kvm_required"))?
                    .file_type()
                    .is_char_device(),
                "kvm_required",
            )?;
            // KVM_GET_API_VERSION: checking a real usable device, not just CPU flags.
            // KVM rejects a nonzero argument, including an omitted vararg register.
            require(
                unsafe { libc::ioctl(device.as_raw_fd(), 0xae00, 0 as libc::c_ulong) } == 12,
                "kvm_api_unavailable",
            )?;
        }
        Ok(())
    }

    pub fn start(
        &self,
        token: Option<&str>,
        provider: Option<Provider>,
        tools: Option<Tools>,
    ) -> Result<()> {
        require(
            token.is_some() == provider.is_some(),
            "invalid_provider_grant",
        )?;
        self.launch(Role::Session, token.is_some(), false)?;
        if let Some(token) = token {
            let stream = UnixStream::connect("/run/oblivion-session/token.sock")
                .map_err(|_| Error("session_channel_unavailable"))?;
            crate::gateway::peer(&stream, VM_UID)?;
            crate::gateway::grant(token, tools)?;
            let mut channel = Channel::new(&stream, Duration::from_secs(60));
            qmp(Role::Session, "cont")?;
            let mut ready = [0u8; 6];
            // Virtio serial can discard bytes before the guest opens its port.
            // Wait for that opening before sending the one-session token.
            channel
                .read_exact(&mut ready)
                .map_err(|_| Error("session_channel_failed"))?;
            require(&ready == b"token\n", "invalid_session_ready")?;
            channel
                .write_all(token.as_bytes())
                .map_err(|_| Error("session_channel_failed"))?;
            channel
                .write_all(
                    format!(
                        "{}\n",
                        provider.ok_or(Error("invalid_provider_grant"))?.id()
                    )
                    .as_bytes(),
                )
                .map_err(|_| Error("session_channel_failed"))?;
            channel
                .read_exact(&mut ready)
                .map_err(|_| Error("session_channel_failed"))?;
            require(&ready == b"ready\n", "invalid_session_ready")?;
        }
        Ok(())
    }

    pub fn start_role(&self, role: Role) -> Result<()> {
        self.launch(role, false, false)
    }

    pub fn start_documents(&self) -> Result<()> {
        self.launch(Role::Session, false, true)?;
        let stream = UnixStream::connect("/run/oblivion-session/ready.sock")
            .map_err(|_| Error("session_channel_unavailable"))?;
        crate::gateway::peer(&stream, VM_UID)?;
        let mut channel = Channel::new(&stream, Duration::from_secs(60));
        // Connect before boot so the guest's readiness marker cannot be lost.
        // QEMU running alone does not mean the vault or power-key handler is ready.
        qmp(Role::Session, "cont")?;
        let mut ready = [0u8; 6];
        channel
            .read_exact(&mut ready)
            .map_err(|_| Error("documents_not_ready"))?;
        require(&ready == b"ready\n", "invalid_session_ready")
    }

    fn launch(&self, role: Role, network: bool, documents: bool) -> Result<()> {
        require(stopped_role(role)?, "vm_already_running")?;
        if matches!(role, Role::Session) {
            let device = fs::metadata(DEVICE).map_err(|_| Error("session_device_missing"))?;
            require(
                device.file_type().is_block_device(),
                "invalid_session_device",
            )?;
            unsafe {
                require(
                    libc::chown(c"/dev/mapper/oblivion-session".as_ptr(), VM_UID, VM_UID) == 0,
                    "device_owner_failed",
                )?;
            }
        }
        let mut args = vec![
            "--quiet".to_owned(),
            "--collect".to_owned(),
            format!("--unit={}", role.name()),
            format!("--description=Oblivion isolated {}", role.name()),
            "--service-type=exec".to_owned(),
        ];
        let properties = vec![
            format!("User={}", role.uid()),
            format!("Group={}", role.uid()),
            "UMask=0077".to_owned(),
            format!("RootDirectory={}", self.root.display()),
            format!(
                "BindReadOnlyPaths={}:/kernel {}:/initrd {}:/root.squashfs",
                self.kernel.display(),
                self.initrd.display(),
                self.filesystem.display()
            ),
            format!("RuntimeDirectory={}", role.name()),
            "RuntimeDirectoryMode=0700".to_owned(),
            format!("ReadWritePaths={}", role.runtime()),
            "TemporaryFileSystem=/tmp:rw,nosuid,nodev,size=32M".to_owned(),
            "PrivateDevices=yes".to_owned(),
            format!(
                "PrivateNetwork={}",
                if !matches!(role, Role::Gateway) {
                    "yes"
                } else {
                    "no"
                }
            ),
            format!(
                "RestrictAddressFamilies={}",
                if !matches!(role, Role::Gateway) {
                    "AF_UNIX"
                } else {
                    "AF_UNIX AF_INET"
                }
            ),
            "ProtectSystem=strict".to_owned(),
            "ProtectHome=yes".to_owned(),
            "ProtectProc=invisible".to_owned(),
            "ProcSubset=pid".to_owned(),
            "ProtectKernelTunables=yes".to_owned(),
            "ProtectKernelModules=yes".to_owned(),
            "ProtectKernelLogs=yes".to_owned(),
            "ProtectControlGroups=yes".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "CapabilityBoundingSet=".to_owned(),
            "RestrictSUIDSGID=yes".to_owned(),
            "LockPersonality=yes".to_owned(),
            "LimitCORE=0".to_owned(),
            "StandardOutput=null".to_owned(),
            if cfg!(feature = "lab-emulation") {
                "StandardError=journal"
            } else {
                "StandardError=null"
            }
            .to_owned(),
            "KillMode=control-group".to_owned(),
            "TimeoutStopSec=5".to_owned(),
            "SendSIGKILL=yes".to_owned(),
            "Restart=no".to_owned(),
            "TasksMax=128".to_owned(),
            format!("MemoryMax={}M", self.memory_mib + 512),
            "MemorySwapMax=0".to_owned(),
        ];
        args.extend(
            properties
                .into_iter()
                .map(|property| format!("--property={property}")),
        );
        if matches!(role, Role::Session) {
            args.extend([
                // Controller recovery asks this persistent guest to power off
                // before systemd falls back to stopping the VM itself.
                "--property=Before=oblivion-controller.service".to_owned(),
                format!("--property=BindPaths={DEVICE}:/dev/oblivion-session"),
                format!("--property=DeviceAllow={DEVICE} rw"),
            ]);
        }
        if matches!(role, Role::Gateway) {
            // No ordering dependency: the owner's ExecStopPost waits for this
            // VM, so Before=owner/controller would deadlock their stop jobs.
            args.push("--property=BindsTo=oblivion-gateway-host.service".to_owned());
        }
        if matches!(role, Role::Import) {
            args.extend([
                "--property=BindsTo=oblivion-transfer-host.service".to_owned(),
                format!("--property=BindReadOnlyPaths={IMPORT_DEVICE}:/dev/oblivion-import"),
                format!("--property=DeviceAllow={IMPORT_DEVICE} r"),
            ]);
        }
        if matches!(role, Role::Export) {
            args.extend([
                "--property=BindsTo=oblivion-transfer-host.service".to_owned(),
                format!("--property=BindPaths={EXPORT_DEVICE}:/dev/oblivion-export"),
                format!("--property=DeviceAllow={EXPORT_DEVICE} rw"),
            ]);
        }
        if network {
            args.push("--property=BindReadOnlyPaths=/run/oblivion-gateway-vm/inside.sock:/run/oblivion-session/network.sock".to_owned());
        }
        if matches!(self.accelerator, Accelerator::Kvm) {
            args.extend([
                "--property=BindPaths=/dev/kvm".to_owned(),
                "--property=DeviceAllow=/dev/kvm rw".to_owned(),
                "--property=SupplementaryGroups=kvm".to_owned(),
            ]);
        }
        let (binary, machine, console) = if cfg!(target_arch = "aarch64") {
            ("/usr/bin/qemu-system-aarch64", "virt", "ttyAMA0")
        } else {
            ("/usr/bin/qemu-system-x86_64", "q35", "ttyS0")
        };
        let console = if matches!(role, Role::Session) {
            "hvc0"
        } else {
            console
        };
        let (accelerator, cpu) = match self.accelerator {
            Accelerator::Kvm => ("kvm", "host"),
            #[cfg(feature = "lab-emulation")]
            Accelerator::Tcg => (
                "tcg",
                if cfg!(target_arch = "aarch64") {
                    "cortex-a72"
                } else {
                    "max"
                },
            ),
        };
        args.extend([
            binary.to_owned(), "-machine".to_owned(), format!("{machine},dump-guest-core=off,mem-merge=off"),
            "-accel".to_owned(), accelerator.to_owned(), "-cpu".to_owned(), cpu.to_owned(),
            "-m".to_owned(), self.memory_mib.to_string(), "-smp".to_owned(), self.cpus.to_string(),
            "-nodefaults".to_owned(), "-no-reboot".to_owned(), "-display".to_owned(), "none".to_owned(),
            "-monitor".to_owned(), "none".to_owned(), "-nic".to_owned(), "none".to_owned(),
            "-object".to_owned(), "rng-random,filename=/dev/urandom,id=rng".to_owned(),
            "-device".to_owned(), "virtio-rng-pci,rng=rng".to_owned(),
            "-sandbox".to_owned(), "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".to_owned(),
            "-qmp".to_owned(), format!("unix:{}/qmp.sock,server=on,wait=off", role.runtime()),
            // Gateway diagnostics are available only in the separate laboratory
            // binary; the production gateway never exposes a serial console.
            "-serial".to_owned(), if !matches!(role, Role::Session) && cfg!(feature = "lab-emulation") { format!("unix:{}/console.sock,server=on,wait=off", role.runtime()) } else { "null".to_owned() },
            "-kernel".to_owned(), "/kernel".to_owned(), "-initrd".to_owned(), "/initrd".to_owned(),
            "-append".to_owned(), format!("root=/dev/vda ro rootfstype=squashfs console={console} quiet loglevel=0 systemd.show_status=false panic=-1{}{}", if network { " oblivion.network=1" } else { "" }, if documents { " oblivion.documents=1" } else { "" }),
            "-drive".to_owned(), "file=/root.squashfs,format=raw,if=none,id=root,readonly=on".to_owned(),
            "-device".to_owned(), "virtio-blk-pci,drive=root,serial=oblivion-root".to_owned(),
        ]);
        if matches!(role, Role::Session) {
            args.extend([
                "-device".to_owned(),
                "virtio-serial-pci,id=oblivion-serial".to_owned(),
                // A TUI sends bursts of screen data. Use virtio rather than an
                // emulated UART, whose per-character I/O stalls large redraws.
                "-chardev".to_owned(),
                "socket,id=console,path=/run/oblivion-session/console.sock,server=on,wait=off"
                    .to_owned(),
                "-device".to_owned(),
                "virtconsole,chardev=console,bus=oblivion-serial.0,name=oblivion.console"
                    .to_owned(),
                "-drive".to_owned(),
                "file=/dev/oblivion-session,format=raw,if=none,id=vault,cache=none".to_owned(),
                "-device".to_owned(),
                "virtio-blk-pci,drive=vault,serial=oblivion-vault".to_owned(),
            ]);
        }
        if matches!(role, Role::Import) {
            args.extend([
                "-S".to_owned(),
                "-device".to_owned(),
                "virtio-serial-pci".to_owned(),
                "-drive".to_owned(),
                "file=/dev/oblivion-import,format=raw,if=none,id=source,readonly=on,cache=none"
                    .to_owned(),
                "-device".to_owned(),
                "virtio-blk-pci,drive=source,serial=oblivion-import".to_owned(),
                "-chardev".to_owned(),
                "socket,id=copy,path=/run/oblivion-import-vm/copy.sock,server=on,wait=off"
                    .to_owned(),
                "-device".to_owned(),
                "virtserialport,chardev=copy,name=oblivion.import".to_owned(),
            ]);
        }
        if matches!(role, Role::Export) {
            args.extend([
                "-S".to_owned(),
                "-device".to_owned(),
                "virtio-serial-pci".to_owned(),
                "-drive".to_owned(),
                "file=/dev/oblivion-export,format=raw,if=none,id=destination,cache=none".to_owned(),
                "-device".to_owned(),
                "virtio-blk-pci,drive=destination,serial=oblivion-export".to_owned(),
                "-chardev".to_owned(),
                "socket,id=copy,path=/run/oblivion-export-vm/copy.sock,server=on,wait=off"
                    .to_owned(),
                "-device".to_owned(),
                "virtserialport,chardev=copy,name=oblivion.export".to_owned(),
            ]);
        }
        if matches!(role, Role::Gateway) {
            // Connect the private control channel before the guest opens its
            // virtio port. No secret is part of QEMU's command line or files.
            args.extend([
                "-S".to_owned(),
                "-device".to_owned(),
                "virtio-serial-pci".to_owned(),
                "-chardev".to_owned(),
                format!(
                    "socket,id=control,path={}/control.sock,server=on,wait=off",
                    role.runtime()
                ),
                "-device".to_owned(),
                "virtserialport,chardev=control,name=oblivion.gateway".to_owned(),
                "-netdev".to_owned(),
                format!(
                    "stream,id=inside,server=on,addr.type=unix,addr.path={}/inside.sock",
                    role.runtime()
                ),
                "-device".to_owned(),
                "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:01,romfile=".to_owned(),
                "-netdev".to_owned(),
                "user,id=outside,ipv6=off".to_owned(),
                "-device".to_owned(),
                "virtio-net-pci,netdev=outside,mac=52:54:00:6f:00:02,romfile=".to_owned(),
            ]);
        }
        if documents {
            args.extend([
                "-S".to_owned(),
                "-chardev".to_owned(),
                "socket,id=ready,path=/run/oblivion-session/ready.sock,server=on,wait=off"
                    .to_owned(),
                "-device".to_owned(),
                "virtserialport,chardev=ready,bus=oblivion-serial.0,name=oblivion.documents"
                    .to_owned(),
            ]);
        }
        if network {
            args.extend([
                "-S".to_owned(),
                "-chardev".to_owned(), "socket,id=token,path=/run/oblivion-session/token.sock,server=on,wait=off".to_owned(),
                "-device".to_owned(), "virtserialport,chardev=token,name=oblivion.session".to_owned(),
                "-netdev".to_owned(), "stream,id=inside,server=off,addr.type=unix,addr.path=/run/oblivion-session/network.sock,reconnect-ms=0".to_owned(),
                "-device".to_owned(), "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:03,romfile=".to_owned(),
            ]);
        }
        execute("/usr/bin/systemd-run", &args)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if stopped_role(role)? {
                return Err(Error("vm_start_failed"));
            }
            if PathBuf::from(role.runtime()).join("qmp.sock").exists() {
                qmp(role, "query-status")?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(Error("vm_start_timeout"))
    }
}

pub fn state() -> Result<String> {
    state_role(Role::Session)
}

pub fn network_devices() -> Result<usize> {
    qmp(Role::Session, "query-rx-filter")?
        .get("return")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or(Error("invalid_vm_response"))
}

pub fn state_role(role: Role) -> Result<String> {
    unit_state(&format!("{}.service", role.name()))
}

pub fn unit_state(unit: &str) -> Result<String> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property=ActiveState", "--value"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error("vm_state_unavailable"))?;
    require(output.status.success(), "vm_state_unavailable")?;
    let value = String::from_utf8(output.stdout).map_err(|_| Error("invalid_vm_state"))?;
    let state = value.trim();
    require(
        matches!(
            state,
            "active" | "inactive" | "failed" | "activating" | "deactivating"
        ),
        "invalid_vm_state",
    )?;
    Ok(state.to_owned())
}

pub fn stopped() -> Result<bool> {
    stopped_role(Role::Session)
}

pub fn stopped_role(role: Role) -> Result<bool> {
    Ok(matches!(state_role(role)?.as_str(), "inactive" | "failed"))
}

pub fn stop(force: bool) -> Result<()> {
    stop_role(Role::Session, force)
}

pub fn stop_role(role: Role, force: bool) -> Result<()> {
    if stopped_role(role)? {
        return Ok(());
    }
    if force {
        execute(
            "/usr/bin/systemctl",
            &["stop".to_owned(), format!("{}.service", role.name())],
        )?;
        require(stopped_role(role)?, "vm_still_running")?;
        return Ok(());
    }
    qmp(role, "system_powerdown")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if stopped_role(role)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // A forced stop is a separate explicit action; a timeout is not a locked vault.
    Err(Error("vm_shutdown_timeout"))
}

pub fn execute(program: &str, args: &[String]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error("vm_command_failed"))?;
    require(status.success(), "vm_command_failed")
}

pub fn resume_gateway() -> Result<()> {
    qmp(Role::Gateway, "cont")?;
    Ok(())
}

pub fn resume_transfer(role: Role) -> Result<()> {
    qmp(role, "cont")?;
    Ok(())
}

/// A fresh channel per transfer. Connect its host side before hotplugging the
/// guest port so the guest's readiness marker cannot be discarded by QEMU.
pub fn copy_port(id: &str, export: bool) -> Result<UnixStream> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_transfer_id",
    )?;
    let name = format!("copy-{id}");
    let path = format!("/run/oblivion-session/{name}.sock");
    qmp_arguments(
        Role::Session,
        "chardev-add",
        json!({"id":name,"backend":{"type":"socket","data":{"addr":{"type":"unix","data":{"path":path}},"server":true,"wait":false}}}),
    )?;
    let stream = UnixStream::connect(&path).map_err(|_| Error("transfer_port_unavailable"))?;
    crate::gateway::peer(&stream, VM_UID)?;
    qmp_arguments(
        Role::Session,
        "device_add",
        json!({"driver":"virtserialport","id":name,"chardev":name,"bus":"oblivion-serial.0","name":format!("oblivion.{}.{id}", if export { "export" } else { "copy" })}),
    )?;
    Ok(stream)
}

pub fn remove_copy_port(id: &str) -> Result<()> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_transfer_id",
    )?;
    if stopped()? {
        return Ok(());
    }
    let name = format!("copy-{id}");
    // Query first: startup may have failed before creating either frontend or
    // backend. Never interpret an arbitrary QMP failure as successful cleanup.
    let devices = qmp(Role::Session, "query-chardev")?;
    let exists = devices
        .get("return")
        .and_then(Value::as_array)
        .ok_or(Error("invalid_vm_response"))?
        .iter()
        .any(|entry| entry.get("label").and_then(Value::as_str) == Some(&name));
    if !exists {
        return Ok(());
    }
    // An absent frontend is harmless; chardev-remove is the authoritative check
    // that no device still owns the backend after a partial startup.
    let _ = qmp_arguments(Role::Session, "device_del", json!({"id":name}));
    // device_del acknowledges the request before the guest has finished
    // unplugging its port. QEMU rejects chardev-remove while it is still in use.
    // The real manager cancellation test exercises this asynchronous interval.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match qmp_arguments(Role::Session, "chardev-remove", json!({"id":name})) {
            Ok(_) => break,
            Err(Error("vm_control_rejected")) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    let path = format!("/run/oblivion-session/{name}.sock");
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error("transfer_port_cleanup_failed")),
    }
}

fn qmp(role: Role, operation: &str) -> Result<Value> {
    qmp_arguments(role, operation, json!({}))
}

fn qmp_arguments(role: Role, operation: &str, arguments: Value) -> Result<Value> {
    let stream = channel::connect(
        &PathBuf::from(format!("{}/qmp.sock", role.runtime())),
        Duration::from_secs(5),
    )
    .map_err(|_| Error("vm_control_unavailable"))?;
    let mut reader = BufReader::new(Channel::new(&stream, Duration::from_secs(5)));
    require(
        read_qmp(&mut reader)?.get("QMP").is_some(),
        "invalid_vm_greeting",
    )?;
    for command in ["qmp_capabilities", operation] {
        reader
            .get_mut()
            .write_all(format!("{}\n", json!({"execute": command, "arguments": if command == operation { arguments.clone() } else { json!({}) }})).as_bytes())
            .map_err(|_| Error("vm_control_failed"))?;
        loop {
            let response = read_qmp(&mut reader)?;
            if response.get("event").is_some() {
                continue;
            }
            require(
                response.get("error").is_none() && response.get("return").is_some(),
                "vm_control_rejected",
            )?;
            if command == operation {
                return Ok(response);
            }
            break;
        }
    }
    Err(Error("vm_control_failed"))
}

fn read_qmp(reader: &mut BufReader<Channel<'_>>) -> Result<Value> {
    let mut bytes = Vec::new();
    loop {
        // Buffered events must not bypass the overall QMP deadline either.
        reader
            .get_ref()
            .remaining()
            .map_err(|_| Error("vm_control_failed"))?;
        let available = reader.fill_buf().map_err(|_| Error("vm_control_failed"))?;
        require(!available.is_empty(), "vm_control_closed")?;
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        require(bytes.len() + count <= 65536, "vm_response_too_large")?;
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| Error("invalid_vm_response"))
}
