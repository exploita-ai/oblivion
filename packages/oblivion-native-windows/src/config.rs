//! Secret-free, portable configuration for the owned HCS controller. Paths are
//! checked lexically here; Windows file identity, leases and ACLs belong to I/O.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CONFIG_LIMIT: usize = 65536;
pub const CONTROL_PORT: u32 = 4050;
pub const CONTROL_SERVICE: &str = "00000fd2-facb-11e6-bd58-64006a7986d3";
const DENY: &str = "D:P(D;;GA;;;WD)";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disk {
    pub path: String,
    pub read_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub version: u8,
    pub backend: String,
    pub runtime_id: String,
    pub kernel: String,
    pub initrd: String,
    pub command_line: String,
    pub disks: Vec<Disk>,
    pub cpu_count: u8,
    pub memory_mi_b: u64,
    pub control_pipe: String,
    pub control_port: u32,
    pub network: bool,
    pub serial_stdio: bool,
}

impl RuntimeConfig {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > CONFIG_LIMIT {
            return Err(Error("invalid_runtime_configuration"));
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| Error("invalid_runtime_configuration"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.backend != "hcs-hyperv"
            || !identifier(&self.runtime_id)
            || !(1..=32).contains(&self.cpu_count)
            || !(1024..=131072).contains(&self.memory_mi_b)
            || self.control_port != CONTROL_PORT
            || self.serial_stdio
            || self.disks.len() != 2
            || !self.disks[0].read_only
            || self.disks[1].read_only
            || !drive_file(&self.kernel)
            || !drive_file(&self.initrd)
            || self.disks.iter().any(|disk| !drive_file(&disk.path))
            || !self.disks[0].path.to_ascii_lowercase().ends_with(".iso")
            || !self.disks[1].path.to_ascii_lowercase().ends_with(".vhdx")
            || self.control_pipe != format!(r"\\.\pipe\oblivion.{}.control", self.runtime_id)
        {
            return Err(Error("invalid_runtime_configuration"));
        }
        // The Windows boundary also compares opened object identities, including
        // aliases/reparse points which cannot be decided by a portable parser.
        let assets = [
            &self.kernel,
            &self.initrd,
            &self.disks[0].path,
            &self.disks[1].path,
        ];
        if assets.iter().enumerate().any(|(index, path)| {
            assets[..index]
                .iter()
                .any(|other| path.eq_ignore_ascii_case(other))
        }) {
            return Err(Error("invalid_runtime_configuration"));
        }
        self.boot_identity()?;
        if self.network {
            return Err(Error("hcs_network_not_implemented"));
        }
        Ok(())
    }

    /// Compute-system name. The live HCS RuntimeId must be queried separately
    /// before addressing AF_HYPERV; it is not inferred from this name.
    pub fn vm_id(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            &self.runtime_id[..8],
            &self.runtime_id[8..12],
            &self.runtime_id[12..16],
            &self.runtime_id[16..20],
            &self.runtime_id[20..]
        )
    }

    /// HCS schema 2.2: LinuxKernelDirect, VirtioSerial, SCSI and explicit
    /// HvSocket permissions. The schema and Microsoft's WSL implementation are
    /// the owners of these field names; callers cannot supply arbitrary devices.
    pub fn hcs(&self, bootstrap_pipe: &str, owner_sddl: &str) -> Result<String> {
        self.validate()?;
        let prefix = format!(r"\\.\pipe\oblivion.{}.auth.", self.runtime_id);
        if !bootstrap_pipe.strip_prefix(&prefix).is_some_and(identifier) {
            return Err(Error("invalid_runtime_auth_pipe"));
        }
        if !owner_descriptor(owner_sddl) {
            return Err(Error("invalid_runtime_owner_descriptor"));
        }
        let document = ComputeSystem {
            owner: "Oblivion",
            schema_version: Version { major: 2, minor: 2 },
            should_terminate_on_last_handle_closed: true,
            virtual_machine: VirtualMachine {
                stop_on_reset: true,
                chipset: Chipset {
                    use_utc: true,
                    linux_kernel_direct: LinuxKernelDirect {
                        kernel_file_path: &self.kernel,
                        init_rd_path: &self.initrd,
                        kernel_cmd_line: &self.command_line,
                    },
                },
                compute_topology: Topology {
                    memory: Memory {
                        size_in_mb: self.memory_mi_b,
                        allow_overcommit: false,
                    },
                    processor: Processor {
                        count: self.cpu_count,
                        expose_virtualization_extensions: true,
                    },
                },
                devices: Devices {
                    scsi: BTreeMap::from([(
                        self.vm_id(),
                        Scsi {
                            attachments: BTreeMap::from([
                                (
                                    "0",
                                    Attachment {
                                        kind: "Iso",
                                        path: &self.disks[0].path,
                                        read_only: true,
                                    },
                                ),
                                (
                                    "1",
                                    Attachment {
                                        kind: "VirtualDisk",
                                        path: &self.disks[1].path,
                                        read_only: false,
                                    },
                                ),
                            ]),
                        },
                    )]),
                    virtio_serial: VirtioSerial {
                        ports: BTreeMap::from([(
                            "0",
                            VirtioSerialPort {
                                named_pipe: bootstrap_pipe,
                                name: "oblivion.runtime-auth",
                                console_support: false,
                            },
                        )]),
                    },
                    hv_socket: HvSocket {
                        hv_socket_config: HvSocketConfig {
                            default_bind_security_descriptor: DENY,
                            default_connect_security_descriptor: DENY,
                            service_table: BTreeMap::from([(
                                CONTROL_SERVICE,
                                HvSocketService {
                                    bind_security_descriptor: owner_sddl,
                                    connect_security_descriptor: owner_sddl,
                                    allow_wildcard_binds: false,
                                },
                            )]),
                        },
                    },
                },
            },
        };
        serde_json::to_string(&document).map_err(|_| Error("runtime_configuration_encode_failed"))
    }

    fn boot_identity(&self) -> Result<()> {
        let parameters: Vec<_> = self.command_line.split(' ').collect();
        let identity = format!("oblivion.runtime-id={}", self.runtime_id);
        let required = [
            "oblivion.runtime=1",
            "oblivion.runtime-backend=hcs-hyperv",
            identity.as_str(),
        ];
        let allowed = ["boot=live", "components", "quiet", "loglevel=0"];
        let unique: BTreeSet<_> = parameters.iter().copied().collect();
        if self.command_line.len() > 4096
            || parameters.len() != unique.len()
            || required.iter().any(|parameter| !unique.contains(parameter))
            || parameters
                .iter()
                .any(|parameter| !required.contains(parameter) && !allowed.contains(parameter))
        {
            return Err(Error("runtime_boot_identity_required"));
        }
        Ok(())
    }
}

fn identifier(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn drive_file(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || value.encode_utf16().count() > 32760
        || !bytes[0].is_ascii_uppercase()
        || bytes[1..3] != *b":\\"
        || value.chars().any(|character| {
            character.is_control() || matches!(character, '/' | '"' | '<' | '>' | '|' | '?' | '*')
        })
    {
        return false;
    }
    value[3..].split('\\').all(|component| {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
            || component.contains(':')
            || component.encode_utf16().count() > 255
        {
            return false;
        }
        let name = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        !matches!(
            name.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !["COM", "LPT"].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    })
}

fn owner_descriptor(value: &str) -> bool {
    if value == "D:P(A;;GA;;;SY)" {
        return true;
    }
    let Some(sid) = value
        .strip_prefix("D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    let parts: Vec<_> = sid.split('-').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ComputeSystem<'a> {
    owner: &'a str,
    schema_version: Version,
    should_terminate_on_last_handle_closed: bool,
    virtual_machine: VirtualMachine<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Version {
    major: u8,
    minor: u8,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VirtualMachine<'a> {
    stop_on_reset: bool,
    chipset: Chipset<'a>,
    compute_topology: Topology,
    devices: Devices<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Chipset<'a> {
    use_utc: bool,
    linux_kernel_direct: LinuxKernelDirect<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct LinuxKernelDirect<'a> {
    kernel_file_path: &'a str,
    #[serde(rename = "InitRdPath")]
    init_rd_path: &'a str,
    kernel_cmd_line: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Topology {
    memory: Memory,
    processor: Processor,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Memory {
    #[serde(rename = "SizeInMB")]
    size_in_mb: u64,
    allow_overcommit: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Processor {
    count: u8,
    expose_virtualization_extensions: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Devices<'a> {
    scsi: BTreeMap<String, Scsi<'a>>,
    virtio_serial: VirtioSerial<'a>,
    hv_socket: HvSocket<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Scsi<'a> {
    attachments: BTreeMap<&'a str, Attachment<'a>>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Attachment<'a> {
    #[serde(rename = "Type")]
    kind: &'a str,
    path: &'a str,
    read_only: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VirtioSerial<'a> {
    ports: BTreeMap<&'a str, VirtioSerialPort<'a>>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VirtioSerialPort<'a> {
    named_pipe: &'a str,
    name: &'a str,
    console_support: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HvSocket<'a> {
    hv_socket_config: HvSocketConfig<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HvSocketConfig<'a> {
    default_bind_security_descriptor: &'a str,
    default_connect_security_descriptor: &'a str,
    service_table: BTreeMap<&'a str, HvSocketService<'a>>,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HvSocketService<'a> {
    bind_security_descriptor: &'a str,
    connect_security_descriptor: &'a str,
    allow_wildcard_binds: bool,
}
