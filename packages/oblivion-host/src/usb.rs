use crate::storage::{Error, Result, require};
use oblivion_host::persistence::{Plan, Status};
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PENDING: &str = "47D5AF95-A733-4B07-9762-CB4B8AF610A6";
const READY: &str = "CA7D7CCB-63ED-4C53-861C-1742536059CC";
const NAME: &str = "Oblivion general";
const BASIC: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
const EFI: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const HFS: &str = "48465300-0000-11AA-AA11-00306543ECAC";

pub struct Inspection {
    pub status: Status,
    pub source: Option<PathBuf>,
}

#[derive(Deserialize)]
struct TableResponse {
    partitiontable: Table,
}

#[derive(Deserialize)]
struct Table {
    label: String,
    id: String,
    unit: String,
    sectorsize: u64,
    partitions: Vec<Partition>,
}

#[derive(Deserialize)]
struct Partition {
    node: PathBuf,
    start: u64,
    size: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
}

pub fn inspect(minimum_bytes: u64) -> Inspection {
    match discover(minimum_bytes) {
        Ok(inspection) => inspection,
        Err(error) => Inspection {
            status: Status {
                unavailable: Some(error.0.to_owned()),
                ..Status::default()
            },
            source: None,
        },
    }
}

fn discover(minimum_bytes: u64) -> Result<Inspection> {
    let mounts =
        fs::read_to_string("/proc/self/mountinfo").map_err(|_| Error("usb_mount_check_failed"))?;
    let fields: Vec<_> = mounts
        .lines()
        .find(|line| line.split_whitespace().nth(4) == Some("/run/live/medium"))
        .ok_or(Error("usb_live_medium_missing"))?
        .split_whitespace()
        .collect();
    let separator = fields
        .iter()
        .position(|s| *s == "-")
        .ok_or(Error("usb_mount_check_failed"))?;
    // GRUB's hybrid image is also readable through its HFS+ boot partition;
    // Debian live-boot may find that before the whole-disk ISO9660 view.
    require(
        matches!(fields.get(separator + 1), Some(&"iso9660" | &"hfsplus")),
        "usb_live_format_unsupported",
    )?;
    require(
        fields
            .get(5)
            .is_some_and(|s| s.split(',').any(|s| s == "ro")),
        "usb_live_must_be_readonly",
    )?;
    let device = fs::canonicalize(format!("/sys/dev/block/{}", fields[2]))
        .map_err(|_| Error("usb_device_missing"))?;
    // live-media-offset=0 asks Debian live-boot to mount the ISO through a
    // loop device. Mounting the whole USB directly would make cryptsetup's
    // exclusive open of its new data partition fail with EBUSY.
    require(device.join("loop").is_dir(), "usb_loop_boot_required")?;
    require(
        fs::read_to_string(device.join("loop/offset")).is_ok_and(|s| s.trim() == "0"),
        "usb_loop_boot_required",
    )?;
    let backing = fs::read_to_string(device.join("loop/backing_file"))
        .map_err(|_| Error("usb_device_missing"))?;
    let backing = Path::new(backing.trim());
    require(
        backing.parent() == Some(Path::new("/dev")),
        "usb_boot_device_required",
    )?;
    let metadata = fs::symlink_metadata(backing).map_err(|_| Error("usb_device_missing"))?;
    require(
        metadata.file_type().is_block_device(),
        "usb_boot_device_required",
    )?;
    let device = fs::canonicalize(format!(
        "/sys/dev/block/{}:{}",
        libc::major(metadata.rdev()),
        libc::minor(metadata.rdev())
    ))
    .map_err(|_| Error("usb_device_missing"))?;
    let disk = if device.join("partition").exists() {
        device
            .parent()
            .ok_or(Error("usb_device_missing"))?
            .to_owned()
    } else {
        device
    };
    require(
        disk.ancestors()
            .any(|p| fs::read_link(p.join("subsystem")).is_ok_and(|s| s.ends_with("usb"))),
        "usb_boot_device_required",
    )?;
    require(
        fs::read_to_string(disk.join("ro")).is_ok_and(|s| s.trim() == "0"),
        "usb_medium_readonly",
    )?;
    require(
        fs::read_to_string(disk.join("queue/logical_block_size")).is_ok_and(|s| s.trim() == "512"),
        "usb_sector_size_unsupported",
    )?;
    let identity = fs::read_to_string(disk.join("dev"))
        .map_err(|_| Error("usb_device_missing"))?
        .trim()
        .to_owned();
    let sectors: u64 = fs::read_to_string(disk.join("size"))
        .map_err(|_| Error("usb_size_failed"))?
        .trim()
        .parse()
        .map_err(|_| Error("usb_size_failed"))?;
    let name = disk
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(Error("usb_device_missing"))?;
    require(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "usb_device_missing",
    )?;
    let path = PathBuf::from(format!("/dev/{name}"));
    let mut file = block(&path, &identity)?;
    // The ISO9660 volume descriptor gives the immutable live image boundary.
    // Partition geometry and all writes are delegated to Debian's sfdisk.
    file.seek(SeekFrom::Start(32768))
        .map_err(|_| Error("usb_iso_read_failed"))?;
    let mut descriptor = [0; 2048];
    file.read_exact(&mut descriptor)
        .map_err(|_| Error("usb_iso_read_failed"))?;
    require(
        &descriptor[..7] == b"\x01CD001\x01",
        "usb_live_format_unsupported",
    )?;
    require(
        u16::from_le_bytes([descriptor[128], descriptor[129]]) == 2048,
        "usb_live_format_unsupported",
    )?;
    let iso_sectors = u32::from_le_bytes(descriptor[80..84].try_into().unwrap()) as u64 * 4;
    let table: TableResponse = serde_json::from_slice(&command(
        "/usr/sbin/sfdisk",
        &["--json", path.to_str().unwrap()],
        None,
    )?)
    .map_err(|_| Error("usb_partition_table_invalid"))?;
    let (plan, state) = layout(
        &table.partitiontable,
        name,
        &identity,
        sectors,
        iso_sectors,
        minimum_bytes,
    )?;
    let source = if state != 0 {
        let source = table.partitiontable.partitions.last().unwrap().node.clone();
        let expected = partition_path(&path, plan.partition);
        require(source == expected, "usb_partition_table_invalid")?;
        let child = disk.join(expected.file_name().unwrap());
        let id = fs::read_to_string(child.join("dev"))
            .map_err(|_| Error("usb_partition_unavailable"))?;
        block(&source, id.trim())?;
        require(
            fs::read_to_string(child.join("start"))
                .is_ok_and(|s| s.trim().parse::<u64>().ok() == Some(plan.start))
                && fs::read_to_string(child.join("size"))
                    .is_ok_and(|s| s.trim().parse::<u64>().ok() == Some(plan.sectors)),
            "usb_partition_geometry_changed",
        )?;
        require(
            !mounts
                .lines()
                .any(|line| line.split_whitespace().nth(2) == Some(id.trim())),
            "usb_partition_busy",
        )?;
        require(
            fs::read_dir(child.join("holders"))
                .map_err(|_| Error("usb_partition_unavailable"))?
                .next()
                .is_none()
                || Path::new("/dev/mapper/oblivion-general").exists(),
            "usb_partition_busy",
        )?;
        Some(source)
    } else {
        None
    };
    Ok(Inspection {
        status: Status {
            plan: Some(plan),
            present: state == 2,
            incomplete: state == 1,
            unavailable: None,
        },
        source,
    })
}

// Only the GRUB ISO layout emitted by our build is eligible. Existing extra
// partitions are never reused or reformatted, even if they have a familiar FS.
fn layout(
    table: &Table,
    name: &str,
    identity: &str,
    sectors: u64,
    iso: u64,
    minimum: u64,
) -> Result<(Plan, u8)> {
    require(
        table.label == "gpt" && table.unit == "sectors" && table.sectorsize == 512,
        "usb_partition_table_unsupported",
    )?;
    require(sectors > iso && iso > 64, "usb_no_free_space")?;
    let boot = if table.partitions.get(2).is_some_and(|p| p.name == "HFSPLUS") {
        4
    } else {
        3
    };
    require(
        table.partitions.len() == boot || table.partitions.len() == boot + 1,
        "usb_foreign_partitions",
    )?;
    let expected = if boot == 4 {
        vec![
            ("Gap0", BASIC),
            ("EFI boot partition", EFI),
            ("HFSPLUS", HFS),
            ("Gap1", BASIC),
        ]
    } else {
        vec![
            ("Gap0", BASIC),
            ("EFI boot partition", EFI),
            ("Gap1", BASIC),
        ]
    };
    let mut end = 64;
    for (part, (label, kind)) in table.partitions.iter().zip(expected) {
        require(
            part.name == label
                && part.kind.eq_ignore_ascii_case(kind)
                && part.start == end
                && part.size > 0,
            "usb_live_layout_unsupported",
        )?;
        end = part
            .start
            .checked_add(part.size)
            .ok_or(Error("usb_partition_table_invalid"))?;
        require(end <= iso, "usb_live_layout_unsupported")?;
    }
    let start = iso.div_ceil(2048) * 2048;
    let limit = sectors.checked_sub(34).ok_or(Error("usb_no_free_space"))? / 2048 * 2048;
    let size = limit.checked_sub(start).ok_or(Error("usb_no_free_space"))?;
    let state = if let Some(part) = table.partitions.get(boot) {
        require(
            part.name == NAME && part.start == start && part.size == size,
            "usb_foreign_partitions",
        )?;
        if part.kind.eq_ignore_ascii_case(READY) {
            2
        } else if part.kind.eq_ignore_ascii_case(PENDING) {
            1
        } else {
            return Err(Error("usb_foreign_partitions"));
        }
    } else {
        0
    };
    require(size >= minimum.div_ceil(512), "usb_no_free_space")?;
    Ok((
        Plan {
            device: name.to_owned(),
            identity: identity.to_owned(),
            table: table.id.clone(),
            disk_bytes: sectors * 512,
            start,
            sectors: size,
            partition: boot as u32 + 1,
        },
        state,
    ))
}

pub fn prepare(plan: &Plan, minimum: u64) -> Result<PathBuf> {
    let current = discover(minimum)?;
    require(
        current.status.plan.as_ref() == Some(plan),
        "usb_selection_changed",
    )?;
    require(
        !current.status.present && !current.status.incomplete,
        "usb_already_prepared",
    )?;
    let disk = format!("/dev/{}", plan.device);
    command(
        "/usr/sbin/sfdisk",
        &[
            "--append",
            "--no-reread",
            "--no-tell-kernel",
            "--lock=nonblock",
            "--wipe=never",
            "--wipe-partitions=never",
            &disk,
        ],
        Some(
            format!(
                "start={}, size={}, type={PENDING}, name=\"{NAME}\"\n",
                plan.start, plan.sectors
            )
            .as_bytes(),
        ),
    )?;
    command(
        "/usr/bin/partx",
        // udev may already have registered the new partition. Update handles
        // both cases; discover below checks the kernel's resulting geometry.
        &["--update", "--nr", &plan.partition.to_string(), &disk],
        None,
    )?;
    command("/usr/bin/udevadm", &["settle", "--timeout=10"], None)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current = inspect(minimum);
        if current.status.incomplete && current.status.plan.as_ref() == Some(plan) {
            return current.source.ok_or(Error("usb_partition_unavailable"));
        }
        require(Instant::now() < deadline, "usb_partition_unavailable")?;
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn publish(plan: &Plan, minimum: u64) -> Result<()> {
    let current = discover(minimum)?;
    require(
        current.status.incomplete && current.status.plan.as_ref() == Some(plan),
        "usb_selection_changed",
    )?;
    command(
        "/usr/sbin/sfdisk",
        &[
            "--no-reread",
            "--no-tell-kernel",
            "--lock=nonblock",
            "--part-type",
            &format!("/dev/{}", plan.device),
            &plan.partition.to_string(),
            READY,
        ],
        None,
    )?;
    require(discover(minimum)?.status.present, "usb_publish_failed")
}

pub fn discard(minimum: u64) -> Result<()> {
    let current = discover(minimum)?;
    require(
        current.status.incomplete && !current.status.present,
        "usb_not_incomplete",
    )?;
    let plan = current
        .status
        .plan
        .ok_or(Error("usb_partition_unavailable"))?;
    let disk = format!("/dev/{}", plan.device);
    command(
        "/usr/sbin/sfdisk",
        &[
            "--no-reread",
            "--no-tell-kernel",
            "--lock=nonblock",
            "--delete",
            &disk,
            &plan.partition.to_string(),
        ],
        None,
    )?;
    command(
        "/usr/bin/partx",
        &["--delete", "--nr", &plan.partition.to_string(), &disk],
        None,
    )?;
    Ok(())
}

fn partition_path(disk: &Path, number: u32) -> PathBuf {
    PathBuf::from(format!(
        "{}{}{number}",
        disk.display(),
        if disk
            .as_os_str()
            .as_encoded_bytes()
            .last()
            .is_some_and(u8::is_ascii_digit)
        {
            "p"
        } else {
            ""
        }
    ))
}

fn block(path: &Path, identity: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("usb_device_missing"))?;
    let meta = file.metadata().map_err(|_| Error("usb_device_missing"))?;
    require(
        meta.file_type().is_block_device()
            && format!("{}:{}", libc::major(meta.rdev()), libc::minor(meta.rdev())) == identity,
        "usb_device_changed",
    )?;
    Ok(file)
}

fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("usb_command_failed"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or(Error("usb_command_failed"))?
            .write_all(input)
            .map_err(|_| Error("usb_command_failed"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| Error("usb_command_failed"))?;
    require(output.status.success(), "usb_command_failed")?;
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        // Geometry from the actual GRUB diagnostic ISO. The USB has additional
        // space; the ISO's backup GPT still sits at its original image end.
        serde_json::from_str(r#"{"label":"gpt","id":"fixture","unit":"sectors","sectorsize":512,"partitions":[
          {"node":"/dev/sda1","start":64,"size":224,"type":"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7","name":"Gap0"},
          {"node":"/dev/sda2","start":288,"size":5760,"type":"C12A7328-F81F-11D2-BA4B-00A0C93EC93B","name":"EFI boot partition"},
          {"node":"/dev/sda3","start":6048,"size":2129036,"type":"48465300-0000-11AA-AA11-00306543ECAC","name":"HFSPLUS"},
          {"node":"/dev/sda4","start":2135084,"size":600,"type":"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7","name":"Gap1"}] }"#).unwrap()
    }

    #[test]
    fn live_image_boundary_and_tail_space() {
        let (plan, state) = layout(
            &table(),
            "sda",
            "8:0",
            16777216,
            2135732,
            4 * 1024 * 1024 * 1024,
        )
        .unwrap_or_else(|e| panic!("{}", e.0));
        assert_eq!(state, 0);
        assert_eq!(plan.partition, 5);
        assert_eq!(plan.start, 2136064);
        assert_eq!(plan.start + plan.sectors, 16775168);
        assert_eq!(
            partition_path(Path::new("/dev/sda"), 5),
            Path::new("/dev/sda5")
        );
        assert_eq!(
            partition_path(Path::new("/dev/nvme0n1"), 5),
            Path::new("/dev/nvme0n1p5")
        );
    }

    #[test]
    fn existing_data_is_never_a_preparation_target() {
        let mut table = table();
        table.partitions.push(Partition {
            node: "/dev/sda5".into(),
            start: 2136064,
            size: 14639104,
            kind: READY.into(),
            name: NAME.into(),
        });
        assert_eq!(
            layout(&table, "sda", "8:0", 16777216, 2135732, 512)
                .unwrap_or_else(|e| panic!("{}", e.0))
                .1,
            2
        );
        table.partitions[4].kind = PENDING.into();
        assert_eq!(
            layout(&table, "sda", "8:0", 16777216, 2135732, 512)
                .unwrap_or_else(|e| panic!("{}", e.0))
                .1,
            1
        );
        table.partitions[4].kind = BASIC.into();
        assert!(layout(&table, "sda", "8:0", 16777216, 2135732, 512).is_err());
        table.partitions[4].kind = READY.into();
        table.partitions[4].start += 1;
        assert!(layout(&table, "sda", "8:0", 16777216, 2135732, 512).is_err());
    }

    #[test]
    fn refuse_unsupported_or_overlapping_boot_layouts() {
        let mut table = table();
        assert!(layout(&table, "sda", "8:0", 2135732, 2135732, 512).is_err());
        assert!(
            layout(
                &table,
                "sda",
                "8:0",
                3000000,
                2135732,
                4 * 1024 * 1024 * 1024
            )
            .is_err()
        );
        table.partitions[1].start -= 1;
        assert!(layout(&table, "sda", "8:0", 16777216, 2135732, 512).is_err());
        table.partitions[1].start += 1;
        table.sectorsize = 4096;
        assert!(layout(&table, "sda", "8:0", 16777216, 2135732, 512).is_err());
    }
}
