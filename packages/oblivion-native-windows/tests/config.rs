use oblivion_native_windows::config::{CONFIG_LIMIT, CONTROL_SERVICE, RuntimeConfig};
use oblivion_native_windows::network_model::Plan;
use serde_json::{Value, json};

const ID: &str = "0123456789abcdef0123456789abcdef";
const OWNER: &str = "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1001)";

fn config() -> Value {
    json!({
        "version":1,"backend":"hcs-hyperv","runtimeId":ID,
        "kernel":r"C:\Oblivion\controller\vmlinuz",
        "initrd":r"C:\Oblivion\controller\initrd.img",
        "commandLine":format!("boot=live components quiet loglevel=0 oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={ID}"),
        "disks":[{"path":r"C:\Oblivion\controller\live.iso","readOnly":true},
            {"path":r"D:\Private files\Oblivion\runtime.vhdx","readOnly":false}],
        "cpuCount":4,"memoryMiB":4096,
        "controlPipe":format!(r"\\.\pipe\oblivion.{ID}.control"),
        "controlPort":4050,"network":false,"serialStdio":false
    })
}

fn decode(value: Value) -> RuntimeConfig {
    RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn auth() -> String {
    format!(r"\\.\pipe\oblivion.{ID}.auth.{}", "a".repeat(32))
}

#[test]
fn hcs_json_has_only_owned_offline_devices_and_exact_security_fields() {
    let config = decode(config());
    assert_eq!(config.vm_id(), "01234567-89ab-cdef-0123-456789abcdef");
    let output: Value = serde_json::from_str(&config.hcs(&auth(), OWNER, None).unwrap()).unwrap();
    assert_eq!(
        output,
        json!({
            "Owner":"Oblivion","SchemaVersion":{"Major":2,"Minor":2},
            "ShouldTerminateOnLastHandleClosed":true,
            "VirtualMachine":{
                "StopOnReset":true,
                "Chipset":{"UseUtc":true,"LinuxKernelDirect":{
                    "KernelFilePath":config.kernel,"InitRdPath":config.initrd,
                    "KernelCmdLine":config.command_line}},
                "ComputeTopology":{"Memory":{"SizeInMB":4096,"AllowOvercommit":false},
                    "Processor":{"Count":4,"ExposeVirtualizationExtensions":true}},
                "Devices":{
                    "Scsi":{"01234567-89ab-cdef-0123-456789abcdef":{"Attachments":{
                        "0":{"Type":"Iso","Path":config.disks[0].path,"ReadOnly":true},
                        "1":{"Type":"VirtualDisk","Path":config.disks[1].path,"ReadOnly":false}}}},
                    "VirtioSerial":{"Ports":{"0":{"NamedPipe":auth(),"Name":"oblivion.runtime-auth","ConsoleSupport":false}}},
                    "HvSocket":{"HvSocketConfig":{
                        "DefaultBindSecurityDescriptor":"D:P(D;;GA;;;WD)",
                        "DefaultConnectSecurityDescriptor":"D:P(D;;GA;;;WD)",
                        "ServiceTable":{CONTROL_SERVICE:{"BindSecurityDescriptor":OWNER,
                            "ConnectSecurityDescriptor":OWNER,"AllowWildcardBinds":false}}}}
                }
            }
        })
    );
    assert!(config.hcs(&auth(), "D:P(A;;GA;;;SY)", None).is_ok());
}

#[test]
fn strict_shape_and_platform_bounds_fail_without_echoing_input() {
    for (field, value) in [
        ("version", json!(2)),
        ("backend", json!("qemu-kvm")),
        ("runtimeId", json!("A".repeat(32))),
        ("runtimeId", json!("a".repeat(31))),
        ("runtimeId", json!("0".repeat(32))),
        ("kernel", Value::Null),
        ("initrd", Value::Null),
        ("cpuCount", json!(0)),
        ("cpuCount", json!(33)),
        ("memoryMiB", json!(1023)),
        ("memoryMiB", json!(131073)),
        ("controlPort", json!(4051)),
        ("serialStdio", json!(true)),
        ("controlSocket", json!("PRIVATE_CANARY")),
        ("guestCID", json!(3)),
        ("VirtualMachine", json!({"Plan9":"PRIVATE_CANARY"})),
    ] {
        let mut value_to_decode = config();
        value_to_decode[field] = value;
        let error = RuntimeConfig::decode(&serde_json::to_vec(&value_to_decode).unwrap())
            .err()
            .unwrap();
        assert_eq!(error.0, "invalid_runtime_configuration");
        assert!(!error.to_string().contains("PRIVATE_CANARY"));
    }
    assert_eq!(
        RuntimeConfig::decode(&vec![b' '; CONFIG_LIMIT + 1])
            .err()
            .unwrap()
            .0,
        "invalid_runtime_configuration"
    );
    let bytes = serde_json::to_string(&config()).unwrap();
    let duplicate = bytes.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert_eq!(
        RuntimeConfig::decode(duplicate.as_bytes()).err().unwrap().0,
        "invalid_runtime_configuration"
    );
    for (cpu, memory) in [(1, 1024), (32, 131072)] {
        let mut value = config();
        value["cpuCount"] = json!(cpu);
        value["memoryMiB"] = json!(memory);
        decode(value);
    }
}

#[test]
fn windows_drive_paths_are_lexical_and_never_accept_devices_unc_or_alias_syntax() {
    for path in [
        "relative",
        r"c:\Oblivion\kernel",
        r"C:kernel",
        r"\kernel",
        r"\\host\share\kernel",
        r"\\?\C:\kernel",
        r"\\.\PhysicalDrive0",
        r"C:\Oblivion\..\kernel",
        r"C:\Oblivion\.\kernel",
        r"C:\\kernel",
        r"C:\Oblivion\kernel.",
        r"C:\Oblivion\kernel ",
        r"C:\Oblivion\kernel:stream",
        r"C:\Oblivion\NUL.bin",
        r"C:\Oblivion\COM1",
        r"C:\Oblivion\lpt².txt",
        "C:\\Oblivion\\kernel\n",
        r"C:/Oblivion/kernel",
        r"C:\Oblivion\file?",
        r"C:\Oblivion\",
    ] {
        let mut value = config();
        value["kernel"] = json!(path);
        assert!(
            RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted {path:?}"
        );
    }
    let mut value = config();
    value["kernel"] = json!(r"C:\Utenti\à è\kernel");
    decode(value);
    let mut value = config();
    value["initrd"] = json!(r"C:\oblivion\controller\VMLINUZ");
    assert!(RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn only_iso_then_writable_vhdx_are_attached() {
    for disks in [
        json!([]),
        json!([{"path":r"C:\live.iso","readOnly":true}]),
        json!([{"path":r"C:\live.iso","readOnly":false},{"path":r"C:\data.vhdx","readOnly":false}]),
        json!([{"path":r"C:\live.iso","readOnly":true},{"path":r"C:\data.vhdx","readOnly":true}]),
        json!([{"path":r"C:\live.img","readOnly":true},{"path":r"C:\data.vhdx","readOnly":false}]),
        json!([{"path":r"C:\live.iso","readOnly":true},{"path":r"C:\data.raw","readOnly":false}]),
        json!([{"path":r"C:\live.iso","readOnly":true,"passthrough":true},{"path":r"C:\data.vhdx","readOnly":false}]),
    ] {
        let mut value = config();
        value["disks"] = disks;
        assert!(RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn bootstrap_and_control_pipe_names_are_bound_to_the_runtime_and_private_namespace() {
    for pipe in [
        r"\\remote\pipe\control".to_owned(),
        r"\\.\pipe\control".into(),
        format!(r"\\.\pipe\oblivion.{}.control", "b".repeat(32)),
        format!(r"\\.\pipe\oblivion.{ID}.control\child"),
        auth(),
    ] {
        let mut value = config();
        value["controlPipe"] = json!(pipe);
        assert!(RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let config = decode(config());
    for pipe in [
        config.control_pipe.clone(),
        format!(
            r"\\.\pipe\oblivion.{}.auth.{}",
            "b".repeat(32),
            "a".repeat(32)
        ),
        format!(r"\\remote\pipe\oblivion.{ID}.auth.{}", "a".repeat(32)),
        format!(r"\\.\pipe\oblivion.{ID}.auth.{}", "A".repeat(32)),
        format!(r"\\.\pipe\oblivion.{ID}.auth.{}\child", "a".repeat(32)),
    ] {
        assert_eq!(
            config.hcs(&pipe, OWNER, None).unwrap_err().0,
            "invalid_runtime_auth_pipe"
        );
    }
}

#[test]
fn kernel_parameters_are_a_positive_identity_allowlist_without_secret_channels() {
    let base =
        format!("oblivion.runtime=1 oblivion.runtime-backend=hcs-hyperv oblivion.runtime-id={ID}");
    let mut value = config();
    value["commandLine"] = json!(base);
    decode(value);
    for line in [
        format!("{base} init=/bin/sh"),
        format!("{base} control-token=PRIVATE_CANARY"),
        format!("{base} oblivion.runtime=1"),
        format!("{base} console=ttyS0"),
        format!("{base} console=hvc0"),
        base.replace(ID, &"b".repeat(32)),
        base.replace("hcs-hyperv", "qemu-kvm"),
        base.replace("oblivion.runtime=1", "oblivion.runtime=0"),
        base.replace("oblivion.runtime=1 ", ""),
        base.replace(' ', "\t"),
        format!("{base} "),
        format!("{base}\0"),
    ] {
        let mut value = config();
        value["commandLine"] = json!(line);
        let error = RuntimeConfig::decode(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert_eq!(error.0, "runtime_boot_identity_required");
        assert!(!error.to_string().contains("PRIVATE_CANARY"));
    }
}

#[test]
fn network_attachment_and_untrusted_owner_descriptors_have_no_permissive_fallback() {
    let mut value = config();
    value["network"] = json!(true);
    assert_eq!(
        decode(value).hcs(&auth(), OWNER, None).unwrap_err().0,
        "runtime_network_attachment_required"
    );
    let config = decode(config());
    for owner in [
        "",
        "D:(A;;GA;;;WD)",
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1001)(A;;GA;;;WD)",
        "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-4294967296)",
        "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-01-2-3-1001)",
    ] {
        assert_eq!(
            config.hcs(&auth(), owner, None).unwrap_err().0,
            "invalid_runtime_owner_descriptor"
        );
    }
}

#[test]
fn only_the_owned_network_lease_can_supply_adapter_and_boot_metadata() {
    let plan = Plan::new(ID, &[]).unwrap();
    let offline = decode(config());
    assert_eq!(
        offline
            .hcs(&auth(), OWNER, Some(&plan.attachment))
            .unwrap_err()
            .0,
        "runtime_network_attachment_required"
    );
    let mut value = config();
    value["network"] = json!(true);
    let online = decode(value);
    let output: Value =
        serde_json::from_str(&online.hcs(&auth(), OWNER, Some(&plan.attachment)).unwrap()).unwrap();
    assert_eq!(
        output["VirtualMachine"]["Devices"]["NetworkAdapters"],
        json!({
            (plan.attachment.adapter_id.clone()): {
                "EndpointId":plan.attachment.endpoint_id,
                "MacAddress":plan.attachment.hcs_mac(),
            }
        })
    );
    assert_eq!(
        output["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelCmdLine"],
        format!("{} {}", online.command_line, plan.attachment.boot_args())
    );
    let foreign = Plan::new("1123456789abcdef0123456789abcdef", &[]).unwrap();
    assert!(
        online
            .hcs(&auth(), OWNER, Some(&foreign.attachment))
            .is_err()
    );
    let mut caller = config();
    caller["commandLine"] = json!(format!(
        "{} {}",
        online.command_line,
        plan.attachment.boot_args()
    ));
    assert!(RuntimeConfig::decode(&serde_json::to_vec(&caller).unwrap()).is_err());
}
