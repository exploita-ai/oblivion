//! Host preparation precedes any Oblivion VM, service or data creation. The
//! only supported host change is the reviewed full Hyper-V optional feature.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Outcome {
    Ready,
    EnableRequired,
    RebootRequired,
    Blocked { reason: Reason },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    UnsupportedArchitecture,
    UnsupportedWindowsVersion,
    UnsupportedEdition,
    FirmwareUnavailable,
    SlatUnavailable,
    DepUnavailable,
    FeatureUnavailable,
    HcsUnavailable,
    HcsSchemaUnsupported,
    NestedUnavailable,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::UnsupportedArchitecture => "Oblivion requires an x64 Windows PC.",
            Self::UnsupportedWindowsVersion => "Oblivion setup requires Windows 11 or later.",
            Self::UnsupportedEdition => "Use a supported Windows Pro, Enterprise, or Education edition. Windows Home cannot provide the required Hyper-V role.",
            Self::FirmwareUnavailable => "Windows cannot report firmware virtualization as available. Check the firmware virtualization setting and Windows hypervisor availability.",
            Self::SlatUnavailable => "Windows cannot report the SLAT processor support required by Hyper-V.",
            Self::DepUnavailable => "Windows cannot report data execution prevention (DEP) as enabled.",
            Self::FeatureUnavailable => "Windows could not verify the Hyper-V feature. Check Windows servicing, then retry setup.",
            Self::HcsUnavailable => "Hyper-V is enabled, but the Windows compute service is not ready. Complete any requested restart, then retry setup.",
            Self::HcsSchemaUnsupported => "The Windows compute service lacks the HCS schema required by Oblivion. Update Windows before retrying setup.",
            Self::NestedUnavailable => "Oblivion's controller VM needs nested virtualization to run isolated Safe VMs. Windows does not report this support.",
        })
    }
}

#[cfg(any(windows, test))]
const OUTPUT_LIMIT: usize = 65536;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Feature {
    Enabled,
    Disabled,
    EnablePending,
    DisablePending,
    Removed,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct Hardware {
    firmware: bool,
    slat: bool,
    dep: bool,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
enum Hcs {
    Ready,
    Unavailable,
    SchemaUnsupported,
    NestedUnavailable,
}

#[cfg(any(windows, test))]
fn decision(feature: Feature, hardware: Hardware, hcs: Hcs) -> Outcome {
    if matches!(feature, Feature::EnablePending | Feature::DisablePending) {
        return Outcome::RebootRequired;
    }
    if matches!(feature, Feature::Enabled) {
        match hcs {
            Hcs::Ready => return Outcome::Ready,
            Hcs::SchemaUnsupported => return blocked(Reason::HcsSchemaUnsupported),
            Hcs::NestedUnavailable => return blocked(Reason::NestedUnavailable),
            Hcs::Unavailable => {}
        }
    }
    // A zero PF flag can also mean that HAL cannot report it. Positive HCS
    // nested/schema evidence is stronger than these coarse hardware flags.
    if !matches!(hcs, Hcs::Ready) {
        if !hardware.firmware {
            return blocked(Reason::FirmwareUnavailable);
        }
        if !hardware.slat {
            return blocked(Reason::SlatUnavailable);
        }
        if !hardware.dep {
            return blocked(Reason::DepUnavailable);
        }
    }
    if matches!(feature, Feature::Disabled | Feature::Removed) {
        return Outcome::EnableRequired;
    }
    blocked(Reason::HcsUnavailable)
}

#[cfg(any(windows, test))]
fn blocked(reason: Reason) -> Outcome {
    Outcome::Blocked { reason }
}

#[cfg(any(windows, test))]
fn supported_build(text: &str) -> crate::Result<bool> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(crate::Error("windows_version_unavailable"));
    }
    Ok(text
        .parse::<u32>()
        .map_err(|_| crate::Error("windows_version_unavailable"))?
        >= 22000)
}

#[cfg(any(windows, test))]
fn parse_feature(bytes: &[u8]) -> crate::Result<Feature> {
    use crate::Error;
    if bytes.is_empty() || bytes.len() > OUTPUT_LIMIT {
        return Err(Error("invalid_windows_feature_output"));
    }
    let text = decode(bytes)?;
    if text.contains('\0') {
        return Err(Error("invalid_windows_feature_output"));
    }
    let mut name = None;
    let mut state = None;
    for line in text.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        match field.trim() {
            "Feature Name" => {
                if name.replace(value.trim()).is_some() {
                    return Err(Error("invalid_windows_feature_output"));
                }
            }
            "State" => {
                if state.replace(value.trim()).is_some() {
                    return Err(Error("invalid_windows_feature_output"));
                }
            }
            _ => {}
        }
    }
    if name != Some("Microsoft-Hyper-V") {
        return Err(Error("invalid_windows_feature_output"));
    }
    match state {
        Some("Enabled") => Ok(Feature::Enabled),
        Some("Disabled") => Ok(Feature::Disabled),
        Some("Enable Pending") => Ok(Feature::EnablePending),
        Some("Disable Pending") => Ok(Feature::DisablePending),
        Some("Disabled with Payload Removed") => Ok(Feature::Removed),
        _ => Err(Error("invalid_windows_feature_output")),
    }
}

#[cfg(any(windows, test))]
fn decode(bytes: &[u8]) -> crate::Result<String> {
    use crate::Error;
    if bytes.starts_with(&[0xfe, 0xff]) {
        return Err(Error("invalid_windows_feature_output"));
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.contains(&0) {
        let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
        if bytes.len() % 2 != 0 {
            return Err(Error("invalid_windows_feature_output"));
        }
        return String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error("invalid_windows_feature_output"));
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(text.to_owned());
    }
    #[cfg(windows)]
    return native::decode_oem(bytes);
    #[cfg(not(windows))]
    Err(Error("invalid_windows_feature_output"))
}

#[cfg(windows)]
mod native {
    use super::{
        Feature, Hardware, Hcs, OUTPUT_LIMIT, Outcome, Reason, blocked, decision, parse_feature,
        supported_build,
    };
    use crate::security::Identity;
    use crate::{Error, Result, hcs};
    use std::io::Read;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, GetLastError,
    };
    use windows_sys::Win32::Globalization::{CP_OEMCP, MB_ERR_INVALID_CHARS, MultiByteToWideChar};
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, REGSTR_VAL_CURRENT_BUILD, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
        RegGetValueW,
    };
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, GetProductInfo, GetSystemDirectoryW, PROCESSOR_ARCHITECTURE_AMD64,
        PRODUCT_EDUCATION, PRODUCT_EDUCATION_N, PRODUCT_ENTERPRISE, PRODUCT_ENTERPRISE_EVALUATION,
        PRODUCT_ENTERPRISE_N, PRODUCT_ENTERPRISE_N_EVALUATION, PRODUCT_ENTERPRISE_S,
        PRODUCT_ENTERPRISE_S_EVALUATION, PRODUCT_ENTERPRISE_S_N, PRODUCT_ENTERPRISE_S_N_EVALUATION,
        PRODUCT_PRO_WORKSTATION, PRODUCT_PRO_WORKSTATION_N, PRODUCT_PROFESSIONAL,
        PRODUCT_PROFESSIONAL_N, SYSTEM_INFO,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, GetCurrentProcessId, IsProcessorFeaturePresent, PF_NX_ENABLED,
        PF_SECOND_LEVEL_ADDRESS_TRANSLATION, PF_VIRT_FIRMWARE_ENABLED,
    };

    /// Called in the authenticated elevated setup process. `false` only
    /// reviews; `true` follows the parent's explicit Hyper-V approval. Neither
    /// path restarts Windows or creates an Oblivion service, VM or data disk.
    pub fn prepare(allow_enable: bool, stop: &AtomicBool, deadline: Instant) -> Result<Outcome> {
        check(stop, deadline)?;
        let mut system = SYSTEM_INFO::default();
        unsafe {
            GetNativeSystemInfo(&mut system);
        }
        if unsafe { system.Anonymous.Anonymous.wProcessorArchitecture }
            != PROCESSOR_ARCHITECTURE_AMD64
        {
            return Ok(blocked(Reason::UnsupportedArchitecture));
        }
        if !windows_11()? {
            return Ok(blocked(Reason::UnsupportedWindowsVersion));
        }
        let mut product = 0;
        if unsafe { GetProductInfo(10, 0, 0, 0, &mut product) } == 0 {
            return Err(Error("windows_edition_unavailable"));
        }
        if !matches!(
            product,
            PRODUCT_PROFESSIONAL
                | PRODUCT_PROFESSIONAL_N
                | PRODUCT_PRO_WORKSTATION
                | PRODUCT_PRO_WORKSTATION_N
                | PRODUCT_ENTERPRISE
                | PRODUCT_ENTERPRISE_N
                | PRODUCT_ENTERPRISE_S
                | PRODUCT_ENTERPRISE_S_N
                | PRODUCT_ENTERPRISE_EVALUATION
                | PRODUCT_ENTERPRISE_N_EVALUATION
                | PRODUCT_ENTERPRISE_S_EVALUATION
                | PRODUCT_ENTERPRISE_S_N_EVALUATION
                | PRODUCT_EDUCATION
                | PRODUCT_EDUCATION_N
        ) {
            return Ok(blocked(Reason::UnsupportedEdition));
        }
        if !Identity::administrators()?.permits(unsafe { GetCurrentProcessId() }, false)? {
            return Err(Error("windows_elevation_required"));
        }
        let hardware = Hardware {
            firmware: unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) } != 0,
            slat: unsafe { IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION) } != 0,
            dep: unsafe { IsProcessorFeaturePresent(PF_NX_ENABLED) } != 0,
        };
        let Some(feature) = query(stop, deadline)? else {
            return Ok(blocked(Reason::FeatureUnavailable));
        };
        let outcome = decision(feature, hardware, observe_hcs());
        if outcome != Outcome::EnableRequired || !allow_enable {
            check(stop, deadline)?;
            return Ok(outcome);
        }
        let enabled = dism(true, stop, deadline)?;
        if enabled.code != 0 && enabled.code != 3010 {
            return Err(Error("windows_feature_enable_failed"));
        }
        let Some(feature) = query(stop, deadline)? else {
            return Ok(blocked(Reason::FeatureUnavailable));
        };
        if enabled.code == 3010
            || matches!(feature, Feature::EnablePending | Feature::DisablePending)
        {
            return Ok(Outcome::RebootRequired);
        }
        if feature != Feature::Enabled {
            return Err(Error("windows_feature_enable_unconfirmed"));
        }
        let outcome = decision(feature, hardware, observe_hcs());
        check(stop, deadline)?;
        Ok(outcome)
    }

    fn windows_11() -> Result<bool> {
        // Microsoft's WSL build gate uses the native CurrentVersion key rather
        // than an app-compatibility-manifest-sensitive version helper.
        let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut build = [0u16; 32];
        let mut bytes = std::mem::size_of_val(&build) as u32;
        if unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                REGSTR_VAL_CURRENT_BUILD,
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                null_mut(),
                build.as_mut_ptr().cast(),
                &mut bytes,
            )
        } != 0
            || bytes < 4
            || bytes as usize > std::mem::size_of_val(&build)
            || bytes % 2 != 0
        {
            return Err(Error("windows_version_unavailable"));
        }
        let length = bytes as usize / 2;
        if build[length - 1] != 0 {
            return Err(Error("windows_version_unavailable"));
        }
        let text = String::from_utf16(&build[..length - 1])
            .map_err(|_| Error("windows_version_unavailable"))?;
        supported_build(&text)
    }

    fn observe_hcs() -> Hcs {
        match hcs::capabilities() {
            Ok(capabilities)
                if !capabilities
                    .schemas
                    .iter()
                    .any(|schema| schema.major == 2 && schema.minor >= 2) =>
            {
                Hcs::SchemaUnsupported
            }
            Ok(capabilities) if !capabilities.nested_virtualization => Hcs::NestedUnavailable,
            Ok(_) => Hcs::Ready,
            Err(_) => Hcs::Unavailable,
        }
    }

    fn query(stop: &AtomicBool, deadline: Instant) -> Result<Option<Feature>> {
        let output = dism(false, stop, deadline)?;
        if output.code != 0 {
            return Ok(None);
        }
        parse_feature(&output.stdout).map(Some)
    }

    struct Output {
        code: i32,
        stdout: Vec<u8>,
    }

    fn dism(enable: bool, stop: &AtomicBool, deadline: Instant) -> Result<Output> {
        check(stop, deadline)?;
        let mut directory = vec![0u16; 32768];
        let length =
            unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
        if length == 0 || length >= directory.len() {
            return Err(Error("windows_system_directory_unavailable"));
        }
        let directory = PathBuf::from(
            String::from_utf16(&directory[..length])
                .map_err(|_| Error("windows_system_directory_unavailable"))?,
        );
        let arguments: &[&str] = if enable {
            &[
                "/Online",
                "/English",
                "/Quiet",
                "/NoRestart",
                "/Enable-Feature",
                "/All",
                "/FeatureName:Microsoft-Hyper-V",
            ]
        } else {
            &[
                "/Online",
                "/English",
                "/Get-FeatureInfo",
                "/FeatureName:Microsoft-Hyper-V",
            ]
        };
        let mut child = Command::new(directory.join("dism.exe"))
            .args(arguments)
            .current_dir(&directory)
            .env("PATH", &directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| Error("windows_feature_process_unavailable"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(Error("windows_feature_process_unavailable"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(Error("windows_feature_process_unavailable"))?;
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let mut failure = None;
        let mut killed = false;
        let mut budget = OUTPUT_LIMIT;
        loop {
            if failure.is_none() {
                failure = check(stop, deadline).err();
            }
            for result in [
                drain(&mut stdout, &mut output, &mut budget, failure.is_none()),
                drain(&mut stderr, &mut errors, &mut budget, failure.is_none()),
            ] {
                if let Err(error) = result {
                    failure.get_or_insert(error);
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    loop {
                        let read = drain(&mut stdout, &mut output, &mut budget, failure.is_none());
                        let error = drain(&mut stderr, &mut errors, &mut budget, failure.is_none());
                        let pending = matches!(read, Ok(true)) || matches!(error, Ok(true));
                        if let Err(error) = read {
                            failure.get_or_insert(error);
                        }
                        if let Err(error) = error {
                            failure.get_or_insert(error);
                        }
                        if !pending {
                            break;
                        }
                    }
                    if let Some(error) = failure {
                        return Err(error);
                    }
                    check(stop, deadline)?;
                    return Ok(Output {
                        code: status
                            .code()
                            .ok_or(Error("windows_feature_process_failed"))?,
                        stdout: output,
                    });
                }
                Ok(None) => {}
                Err(_) => {
                    failure.get_or_insert(Error("windows_feature_process_cleanup_unconfirmed"));
                }
            }
            if failure.is_some() && !killed {
                let _ = child.kill();
                killed = true;
            }
            // Never detach a mutating worker or claim rollback after timeout.
            // Even after cancellation, retain ownership until actual exit. CBS
            // servicing may still be pending and the next setup must re-query.
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn drain(
        pipe: &mut (impl Read + AsRawHandle),
        output: &mut Vec<u8>,
        budget: &mut usize,
        store: bool,
    ) -> Result<bool> {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            return if matches!(
                unsafe { GetLastError() },
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            ) {
                Ok(false)
            } else {
                Err(Error("windows_feature_output_unavailable"))
            };
        }
        if available == 0 {
            return Ok(false);
        }
        let mut bytes = [0u8; 4096];
        let count = pipe
            .read(&mut bytes[..(available as usize).min(4096)])
            .map_err(|_| Error("windows_feature_output_unavailable"))?;
        if store {
            if count > *budget {
                return Err(Error("windows_feature_output_limit"));
            }
            output.extend_from_slice(&bytes[..count]);
            *budget -= count;
        }
        Ok(count > 0)
    }

    fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Error("windows_feature_servicing_unconfirmed"));
        }
        Ok(())
    }

    pub(super) fn decode_oem(bytes: &[u8]) -> Result<String> {
        let required = unsafe {
            MultiByteToWideChar(
                CP_OEMCP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                bytes.len() as i32,
                null_mut(),
                0,
            )
        };
        if required <= 0 || required as usize > OUTPUT_LIMIT {
            return Err(Error("invalid_windows_feature_output"));
        }
        let mut wide = vec![0u16; required as usize];
        if unsafe {
            MultiByteToWideChar(
                CP_OEMCP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                bytes.len() as i32,
                wide.as_mut_ptr(),
                required,
            )
        } != required
        {
            return Err(Error("invalid_windows_feature_output"));
        }
        String::from_utf16(&wide).map_err(|_| Error("invalid_windows_feature_output"))
    }
}

#[cfg(windows)]
pub use native::prepare;

#[cfg(test)]
mod tests {
    use super::{
        Feature, Hardware, Hcs, Outcome, Reason, decision, parse_feature, supported_build,
    };

    fn output(state: &str) -> String {
        format!(
            "Deployment Image Servicing and Management tool\r\nFeature Name : Microsoft-Hyper-V\r\nState : {state}\r\nThe operation completed successfully.\r\n"
        )
    }
    fn hardware() -> Hardware {
        Hardware {
            firmware: true,
            slat: true,
            dep: true,
        }
    }

    #[test]
    fn installed_windows_build_gate_rejects_windows_10_and_malformed_observations() {
        assert!(!supported_build("19045").unwrap());
        assert!(supported_build("22000").unwrap());
        assert!(supported_build("26100").unwrap());
        for value in [
            "",
            "Windows11",
            "22000junk",
            "22000\0",
            "4294967296",
            " 26100",
        ] {
            assert_eq!(
                supported_build(value).unwrap_err().0,
                "windows_version_unavailable"
            );
        }
    }

    #[test]
    fn blocked_reasons_are_static_human_messages_with_honest_hardware_wording() {
        for reason in [
            Reason::UnsupportedArchitecture,
            Reason::UnsupportedWindowsVersion,
            Reason::UnsupportedEdition,
            Reason::FirmwareUnavailable,
            Reason::SlatUnavailable,
            Reason::DepUnavailable,
            Reason::FeatureUnavailable,
            Reason::HcsUnavailable,
            Reason::HcsSchemaUnsupported,
            Reason::NestedUnavailable,
        ] {
            assert_ne!(reason.to_string(), format!("{reason:?}"));
        }
        assert!(
            Reason::UnsupportedWindowsVersion
                .to_string()
                .contains("Windows 11")
        );
        assert!(
            Reason::NestedUnavailable
                .to_string()
                .contains("controller VM")
        );
        assert!(
            Reason::NestedUnavailable
                .to_string()
                .contains("nested virtualization")
        );
        assert!(
            Reason::FirmwareUnavailable
                .to_string()
                .contains("cannot report")
        );
    }

    #[test]
    fn english_query_states_include_both_pending_directions_and_removed_payload() {
        for (text, expected) in [
            ("Enabled", Feature::Enabled),
            ("Disabled", Feature::Disabled),
            ("Enable Pending", Feature::EnablePending),
            ("Disable Pending", Feature::DisablePending),
            ("Disabled with Payload Removed", Feature::Removed),
        ] {
            assert_eq!(parse_feature(output(text).as_bytes()).unwrap(), expected);
        }
    }

    #[test]
    fn redirected_utf16_with_or_without_bom_and_utf8_bom_have_identical_meaning() {
        let text = output("Enable Pending");
        let encoded = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        for bytes in [
            encoded.clone(),
            [vec![0xff, 0xfe], encoded].concat(),
            [vec![0xef, 0xbb, 0xbf], text.into_bytes()].concat(),
        ] {
            assert_eq!(parse_feature(&bytes).unwrap(), Feature::EnablePending);
        }
    }

    #[test]
    fn ambiguous_unknown_or_invalid_encoding_never_means_disabled_and_leaks_no_peer_text() {
        for bytes in [
            output("PRIVATE_CANARY").into_bytes(),
            output("Enabled")
                .replace("Microsoft-Hyper-V", "Other-Feature")
                .into_bytes(),
            format!("{}State : Disabled\n", output("Enabled")).into_bytes(),
            format!("{}Feature Name : Microsoft-Hyper-V\n", output("Enabled")).into_bytes(),
            b"State : Disabled\n".to_vec(),
            vec![0xff, 0xfe, 0, 0xd8],
            vec![0, b'a', 0],
            vec![0xfe, 0xff, 0, 0x61],
        ] {
            let error = parse_feature(&bytes).unwrap_err();
            assert_eq!(error.0, "invalid_windows_feature_output");
            assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
        }
    }

    #[test]
    fn pending_always_requires_restart_and_disabled_requires_explicit_enable() {
        for feature in [Feature::EnablePending, Feature::DisablePending] {
            assert_eq!(
                decision(feature, hardware(), Hcs::Ready),
                Outcome::RebootRequired
            );
        }
        for feature in [Feature::Disabled, Feature::Removed] {
            assert_eq!(
                decision(feature, hardware(), Hcs::Ready),
                Outcome::EnableRequired
            );
            assert_eq!(
                decision(feature, hardware(), Hcs::Unavailable),
                Outcome::EnableRequired
            );
        }
    }

    #[test]
    fn positive_hcs_overrides_coarse_pf_flags_but_preserves_schema_and_nested_failures() {
        let unavailable = Hardware {
            firmware: false,
            slat: false,
            dep: false,
        };
        assert_eq!(
            decision(Feature::Enabled, unavailable, Hcs::Ready),
            Outcome::Ready
        );
        assert_eq!(
            decision(Feature::Disabled, unavailable, Hcs::Ready),
            Outcome::EnableRequired
        );
        assert_eq!(
            decision(Feature::Enabled, unavailable, Hcs::SchemaUnsupported),
            Outcome::Blocked {
                reason: Reason::HcsSchemaUnsupported
            }
        );
        assert_eq!(
            decision(Feature::Enabled, unavailable, Hcs::NestedUnavailable),
            Outcome::Blocked {
                reason: Reason::NestedUnavailable
            }
        );
        assert_eq!(
            decision(Feature::Enabled, hardware(), Hcs::Unavailable),
            Outcome::Blocked {
                reason: Reason::HcsUnavailable
            }
        );
        assert_eq!(
            decision(Feature::Disabled, unavailable, Hcs::Unavailable),
            Outcome::Blocked {
                reason: Reason::FirmwareUnavailable
            }
        );
        assert_eq!(
            decision(
                Feature::Disabled,
                Hardware {
                    slat: false,
                    ..hardware()
                },
                Hcs::Unavailable
            ),
            Outcome::Blocked {
                reason: Reason::SlatUnavailable
            }
        );
        assert_eq!(
            decision(
                Feature::Disabled,
                Hardware {
                    dep: false,
                    ..hardware()
                },
                Hcs::Unavailable
            ),
            Outcome::Blocked {
                reason: Reason::DepUnavailable
            }
        );
    }
}
