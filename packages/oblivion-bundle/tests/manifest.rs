use oblivion_bundle::{Channel, File, MAX_MANIFEST, Manifest, relative, target};
use serde_json::{Value, json};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WINDOWS: &str = "windows-x86_64";
const GOLDEN: &[u8] = include_bytes!("fixtures/windows-v2.json");
fn fixture() -> Manifest {
    Manifest::decode(GOLDEN, Some(SOURCE), WINDOWS).unwrap()
}
fn refresh(manifest: &mut Manifest) {
    manifest.bundle_id = manifest.identity().unwrap();
}
fn add(manifest: &mut Manifest, path: &str) {
    manifest.files.push(File {
        path: path.into(),
        sha256: "b".repeat(64),
        bytes: 1,
        executable: false,
    });
    manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
    refresh(manifest);
}
fn validate(manifest: &Manifest) -> Result<Manifest, &'static str> {
    Manifest::decode(
        &serde_json::to_vec(manifest).unwrap(),
        Some(SOURCE),
        &manifest.platform,
    )
}

#[test]
fn current_v2_canonical_identity_matches_the_python_json_contract() {
    let manifest = fixture();
    assert_eq!(
        manifest.bundle_id,
        "7b76285774381bc9014f62361172212054f656f950c559179eaa1fa9957b693d"
    );
    assert_eq!(manifest.identity().unwrap(), manifest.bundle_id);
    assert_eq!(
        serde_json::from_slice::<Value>(GOLDEN).unwrap(),
        serde_json::to_value(&manifest).unwrap()
    );
    manifest.binding().unwrap().validate().unwrap();
}

#[test]
fn each_channel_requires_its_canonical_product_version() {
    for (channel, version) in [
        (Channel::Dev, "1.0.0~dev1.abcdef012345"),
        (Channel::Dev, "0.0.0~dev12.0123456789ab"),
        (Channel::Rc, "1.0.0~rc1"),
        (Channel::Rc, "10.20.30~rc123"),
        (Channel::Stable, "1.0.0"),
        (Channel::Stable, "0.0.0"),
    ] {
        let mut manifest = fixture();
        manifest.product_version = version.into();
        for candidate in [Channel::Dev, Channel::Rc, Channel::Stable] {
            manifest.channel = candidate;
            refresh(&mut manifest);
            assert_eq!(
                validate(&manifest).is_ok(),
                candidate == channel,
                "{candidate:?}: {version}"
            );
        }
    }
}

#[test]
fn malformed_versions_are_rejected_even_with_a_matching_identity() {
    for (channel, versions) in [
        (
            Channel::Stable,
            &[
                "",
                "1",
                "1.0",
                "1.0.0.0",
                ".0.0",
                "1..0",
                "1.0.",
                "01.0.0",
                "1.00.0",
                "1.0.01",
                "-1.0.0",
                "+1.0.0",
                "1e1.0.0",
                "1:1.0.0",
                "1.0.0+build",
                "1.0.0-rc1",
                "1.0.0\n",
                "1.0.0 ",
                "١.0.0",
            ][..],
        ),
        (
            Channel::Rc,
            &[
                "1.0.0~rc",
                "1.0.0~rc0",
                "1.0.0~rc01",
                "1.0.0~rc-1",
                "1.0.0~rc+1",
                "1.0.0~rc1.0",
                "1.0.0~RC1",
                "1.0.0~rc1~rc2",
                "01.0.0~rc1",
                "1.0.0~rc١",
            ][..],
        ),
        (
            Channel::Dev,
            &[
                "1.0.0~dev-fixture",
                "1.0.0~dev1",
                "1.0.0~dev.abcdef012345",
                "1.0.0~dev0.abcdef012345",
                "1.0.0~dev01.abcdef012345",
                "1.0.0~dev-1.abcdef012345",
                "1.0.0~dev+1.abcdef012345",
                "1.0.0~dev1.abcdef01234",
                "1.0.0~dev1.abcdef0123456",
                "1.0.0~dev1.ABCDEF012345",
                "1.0.0~dev1.ghijkl012345",
                "1.0.0~dev1.abcdef012345.extra",
                "1.0.0~DEV1.abcdef012345",
                "1.0.00~dev1.abcdef012345",
                "1.0.0~dev١.abcdef012345",
            ][..],
        ),
    ] {
        for version in versions {
            let mut manifest = fixture();
            manifest.channel = channel;
            manifest.product_version = (*version).into();
            refresh(&mut manifest);
            assert_eq!(
                validate(&manifest).err(),
                Some("desktop_bundle_does_not_match_this_build"),
                "{channel:?}: {version:?}"
            );
        }
    }
}

#[test]
fn the_version_limit_is_64_ascii_bytes_for_every_channel() {
    for (channel, suffix) in [
        (Channel::Dev, ".0.0~dev1.abcdef012345"),
        (Channel::Rc, ".0.0~rc1"),
        (Channel::Stable, ".0.0"),
    ] {
        let mut manifest = fixture();
        manifest.channel = channel;
        manifest.product_version = format!("{}{suffix}", "1".repeat(64 - suffix.len()));
        refresh(&mut manifest);
        validate(&manifest).unwrap();
        manifest.product_version.insert(0, '1');
        refresh(&mut manifest);
        assert!(validate(&manifest).is_err());
    }
}

#[test]
fn channel_is_required_exact_and_part_of_the_canonical_identity() {
    let mut value: Value = serde_json::from_slice(GOLDEN).unwrap();
    value.as_object_mut().unwrap().remove("channel");
    assert_eq!(
        Manifest::decode(&serde_json::to_vec(&value).unwrap(), Some(SOURCE), WINDOWS).err(),
        Some("invalid_desktop_bundle")
    );
    for channel in [
        json!("beta"),
        json!("DEV"),
        json!("development"),
        json!(null),
        json!(1),
        json!({"dev": null}),
        json!(["dev"]),
    ] {
        value["channel"] = channel;
        assert_eq!(
            Manifest::decode(&serde_json::to_vec(&value).unwrap(), Some(SOURCE), WINDOWS).err(),
            Some("invalid_desktop_bundle")
        );
    }
    let mut manifest = fixture();
    manifest.channel = Channel::Stable;
    assert_ne!(manifest.identity().unwrap(), manifest.bundle_id);
    manifest.product_version = "1.0.0".into();
    assert!(validate(&manifest).is_err());
    refresh(&mut manifest);
    validate(&manifest).unwrap();
    manifest.product_version = "1.0.1".into();
    assert!(validate(&manifest).is_err());
}

#[test]
fn prior_manifest_versions_and_the_removed_development_field_are_rejected() {
    let mut manifest = fixture();
    manifest.version = 1;
    refresh(&mut manifest);
    assert_eq!(
        validate(&manifest).err(),
        Some("desktop_bundle_does_not_match_this_build")
    );
    let mut value: Value = serde_json::from_slice(GOLDEN).unwrap();
    value["development_only"] = json!(true);
    assert_eq!(
        Manifest::decode(&serde_json::to_vec(&value).unwrap(), Some(SOURCE), WINDOWS).err(),
        Some("invalid_desktop_bundle")
    );
    value["version"] = json!(1);
    value.as_object_mut().unwrap().remove("channel");
    assert_eq!(
        Manifest::decode(&serde_json::to_vec(&value).unwrap(), Some(SOURCE), WINDOWS).err(),
        Some("invalid_desktop_bundle")
    );
}

#[test]
fn the_same_schema_covers_every_current_platform_with_exact_native_artifacts() {
    for platform in ["darwin-arm64", "linux-x86_64", "linux-arm64", WINDOWS] {
        let selected = target(platform).unwrap();
        let mut manifest = fixture();
        manifest.platform = platform.into();
        manifest.backend = selected.backend.into();
        manifest.files = selected
            .binaries
            .into_iter()
            .chain([
                selected.native_library,
                "runtime/controller.iso",
                "runtime/kernel",
                "runtime/initrd",
            ])
            .map(|path| File {
                path: path.into(),
                sha256: "b".repeat(64),
                bytes: 1,
                executable: path.starts_with("bin/"),
            })
            .collect();
        manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
        refresh(&mut manifest);
        validate(&manifest).unwrap();
    }
    assert!(target("windows-arm64").is_err());
    let mut wrong = fixture();
    wrong.backend = "qemu-kvm".into();
    refresh(&mut wrong);
    assert!(validate(&wrong).is_err());
    assert!(Manifest::decode(GOLDEN, Some(&"c".repeat(64)), WINDOWS).is_err());
}

#[test]
fn portable_names_refuse_drive_ads_devices_and_reserved_manifest_aliases() {
    for path in [
        "C:/outside",
        "C:outside",
        "a/file:stream",
        "/outside",
        "a\\b",
        "../outside",
        "a/./b",
        "a//b",
        "bundle.json",
        "BUNDLE.JSON",
        "CON",
        "a/con.txt",
        "a/COM1.log",
        "a/lpt9",
        "a/prn",
        "a/nul.txt",
        "a/con .txt",
        "a/file.",
        "a/file ",
        "a/file?",
        "a/file*",
        "a/<file>",
        "a/\u{1b}file",
        "a/\u{7f}file",
        "a/é",
    ] {
        assert!(!relative(path), "{path:?}");
    }
    for path in [
        "lib/manager/@opentui/core-win32-x64/opentui.dll",
        ".meta/file",
        "docs/file name.md",
        "a/COM10.txt",
    ] {
        assert!(relative(path));
    }
    assert!(!relative(&"a".repeat(513)));
}

#[test]
fn windows_rejects_case_aliases_of_leaves_and_ancestors_and_file_directory_collisions() {
    for (first, second) in [
        ("extras/A", "extras/a"),
        ("extras/A/one", "extras/a/two"),
        ("extras/file", "extras/file/child"),
    ] {
        let mut manifest = fixture();
        add(&mut manifest, first);
        add(&mut manifest, second);
        assert_eq!(
            validate(&manifest).err(),
            Some("invalid_desktop_bundle_inventory")
        );
    }
    let mut manifest = fixture();
    add(&mut manifest, "extras/a");
    add(&mut manifest, "extras/A/child");
    assert!(validate(&manifest).is_err());
}

#[test]
fn missing_mutated_unsorted_and_untrusted_metadata_never_become_a_valid_bundle() {
    let mut manifest = fixture();
    manifest
        .files
        .retain(|file| file.path != "bin/oblivion.exe");
    refresh(&mut manifest);
    assert_eq!(
        validate(&manifest).err(),
        Some("desktop_bundle_file_missing")
    );
    let mut manifest = fixture();
    manifest.files[0].bytes = 0;
    refresh(&mut manifest);
    assert!(validate(&manifest).is_err());
    let mut manifest = fixture();
    manifest.files[0].executable = false;
    refresh(&mut manifest);
    assert!(validate(&manifest).is_err());
    let mut manifest = fixture();
    manifest.files.swap(0, 1);
    refresh(&mut manifest);
    assert!(validate(&manifest).is_err());
    let mut manifest = fixture();
    manifest.files[0].sha256 = "PRIVATE_CANARY".into();
    refresh(&mut manifest);
    let error = validate(&manifest).err().unwrap();
    assert!(!error.contains("CANARY"));
    let mut manifest = fixture();
    manifest.files[0].bytes += 1;
    assert!(validate(&manifest).is_err());
    let mut value: Value = serde_json::from_slice(GOLDEN).unwrap();
    value["arbitrary_command"] = json!("PRIVATE_CANARY");
    assert_eq!(
        Manifest::decode(&serde_json::to_vec(&value).unwrap(), Some(SOURCE), WINDOWS).err(),
        Some("invalid_desktop_bundle")
    );
    assert_eq!(
        Manifest::decode(&vec![b' '; MAX_MANIFEST + 1], None, WINDOWS).err(),
        Some("desktop_bundle_manifest_limit")
    );
}

#[test]
fn binding_keeps_only_the_exact_nonexecutable_boot_inventory() {
    let mut binding = fixture().binding().unwrap();
    binding.boot[0].path = "elsewhere.iso".into();
    assert!(binding.validate().is_err());
    let mut binding = fixture().binding().unwrap();
    binding.boot[1].executable = true;
    assert!(binding.validate().is_err());
    let mut binding = fixture().binding().unwrap();
    binding.boot[2].bytes = 0;
    assert!(binding.validate().is_err());
    let mut binding = fixture().binding().unwrap();
    binding.source_sha256 = "PRIVATE_CANARY".into();
    assert_eq!(
        binding.validate().err(),
        Some("invalid_runtime_bundle_binding")
    );
}
