use crate::{Entry, Limits, Manifest};
use std::io::Cursor;

const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LIMITS: Limits = Limits { entries: 64, bytes: 1024 * 1024 };

fn empty(path: &str) -> Entry {
    Entry::File {
        path: path.into(),
        size: 0,
        sha256: EMPTY.into(),
    }
}

#[test]
fn hostile_paths_and_tree_conflicts_are_rejected_before_receiving() {
    for path in [
        "",
        "/absolute",
        "../outside",
        "a/../b",
        "./a",
        "a//b",
        "a/",
        "a\\b",
        "a\0b",
        "a\nb",
        "\x1b[2J",
        "a\u{202e}b",
    ] {
        assert!(
            Manifest::new(vec![empty(path)], LIMITS).is_err(),
            "{path:?}"
        );
    }
    for entries in [
        vec![empty("a"), empty("a")],
        vec![empty("a/b")],
        vec![empty("a"), empty("a/b")],
        vec![empty("a"), Entry::Directory { path: "a".into() }],
    ] {
        assert!(Manifest::new(entries, LIMITS).is_err());
    }
    assert!(Manifest::new(vec![empty(&"x".repeat(256))], LIMITS).is_err());
    assert!(Manifest::new(vec![empty(&vec!["a"; 33].join("/"))], LIMITS).is_err());
}

#[test]
fn manifest_limits_and_numeric_overflow_cannot_allocate_a_destination() {
    assert!(Manifest::new(vec![], LIMITS).is_err());
    assert!(
        Manifest::new(
            vec![empty("a"), empty("b")],
            Limits {
                entries: 1,
                bytes: 0
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![Entry::File {
                path: "a".into(),
                size: 2,
                sha256: EMPTY.into()
            }],
            Limits {
                entries: 1,
                bytes: 1
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![
                Entry::File {
                    path: "a".into(),
                    size: u64::MAX,
                    sha256: EMPTY.into()
                },
                Entry::File {
                    path: "b".into(),
                    size: 1,
                    sha256: EMPTY.into()
                }
            ],
            Limits {
                entries: 2,
                bytes: u64::MAX
            }
        )
        .is_err()
    );
    assert!(
        Manifest::new(
            vec![Entry::File {
                path: "a".into(),
                size: 0,
                sha256: "not-a-hash".into()
            }],
            LIMITS
        )
        .is_err()
    );
    let mut oversize = b"OBLVCP01".to_vec();
    oversize.extend(u32::MAX.to_be_bytes());
    assert_eq!(
        Manifest::read(&mut Cursor::new(oversize), LIMITS)
            .err()
            .unwrap()
            .to_string(),
        "header_limit"
    );
}

#[test]
fn protocol_rejects_unknown_fields_version_truncated_or_malformed_headers() {
    for json in [
        r#"[{"kind":"directory","path":"a","mode":511}]"#,
        r#"[{"kind":"symlink","path":"a","target":"/etc"}]"#,
        r#"{}"#,
        "[",
    ] {
        let mut wire = b"OBLVCP01".to_vec();
        wire.extend((json.len() as u32).to_be_bytes());
        wire.extend(json.as_bytes());
        assert!(Manifest::read(&mut Cursor::new(wire), LIMITS).is_err());
    }
    for wire in [
        b"OBLVCP02".to_vec(),
        b"OBLV".to_vec(),
        b"OBLVCP01\0\0\0\x10[]".to_vec(),
    ] {
        assert!(Manifest::read(&mut Cursor::new(wire), LIMITS).is_err());
    }
}

#[test]
fn portable_scope_rejects_credentials_and_native_state_on_both_sides() {
    for path in ["home", "workspace/.ssh", "workspace/.oblivion-jobs", "workspace/auth.json", "history/history.sqlite", "history/source-chunks", "state"] {
        let mut entries = Vec::new();
        let mut prefix = String::new();
        for part in path.split('/') {
            if !prefix.is_empty() { prefix.push('/'); }
            prefix.push_str(part);
            entries.push(Entry::Directory { path: prefix.clone() });
        }
        let manifest = Manifest::new(entries, LIMITS).unwrap();
        assert!(crate::share::validate_manifest(&manifest).is_err(), "{path}");
    }
}

#[test]
fn manifest_and_payload_keep_the_same_verified_wire_bytes() {
    let manifest = Manifest::new(vec![Entry::File {
        path: "città.txt".into(),
        size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    }], LIMITS).unwrap();
    let mut header = Vec::new();
    manifest.write(&mut header).unwrap();
    let decoded = Manifest::read(&mut Cursor::new(header), LIMITS).unwrap();
    assert_eq!(decoded.sha256(), manifest.sha256());
    assert_eq!(decoded.bytes(), 3);
    assert_eq!(decoded.entries()[0].path(), "città.txt");

    let mut forwarded = Vec::new();
    crate::relay_payload(&mut Cursor::new(b"abcOBLVEND1"), &mut forwarded, &decoded).unwrap();
    assert_eq!(forwarded, b"abcOBLVEND1");
    for bytes in [b"abdOBLVEND1".as_slice(), b"abcOBLVEND2", b"ab", b"abc"] {
        let mut forwarded = Vec::new();
        assert!(crate::relay_payload(&mut Cursor::new(bytes), &mut forwarded, &decoded).is_err());
        assert!(!forwarded.ends_with(b"OBLVEND1"));
    }
}

#[test]
fn control_messages_remain_bounded_and_preserve_literal_paths() {
    let offer = crate::endpoint::OfferRequest {
        id: "0123456789abcdef0123456789abcdef".into(),
        limits: LIMITS,
        paths: vec!["workspace/città $file.txt".into()],
    };
    let mut bytes = Vec::new();
    crate::endpoint::write_message(&mut bytes, &offer).unwrap();
    let decoded: crate::endpoint::OfferRequest = crate::endpoint::read_message(&mut Cursor::new(&bytes), 4096).unwrap();
    assert_eq!(decoded.id, offer.id);
    assert_eq!(decoded.paths, offer.paths);
    assert!(crate::endpoint::read_message::<crate::endpoint::OfferRequest>(&mut Cursor::new(&bytes), 1).is_err());
    assert!(crate::endpoint::read_message::<crate::endpoint::OfferRequest>(&mut Cursor::new(u32::MAX.to_be_bytes()), 4096).is_err());

    let json = br#"{"id":"0123456789abcdef0123456789abcdef","limits":{"entries":1,"bytes":0},"paths":["workspace"],"execute":"no"}"#;
    let mut unknown = (json.len() as u32).to_be_bytes().to_vec();
    unknown.extend(json);
    assert!(crate::endpoint::read_message::<crate::endpoint::OfferRequest>(&mut Cursor::new(unknown), 4096).is_err());
}

#[test]
fn directory_pages_are_validated_without_accessing_a_filesystem() {
    let request = crate::browser::Request { path: "workspace".into(), after: Some("a".into()), limit: 2 };
    request.validate().unwrap();
    let page = crate::browser::Page {
        path: request.path.clone(),
        entries: vec![crate::browser::Entry { name: "città".into(), directory: true, bytes: 0 }],
        next: Some("città".into()),
        skipped: 0,
    };
    page.validate(&request).unwrap();
    assert!(page.validate(&crate::browser::Request { path: "imports".into(), ..request }).is_err());
    for name in ["../outside", "a/b", "a", "x\u{202e}y"] {
        let page = crate::browser::Page {
            path: "workspace".into(),
            entries: vec![crate::browser::Entry { name: name.into(), directory: false, bytes: 0 }],
            next: None,
            skipped: 0,
        };
        assert!(page.validate(&crate::browser::Request { path: "workspace".into(), after: Some("a".into()), limit: 2 }).is_err());
    }
}

