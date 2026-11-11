use oblivion_share::{
    Agent, Entry, Import, Manifest, Package, Policy, Provenance, Safe, SecretString, Source,
    decrypt, encrypt,
};
use oblivion_transfer::{Limits, Selection};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oblivion-share-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        for root in ["workspace", "imports", "history", "home"] {
            std::fs::create_dir(path.join(root)).unwrap();
        }
        std::fs::write(
            path.join("workspace/caffè.txt"),
            "File condiviso, città e perché.\n",
        )
        .unwrap();
        std::fs::write(path.join("workspace/payload.bin"), vec![0xa5; 300_000]).unwrap();
        std::fs::write(path.join("history/chats.jsonl"), "{\"version\":1}\n").unwrap();
        std::fs::write(
            path.join("home/provider.key"),
            "DO-NOT-SHARE-THIS-AUTHENTICATION-FILE",
        )
        .unwrap();
        Self(path)
    }

    fn selection(&self) -> Selection {
        Selection::prepare(
            &self.0,
            &["workspace".into(), "imports".into(), "history".into()],
            Limits {
                entries: 20,
                bytes: 1024 * 1024,
            },
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ReviewedSource {
    payloads: BTreeMap<String, Vec<u8>>,
    completed: Vec<String>,
}

impl Source for ReviewedSource {
    fn open<'a>(&'a mut self, safe: &Safe) -> io::Result<Box<dyn Read + 'a>> {
        Ok(Box::new(Cursor::new(
            self.payloads.get(&safe.id).unwrap().as_slice(),
        )))
    }

    fn complete(&mut self, safe: &Safe, _: &Manifest) -> io::Result<()> {
        self.completed.push(safe.id.clone());
        Ok(())
    }
}

#[derive(Default)]
struct Staging {
    staged: BTreeMap<String, Vec<u8>>,
    aborted: bool,
    began: bool,
}

impl Import for Staging {
    type Writer = Vec<u8>;
    fn begin(&mut self, _: &Package, metadata_sha256: &str) -> io::Result<()> {
        assert_eq!(metadata_sha256.len(), 64);
        self.began = true;
        Ok(())
    }
    fn begin_safe(&mut self, _: &Safe, _: &Manifest) -> io::Result<Self::Writer> {
        Ok(Vec::new())
    }
    fn finish_safe(&mut self, safe: &Safe, data: Self::Writer) -> io::Result<()> {
        self.staged.insert(safe.id.clone(), data);
        Ok(())
    }
    fn abort(&mut self) -> io::Result<()> {
        self.aborted = true;
        self.staged.clear();
        Ok(())
    }
}

fn password() -> SecretString {
    "a separate sharing passphrase 2026".into()
}

fn reviewed(fixture: &Fixture) -> (Package, ReviewedSource) {
    let mut selection = fixture.selection();
    let manifest = selection.manifest();
    let safe = Safe {
        id: "11111111111111111111111111111111".into(),
        title: "Shared research".into(),
        parent: None,
        provenance: Some(Provenance {
            created_by_agent: false,
            requested_agent: None,
            parent_not_included: false,
        }),
        policy: Policy::Offline,
        required_proxy: None,
        contents_sha256: manifest.sha256(),
        entries: manifest.entries().len(),
        bytes: manifest.bytes(),
    };
    let mut child = safe.clone();
    child.id = "22222222222222222222222222222222".into();
    child.parent = Some(safe.id.clone());
    child.provenance = Some(Provenance {
        created_by_agent: true,
        requested_agent: Some(Agent::Codex),
        parent_not_included: false,
    });
    let mut payload = Vec::new();
    selection.manifest().write(&mut payload).unwrap();
    selection.send_data(&mut payload).unwrap();
    let source = ReviewedSource {
        payloads: [
            (safe.id.clone(), payload.clone()),
            (child.id.clone(), payload),
        ]
        .into(),
        completed: vec![],
    };
    (
        Package {
            format: "oblivion-share".into(),
            version: 1,
            id: "33333333333333333333333333333333".into(),
            safes: vec![safe, child],
            settings: None,
        },
        source,
    )
}

#[test]
fn encrypted_share_authenticates_all_safes_before_returning_publication_proof() {
    let fixture = Fixture::new();
    let (package, mut source) = reviewed(&fixture);
    let mut ciphertext = Vec::new();
    encrypt(&mut ciphertext, password(), &package, &mut source).unwrap();
    assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !ciphertext
            .windows(15)
            .any(|bytes| bytes == b"Shared research")
    );
    assert!(
        !ciphertext
            .windows(16)
            .any(|bytes| bytes == b"DO-NOT-SHARE-THI")
    );
    assert_eq!(source.completed.len(), 2);
    let mut target = Staging::default();
    let verified = decrypt(Cursor::new(&ciphertext), password(), &mut target).unwrap();
    assert_eq!(verified.package(), &package);
    assert_eq!(
        verified.bytes(),
        package.safes.iter().map(|safe| safe.bytes).sum::<u64>()
    );
    assert_eq!(verified.package_sha256().len(), 64);
    assert!(target.began && !target.aborted);
    assert_eq!(target.staged.len(), 2);

    // The final AEAD chunk is required even after earlier Safes were staged.
    let mut target = Staging::default();
    assert!(
        decrypt(
            Cursor::new(&ciphertext[..ciphertext.len() - 1]),
            password(),
            &mut target
        )
        .is_err()
    );
    assert!(target.aborted && target.staged.is_empty());
    let mut altered = ciphertext.clone();
    *altered.last_mut().unwrap() ^= 1;
    let mut target = Staging::default();
    assert!(decrypt(Cursor::new(altered), password(), &mut target).is_err());
    assert!(target.aborted && target.staged.is_empty());
    // A valid first container must not hide bytes appended to the age stream.
    let mut trailing = ciphertext.clone();
    trailing.extend_from_slice(b"unapproved trailing data");
    let mut target = Staging::default();
    assert!(decrypt(Cursor::new(trailing), password(), &mut target).is_err());
    assert!(target.aborted && target.staged.is_empty());
    let mut target = Staging::default();
    assert!(
        decrypt(
            Cursor::new(&ciphertext),
            "a different sharing passphrase".into(),
            &mut target
        )
        .is_err()
    );
    assert!(!target.began && target.aborted);
}

#[test]
fn review_is_bound_to_manifest_and_only_portable_roots_are_admitted() {
    let fixture = Fixture::new();
    let (mut package, _) = reviewed(&fixture);
    package.safes[0].parent = Some(package.safes[1].id.clone());
    assert_eq!(
        package.validate().unwrap_err().to_string(),
        "share_parent_cycle"
    );
    package.safes[0].parent = None;
    package.safes[0].required_proxy = Some("office".into());
    package.validate().unwrap();
    for root in ["home", "state", "config", "system", "history/native"] {
        let mut entries = vec![Entry::Directory {
            path: root.split('/').next().unwrap().into(),
        }];
        if root.contains('/') {
            entries.push(Entry::Directory { path: root.into() });
        }
        entries.push(Entry::File {
            path: format!("{root}/auth.json"),
            size: 0,
            sha256: format!("{:x}", Sha256::digest([])),
        });
        let manifest = Manifest::new(
            entries,
            Limits {
                entries: 3,
                bytes: 0,
            },
        )
        .unwrap();
        let mut safe = package.safes[0].clone();
        safe.contents_sha256 = manifest.sha256();
        safe.entries = manifest.entries().len();
        safe.bytes = manifest.bytes();
        assert!(oblivion_share::manifest::validate_contents(&manifest, &safe).is_err());
    }
    let manifest = fixture.selection();
    package.safes[0].contents_sha256 = "0".repeat(64);
    assert_eq!(
        oblivion_share::manifest::validate_contents(manifest.manifest(), &package.safes[0])
            .unwrap_err()
            .to_string(),
        "share_contents_changed"
    );
}
