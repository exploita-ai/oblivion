use oblivion_host::tor_profile::{self, Purpose};
use oblivion_tor_state::State;
use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Profile(PathBuf);

impl Profile {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oblivion-tor-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn state(id: char) -> State {
    State::parse(&format!("Guard in=default rsa_id={} sampled_on=2026-10-28T12:00:00 sampled_idx=0 listed=1\nTorVersion Tor {}\nLastWritten 2026-10-28 12:00:00\n", id.to_string().repeat(40), oblivion_tor_state::VERSION)).unwrap()
}

fn private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
fn existing_model_state_loads_without_transfer_fallback_or_transport_changes() {
    let profile = Profile::new();
    let model = state('A');
    let transfer = state('B');
    let transport = oblivion_host::egress::Profile::new(oblivion_transport::Transport::Socks5 {
        endpoint: "192.168.1.20:1080".parse().unwrap(),
        authentication: Some(oblivion_transport::Authentication {
            username: zeroize::Zeroizing::new("synthetic-proxy-user".into()),
            password: zeroize::Zeroizing::new("synthetic-proxy-password".into()),
        }),
    })
    .unwrap()
    .encode()
    .unwrap();
    private(&profile.0.join("tor-state"), model.as_str().as_bytes());
    private(&profile.0.join("transport.json"), &transport);
    private(
        &profile.0.join("provider.keys.json"),
        b"synthetic unchanged key archive",
    );
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Model)
            .unwrap()
            .as_ref(),
        Some(&model)
    );
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer).unwrap(),
        None
    );
    tor_profile::save(&profile.0, Purpose::Transfer, &transfer).unwrap();
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer)
            .unwrap()
            .as_ref(),
        Some(&transfer)
    );
    assert_eq!(
        fs::read(profile.0.join("tor-state")).unwrap(),
        model.as_str().as_bytes()
    );
    assert_eq!(
        fs::read(profile.0.join("transport.json")).unwrap(),
        transport.as_slice()
    );
    assert_eq!(
        fs::read(profile.0.join("provider.keys.json")).unwrap(),
        b"synthetic unchanged key archive"
    );
    tor_profile::save(&profile.0, Purpose::Model, &state('C')).unwrap();
    assert_eq!(
        fs::read(profile.0.join("onion-tor-state")).unwrap(),
        transfer.as_str().as_bytes()
    );
}

#[test]
fn private_pending_writes_are_replaced_and_final_files_stay_private() {
    let profile = Profile::new();
    private(
        &profile.0.join("onion-tor-state.pending"),
        b"interrupted selective write",
    );
    tor_profile::save(&profile.0, Purpose::Transfer, &state('A')).unwrap();
    assert!(!profile.0.join("onion-tor-state.pending").exists());
    let metadata = fs::metadata(profile.0.join("onion-tor-state")).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(fs::read_dir(&profile.0).unwrap().count(), 1);
    tor_profile::save(&profile.0, Purpose::Transfer, &state('B')).unwrap();
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer)
            .unwrap()
            .unwrap(),
        state('B')
    );
}

#[test]
fn final_symlinks_and_hardlinks_never_disclose_or_overwrite_another_profile() {
    for hardlink in [false, true] {
        let profile = Profile::new();
        let target = profile.0.join("provider.keys.json");
        let alias = profile.0.join("onion-tor-state");
        private(&target, b"synthetic secret archive");
        if hardlink {
            fs::hard_link(&target, &alias).unwrap();
        }
        if !hardlink {
            symlink(&target, &alias).unwrap();
        }
        assert!(tor_profile::load(&profile.0, Purpose::Transfer).is_err());
        assert!(tor_profile::save(&profile.0, Purpose::Transfer, &state('A')).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"synthetic secret archive");
        assert!(!profile.0.join("onion-tor-state.pending").exists());
    }
}

#[test]
fn unsafe_pending_links_are_preserved_and_do_not_replace_saved_state() {
    let profile = Profile::new();
    let original = state('A');
    private(
        &profile.0.join("onion-tor-state"),
        original.as_str().as_bytes(),
    );
    let target = profile.0.join("other-private-file");
    private(&target, b"preserve pending target");
    let pending = profile.0.join("onion-tor-state.pending");
    symlink(&target, &pending).unwrap();
    assert!(tor_profile::save(&profile.0, Purpose::Transfer, &state('B')).is_err());
    assert!(
        fs::symlink_metadata(&pending)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&target).unwrap(), b"preserve pending target");
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer)
            .unwrap()
            .unwrap(),
        original
    );
}

#[test]
fn oversized_nonselective_and_wrong_version_state_are_rejected_without_mutation() {
    for content in [
        "x".repeat(oblivion_tor_state::LIMIT + 1),
        format!(
            "{}OnionServicePrivateKey synthetic-disallowed-key\n",
            state('A').as_str()
        ),
        format!("{}BWHistoryReadValues 123\n", state('A').as_str()),
        "TorVersion Tor 0.0.0\nLastWritten 2026-10-28 12:00:00\n".into(),
    ] {
        let profile = Profile::new();
        private(&profile.0.join("onion-tor-state"), content.as_bytes());
        assert_eq!(
            tor_profile::load(&profile.0, Purpose::Transfer).unwrap_err(),
            "invalid_tor_state"
        );
        assert_eq!(
            fs::read(profile.0.join("onion-tor-state")).unwrap(),
            content.as_bytes()
        );
    }
}

#[test]
fn public_or_symlinked_profile_directories_are_refused() {
    let profile = Profile::new();
    fs::set_permissions(&profile.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer).unwrap_err(),
        "unsafe_profile"
    );
    assert!(tor_profile::save(&profile.0, Purpose::Transfer, &state('A')).is_err());
    fs::set_permissions(&profile.0, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = profile.0.join("alias");
    symlink(&profile.0, &alias).unwrap();
    assert!(tor_profile::load(&alias, Purpose::Transfer).is_err());
    assert!(tor_profile::save(&alias, Purpose::Transfer, &state('A')).is_err());
    assert_eq!(fs::read_dir(&profile.0).unwrap().count(), 1);
}

#[test]
fn nonregular_state_is_refused_without_waiting_for_a_fifo_writer() {
    let profile = Profile::new();
    let path = std::ffi::CString::new(
        profile
            .0
            .join("onion-tor-state")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert_eq!(
        tor_profile::load(&profile.0, Purpose::Transfer).unwrap_err(),
        "unsafe_file"
    );
    assert!(tor_profile::save(&profile.0, Purpose::Transfer, &state('A')).is_err());
}
