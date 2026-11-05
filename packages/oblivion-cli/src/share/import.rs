//! One authenticated Share import and publication workflow for native platforms.
//! Decryption streams directly into new offline Safes; only Verified can commit.
use super::io::{Attachment, Native};
use super::{as_io, random_id, share_password, writable_state};
use crate::controller::{Call, Result};
use oblivion_share::{Import, Manifest, Package, Safe, Verified, control};
use oblivion_transfer::Receipt;
use oblivion_transfer::endpoint::{read_message, write_message};
use oblivion_transfer::local_file::Input;
use oblivion_wire::control::Operation;
use oblivion_wire::idle::{Opening, Preferences};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn run<R: Native>(
    runtime: &mut R,
    path: &str,
    settings: bool,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32>
where
    R::Slot: Default + Serialize,
{
    let input = Input::open(Path::new(path))?;
    let state = writable_state(runtime)?;
    if state.recovery_required {
        return Err("Complete recovery before importing Share".into());
    }
    let password = share_password(runtime.password("Share password")?)?;
    let mut target = Target {
        runtime,
        diagnostics,
        transaction: None,
        password: None,
        metadata_sha256: String::new(),
        apply_settings: settings,
        existing: state.sessions.into_iter().collect(),
    };
    let verified = match oblivion_share::decrypt(input, password, &mut target) {
        Ok(verified) => verified,
        Err(error) if error.to_string() == "share_cancelled" => return Ok(130),
        Err(error) => return Err(error.into()),
    };
    target.commit(&verified)?;
    let transaction = target
        .transaction
        .as_ref()
        .ok_or("Import transaction missing")?;
    writeln!(
        target.diagnostics,
        "Share imported. New Safes remain offline and need your own provider login."
    )?;
    for destination in &transaction.destinations {
        writeln!(output, "{:?} · {}", destination.title, destination.safe_id)?;
    }
    if settings {
        if let Some(settings) = &verified.package().settings {
            let preferences = Preferences {
                version: 1,
                safe_minutes: settings.safe_idle_minutes,
                host_minutes: settings.host_idle_minutes,
            };
            if let Err(error) = target.runtime.request(Call {
                operation: Operation::IdleSettings,
                slot: Some(Default::default()),
                session: None,
                expected_session: None,
                secret: &serde_json::to_vec(&preferences)?,
            }) {
                writeln!(
                    target.diagnostics,
                    "Safes are already imported. Shared automatic-lock settings were not applied: {error}. Do not import the package again; change Settings instead."
                )?;
                return Ok(2);
            }
        }
    }
    Ok(0)
}

pub(super) fn status<R: Native>(runtime: &mut R, json: bool, output: &mut impl Write) -> Result<i32>
where
    R::Slot: Default + Serialize,
{
    writable_state(runtime)?;
    let statuses = statuses(runtime)?;
    if json {
        writeln!(output, "{}", serde_json::to_string(&statuses)?)?;
        return Ok(0);
    }
    for state in statuses {
        oblivion_share::manifest::validate_id(&state.transaction)?;
        writeln!(
            output,
            "{}\t{}\t{}/{} Safes ready",
            state.transaction,
            match state.outcome {
                control::Outcome::Pending => "Pending — not published",
                control::Outcome::Committed => "Imported",
                control::Outcome::RecoveryRequired => "Recovery required",
            },
            state.ready,
            state.safes
        )?;
    }
    Ok(0)
}

pub(super) fn discard<R: Native>(
    runtime: &mut R,
    transaction: &str,
    diagnostics: &mut impl Write,
) -> Result<i32>
where
    R::Slot: Default,
{
    writable_state(runtime)?;
    oblivion_share::manifest::validate_id(transaction)?;
    writeln!(
        diagnostics,
        "Discard incomplete import {transaction}. Existing Safes and committed imports cannot be removed by this action."
    )?;
    if !runtime.confirm("DISCARD")? {
        return Ok(130);
    }
    runtime.request(Call {
        operation: Operation::ShareImportDiscard,
        slot: Some(Default::default()),
        session: None,
        expected_session: None,
        secret: &serde_json::to_vec(&control::Discard {
            transaction: transaction.into(),
        })?,
    })?;
    writeln!(diagnostics, "Incomplete import removed.")?;
    Ok(0)
}

fn statuses<R: Native>(runtime: &mut R) -> Result<Vec<control::Status<R::Slot>>>
where
    R::Slot: Default,
{
    let response = runtime.request(Call {
        operation: Operation::ShareImportStatus,
        slot: Some(Default::default()),
        session: None,
        expected_session: None,
        secret: &[],
    })?;
    serde_json::from_str(&response).map_err(|_| "invalid_share_import_status".into())
}

struct Target<'a, R: Native, W: Write> {
    runtime: &'a mut R,
    diagnostics: &'a mut W,
    transaction: Option<control::Begun>,
    password: Option<Zeroizing<String>>,
    metadata_sha256: String,
    apply_settings: bool,
    existing: BTreeSet<String>,
}

struct GuestWriter<A: Attachment, S> {
    attachment: A,
    opening: Opening<S>,
    package_id: String,
    expected: Receipt,
}
impl<A: Attachment, S> Write for GuestWriter<A, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.attachment.stream().write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.attachment.stream().flush()
    }
}
impl<A: Attachment, S> Drop for GuestWriter<A, S> {
    fn drop(&mut self) {
        let _ = self.attachment.close();
    }
}

impl<R: Native, W: Write> Import for Target<'_, R, W>
where
    R::Slot: Default + Serialize,
{
    type Writer = GuestWriter<R::Attachment, R::Slot>;

    fn begin(&mut self, package: &Package, metadata_sha256: &str) -> io::Result<()> {
        let result = (|| -> Result<()> {
            let response = self.runtime.request(Call {
                operation: Operation::ShareImportBegin,
                slot: Some(Default::default()),
                session: None,
                expected_session: None,
                secret: &serde_json::to_vec(&control::Begin {
                    package: package.clone(),
                    metadata_sha256: metadata_sha256.into(),
                })?,
            })?;
            let begun: control::Begun =
                serde_json::from_str(&response).map_err(|_| "invalid_share_import_preparation")?;
            self.metadata_sha256 = metadata_sha256.into();
            self.transaction = Some(begun);
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            validate_destinations(package, transaction, &self.existing)?;
            writeln!(
                self.diagnostics,
                "Import {} Safes into new encrypted volumes. Verification must finish before they become visible.",
                package.safes.len()
            )?;
            for safe in &package.safes {
                let destination = transaction
                    .destinations
                    .iter()
                    .find(|entry| entry.package_id == safe.id)
                    .ok_or("Import destination missing")?;
                writeln!(
                    self.diagnostics,
                    "  {:?} · {} MiB · Offline",
                    destination.title, destination.mib
                )?;
                if destination.title != safe.title {
                    writeln!(
                        self.diagnostics,
                        "    Source title: {:?} · renamed to avoid a conflict",
                        safe.title
                    )?;
                }
                if let Some(proxy) = &safe.required_proxy {
                    writeln!(
                        self.diagnostics,
                        "    Source used {proxy:?}; configure your own transport before going online."
                    )?;
                }
            }
            writeln!(
                self.diagnostics,
                "Provider profiles, source passwords and installed OS overlays are not imported. Files and conversations can still contain secrets supplied by the sender."
            )?;
            if self.apply_settings {
                if let Some(settings) = &package.settings {
                    writeln!(
                        self.diagnostics,
                        "Shared automatic lock: Safe {} minutes, Oblivion {} minutes (0 means disabled).",
                        settings.safe_idle_minutes, settings.host_idle_minutes
                    )?;
                } else {
                    writeln!(
                        self.diagnostics,
                        "No shared application settings in this package. Current settings remain unchanged."
                    )?;
                }
            } else {
                writeln!(
                    self.diagnostics,
                    "Your application settings remain unchanged."
                )?;
            }
            if !self.runtime.confirm("IMPORT")? {
                return Err("share_cancelled".into());
            }
            let secret = self
                .runtime
                .new_password("New password for imported Safes")?;
            self.password = Some(Zeroizing::new(
                std::str::from_utf8(&secret)
                    .map_err(|_| "invalid_secret_encoding")?
                    .to_owned(),
            ));
            Ok(())
        })();
        result.map_err(as_io)
    }

    fn begin_safe(&mut self, safe: &Safe, manifest: &Manifest) -> io::Result<Self::Writer> {
        let result = (|| -> Result<Self::Writer> {
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            let destination = transaction
                .destinations
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("Import destination missing")?;
            let state = writable_state(self.runtime)?;
            let slot = crate::run::free_slot(self.runtime, &state)?;
            let request = random_id()?;
            let payload = Zeroizing::new(
                serde_json::to_vec(&control::Open {
                    transaction: transaction.transaction.clone(),
                    nonce: transaction.nonce.clone(),
                    package_id: safe.id.clone(),
                    request_id: request.clone(),
                    password: self
                        .password
                        .as_ref()
                        .ok_or("Import password missing")?
                        .clone(),
                })
                .map_err(|_| "invalid_share_import_request")?,
            );
            let response = self.runtime.request(Call {
                operation: Operation::ShareImportOpen,
                slot: Some(slot),
                session: None,
                expected_session: Some(&destination.safe_id),
                secret: &payload,
            })?;
            drop(payload);
            let opening: control::Opened<R::Slot> =
                serde_json::from_str(&response).map_err(|_| "invalid_share_import_opening")?;
            if opening.slot != slot || opening.safe_id != destination.safe_id {
                return Err("Import opening changed".into());
            }
            oblivion_share::manifest::validate_id(&opening.nonce)?;
            let mut attachment = self.runtime.attach_share_import(&opening)?;
            let prepare = (|| -> Result<()> {
                let mut ready = [0; 6];
                attachment.stream().read_exact(&mut ready)?;
                if &ready != b"OBSH1\n" {
                    return Err("Import guest is not ready".into());
                }
                write_message(
                    attachment.stream(),
                    &serde_json::json!({"version":1,"operation":"import","request_id":request}),
                )?;
                manifest.write(attachment.stream())?;
                writeln!(
                    self.diagnostics,
                    "Importing {:?} into its new offline Safe…",
                    destination.title
                )?;
                Ok(())
            })();
            if let Err(error) = prepare {
                attachment.close()?;
                return Err(error);
            }
            Ok(GuestWriter {
                attachment,
                opening,
                package_id: safe.id.clone(),
                expected: Receipt {
                    id: request,
                    manifest_sha256: manifest.sha256(),
                    entries: manifest.entries().len(),
                    bytes: manifest.bytes(),
                },
            })
        })();
        result.map_err(as_io)
    }

    fn finish_safe(&mut self, safe: &Safe, mut writer: Self::Writer) -> io::Result<()> {
        let result = (|| -> Result<()> {
            writer.flush()?;
            let receipt: Receipt = read_message(writer.attachment.stream(), 1024)?;
            if receipt != writer.expected || safe.id != writer.package_id {
                return Err("Import receipt does not match the approved Safe".into());
            }
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            self.runtime.request(Call {
                operation: Operation::ShareImportFinish,
                slot: Some(writer.opening.slot),
                session: Some(writer.attachment.client_id()),
                expected_session: Some(&writer.opening.safe_id),
                secret: &serde_json::to_vec(&control::Finish {
                    transaction: transaction.transaction.clone(),
                    nonce: transaction.nonce.clone(),
                    package_id: safe.id.clone(),
                    receipt,
                })?,
            })?;
            Ok(())
        })();
        writer.attachment.close()?;
        result.map_err(as_io)
    }

    fn abort(&mut self) -> io::Result<()> {
        self.password = None;
        let Some(transaction) = &self.transaction else {
            return Ok(());
        };
        self.runtime
            .cleanup(Call {
                operation: Operation::ShareImportAbort,
                slot: Some(Default::default()),
                session: None,
                expected_session: None,
                secret: &serde_json::to_vec(&control::Abort {
                    transaction: transaction.transaction.clone(),
                    nonce: transaction.nonce.clone(),
                })
                .map_err(as_io)?,
            })
            .map(|_| ())
            .map_err(as_io)
    }
}

impl<R: Native, W: Write> Target<'_, R, W>
where
    R::Slot: Default + Serialize,
{
    fn commit(&mut self, proof: &Verified) -> Result<()> {
        self.password = None;
        let transaction = self
            .transaction
            .as_ref()
            .ok_or("Import transaction missing")?;
        if self.metadata_sha256 != proof.package_sha256() {
            return Err("Import verification identity changed".into());
        }
        let commit = control::Commit {
            transaction: transaction.transaction.clone(),
            nonce: transaction.nonce.clone(),
            metadata_sha256: proof.package_sha256().into(),
        };
        let result = self.runtime.request(Call {
            operation: Operation::ShareImportCommit,
            slot: Some(Default::default()),
            session: None,
            expected_session: None,
            secret: &serde_json::to_vec(&commit)?,
        });
        match result {
            Ok(response) => {
                let committed: control::Committed = serde_json::from_str(&response)
                    .map_err(|_| "invalid_share_import_completion")?;
                if committed.transaction != transaction.transaction
                    || committed.metadata_sha256 != self.metadata_sha256
                    || serde_json::to_value(&committed.destinations)?
                        != serde_json::to_value(&transaction.destinations)?
                {
                    return Err(
                        "Import publication needs review with oblivion share imports".into(),
                    );
                }
                Ok(())
            }
            Err(error) => {
                let observed = statuses(self.runtime)?;
                match observed.iter().find(|entry|entry.transaction==transaction.transaction && entry.metadata_sha256.as_deref()==Some(self.metadata_sha256.as_str())) {
                    Some(state) if matches!(state.outcome,control::Outcome::Committed) && state.safes==transaction.destinations.len()=>Ok(()),
                    Some(state) if matches!(state.outcome,control::Outcome::Pending)=>{self.abort()?;Err(error)}
                    _=>Err("Import outcome is unknown. Inspect oblivion share imports before retrying.".into()),
                }
            }
        }
    }
}

fn validate_destinations(
    package: &Package,
    begun: &control::Begun,
    existing: &BTreeSet<String>,
) -> Result<()> {
    oblivion_share::manifest::validate_id(&begun.transaction)?;
    oblivion_share::manifest::validate_id(&begun.nonce)?;
    if begun.destinations.len() != package.safes.len() {
        return Err("Import destination count changed".into());
    }
    let mut mappings = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for destination in &begun.destinations {
        oblivion_share::manifest::validate_id(&destination.safe_id)?;
        oblivion_wire::session_title::validate(&destination.title)?;
        oblivion_wire::volume::size(destination.mib)?;
        if !package
            .safes
            .iter()
            .any(|safe| safe.id == destination.package_id)
            || existing.contains(&destination.safe_id)
            || !ids.insert(&destination.safe_id)
            || mappings
                .insert(
                    destination.package_id.as_str(),
                    destination.safe_id.as_str(),
                )
                .is_some()
        {
            return Err("Import cannot reuse existing Safe identities".into());
        }
    }
    for safe in &package.safes {
        let destination = begun
            .destinations
            .iter()
            .find(|entry| entry.package_id == safe.id)
            .ok_or("Import destination missing")?;
        if destination.parent.as_deref()
            != safe
                .parent
                .as_deref()
                .and_then(|parent| mappings.get(parent).copied())
        {
            return Err("Import family mapping changed".into());
        }
        if oblivion_wire::volume::size(destination.mib)? <= safe.bytes {
            return Err("Import destination is too small".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_destinations;
    use oblivion_share::{Package, Safe, control};
    use std::collections::BTreeSet;

    fn package() -> Package {
        Package {
            format: "oblivion-share".into(),
            version: 1,
            id: "a".repeat(32),
            settings: None,
            safes: vec![Safe {
                id: "b".repeat(32),
                title: "GB".into(),
                parent: None,
                provenance: None,
                policy: oblivion_share::Policy::Offline,
                required_proxy: None,
                contents_sha256: "c".repeat(64),
                entries: 2,
                bytes: 0,
            }],
        }
    }
    fn begun() -> control::Begun {
        control::Begun {
            transaction: "d".repeat(32),
            nonce: "e".repeat(32),
            destinations: vec![control::Destination {
                package_id: "b".repeat(32),
                safe_id: "f".repeat(32),
                title: "GB".into(),
                parent: None,
                mib: 128,
            }],
        }
    }

    #[test]
    fn destination_mapping_requires_new_identities_exact_families_and_sufficient_private_volume() {
        let package = package();
        let existing = BTreeSet::new();
        validate_destinations(&package, &begun(), &existing).unwrap();
        assert!(
            validate_destinations(&package, &begun(), &BTreeSet::from(["f".repeat(32)])).is_err()
        );
        let mut changed = begun();
        changed.destinations.clear();
        assert!(validate_destinations(&package, &changed, &existing).is_err());
        let mut changed = begun();
        changed.destinations[0].package_id = "1".repeat(32);
        assert!(validate_destinations(&package, &changed, &existing).is_err());
        let mut changed = begun();
        changed.destinations[0].parent = Some("1".repeat(32));
        assert!(validate_destinations(&package, &changed, &existing).is_err());
        let mut changed = begun();
        changed.destinations[0].title = "GB\u{1b}[2J".into();
        assert!(validate_destinations(&package, &changed, &existing).is_err());
        let mut changed = begun();
        changed.destinations[0].mib = 1;
        assert!(validate_destinations(&package, &changed, &existing).is_err());
        let mut large = package;
        large.safes[0].bytes = 128 * 1024 * 1024;
        assert!(validate_destinations(&large, &begun(), &existing).is_err());
    }

    #[cfg(unix)]
    mod native {
        use super::{begun, package};
        use crate::controller::{Call, Controller, Result};
        use crate::run::{Notice, Runtime};
        use crate::share::import::Target;
        use crate::share::io::{Attachment, Lease, Native};
        use oblivion_share::{Import, Manifest};
        use oblivion_transfer::copy_protocol::Transport;
        use oblivion_transfer::endpoint::{read_message, write_message};
        use oblivion_transfer::{Entry, Receipt};
        use oblivion_wire::control::Operation;
        use oblivion_wire::idle::Opening;
        use serde_json::{Value, json};
        use std::collections::BTreeSet;
        use std::io::{self, Read, Write};
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use zeroize::Zeroizing;

        struct Socket(UnixStream);
        impl Read for Socket {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.0.read(bytes)
            }
        }
        impl Write for Socket {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        impl Transport for Socket {
            fn check(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct Attached {
            socket: Socket,
            closed: bool,
            count: Arc<AtomicUsize>,
        }
        impl Attachment for Attached {
            type Stream = Socket;
            fn stream(&mut self) -> &mut Socket {
                &mut self.socket
            }
            fn client_id(&self) -> &str {
                "11111111111111111111111111111111"
            }
            fn close(&mut self) -> io::Result<()> {
                if !self.closed {
                    self.closed = true;
                    self.count.fetch_add(1, Ordering::SeqCst);
                    self.socket.0.shutdown(std::net::Shutdown::Both)?;
                }
                Ok(())
            }
        }
        struct NoExport;
        impl Lease for NoExport {
            fn check(&mut self) -> io::Result<()> {
                panic!("import cannot own export lease")
            }
            fn close(&mut self) -> io::Result<()> {
                panic!("import cannot own export lease")
            }
        }
        struct Sent {
            operation: Operation,
            slot: Option<u8>,
            session: Option<String>,
            expected: Option<String>,
            body: Zeroizing<Vec<u8>>,
            cleanup: bool,
        }
        struct Frontend {
            socket: Option<UnixStream>,
            closed: Arc<AtomicUsize>,
            sent: Vec<Sent>,
        }
        impl Controller for Frontend {
            type Slot = u8;
            fn request(&mut self, call: Call<'_, u8>) -> Result<String> {
                let response=match call.operation {
                    Operation::ShareImportBegin=>serde_json::to_string(&begun())?,
                    Operation::Status=>json!({"app_open":true,"app_mode":"persistent","general_present":true,"general_incomplete":false,"general_bytes":8589934592u64,"recovery_required":false,"sessions":[],"session_titles":{},"open_sessions":[],"agent_safes":[]}).to_string(),
                    Operation::ShareImportOpen=>json!({"slot":3,"safe_id":"f".repeat(32),"nonce":"2".repeat(32)}).to_string(),
                    Operation::ShareImportFinish|Operation::ShareImportAbort=>String::new(),
                    _=>panic!("unexpected controller operation"),
                };
                self.sent.push(Sent {
                    operation: call.operation,
                    slot: call.slot,
                    session: call.session.map(str::to_owned),
                    expected: call.expected_session.map(str::to_owned),
                    body: Zeroizing::new(call.secret.to_vec()),
                    cleanup: false,
                });
                Ok(response)
            }
        }
        impl Runtime for Frontend {
            type Mark = ();
            fn slots(&self) -> Vec<u8> {
                vec![3]
            }
            fn password(&mut self, _: &'static str) -> Result<Zeroizing<Vec<u8>>> {
                panic!("no unlock needed")
            }
            fn new_password(&mut self, _: &'static str) -> Result<Zeroizing<Vec<u8>>> {
                Ok(Zeroizing::new(b"PRIVATE_TEST_PASSWORD_CANARY".to_vec()))
            }
            fn confirm(&mut self, word: &'static str) -> Result<bool> {
                assert_eq!(word, "IMPORT");
                Ok(true)
            }
            fn now(&self) {}
            fn elapsed(&self, _: &()) -> Duration {
                Duration::ZERO
            }
            fn wait(&mut self, _: Duration) -> Result<()> {
                panic!("no wait")
            }
            fn notice(&mut self, _: Notice<'_>) -> Result<()> {
                panic!("no notice")
            }
            fn attach(&mut self, _: u8, _: &str, _: &str, _: &[String]) -> Result<i32> {
                panic!("no agent")
            }
            fn attach_workspace(&mut self, _: u8, _: &str) -> Result<i32> {
                panic!("no workspace")
            }
        }
        impl Native for Frontend {
            type Attachment = Attached;
            type ExportLease = NoExport;
            fn review_share(&mut self) -> Result<Option<String>> {
                panic!("no export review")
            }
            fn lease_share_export(&mut self, _: &str) -> Result<NoExport> {
                panic!("no export")
            }
            fn attach_share_source(
                &mut self,
                _: &Opening<u8>,
                _: &mut NoExport,
            ) -> Result<Attached> {
                panic!("no source")
            }
            fn attach_share_import(&mut self, opening: &Opening<u8>) -> Result<Attached> {
                assert_eq!(opening.slot, 3);
                assert_eq!(opening.safe_id, "f".repeat(32));
                Ok(Attached {
                    socket: Socket(self.socket.take().unwrap()),
                    closed: false,
                    count: Arc::clone(&self.closed),
                })
            }
            fn cleanup(&mut self, call: Call<'_, u8>) -> Result<String> {
                let response = self.request(call)?;
                self.sent.last_mut().unwrap().cleanup = true;
                Ok(response)
            }
        }

        #[test]
        fn real_import_stream_scopes_finish_and_rejects_changed_receipts_before_publication() {
            for corrupt in [false, true] {
                let (client, mut peer) = UnixStream::pair().unwrap();
                for stream in [&client, &peer] {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                }
                let guest = std::thread::spawn(move || {
                    peer.write_all(b"OBSH1\n").unwrap();
                    let request: Value = read_message(&mut peer, 4096).unwrap();
                    assert_eq!(request["operation"], "import");
                    let manifest =
                        Manifest::read(&mut peer, oblivion_transfer::share::LIMITS).unwrap();
                    oblivion_transfer::relay_payload(&mut peer, &mut io::sink(), &manifest)
                        .unwrap();
                    write_message(
                        &mut peer,
                        &Receipt {
                            id: if corrupt {
                                "9".repeat(32)
                            } else {
                                request["request_id"].as_str().unwrap().into()
                            },
                            manifest_sha256: manifest.sha256(),
                            entries: manifest.entries().len(),
                            bytes: manifest.bytes(),
                        },
                    )
                    .unwrap();
                    let mut closed = [0];
                    assert_eq!(peer.read(&mut closed).unwrap(), 0);
                });
                let closed = Arc::new(AtomicUsize::new(0));
                let mut frontend = Frontend {
                    socket: Some(client),
                    closed: Arc::clone(&closed),
                    sent: vec![],
                };
                let mut diagnostics = Vec::new();
                let mut package = package();
                let manifest = Manifest::new(
                    vec![
                        Entry::Directory {
                            path: "workspace".into(),
                        },
                        Entry::File {
                            path: "workspace/empty".into(),
                            size: 0,
                            sha256:
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                    .into(),
                        },
                    ],
                    oblivion_transfer::share::LIMITS,
                )
                .unwrap();
                package.safes[0].contents_sha256 = manifest.sha256();
                let mut target = Target {
                    runtime: &mut frontend,
                    diagnostics: &mut diagnostics,
                    transaction: None,
                    password: None,
                    metadata_sha256: String::new(),
                    apply_settings: false,
                    existing: BTreeSet::new(),
                };
                target.begin(&package, &"c".repeat(64)).unwrap();
                let mut writer = target.begin_safe(&package.safes[0], &manifest).unwrap();
                writer.write_all(b"OBLVEND1").unwrap();
                let result = target.finish_safe(&package.safes[0], writer);
                assert_eq!(result.is_err(), corrupt, "{result:?}");
                if corrupt {
                    target.abort().unwrap();
                }
                drop(target);
                guest.join().unwrap();
                assert_eq!(closed.load(Ordering::SeqCst), 1);
                assert_eq!(frontend.sent[0].slot, Some(0));
                let opened = &frontend.sent[2];
                assert_eq!(opened.operation, Operation::ShareImportOpen);
                assert_eq!(opened.slot, Some(3));
                assert!(opened.session.is_none());
                assert_eq!(
                    opened.expected.as_deref(),
                    Some("ffffffffffffffffffffffffffffffff")
                );
                assert_eq!(
                    serde_json::from_slice::<Value>(&opened.body).unwrap()["password"],
                    "PRIVATE_TEST_PASSWORD_CANARY"
                );
                let last = frontend.sent.last().unwrap();
                assert_eq!(
                    last.operation,
                    if corrupt {
                        Operation::ShareImportAbort
                    } else {
                        Operation::ShareImportFinish
                    }
                );
                assert_eq!(last.slot, Some(if corrupt { 0 } else { 3 }));
                assert_eq!(last.cleanup, corrupt);
                if !corrupt {
                    assert_eq!(
                        last.session.as_deref(),
                        Some("11111111111111111111111111111111")
                    );
                    assert_eq!(
                        last.expected.as_deref(),
                        Some("ffffffffffffffffffffffffffffffff")
                    );
                }
                assert!(!String::from_utf8(diagnostics).unwrap().contains("CANARY"));
                assert!(
                    frontend
                        .sent
                        .iter()
                        .all(|call| call.operation != Operation::ShareImportCommit)
                );
            }
        }
    }
}
