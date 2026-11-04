use oblivion_host::{autolock, control, scope, sharing};
use oblivion_share::{Import, Manifest, Package, SecretString, Verified};
use oblivion_transfer::Receipt;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{read_message, write_message};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use zeroize::Zeroizing;

pub(super) fn run(args: &[String]) -> control::Result<i32> {
    let mut file = None;
    let mut settings = false;
    for value in args {
        match value.as_str() {
            "--apply-settings" if !settings => settings = true,
            value if !value.starts_with('-') && file.is_none() => file = Some(value),
            _ => return Err("Use share import FILE [--apply-settings]".into()),
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(file.ok_or("Choose an encrypted Share file")?)?;
    if !file.metadata()?.is_file() {
        return Err("Choose a regular encrypted Share file".into());
    }
    let state = crate::status()?;
    if state.app_mode != crate::AppMode::Persistent {
        return Err("Unlock writable encrypted storage before importing Share".into());
    }
    if state.recovery_required {
        return Err("Complete recovery before importing Share".into());
    }
    let password = SecretString::from(String::from_utf8(
        crate::password("Share password", false)?.to_vec(),
    )?);
    let mut target = Target {
        transaction: None,
        password: None,
        metadata_sha256: String::new(),
        apply_settings: settings,
        existing: state.sessions.into_iter().collect(),
    };
    let verified = match oblivion_share::decrypt(file, password, &mut target) {
        Ok(verified) => verified,
        Err(error) if error.to_string() == "share_cancelled" => return Ok(130),
        Err(error) => return Err(error.into()),
    };
    // Publication is deliberately reachable only with the private Verified
    // value returned after the last age authentication chunk was consumed.
    target.commit(&verified)?;
    let transaction = target
        .transaction
        .as_ref()
        .ok_or("Import transaction missing")?;
    eprintln!("Share imported. New Safes remain offline and need your own provider login.");
    for destination in &transaction.destinations {
        eprintln!("  {} · {}", destination.title, destination.safe_id);
    }
    if settings {
        if let Some(settings) = &verified.package().settings {
            let preferences = autolock::Preferences {
                version: 1,
                safe_minutes: settings.safe_idle_minutes,
                host_minutes: settings.host_idle_minutes,
            };
            if let Err(error) =
                control::request("idle-settings", None, &serde_json::to_vec(&preferences)?)
            {
                eprintln!(
                    "Safes are already imported. Shared automatic-lock settings were not applied: {error}. Do not import the package again; change Settings instead."
                );
                return Ok(2);
            }
        }
    }
    Ok(0)
}

pub(super) fn status(args: &[String]) -> control::Result<i32> {
    if !args.is_empty() && args != ["--json"] {
        return Err("Use share imports [--json]".into());
    }
    let output = control::request("share-import-status", None, &[])?;
    let statuses: Vec<sharing::Status> = serde_json::from_str(&output)?;
    if args == ["--json"] {
        println!("{}", serde_json::to_string(&statuses)?);
        return Ok(0);
    }
    for state in statuses {
        oblivion_share::manifest::validate_id(&state.transaction)?;
        println!(
            "{}\t{}\t{}/{} Safes ready",
            state.transaction,
            match state.outcome {
                sharing::Outcome::Pending => "Pending — not published",
                sharing::Outcome::Committed => "Imported",
                sharing::Outcome::RecoveryRequired => "Recovery required",
            },
            state.ready,
            state.safes
        );
    }
    Ok(0)
}

pub(super) fn discard(args: &[String]) -> control::Result<i32> {
    if args.len() != 1 {
        return Err("Use share discard TRANSACTION".into());
    }
    oblivion_share::manifest::validate_id(&args[0])?;
    eprintln!(
        "Discard incomplete import {}. Existing Safes and committed imports cannot be removed by this action.",
        args[0]
    );
    if !crate::init_commands::confirm("DISCARD")? {
        return Ok(130);
    }
    control::request(
        "share-import-discard",
        None,
        &serde_json::to_vec(&sharing::Discard {
            transaction: args[0].clone(),
        })?,
    )?;
    eprintln!("Incomplete import removed.");
    Ok(0)
}

struct Target {
    transaction: Option<sharing::Begun>,
    password: Option<Zeroizing<String>>,
    metadata_sha256: String,
    apply_settings: bool,
    existing: BTreeSet<String>,
}

struct GuestWriter {
    channel: Channel,
    lease: UnixStream,
    client: String,
    opening: autolock::Opening,
    package_id: String,
    expected: Receipt,
}

impl Write for GuestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.channel.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

impl Import for Target {
    type Writer = GuestWriter;

    fn begin(&mut self, package: &Package, metadata_sha256: &str) -> io::Result<()> {
        let result = (|| -> control::Result<()> {
            let begun: sharing::Begun = serde_json::from_str(&control::request(
                "share-import-begin",
                None,
                &serde_json::to_vec(&sharing::Begin {
                    package: package.clone(),
                    metadata_sha256: metadata_sha256.into(),
                })?,
            )?)?;
            self.metadata_sha256 = metadata_sha256.into();
            self.transaction = Some(begun);
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            validate_destinations(package, transaction, &self.existing)?;
            eprintln!(
                "Import {} Safes into new encrypted volumes. Verification must finish before they become visible.",
                package.safes.len()
            );
            for safe in &package.safes {
                let destination = transaction
                    .destinations
                    .iter()
                    .find(|entry| entry.package_id == safe.id)
                    .ok_or("Import destination missing")?;
                eprintln!(
                    "  {} · {} MiB · Offline",
                    destination.title, destination.mib
                );
                if destination.title != safe.title {
                    eprintln!(
                        "    Source title: {} · renamed to avoid a conflict",
                        safe.title
                    );
                }
                if let Some(proxy) = &safe.required_proxy {
                    eprintln!(
                        "    Source used {proxy}; configure your own transport before going online."
                    );
                }
            }
            eprintln!(
                "Provider profiles, source passwords and installed OS overlays are not imported. Files and conversations can still contain secrets supplied by the sender."
            );
            if self.apply_settings {
                if let Some(settings) = &package.settings {
                    eprintln!(
                        "Shared automatic lock: Safe {} minutes, Oblivion {} minutes (0 means disabled).",
                        settings.safe_idle_minutes, settings.host_idle_minutes
                    );
                } else {
                    eprintln!(
                        "No shared application settings in this package. Current settings remain unchanged."
                    );
                }
            } else {
                eprintln!("Your application settings remain unchanged.");
            }
            if !crate::init_commands::confirm("IMPORT")? {
                return Err("share_cancelled".into());
            }
            self.password = Some(Zeroizing::new(String::from_utf8(
                crate::new_password("New password for imported Safes")?.to_vec(),
            )?));
            Ok(())
        })();
        result.map_err(as_io)
    }

    fn begin_safe(
        &mut self,
        safe: &oblivion_share::Safe,
        manifest: &Manifest,
    ) -> io::Result<GuestWriter> {
        let result = (|| -> control::Result<GuestWriter> {
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            let destination = transaction
                .destinations
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("Import destination missing")?;
            let slot = crate::free_slot(&crate::status()?)?;
            scope::within(slot, || {
                let request = super::random_id()?;
                let payload = Zeroizing::new(serde_json::to_vec(&sharing::Open {
                    transaction: transaction.transaction.clone(),
                    nonce: transaction.nonce.clone(),
                    package_id: safe.id.clone(),
                    request_id: request.clone(),
                    password: self
                        .password
                        .as_ref()
                        .ok_or("Import password missing")?
                        .clone(),
                })?);
                let opening: sharing::Opened = serde_json::from_str(&control::request_for(
                    &destination.safe_id,
                    "share-import-open",
                    None,
                    &payload,
                )?)?;
                if opening.slot != slot || opening.safe_id != destination.safe_id {
                    return Err("Import opening changed".into());
                }
                oblivion_share::manifest::validate_id(&opening.nonce)?;
                let (connection, lease, client) =
                    control::attach_client("share-import-attach", &destination.safe_id)?;
                let mut channel = Channel::new(
                    File::from(OwnedFd::from(connection)),
                    Duration::from_secs(3600),
                )?;
                let mut ready = [0; 6];
                channel.read_exact(&mut ready)?;
                if &ready != b"OBSH1\n" {
                    return Err("Import guest is not ready".into());
                }
                write_message(
                    &mut channel,
                    &serde_json::json!({"version":1,"operation":"import","request_id":request}),
                )?;
                manifest.write(&mut channel)?;
                eprintln!("Importing {} into its new offline Safe…", destination.title);
                Ok(GuestWriter {
                    channel,
                    lease,
                    client,
                    opening,
                    package_id: safe.id.clone(),
                    expected: Receipt {
                        id: request,
                        manifest_sha256: manifest.sha256(),
                        entries: manifest.entries().len(),
                        bytes: manifest.bytes(),
                    },
                })
            })
        })();
        result.map_err(as_io)
    }

    fn finish_safe(
        &mut self,
        safe: &oblivion_share::Safe,
        mut writer: GuestWriter,
    ) -> io::Result<()> {
        let result = (|| -> control::Result<()> {
            let receipt: Receipt = read_message(&mut writer.channel, 1024)?;
            if receipt != writer.expected || safe.id != writer.package_id {
                return Err("Import receipt does not match the approved Safe".into());
            }
            let transaction = self
                .transaction
                .as_ref()
                .ok_or("Import transaction missing")?;
            scope::within(writer.opening.slot, || {
                control::request_for(
                    &writer.opening.safe_id,
                    "share-import-finish",
                    Some(&writer.client),
                    &serde_json::to_vec(&sharing::Finish {
                        transaction: transaction.transaction.clone(),
                        nonce: transaction.nonce.clone(),
                        package_id: safe.id.clone(),
                        receipt,
                    })?,
                )
            })?;
            Ok(())
        })();
        drop(writer.channel);
        drop(writer.lease);
        result.map_err(as_io)
    }

    fn abort(&mut self) -> io::Result<()> {
        self.password = None;
        let Some(transaction) = &self.transaction else {
            return Ok(());
        };
        control::request(
            "share-import-abort",
            None,
            &serde_json::to_vec(&sharing::Abort {
                transaction: transaction.transaction.clone(),
                nonce: transaction.nonce.clone(),
            })?,
        )
        .map(|_| ())
        .map_err(as_io)
    }
}

impl Target {
    fn commit(&mut self, proof: &Verified) -> control::Result<()> {
        self.password = None;
        let transaction = self
            .transaction
            .as_ref()
            .ok_or("Import transaction missing")?;
        if self.metadata_sha256 != proof.package_sha256() {
            return Err("Import verification identity changed".into());
        }
        let commit = sharing::Commit {
            transaction: transaction.transaction.clone(),
            nonce: transaction.nonce.clone(),
            metadata_sha256: proof.package_sha256().into(),
        };
        let result = control::request("share-import-commit", None, &serde_json::to_vec(&commit)?);
        match result {
            Ok(output) => {
                let committed: sharing::Committed = serde_json::from_str(&output)?;
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
                // Never replay a possibly successful publication. A read-only
                // outcome check distinguishes an acknowledged commit from a
                // still-unpublished batch without risking duplicate imports.
                let statuses: Vec<sharing::Status> =
                    serde_json::from_str(&control::request("share-import-status", None, &[])?)?;
                match statuses.iter().find(|entry| entry.transaction == transaction.transaction && entry.metadata_sha256.as_deref() == Some(self.metadata_sha256.as_str())) {
                    Some(state) if matches!(state.outcome, sharing::Outcome::Committed) && state.safes == transaction.destinations.len() => Ok(()),
                    Some(state) if matches!(state.outcome, sharing::Outcome::Pending) => { self.abort()?; Err(error) }
                    _ => Err("Import outcome is unknown. Inspect oblivion share imports before retrying.".into()),
                }
            }
        }
    }
}

fn validate_destinations(
    package: &Package,
    begun: &sharing::Begun,
    existing: &BTreeSet<String>,
) -> control::Result<()> {
    oblivion_share::manifest::validate_id(&begun.transaction)?;
    oblivion_share::manifest::validate_id(&begun.nonce)?;
    if begun.destinations.len() != package.safes.len() {
        return Err("Import destination count changed".into());
    }
    let mut mappings = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for destination in &begun.destinations {
        oblivion_share::manifest::validate_id(&destination.safe_id)?;
        oblivion_host::session_title::validate(&destination.title)?;
        oblivion_host::volume::size(destination.mib)?;
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
        if oblivion_host::volume::size(destination.mib)? <= safe.bytes {
            return Err("Import destination is too small".into());
        }
    }
    Ok(())
}

fn as_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
