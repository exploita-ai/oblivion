//! One reviewed Share workflow for native launchers. The container and guest
//! endpoints keep provider stores out; OS adapters own only private authorities.
pub mod command;
mod import;
pub mod io;
pub mod review;

use crate::controller::{self, AppMode, Call, Result, State};
use command::{Action, Selection, Selector};
pub use command::{Command, parse};
use io::{Attachment, Lease, Native};
use oblivion_share::control::{
    ExportIdentity, ExportOpen, ExportSelection, ExportStarted, SourceMetadata,
};
use oblivion_share::{Manifest, Package, Provenance, Safe, SecretString, Source};
use oblivion_transfer::endpoint::{read_message, write_message};
use oblivion_transfer::local_file::Target;
use oblivion_transfer::{Receipt, copy_protocol::Transport};
use oblivion_wire::control::Operation;
use oblivion_wire::idle::Opening;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub fn run<R: Native>(
    runtime: &mut R,
    command: Command,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<i32>
where
    R::Slot: Default + Serialize,
{
    let (selector, path, selection) = match command.into_action() {
        Action::Import { file, settings } => {
            return import::run(runtime, &file, settings, output, diagnostics);
        }
        Action::Imports { json } => return import::status(runtime, json, output),
        Action::Discard { transaction } => {
            return import::discard(runtime, &transaction, diagnostics);
        }
        Action::Export {
            selector,
            output,
            selection,
        } => (selector, output, selection),
    };
    let destination = Target::new(Path::new(&path))?;
    let state = writable_state(runtime)?;
    let selector = match selector {
        Selector::Safe(name) => ExportSelection::Safe {
            safe_id: state.find_safe(&name)?.ok_or("Safe not found")?,
        },
        Selector::Branch(name) => ExportSelection::Branch {
            safe_id: state.find_safe(&name)?.ok_or("Safe not found")?,
        },
        Selector::All { include_settings } => ExportSelection::All { include_settings },
    };
    let include_settings = matches!(
        selector,
        ExportSelection::All {
            include_settings: true
        }
    );
    let started: ExportStarted = serde_json::from_str(&runtime.request(Call {
        operation: Operation::ShareExportBegin,
        slot: Some(Default::default()),
        session: None,
        expected_session: None,
        secret: &serde_json::to_vec(&selector)?,
    })?)
    .map_err(|_| "invalid_share_preparation")?;
    oblivion_share::manifest::validate_id(&started.export_id)?;
    let lease = match runtime.lease_share_export(&started.export_id) {
        Ok(lease) => lease,
        Err(error) => {
            runtime.cleanup(Call {
                operation: Operation::ShareExportEnd,
                slot: Some(Default::default()),
                session: None,
                expected_session: None,
                secret: &serde_json::to_vec(&ExportIdentity {
                    export_id: started.export_id,
                })?,
            })?;
            return Err(error);
        }
    };
    let mut sources = BatchSource {
        runtime,
        export_id: started.export_id,
        lease,
        approved: Vec::new(),
        current: None,
        ended: false,
        diagnostics,
    };
    let result = (|| -> Result<i32> {
        if started.settings.is_some() != include_settings {
            return Err("Share settings approval changed".into());
        }
        if started.sources.is_empty() || started.sources.len() > oblivion_share::manifest::MAX_SAFES
        {
            return Err("invalid_share_source_set".into());
        }
        let mut ids = BTreeMap::new();
        for source in &started.sources {
            oblivion_share::manifest::validate_id(&source.id)?;
            if ids.insert(source.id.as_str(), random_id()?).is_some() {
                return Err("duplicate_share_source".into());
            }
        }
        let mut package = Package {
            format: "oblivion-share".into(),
            version: 1,
            id: random_id()?,
            safes: Vec::new(),
            settings: started.settings,
        };
        for (index, source) in started.sources.iter().enumerate() {
            writeln!(
                sources.diagnostics,
                "Reviewing Safe {} of {}…",
                index + 1,
                started.sources.len()
            )?;
            let metadata = sources.open_source(&source.id, true)?;
            let request = random_id()?;
            let Some((review, manifest, selection)) =
                sources.review_source(&request, &metadata.title, &selection)?
            else {
                sources.cancel_plan(&request)?;
                sources.close_source()?;
                return Ok(130);
            };
            let parent = source
                .parent
                .as_deref()
                .and_then(|parent| ids.get(parent))
                .cloned();
            let safe = Safe {
                id: ids
                    .get(source.id.as_str())
                    .ok_or("share_source_missing")?
                    .clone(),
                title: metadata.title,
                parent: parent.clone(),
                provenance: Some(Provenance {
                    created_by_agent: metadata.created_by_agent,
                    requested_agent: metadata.requested_agent,
                    parent_not_included: parent.is_none()
                        && (source.parent.is_some() || metadata.parent_not_included),
                }),
                policy: metadata.policy,
                required_proxy: metadata.required_proxy,
                contents_sha256: review.manifest_sha256,
                entries: manifest.entries().len(),
                bytes: review.bytes,
            };
            sources.approved.push(Approved {
                source: source.id.clone(),
                package_id: safe.id.clone(),
                request_id: request.clone(),
                plan_sha256: review.plan_sha256,
                selection,
            });
            package.safes.push(safe);
            sources.cancel_plan(&request)?;
            sources.close_source()?;
        }
        package.validate()?;
        writeln!(
            sources.diagnostics,
            "Share {} Safe(s). Provider credential stores and OS customizations are excluded. Content scanning is best effort.",
            package.safes.len()
        )?;
        if let Some(settings) = &package.settings {
            writeln!(
                sources.diagnostics,
                "Included app settings: Safe lock {} min, Oblivion lock {} min (0 means disabled).",
                settings.safe_idle_minutes, settings.host_idle_minutes
            )?;
        }
        if !sources.runtime.confirm("SHARE")? {
            return Ok(130);
        }
        let passphrase = share_password(sources.runtime.new_password("Separate Share password")?)?;
        let mut publication = destination.create(&package.id)?;
        let mut file = publication.copy_file()?;
        oblivion_share::encrypt(&mut file, passphrase, &package, &mut sources)?;
        file.sync_all()?;
        drop(file);
        sources.end()?;
        publication.publish()?;
        writeln!(
            sources.diagnostics,
            "Encrypted Share saved to {:?}",
            publication.path()
        )?;
        Ok(0)
    })();
    sources.end()?;
    result
}

pub(super) fn writable_state<R: Native>(runtime: &mut R) -> Result<State<R::Slot>>
where
    R::Slot: Default,
{
    let state = controller::status_at(runtime, Some(Default::default()))?;
    if !state.app_open || state.app_mode != AppMode::Persistent {
        return Err("Unlock writable encrypted storage before sharing Safes".into());
    }
    if state.recovery_required {
        return Err("Complete recovery before sharing Safes".into());
    }
    Ok(state)
}

#[derive(Clone)]
struct Approved {
    source: String,
    package_id: String,
    request_id: String,
    plan_sha256: String,
    selection: Selection,
}
struct Attached<A, S> {
    capability: A,
    opening: Opening<S>,
}
struct BatchSource<'a, R: Native> {
    runtime: &'a mut R,
    export_id: String,
    lease: R::ExportLease,
    approved: Vec<Approved>,
    current: Option<Attached<R::Attachment, R::Slot>>,
    ended: bool,
    diagnostics: &'a mut dyn Write,
}

impl<R: Native> BatchSource<'_, R>
where
    R::Slot: Default + Serialize,
{
    fn open_source(&mut self, id: &str, prompt: bool) -> Result<SourceMetadata<R::Slot>> {
        if self.current.is_some() {
            return Err("share_source_already_open".into());
        }
        self.lease.check()?;
        let state = writable_state(self.runtime)?;
        let slot = crate::run::free_slot(self.runtime, &state)?;
        let payload = serde_json::to_vec(&ExportOpen {
            export_id: self.export_id.clone(),
            password: None,
        })?;
        let opened = self.runtime.request(Call {
            operation: Operation::ShareExportSourceOpen,
            slot: Some(slot),
            session: Some(id),
            expected_session: Some(id),
            secret: &payload,
        });
        let output = match opened {
            Err(error) if error.to_string() == "share_password_required" && prompt => {
                writeln!(self.diagnostics, "Password for Safe {}", &id[..8])?;
                let password = self.runtime.password("Safe password")?;
                let payload = Zeroizing::new(serde_json::to_vec(&ExportOpen {
                    export_id: self.export_id.clone(),
                    password: Some(Zeroizing::new(
                        std::str::from_utf8(&password)
                            .map_err(|_| "invalid_secret_encoding")?
                            .to_owned(),
                    )),
                })?);
                self.runtime.request(Call {
                    operation: Operation::ShareExportSourceOpen,
                    slot: Some(slot),
                    session: Some(id),
                    expected_session: Some(id),
                    secret: &payload,
                })?
            }
            result => result?,
        };
        let metadata: SourceMetadata<R::Slot> =
            serde_json::from_str(&output).map_err(|_| "invalid_share_source_metadata")?;
        if metadata.opening.safe_id != id || metadata.opening.slot != slot {
            return Err("share_opening_changed".into());
        }
        oblivion_share::manifest::validate_id(&metadata.opening.nonce)?;
        oblivion_wire::session_title::validate(&metadata.title)?;
        let capability = match self
            .runtime
            .attach_share_source(&metadata.opening, &mut self.lease)
        {
            Ok(capability) => capability,
            Err(error) => {
                self.runtime.cleanup(Call {
                    operation: Operation::ShareExportCancel,
                    slot: Some(slot),
                    session: None,
                    expected_session: Some(id),
                    secret: &serde_json::to_vec(&metadata.opening)?,
                })?;
                return Err(error);
            }
        };
        self.current = Some(Attached {
            capability,
            opening: metadata.opening.clone(),
        });
        let mut ready = [0; 6];
        self.channel()?.read_exact(&mut ready)?;
        if &ready != b"OBSH1\n" {
            return Err("share_guest_not_ready".into());
        }
        Ok(metadata)
    }

    fn channel(&mut self) -> Result<&mut <R::Attachment as Attachment>::Stream> {
        Ok(self
            .current
            .as_mut()
            .ok_or("share_source_missing")?
            .capability
            .stream())
    }

    fn review_source(
        &mut self,
        request: &str,
        title: &str,
        original: &Selection,
    ) -> Result<Option<(review::Review, Manifest, Selection)>> {
        let mut selection = original.clone();
        let mut current = self.plan(request, &selection)?;
        loop {
            review::show_review(&mut self.diagnostics, title, &current.0, &current.1)?;
            let mut edited = selection.clone();
            let mut changes = 0;
            loop {
                write!(
                    self.diagnostics,
                    "{} · F <numbers> exclude files or folders · C <numbers> exclude chats · U reset edits · Q cancel: ",
                    if changes == 0 {
                        "Enter keep this selection"
                    } else {
                        "Enter review edited selection"
                    },
                )?;
                self.diagnostics.flush()?;
                let Some(line) = self.runtime.review_share()? else {
                    return Ok(None);
                };
                match line.trim() {
                    "" => break,
                    "Q" | "q" => return Ok(None),
                    "U" | "u" => {
                        edited = selection.clone();
                        changes = 0;
                    }
                    input => match review::exclude(input, &mut edited, &current.1, &current.0) {
                        Some(added) => {
                            changes += added;
                            writeln!(self.diagnostics, "{changes} exclusion(s) staged.")?;
                        }
                        None => writeln!(
                            self.diagnostics,
                            "Choose numbers shown beside F or C in the current review."
                        )?,
                    },
                }
            }
            if changes == 0 {
                return Ok(Some((current.0, current.1, selection)));
            }
            match self.plan(request, &edited) {
                Ok(plan) => {
                    current = plan;
                    selection = edited;
                }
                Err(error) if error.is::<review::Conflict>() => {
                    writeln!(
                        self.diagnostics,
                        "{error} These edits were cleared. Stage both exclusions together."
                    )?;
                    current = self.plan(request, &selection)?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn plan(&mut self, request: &str, selection: &Selection) -> Result<(review::Review, Manifest)> {
        let current = self
            .current
            .as_mut()
            .ok_or("share_source_missing")?
            .capability
            .stream();
        current.check()?;
        write_message(
            current,
            &serde_json::json!({"version":1,"operation":"plan","request_id":request,
            "paths":selection.paths,"chat_ids":selection.chat_ids,"exclude_paths":selection.exclude_paths,
            "exclude_chats":selection.exclude_chats,"include_sensitive_paths":selection.include_sensitive_paths,"include_sensitive_chats":selection.include_sensitive_chats}),
        )?;
        current.flush()?;
        review::validate_reply(read_message(current, 10 * 1024 * 1024)?, request)
    }

    fn cancel_plan(&mut self, request: &str) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cancelled {
            version: u8,
            request_id: String,
            ok: bool,
            cancelled: bool,
        }
        let channel = self.channel()?;
        write_message(
            channel,
            &serde_json::json!({"version":1,"operation":"cancel","request_id":request}),
        )?;
        channel.flush()?;
        let reply: Cancelled = read_message(channel, 1024)?;
        if reply.version != 1 || reply.request_id != request || !reply.ok || !reply.cancelled {
            return Err("share_cancellation_unconfirmed".into());
        }
        Ok(())
    }

    fn close_source(&mut self) -> Result<()> {
        let Some(mut current) = self.current.take() else {
            return Ok(());
        };
        let result = self.runtime.cleanup(Call {
            operation: Operation::ShareRelease,
            slot: Some(current.opening.slot),
            session: Some(current.capability.client_id()),
            expected_session: Some(&current.opening.safe_id),
            secret: &serde_json::to_vec(&current.opening)?,
        });
        let closed = current.capability.close();
        result?;
        closed?;
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        let result = self.runtime.cleanup(Call {
            operation: Operation::ShareExportEnd,
            slot: Some(Default::default()),
            session: None,
            expected_session: None,
            secret: &serde_json::to_vec(&ExportIdentity {
                export_id: self.export_id.clone(),
            })?,
        });
        let closed = self
            .current
            .as_mut()
            .map_or(Ok(()), |current| current.capability.close());
        self.current = None;
        let lease_closed = self.lease.close();
        if result.is_ok() {
            self.ended = true
        }
        result?;
        closed?;
        lease_closed?;
        Ok(())
    }
}

impl<R: Native> Source for BatchSource<'_, R>
where
    R::Slot: Default + Serialize,
{
    fn open<'a>(&'a mut self, safe: &Safe) -> std::io::Result<Box<dyn Read + 'a>> {
        let result = (|| -> Result<()> {
            let approved = self
                .approved
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("unreviewed_share_source")?
                .clone();
            let metadata = self.open_source(&approved.source, false)?;
            writeln!(self.diagnostics, "Sharing {:?}…", metadata.title)?;
            let (review, manifest) = self.plan(&approved.request_id, &approved.selection)?;
            if review.plan_sha256 != approved.plan_sha256
                || review.manifest_sha256 != safe.contents_sha256
                || review.bytes != safe.bytes
                || manifest.entries().len() != safe.entries
            {
                self.cancel_plan(&approved.request_id)?;
                return Err(
                    "Share source changed after review. No output will be published.".into(),
                );
            }
            let channel = self.channel()?;
            write_message(
                channel,
                &serde_json::json!({"version":1,"operation":"confirm","request_id":approved.request_id,"plan_sha256":approved.plan_sha256}),
            )?;
            channel.flush()?;
            Ok(())
        })();
        result.map_err(as_io)?;
        Ok(Box::new(self.channel().map_err(as_io)?))
    }
    fn complete(&mut self, safe: &Safe, manifest: &Manifest) -> std::io::Result<()> {
        let result = (|| -> Result<()> {
            let request = self
                .approved
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("unreviewed_share_source")?
                .request_id
                .clone();
            let channel = self.channel()?;
            write_message(
                channel,
                &Receipt {
                    id: request,
                    manifest_sha256: manifest.sha256(),
                    entries: manifest.entries().len(),
                    bytes: manifest.bytes(),
                },
            )?;
            channel.flush()?;
            let mut ack = [0; 7];
            channel.read_exact(&mut ack)?;
            if &ack != b"copied\n" {
                return Err("share_receipt_unconfirmed".into());
            }
            self.close_source()
        })();
        result.map_err(as_io)
    }
}

pub(super) fn random_id() -> std::io::Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| std::io::Error::other("share_random_failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub(super) fn share_password(secret: Zeroizing<Vec<u8>>) -> Result<SecretString> {
    Ok(SecretString::from(
        std::str::from_utf8(&secret)
            .map_err(|_| "invalid_secret_encoding")?
            .to_owned(),
    ))
}
pub(super) fn as_io(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
