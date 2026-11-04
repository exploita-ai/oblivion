mod import;

use oblivion_host::{control, scope};
use oblivion_share::{Manifest, Package, Policy, Provenance, Safe, SecretString, Source};
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{read_message, write_message};
use oblivion_transfer::{Entry, Receipt};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    opening: oblivion_host::autolock::Opening,
    title: String,
    created_by_agent: bool,
    requested_agent: Option<oblivion_share::Agent>,
    parent_not_included: bool,
    policy: Policy,
    required_proxy: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u8,
    request_id: String,
    manifest: Vec<Entry>,
    manifest_sha256: String,
    plan_sha256: String,
    bytes: u64,
    chats: Vec<String>,
    omitted: BTreeMap<String, u64>,
    warnings: Vec<Warning>,
    warning_count: u64,
    scan: Scan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Warning {
    reason: String,
    path: Option<String>,
    chat_id: Option<String>,
    included: bool,
    default_excluded: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scan {
    files_bytes: u64,
    history_bytes: u64,
    limit_per_kind: u64,
    best_effort: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportStarted {
    export_id: String,
    sources: Vec<ExportSource>,
    settings: Option<oblivion_share::Settings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportSource {
    id: String,
    parent: Option<String>,
}

#[derive(serde::Serialize)]
struct ExportOpen<'a> {
    export_id: &'a str,
    password: Option<&'a str>,
}

#[derive(Clone, serde::Serialize)]
struct Selection {
    paths: Vec<String>,
    chat_ids: Option<Vec<String>>,
    exclude_paths: Vec<String>,
    exclude_chats: Vec<String>,
    include_sensitive_paths: Vec<String>,
    include_sensitive_chats: Vec<String>,
}

#[derive(Clone)]
struct Approved {
    source: String,
    package_id: String,
    request_id: String,
    plan_sha256: String,
}

pub fn run(args: &[String]) -> control::Result<i32> {
    match args.first().map(String::as_str) {
        Some("import") => return import::run(&args[1..]),
        Some("imports") => return import::status(&args[1..]),
        Some("discard") => return import::discard(&args[1..]),
        Some("export") => {}
        _ => return Err("Use share export --safe SAFE FILE, share export --branch SAFE FILE, share export --all FILE or share import FILE".into()),
    }
    let mut selector = None;
    let mut output = None;
    let mut selection = Selection {
        paths: vec![],
        chat_ids: None,
        exclude_paths: vec![],
        exclude_chats: vec![],
        include_sensitive_paths: vec![],
        include_sensitive_chats: vec![],
    };
    let mut values = args.iter().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--safe" | "--branch" if selector.is_none() => {
                selector = Some((
                    value.as_str(),
                    Some(values.next().ok_or("Missing Safe name")?),
                ))
            }
            "--all" if selector.is_none() => selector = Some(("--all", None)),
            "--path" => selection
                .paths
                .push(values.next().ok_or("Missing guest path")?.clone()),
            "--chat" => selection
                .chat_ids
                .get_or_insert_with(Vec::new)
                .push(values.next().ok_or("Missing chat ID")?.clone()),
            "--no-chats" if selection.chat_ids.is_none() => selection.chat_ids = Some(Vec::new()),
            "--exclude" => selection
                .exclude_paths
                .push(values.next().ok_or("Missing excluded path")?.clone()),
            "--exclude-chat" => selection
                .exclude_chats
                .push(values.next().ok_or("Missing excluded chat ID")?.clone()),
            "--include-sensitive" => selection.include_sensitive_paths.push(
                values
                    .next()
                    .ok_or("Missing reviewed sensitive path")?
                    .clone(),
            ),
            "--include-sensitive-chat" => selection.include_sensitive_chats.push(
                values
                    .next()
                    .ok_or("Missing reviewed sensitive chat ID")?
                    .clone(),
            ),
            value if !value.starts_with('-') && output.is_none() => output = Some(value.to_owned()),
            _ => return Err("Unknown or duplicate Share option".into()),
        }
    }
    let selector = selector.ok_or("Choose --safe NAME, --branch NAME or --all")?;
    if selector.0 != "--safe"
        && selection
            .chat_ids
            .as_ref()
            .is_some_and(|ids| !ids.is_empty())
    {
        return Err("Use --chat with a single --safe export. --exclude-chat applies to branches and all Safes.".into());
    }
    if selection.paths.is_empty() {
        selection
            .paths
            .extend(["workspace".into(), "imports".into()]);
    }
    for path in selection
        .paths
        .iter()
        .chain(&selection.exclude_paths)
        .chain(&selection.include_sensitive_paths)
    {
        validate_path(path)?;
    }
    for chat in selection
        .chat_ids
        .iter()
        .flatten()
        .chain(&selection.exclude_chats)
        .chain(&selection.include_sensitive_chats)
    {
        validate_chat(chat)?;
    }
    let output = std::path::absolute(output.ok_or("Choose an output Share file")?)?;
    let parent = output
        .parent()
        .ok_or("Choose an output directory")?
        .canonicalize()?;
    let output = parent.join(output.file_name().ok_or("Choose an output filename")?);
    if output.try_exists()? {
        return Err("The output file already exists. Choose another filename.".into());
    }
    let state = crate::status()?;
    if state.app_mode != crate::AppMode::Persistent {
        return Err("Unlock writable encrypted storage before sharing Safes".into());
    }
    let selector = if let Some(name) = selector.1 {
        let id = crate::find_safe(&state, name)?.ok_or("Safe not found")?;
        json!({"kind":if selector.0 == "--safe" { "safe" } else { "branch" },"safe_id":id})
    } else {
        json!({"kind":"all"})
    };
    let started: ExportStarted = serde_json::from_str(&control::request(
        "share-export-begin",
        None,
        &serde_json::to_vec(&selector)?,
    )?)?;
    oblivion_share::manifest::validate_id(&started.export_id)?;
    let attached = control::attach_export(&started.export_id);
    let (signal, lease, _client) = match attached {
        Ok(attached) => attached,
        Err(error) => {
            control::request(
                "share-export-end",
                None,
                &serde_json::to_vec(&json!({"export_id":started.export_id}))?,
            )?;
            return Err(error);
        }
    };
    let mut sources = BatchSource {
        export_id: started.export_id,
        signal,
        lease,
        selection,
        approved: vec![],
        current: None,
        ended: false,
    };
    let result = (|| -> control::Result<i32> {
        if started.sources.is_empty() || started.sources.len() > oblivion_share::manifest::MAX_SAFES
        {
            return Err("Invalid Share source set".into());
        }
        let mut ids = BTreeMap::new();
        for source in &started.sources {
            oblivion_share::manifest::validate_id(&source.id)?;
            if ids.insert(source.id.as_str(), random_id()?).is_some() {
                return Err("Duplicate Share source".into());
            }
        }
        let mut package = Package {
            format: "oblivion-share".into(),
            version: 1,
            id: random_id()?,
            safes: vec![],
            settings: started.settings,
        };
        for (index, source) in started.sources.iter().enumerate() {
            eprintln!("Reviewing Safe {} of {}…", index + 1, started.sources.len());
            let metadata = sources.open_source(&source.id, true)?;
            let request = random_id()?;
            let (review, manifest) = sources.plan(&request)?;
            show_review(&metadata.title, &review, &manifest)?;
            let parent = source
                .parent
                .as_deref()
                .and_then(|parent| ids.get(parent))
                .cloned();
            let safe = Safe {
                id: ids
                    .get(source.id.as_str())
                    .ok_or("Share source missing")?
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
                contents_sha256: review.manifest_sha256.clone(),
                entries: manifest.entries().len(),
                bytes: review.bytes,
            };
            sources.approved.push(Approved {
                source: source.id.clone(),
                package_id: safe.id.clone(),
                request_id: request.clone(),
                plan_sha256: review.plan_sha256.clone(),
            });
            package.safes.push(safe);
            sources.cancel_plan(&request)?;
            sources.close_source()?;
        }
        package.validate()?;
        eprintln!(
            "Share {} Safe(s). Provider credential stores and OS customizations are excluded. Content scanning is best effort.",
            package.safes.len()
        );
        if let Some(settings) = &package.settings {
            eprintln!(
                "Included app settings: Safe lock {} min, Oblivion lock {} min (0 means disabled).",
                settings.safe_idle_minutes, settings.host_idle_minutes
            );
        }
        eprintln!(
            "Use --exclude PATH or --exclude-chat UUID to omit more content before confirming a new export."
        );
        if !crate::init_commands::confirm("SHARE")? {
            return Ok(130);
        }
        let passphrase = SecretString::from(String::from_utf8(
            crate::new_password("Separate Share password")?.to_vec(),
        )?);
        let pending = parent.join(format!(".oblivion-share-{}.pending", package.id));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&pending)?;
        let exported = (|| -> control::Result<()> {
            oblivion_share::encrypt(&mut file, passphrase, &package, &mut sources)?;
            file.sync_all()?;
            sources.end()?;
            std::fs::hard_link(&pending, &output)?;
            File::open(&parent)?.sync_all()?;
            Ok(())
        })();
        let cleanup = std::fs::remove_file(&pending);
        exported?;
        cleanup?;
        eprintln!("Encrypted Share saved to {}", output.display());
        Ok(0)
    })();
    let cleanup = sources.end();
    cleanup?;
    result
}

struct Attachment {
    channel: Channel,
    lease: std::os::unix::net::UnixStream,
    client: String,
    opening: oblivion_host::autolock::Opening,
}

struct BatchSource {
    export_id: String,
    signal: std::os::unix::net::UnixStream,
    lease: std::os::unix::net::UnixStream,
    selection: Selection,
    approved: Vec<Approved>,
    current: Option<Attachment>,
    ended: bool,
}

impl BatchSource {
    fn open_source(&mut self, id: &str, prompt: bool) -> control::Result<Metadata> {
        if self.current.is_some() {
            return Err("A Share source is already open".into());
        }
        let slot = crate::free_slot(&crate::status()?)?;
        scope::within(slot, || {
            let payload = serde_json::to_vec(&ExportOpen { export_id: &self.export_id, password: None })?;
            let opened = control::request_for(id, "share-export-source-open", Some(id), &payload);
            let output = match opened {
                Err(error) if error.to_string() == "share_password_required" && prompt => {
                    let password =
                        crate::password(&format!("Password for Safe {}", &id[..8]), false)?;
                    let payload = zeroize::Zeroizing::new(serde_json::to_vec(&ExportOpen {
                        export_id: &self.export_id,
                        password: Some(std::str::from_utf8(&password)?),
                    })?);
                    control::request_for(id, "share-export-source-open", Some(id), &payload)?
                }
                result => result?,
            };
            let metadata: Metadata = serde_json::from_str(&output)?;
            if metadata.opening.safe_id != id || metadata.opening.slot != slot {
                return Err("Share opening changed".into());
            }
            oblivion_share::manifest::validate_id(&metadata.opening.nonce)?;
            let (connection, lease, client) = match control::attach_client("share-attach", id) {
                Ok(attached) => attached,
                Err(error) => {
                    control::request_for(
                        id,
                        "share-export-cancel",
                        None,
                        &serde_json::to_vec(&metadata.opening)?,
                    )?;
                    return Err(error);
                }
            };
            let mut channel = Channel::new(
                File::from(OwnedFd::from(connection)),
                Duration::from_secs(3600),
            )?;
            channel.watch(OwnedFd::from(self.signal.try_clone()?));
            let mut ready = [0; 6];
            channel.read_exact(&mut ready)?;
            if &ready != b"OBSH1\n" {
                return Err("Share guest is not ready".into());
            }
            self.current = Some(Attachment {
                channel,
                lease,
                client,
                opening: metadata.opening.clone(),
            });
            Ok(metadata)
        })
    }

    fn plan(&mut self, request: &str) -> control::Result<(Review, Manifest)> {
        let current = self.current.as_mut().ok_or("Share source missing")?;
        write_message(
            &mut current.channel,
            &json!({"version":1,"operation":"plan","request_id":request,
            "paths":self.selection.paths,"chat_ids":self.selection.chat_ids,"exclude_paths":self.selection.exclude_paths,
            "exclude_chats":self.selection.exclude_chats,"include_sensitive_paths":self.selection.include_sensitive_paths,"include_sensitive_chats":self.selection.include_sensitive_chats}),
        )?;
        let mut review: Review = read_message(&mut current.channel, 10 * 1024 * 1024)?;
        let manifest = validate_review(&mut review, request)?;
        Ok((review, manifest))
    }

    fn cancel_plan(&mut self, request: &str) -> control::Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cancelled {
            version: u8,
            request_id: String,
            ok: bool,
            cancelled: bool,
        }
        let current = self.current.as_mut().ok_or("Share source missing")?;
        write_message(
            &mut current.channel,
            &json!({"version":1,"operation":"cancel","request_id":request}),
        )?;
        let reply: Cancelled = read_message(&mut current.channel, 1024)?;
        if reply.version != 1 || reply.request_id != request || !reply.ok || !reply.cancelled {
            return Err("Share cancellation was not acknowledged".into());
        }
        Ok(())
    }

    fn close_source(&mut self) -> control::Result<()> {
        if let Some(current) = self.current.take() {
            let result = scope::within(current.opening.slot, || {
                control::request_for(
                    &current.opening.safe_id,
                    "share-release",
                    Some(&current.client),
                    &[],
                )
            });
            drop(current.channel);
            drop(current.lease);
            result?;
        }
        Ok(())
    }

    fn end(&mut self) -> control::Result<()> {
        if self.ended {
            return Ok(());
        }
        let result = control::request(
            "share-export-end",
            None,
            &serde_json::to_vec(&json!({"export_id":self.export_id}))?,
        );
        self.current = None;
        if result.is_ok() {
            self.ended = true;
        }
        // Retain the lease until End acknowledgement. EOF is a second bounded
        // revocation path, never authority to open a different source.
        let _keep_alive = &self.lease;
        result.map(|_| ())
    }
}

impl Source for BatchSource {
    fn open<'a>(&'a mut self, safe: &Safe) -> io::Result<Box<dyn Read + 'a>> {
        let result = (|| -> control::Result<()> {
            let approved = self
                .approved
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("Unreviewed Share source")?
                .clone();
            let metadata = self.open_source(&approved.source, false)?;
            eprintln!("Sharing {}…", metadata.title);
            let (review, manifest) = self.plan(&approved.request_id)?;
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
            let channel = &mut self.current.as_mut().ok_or("Share source missing")?.channel;
            write_message(
                channel,
                &json!({"version":1,"operation":"confirm","request_id":approved.request_id,"plan_sha256":approved.plan_sha256}),
            )?;
            Ok(())
        })();
        result.map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Box::new(
            &mut self
                .current
                .as_mut()
                .ok_or_else(|| io::Error::other("share_source_missing"))?
                .channel,
        ))
    }
    fn complete(&mut self, safe: &Safe, manifest: &Manifest) -> io::Result<()> {
        let result = (|| -> control::Result<()> {
            let approved = self
                .approved
                .iter()
                .find(|entry| entry.package_id == safe.id)
                .ok_or("Unreviewed Share source")?;
            let channel = &mut self.current.as_mut().ok_or("Share source missing")?.channel;
            write_message(
                channel,
                &Receipt {
                    id: approved.request_id.clone(),
                    manifest_sha256: manifest.sha256(),
                    entries: manifest.entries().len(),
                    bytes: manifest.bytes(),
                },
            )?;
            let mut ack = [0; 7];
            channel.read_exact(&mut ack)?;
            if &ack != b"copied\n" {
                return Err("Share receipt unconfirmed".into());
            }
            self.close_source()
        })();
        result.map_err(|error| io::Error::other(error.to_string()))
    }
}

fn show_review(title: &str, review: &Review, manifest: &Manifest) -> control::Result<()> {
    eprintln!(
        "{title} · {} entries · {} bytes · {} conversations",
        manifest.entries().len(),
        review.bytes,
        review.chats.len()
    );
    for entry in manifest.entries() {
        eprintln!(
            "  {}{}",
            entry.path(),
            if matches!(entry, Entry::Directory { .. }) {
                "/"
            } else {
                ""
            }
        );
    }
    for (kind, count) in &review.omitted {
        eprintln!("  Omitted {kind}: {count}");
    }
    for warning in &review.warnings {
        eprintln!(
            "  {}: {} · {}",
            warning.reason,
            warning
                .path
                .as_deref()
                .or(warning.chat_id.as_deref())
                .unwrap_or("selection"),
            if warning.included {
                "included"
            } else {
                "excluded"
            }
        );
    }
    if review.warning_count > review.warnings.len() as u64 {
        return Err("Too many Share warnings to review; narrow the selection".into());
    }
    Ok(())
}

fn validate_review(review: &mut Review, request: &str) -> io::Result<Manifest> {
    let hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if review.version != 1
        || review.request_id != request
        || !hash(&review.plan_sha256)
        || review.chats.len() > 2048
        || review.chats.iter().collect::<BTreeSet<_>>().len() != review.chats.len()
        || review.warnings.len() > 512
        || review.warning_count < review.warnings.len() as u64
        || review.omitted.len() > 64
        || !review.scan.best_effort
        || review.scan.limit_per_kind != 16 * 1024 * 1024
        || review.scan.files_bytes > review.scan.limit_per_kind
        || review.scan.history_bytes > review.scan.limit_per_kind
    {
        return Err(io::Error::other("invalid_share_review"));
    }
    for chat in &review.chats {
        validate_chat(chat)?;
    }
    for kind in review.omitted.keys() {
        if kind.len() > 64
            || kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(io::Error::other("invalid_share_review"));
        }
    }
    for warning in &review.warnings {
        if !matches!(
            warning.reason.as_str(),
            "credential_store_excluded"
                | "invalid_name_excluded"
                | "unsupported_entry_excluded"
                | "potential_secret"
                | "partial_content_scan"
        ) || warning.path.is_some() == warning.chat_id.is_some()
            || warning.default_excluded.is_some_and(|value| !value)
        {
            return Err(io::Error::other("invalid_share_warning"));
        }
        if let Some(path) = &warning.path {
            validate_path(path)?;
        }
        if let Some(chat) = &warning.chat_id {
            validate_chat(chat)?;
        }
    }
    let manifest = Manifest::new(
        std::mem::take(&mut review.manifest),
        oblivion_transfer::share::LIMITS,
    )?;
    oblivion_transfer::share::validate_manifest(&manifest)?;
    if manifest.sha256() != review.manifest_sha256 || manifest.bytes() != review.bytes {
        return Err(io::Error::other("share_review_changed"));
    }
    Ok(manifest)
}

fn validate_path(value: &str) -> io::Result<()> {
    oblivion_transfer::browser::Request {
        path: value.into(),
        after: None,
        limit: 1,
    }
    .validate()?;
    if !matches!(value.split('/').next(), Some("workspace" | "imports")) {
        return Err(io::Error::other("share_root_not_allowed"));
    }
    Ok(())
}

fn validate_chat(value: &str) -> io::Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(io::Error::other("invalid_portable_chat_identity"));
    }
    Ok(())
}

fn random_id() -> io::Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_accepts_the_real_guest_plan_and_keeps_secret_candidates_out() {
        let root =
            std::env::temp_dir().join(format!("oblivion-share-review-{}", random_id().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let output = std::process::Command::new("python3").args(["-I", "-B", "-c", r#"
import json,pathlib,sys
repo,vault=map(pathlib.Path,sys.argv[1:])
sys.path[:0]=[str(repo/'guest'),str(repo.parent/'oblivion-history')]
from share_plan import Plan
(vault/'workspace'/'project').mkdir(parents=True)
(vault/'imports').mkdir()
(vault/'workspace'/'project'/'caffè.txt').write_text('public synthetic fixture')
(vault/'workspace'/'project'/'.env').write_text('PUBLIC_TEST_ONLY=not-a-real-secret')
request={'version':1,'operation':'plan','request_id':'1'*32,'paths':['workspace','imports'],'chat_ids':[],
'exclude_paths':[],'exclude_chats':[],'include_sensitive_paths':[],'include_sensitive_chats':[]}
plan=Plan(vault,request)
try: print(json.dumps(plan.public,ensure_ascii=False))
finally: plan.close()
"#]).arg(env!("CARGO_MANIFEST_DIR")).arg(&root).output().unwrap();
        let result = (|| {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut review: Review = serde_json::from_slice(&output.stdout).unwrap();
            let manifest = validate_review(&mut review, &"1".repeat(32)).unwrap();
            assert!(
                manifest
                    .entries()
                    .iter()
                    .any(|entry| entry.path() == "workspace/project/caffè.txt")
            );
            assert!(
                !manifest
                    .entries()
                    .iter()
                    .any(|entry| entry.path().ends_with("/.env"))
            );
            assert!(review.warnings.iter().any(|warning| warning.path.as_deref()
                == Some("workspace/project/.env")
                && !warning.included));
            let mut escaped: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            escaped["warnings"][0]["path"] = json!("workspace/../outside");
            assert!(
                validate_review(
                    &mut serde_json::from_value(escaped).unwrap(),
                    &"1".repeat(32)
                )
                .is_err()
            );
        })();
        std::fs::remove_dir_all(&root).unwrap();
        result
    }
}
