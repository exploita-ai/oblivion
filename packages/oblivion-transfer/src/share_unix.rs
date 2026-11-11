use super::{LIMITS, validate_manifest};
use crate::{Entry, Manifest, Receipt, Selection, invalid, require, validate_id};
use crate::channel::Channel;
use crate::directory::Directory;
use crate::endpoint::read_message;
use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const PLAN_LIMIT: u64 = 24 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approved {
    version: u8,
    request_id: String,
    manifest_sha256: String,
    entries: Vec<Entry>,
    aliases: Vec<String>,
}

/// FD4 carries the locally approved planner output, never a path supplied by
/// a peer. The source aliases cannot expand beyond portable roots or the one
/// generated native-transfer index for this request.
pub fn send(channel: &mut Channel, root: &Path, plan: File) -> io::Result<Receipt> {
    let info = plan.metadata()?;
    require(info.is_file() && info.nlink() <= 1 && (1..=PLAN_LIMIT).contains(&info.len()), "invalid_share_plan")?;
    let mut bytes = Vec::new();
    plan.take(PLAN_LIMIT + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= PLAN_LIMIT, "invalid_share_plan")?;
    let plan: Approved = serde_json::from_slice(&bytes).map_err(|_| invalid("invalid_share_plan"))?;
    require(plan.version == 1, "unsupported_share_plan")?;
    validate_id(&plan.request_id)?;
    let manifest = Manifest::new(plan.entries, LIMITS)?;
    validate_manifest(&manifest)?;
    require(manifest.sha256() == plan.manifest_sha256, "share_plan_changed")?;
    let files = manifest.entries().iter().filter_map(|entry| matches!(entry, Entry::File { .. }).then_some(entry.path())).collect::<Vec<_>>();
    require(files.len() == plan.aliases.len(), "invalid_share_aliases")?;
    for (destination, alias) in files.into_iter().zip(&plan.aliases) {
        let expected = if destination == "history/chats.jsonl" {
            format!("state/.oblivion-share/{}/chats.jsonl", plan.request_id)
        } else { destination.to_owned() };
        require(*alias == expected, "invalid_share_alias")?;
    }
    let mut selected = Selection::approved(root, manifest, &plan.aliases)?;
    selected.manifest().write(channel)?;
    selected.send_data(channel)?;
    let receipt: Receipt = read_message(channel, 1024)?;
    require(receipt.id == plan.request_id && receipt.manifest_sha256 == selected.manifest().sha256()
        && receipt.entries == selected.manifest().entries().len() && receipt.bytes == selected.manifest().bytes(), "invalid_share_receipt")?;
    // The guest wrapper removes generated native-history staging before acknowledging
    // completion to the controller. Do not use EOF as that acknowledgement.
    Ok(receipt)
}

/// A new destination Safe receives only reviewed portable data in its private
/// inbox. The guest wrapper imports native histories and fixes ownership
/// before it returns this receipt to the controller. No Safe is published here.
pub fn receive(channel: &mut Channel, inbox: &Path, id: &str) -> io::Result<Receipt> {
    validate_id(id)?;
    let directory = Directory::open(inbox)?;
    directory.require_private()?;
    directory.lock()?;
    let manifest = Manifest::read(channel, LIMITS)?;
    validate_manifest(&manifest)?;
    crate::receive(channel, &manifest, inbox, id)
}
