//! Windows receiver I/O for the common Files journal and publication policy.
//! Staging uses the explicitly reviewed destination's own volume; no fallback
//! directory, overwrite or second completion protocol exists.
use crate::directory::Directory;
use crate::{END, Entry, Manifest, Receipt, copy_hash, invalid, require, validate_id};
use std::collections::BTreeMap;
use std::io::{self, Read};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

/// Validate every native name and case-insensitive sibling collision before
/// review. Invalid internal project names are rejected, never silently renamed.
pub(crate) fn validate(manifest: &Manifest, publication_name: &str) -> io::Result<()> {
    crate::directory::validate_name(publication_name)?;
    let mut siblings: BTreeMap<&str, Vec<Vec<u16>>> = BTreeMap::new();
    for entry in manifest.entries() {
        for component in entry.path().split('/') {
            crate::directory::validate_name(component)?;
        }
        let (parent, name) = entry.path().rsplit_once('/').unwrap_or(("", entry.path()));
        siblings
            .entry(parent)
            .or_default()
            .push(name.encode_utf16().collect());
    }
    for names in siblings.values_mut() {
        let mut valid = true;
        names.sort_by(|left, right| {
            let order = unsafe {
                CompareStringOrdinal(
                    left.as_ptr(),
                    left.len() as i32,
                    right.as_ptr(),
                    right.len() as i32,
                    1,
                )
            };
            valid &= order != 0;
            order.cmp(&CSTR_EQUAL)
        });
        require(valid, "native_name_comparison_failed")?;
        for pair in names.windows(2) {
            let order = unsafe {
                CompareStringOrdinal(
                    pair[0].as_ptr(),
                    pair[0].len() as i32,
                    pair[1].as_ptr(),
                    pair[1].len() as i32,
                    1,
                )
            };
            require(order != 0 && order != CSTR_EQUAL, "native_name_collision")?;
        }
    }
    Ok(())
}

pub(crate) fn receive_at(
    reader: &mut impl Read,
    manifest: &Manifest,
    root: &Directory,
    id: &str,
) -> io::Result<Receipt> {
    validate_id(id)?;
    root.require_private()?;
    let transaction = root.create_directory(id)?;
    let result = receive_transaction(reader, manifest, &transaction);
    if let Err(error) = result {
        drop(transaction);
        root.remove_directory(id)?;
        root.sync()?;
        return Err(error);
    }
    root.sync()?;
    let receipt = Receipt {
        id: id.to_owned(),
        manifest_sha256: manifest.sha256(),
        entries: manifest.entries().len(),
        bytes: manifest.bytes(),
    };
    let mut file = transaction.create_file("receipt.pending")?;
    serde_json::to_writer(&mut file, &receipt).map_err(|_| invalid("invalid_receipt"))?;
    file.sync_all()?;
    drop(file);
    transaction.rename("receipt.pending", "receipt.json")?;
    transaction.sync()?;
    Ok(receipt)
}

fn receive_transaction(
    reader: &mut impl Read,
    manifest: &Manifest,
    transaction: &Directory,
) -> io::Result<()> {
    let pending = transaction.create_directory("pending")?;
    for entry in manifest.entries() {
        let mut components = entry.path().split('/').peekable();
        let mut parent = pending.clone()?;
        while let Some(name) = components.next() {
            if components.peek().is_some() {
                parent = parent.directory(name)?;
                continue;
            }
            match entry {
                Entry::Directory { .. } => {
                    parent.create_directory(name)?.sync()?;
                }
                Entry::File { size, sha256, .. } => {
                    let mut file = parent.create_file(name)?;
                    require(
                        &copy_hash(reader, &mut file, *size)? == sha256,
                        "digest_mismatch",
                    )?;
                    file.sync_all()?;
                }
            }
            parent.sync()?;
        }
    }
    let mut end = [0; 8];
    reader.read_exact(&mut end)?;
    require(&end == END, "transfer_incomplete")?;
    pending.sync()?;
    drop(pending);
    transaction.rename("pending", "files")?;
    transaction.sync()
}
