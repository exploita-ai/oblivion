//! Windows source authority for reviewed native Files imports. Local paths
//! remain in this process; the peer receives only the common manifest aliases.
use crate::directory::{Directory, canonical_path, verify_source};
use crate::file_identity::FileIdentity;
use crate::selection::{self, Input, Plan};
use crate::{
    END, Entry, Limits, MAX_ENTRIES, Manifest, copy_hash, invalid, require, validate_path,
};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct SourceSelection {
    manifest: Manifest,
    plan: Plan,
    files: Vec<Source>,
    directories: Vec<SourceDirectory>,
}

struct Source {
    file: File,
    identity: FileIdentity,
    size: u64,
    modified: SystemTime,
    _parent: Directory,
}

struct SourceDirectory {
    directory: Directory,
    names: Vec<String>,
}

struct Collection {
    entries: Vec<Entry>,
    files: Vec<Source>,
    directories: Vec<SourceDirectory>,
    bytes: u64,
    limits: Limits,
}

impl SourceSelection {
    pub fn prepare(
        paths: &[PathBuf],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        require(
            (1..=selection::MAX_SELECTIONS).contains(&paths.len()),
            "selection_limit",
        )?;
        let mut collection = Collection::new(limits)?;
        let keys = paths
            .iter()
            .map(|path| local_key(path, false))
            .collect::<io::Result<Vec<_>>>()?;
        selection::validate_paths(&keys)?;
        let mut chosen = Vec::with_capacity(paths.len());
        for key in keys {
            check()?;
            let path = PathBuf::from(key.replace('/', "\\"));
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("invalid_source_name"))?;
            let parent = Directory::open(
                path.parent()
                    .ok_or_else(|| invalid("invalid_source_root"))?,
            )?;
            let file = parent.source(name)?;
            let canonical = local_key(&canonical_path(&file)?, true)?;
            let directory = file.metadata()?.is_dir();
            chosen.push((
                parent,
                file,
                Input {
                    path: canonical,
                    directory,
                },
            ));
        }
        let plan = Plan::new(
            &chosen
                .iter()
                .map(|(_, _, input)| Input {
                    path: input.path.clone(),
                    directory: input.directory,
                })
                .collect::<Vec<_>>(),
        )?;
        if paths.len() > 1 {
            collection.entries.push(Entry::Directory {
                path: plan.selected.clone(),
            });
        }
        for (index, (parent, file, _)) in chosen.into_iter().enumerate() {
            if let Some(path) = plan.manifest_path(index) {
                collection.collect(parent, file, &path, check)?;
            }
        }
        let manifest = Manifest::new(collection.entries, limits)?;
        let selection = Self {
            manifest,
            plan,
            files: collection.files,
            directories: collection.directories,
        };
        selection.verify()?;
        Ok(selection)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Rehash a pinned private selection with the same collector used by native
    /// imports. Recovery supplies the directory capability, not a host path.
    pub(crate) fn manifest_at(
        root: &Directory,
        paths: &[String],
        limits: Limits,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Manifest> {
        let mut collection = Collection::new(limits)?;
        for path in paths {
            check()?;
            validate_path(path)?;
            let mut components = path.split('/').peekable();
            let mut parent = root.clone()?;
            let mut prefix = String::new();
            while let Some(component) = components.next() {
                if components.peek().is_none() {
                    let file = parent.source(component)?;
                    collection.collect(parent, file, path, check)?;
                    break;
                }
                parent = parent.directory(component)?;
                if !prefix.is_empty() {
                    prefix.push('/')
                }
                prefix.push_str(component);
                if !collection
                    .entries
                    .iter()
                    .any(|entry| entry.path() == prefix)
                {
                    require(collection.entries.len() < limits.entries, "entry_limit")?;
                    collection.entries.push(Entry::Directory {
                        path: prefix.clone(),
                    });
                }
            }
        }
        collection.verify()?;
        Manifest::new(collection.entries, limits)
    }

    /// Uses the exact already pinned files after approval. A changed source
    /// withholds END, so the common receiver cannot publish a verified copy.
    pub fn send_data(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.verify()?;
        let mut sources = self.files.iter_mut();
        for entry in self.manifest.entries() {
            if let Entry::File { size, sha256, .. } = entry {
                let source = sources.next().ok_or_else(|| invalid("source_changed"))?;
                source.verify()?;
                source.file.rewind()?;
                require(
                    copy_hash(&mut source.file, writer, *size)? == *sha256,
                    "source_changed",
                )?;
                source.verify()?;
            }
        }
        self.verify()?;
        writer.write_all(END)?;
        writer.flush()
    }

    fn verify(&self) -> io::Result<()> {
        for source in &self.files {
            source.verify()?
        }
        for directory in &self.directories {
            directory.verify()?
        }
        Ok(())
    }
}

impl crate::copy_protocol::Source for SourceSelection {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.send_data(writer)
    }
}

impl Collection {
    fn new(limits: Limits) -> io::Result<Self> {
        require(
            limits.entries > 0 && limits.entries <= MAX_ENTRIES,
            "invalid_entry_limit",
        )?;
        Ok(Self {
            entries: Vec::new(),
            files: Vec::new(),
            directories: Vec::new(),
            bytes: 0,
            limits,
        })
    }

    fn collect(
        &mut self,
        parent: Directory,
        file: File,
        path: &str,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        validate_path(path)?;
        require(self.entries.len() < self.limits.entries, "entry_limit")?;
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            let directory = Directory::from_file(file)?;
            self.entries.push(Entry::Directory { path: path.into() });
            let names = directory.names(self.limits.entries - self.entries.len())?;
            for name in &names {
                let file = directory.source(name)?;
                self.collect(directory.clone()?, file, &format!("{path}/{name}"), check)?;
            }
            let source = SourceDirectory { directory, names };
            source.verify()?;
            self.directories.push(source);
            return Ok(());
        }
        require(metadata.is_file(), "unsupported_source")?;
        let identity = FileIdentity::of(&file)?;
        self.bytes = self
            .bytes
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("byte_limit"))?;
        require(self.bytes <= self.limits.bytes, "byte_limit")?;
        let mut source = Source {
            identity,
            size: metadata.len(),
            modified: metadata.modified()?,
            _parent: parent,
            file,
        };
        let sha256 = copy_hash(
            &mut CheckedRead {
                file: &mut source.file,
                check,
            },
            &mut io::sink(),
            source.size,
        )?;
        source.verify()?;
        self.entries.push(Entry::File {
            path: path.into(),
            size: source.size,
            sha256,
        });
        self.files.push(source);
        Ok(())
    }

    fn verify(&self) -> io::Result<()> {
        for source in &self.files {
            source.verify()?
        }
        for directory in &self.directories {
            directory.verify()?
        }
        Ok(())
    }
}

impl Source {
    fn verify(&self) -> io::Result<()> {
        verify_source(&self.file)?;
        let metadata = self.file.metadata()?;
        require(
            self.identity.matches(&self.file)?
                && metadata.is_file()
                && metadata.len() == self.size
                && metadata.modified()? == self.modified,
            "source_changed",
        )
    }
}

impl SourceDirectory {
    fn verify(&self) -> io::Result<()> {
        require(
            self.directory.names(self.names.len())? == self.names,
            "source_changed",
        )
    }
}

struct CheckedRead<'a> {
    file: &'a mut File,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}

impl Read for CheckedRead<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // Cancellation is terminal; read_exact retries Interrupted I/O errors.
        (self.check)().map_err(|error| {
            if error.kind() == io::ErrorKind::Interrupted {
                return io::Error::other(error);
            }
            error
        })?;
        self.file.read(output)
    }
}

fn local_key(path: &Path, canonical: bool) -> io::Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("invalid_file_source"))?;
    let text = if canonical {
        text.strip_prefix(r"\\?\").unwrap_or(text)
    } else {
        text
    };
    // Keep literal components for the common planner: Path::components would
    // normalize an interior '.' before it can reject ambiguous source paths.
    let mut key = text.replace('\\', "/");
    let drive = *key
        .as_bytes()
        .first()
        .ok_or_else(|| invalid("invalid_file_source"))?;
    require(
        drive.is_ascii_alphabetic() && key.as_bytes().get(1..3) == Some(b":/"),
        "invalid_file_source",
    )?;
    key.replace_range(..1, &(drive as char).to_ascii_uppercase().to_string());
    Ok(key)
}
