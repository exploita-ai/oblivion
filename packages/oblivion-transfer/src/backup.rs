//! Native personal backups carry one opaque LUKS2 volume. Local filenames and
//! private publication authority never enter the existing ciphertext protocol.
use crate::copy_protocol;
use crate::local_file::Input;
use crate::{
    ENCRYPTED_VOLUME_NAME, END, Entry, Limits, MAX_ENCRYPTED_VOLUME_BYTES, Manifest, copy_hash,
    invalid, require,
};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::Path;

pub struct Source {
    manifest: Manifest,
    input: Input,
}
impl Source {
    pub fn open(path: &Path, maximum: u64) -> io::Result<Self> {
        Self::from_input(Input::open(path)?, maximum)
    }
    pub fn from_file(file: File, maximum: u64) -> io::Result<Self> {
        Self::from_input(Input::from_file(file)?, maximum)
    }
    fn from_input(mut input: Input, maximum: u64) -> io::Result<Self> {
        require(
            (32 * 1024 * 1024..=MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
            "invalid_backup_limit",
        )?;
        let size = input.size()?;
        require((32 * 1024 * 1024..=maximum).contains(&size), "byte_limit")?;
        input.rewind()?;
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        require(
            &magic == b"LUKS\xba\xbe\x00\x02",
            "invalid_encrypted_volume",
        )?;
        input.rewind()?;
        let sha256 = copy_hash(&mut input, &mut io::sink(), size)?;
        require(input.size()? == size, "source_changed")?;
        input.verify()?;
        Ok(Self {
            input,
            manifest: Manifest::new(
                vec![Entry::File {
                    path: ENCRYPTED_VOLUME_NAME.into(),
                    size,
                    sha256,
                }],
                Limits {
                    entries: 1,
                    bytes: maximum,
                },
            )?,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn bytes(&self) -> u64 {
        self.manifest.bytes()
    }
    #[cfg(unix)]
    pub(crate) fn into_parts(self) -> (Manifest, File) {
        (self.manifest, self.input.into_file())
    }
}
impl copy_protocol::Source for Source {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        write_volume(self.input.file_mut(), &self.manifest, writer)
    }
}

pub(crate) fn write_volume(
    file: &mut File,
    manifest: &Manifest,
    writer: &mut impl Write,
) -> io::Result<()> {
    let [Entry::File { size, sha256, .. }] = manifest.entries() else {
        return Err(invalid("invalid_backup_selection"));
    };
    crate::local_file::verify_input(file)?;
    require(file.metadata()?.len() == *size, "source_changed")?;
    file.rewind()?;
    require(
        copy_hash(file, writer, *size)? == *sha256 && file.metadata()?.len() == *size,
        "source_changed",
    )?;
    crate::local_file::verify_input(file)?;
    writer.write_all(END)?;
    writer.flush()
}
