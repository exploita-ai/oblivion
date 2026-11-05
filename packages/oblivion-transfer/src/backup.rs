//! Native personal backups carry one opaque LUKS2 volume. Local filenames and
//! private publication authority never enter the existing ciphertext protocol.
use crate::copy_protocol;
use crate::directory::Directory;
use crate::{
    ENCRYPTED_VOLUME_NAME, END, Entry, Limits, MAX_ENCRYPTED_VOLUME_BYTES, Manifest, copy_hash,
    invalid, require, validate_id,
};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

pub struct Source {
    manifest: Manifest,
    file: File,
    _parent: Option<Directory>,
}
impl Source {
    pub fn open(path: &Path, maximum: u64) -> io::Result<Self> {
        let path = absolute(path)?;
        let name = leaf(&path)?;
        let parent = Directory::open(
            path.parent()
                .ok_or_else(|| invalid("invalid_backup_source"))?,
        )?;
        let mut source = Self::from_file(parent.source(name)?, maximum)?;
        source._parent = Some(parent);
        Ok(source)
    }

    pub fn from_file(mut file: File, maximum: u64) -> io::Result<Self> {
        require(
            (32 * 1024 * 1024..=MAX_ENCRYPTED_VOLUME_BYTES).contains(&maximum),
            "invalid_backup_limit",
        )?;
        source_file(&file)?;
        let size = file.metadata()?.len();
        require((32 * 1024 * 1024..=maximum).contains(&size), "byte_limit")?;
        file.rewind()?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        require(
            &magic == b"LUKS\xba\xbe\x00\x02",
            "invalid_encrypted_volume",
        )?;
        file.rewind()?;
        let sha256 = copy_hash(&mut file, &mut io::sink(), size)?;
        require(file.metadata()?.len() == size, "source_changed")?;
        source_file(&file)?;
        Ok(Self {
            file,
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
            _parent: None,
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
        (self.manifest, self.file)
    }
}
impl copy_protocol::Source for Source {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn write_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        write_volume(&mut self.file, &self.manifest, writer)
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
    source_file(file)?;
    require(file.metadata()?.len() == *size, "source_changed")?;
    file.rewind()?;
    require(
        copy_hash(file, writer, *size)? == *sha256 && file.metadata()?.len() == *size,
        "source_changed",
    )?;
    source_file(file)?;
    writer.write_all(END)?;
    writer.flush()
}

pub struct OutputTarget {
    parent: Directory,
    name: String,
    path: PathBuf,
}
impl OutputTarget {
    pub fn new(path: &Path) -> io::Result<Self> {
        let path = absolute(path)?;
        let name = leaf(&path)?.to_owned();
        #[cfg(unix)]
        crate::native_files::validate_name(&name)?;
        #[cfg(windows)]
        crate::directory::validate_name(&name)?;
        let parent = Directory::open(
            path.parent()
                .ok_or_else(|| invalid("invalid_backup_destination"))?,
        )?;
        parent.require_controlled()?;
        match parent.source(&name) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "backup_output_exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(Self { parent, name, path })
    }

    pub fn create(self, transaction: &str) -> io::Result<Output> {
        validate_id(transaction)?;
        let temporary = format!(".oblivion-backup-{transaction}.partial");
        let file = self.parent.create_file(&temporary)?;
        destination_file(&file, true)?;
        Ok(Output {
            target: self,
            temporary: Some(temporary),
            file,
        })
    }
}

pub struct Output {
    target: OutputTarget,
    temporary: Option<String>,
    file: File,
}
impl Output {
    pub fn path(&self) -> &Path {
        &self.target.path
    }
    pub fn copy_file(&self) -> io::Result<File> {
        self.file.try_clone()
    }
    pub fn publish(&mut self) -> io::Result<()> {
        let temporary = self
            .temporary
            .as_deref()
            .ok_or_else(|| invalid("backup_output_unavailable"))?;
        destination_file(&self.file, false)?;
        self.file.sync_all()?;
        self.target.parent.move_file_exclusive(
            temporary,
            &self.target.parent,
            &self.target.name,
            &self.file,
        )?;
        // Publication may have happened even if the following directory flush
        // fails. Drop must never remove the published output in that case.
        self.temporary = None;
        self.target.parent.sync()
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        if let Some(name) = self.temporary.take() {
            let _ = self.target.parent.remove_file(&name, &self.file);
        }
    }
}

pub(crate) fn destination_file(file: &File, empty: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let metadata = file.metadata()?;
        require(
            flags >= 0
                && flags & libc::O_ACCMODE != libc::O_RDONLY
                && flags & libc::O_APPEND == 0
                && metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0,
            "unsafe_backup_destination",
        )?;
    }
    #[cfg(windows)]
    {
        use oblivion_native_windows::security::{FilePolicy, Identity, file_permissions};
        use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;
        crate::directory::verify_source(file)?;
        require(
            file.metadata()?.is_file() && access(file)? & FILE_WRITE_DATA != 0,
            "unsafe_backup_destination",
        )?;
        let identity = Identity::current().map_err(|error| invalid(error.0))?;
        file_permissions(file, identity.sid(), FilePolicy::Private)
            .map_err(|error| invalid(error.0))?;
    }
    require(
        !empty || file.metadata()?.len() == 0,
        "unsafe_backup_destination",
    )
}

fn source_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "source_not_read_only",
        )?;
        let metadata = file.metadata()?;
        require(
            metadata.is_file() && metadata.nlink() == 1,
            "unsupported_source",
        )?;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA,
        };
        crate::directory::verify_source(file)?;
        let access = access(file)?;
        require(
            access & FILE_READ_DATA != 0 && access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0,
            "source_not_read_only",
        )?;
        require(file.metadata()?.is_file(), "unsupported_source")?;
    }
    Ok(())
}

#[cfg(windows)]
fn access(file: &File) -> io::Result<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_ACCESS_INFORMATION, FileAccessInformation, NtQueryInformationFile,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    let mut status = IO_STATUS_BLOCK::default();
    let mut information = FILE_ACCESS_INFORMATION::default();
    let result = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&mut information as *mut FILE_ACCESS_INFORMATION).cast(),
            size_of::<FILE_ACCESS_INFORMATION>() as u32,
            FileAccessInformation,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    Ok(information.AccessFlags)
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    let path = std::path::absolute(path)?;
    #[cfg(windows)]
    let path = PathBuf::from(
        path.to_str()
            .ok_or_else(|| invalid("invalid_backup_path"))?
            .replace('/', "\\"),
    );
    Ok(path)
}
fn leaf(path: &Path) -> io::Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid("invalid_backup_path"))
}
