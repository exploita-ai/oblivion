//! Bounded u32 big-endian frames over any byte stream.
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::InvalidLength => f.write_str("invalid_frame_length"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidLength => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn read(reader: &mut impl Read, bounds: RangeInclusive<usize>) -> Result<Vec<u8>, Error> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if !bounds.contains(&length) {
        return Err(Error::InvalidLength);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write(
    writer: &mut impl Write,
    bytes: &[u8],
    bounds: RangeInclusive<usize>,
) -> Result<(), Error> {
    if !bounds.contains(&bytes.len()) || bytes.len() > u32::MAX as usize {
        return Err(Error::InvalidLength);
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}
