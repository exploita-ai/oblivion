//! Existing agent stream: one kind byte, u32-BE payload length, then raw bytes.
//! Linux signal numbers carried by kind 6 belong to the guest protocol, never
//! to the desktop OS. Agent argv remains data, not shell source.
use crate::frame;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const LIMIT: usize = 65536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    pub fn valid(self) -> bool {
        (1..=1000).contains(&self.rows) && (1..=1000).contains(&self.cols)
    }
}

pub fn write_frame(writer: &mut impl Write, kind: u8, payload: &[u8]) -> Result<(), frame::Error> {
    // Validate before emitting the kind so a rejected write emits no prefix.
    if payload.len() > LIMIT {
        return Err(frame::Error::InvalidLength);
    }
    writer.write_all(&[kind])?;
    frame::write(writer, payload, 0..=LIMIT)
}

pub fn read_frame(reader: &mut impl Read) -> Result<(u8, Vec<u8>), frame::Error> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;
    Ok((kind[0], frame::read(reader, 0..=LIMIT)?))
}
