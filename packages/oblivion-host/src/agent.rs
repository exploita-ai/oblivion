//! Native error mapping for the shared guest agent protocol.
use crate::control::Result;
pub use oblivion_wire::agent::{Command, LIMIT, Launch, Size};
use oblivion_wire::frame;
use std::io::{Read, Write};

pub fn write_frame(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    oblivion_wire::agent::write_frame(stream, kind, payload).map_err(frame_error)
}

pub fn read_frame(stream: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    oblivion_wire::agent::read_frame(stream).map_err(frame_error)
}

fn frame_error(error: frame::Error) -> Box<dyn std::error::Error> {
    match error {
        frame::Error::InvalidLength => "agent_frame_too_large".into(),
        frame::Error::Io(error) => error.into(),
    }
}
