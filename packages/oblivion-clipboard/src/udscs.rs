// udscs protocol — matches spice-vdagent/src/udscs.h
//
// Header: type(4) + arg1(4) + arg2(4) + size(4) = 16 bytes
// Followed by `size` bytes of data

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

const HDR_SIZE: usize = 16;
pub const MAX_PAYLOAD: usize = 256 * 1024;

// Message types — matches vdagentd-proto.h enum
pub const VDAGENTD_GUEST_XORG_RESOLUTION: u32 = 0;
pub const VDAGENTD_CLIPBOARD_GRAB: u32 = 2;
pub const VDAGENTD_CLIPBOARD_REQUEST: u32 = 3;
pub const VDAGENTD_CLIPBOARD_DATA: u32 = 4;
pub const VDAGENTD_CLIPBOARD_RELEASE: u32 = 5;
pub const VDAGENTD_VERSION: u32 = 6;
pub const VDAGENTD_CLIENT_DISCONNECTED: u32 = 12;
pub const VDAGENTD_GRAPHICS_DEVICE_INFO: u32 = 13;

// Clipboard types — matches spice/vd_agent.h
pub const VD_AGENT_CLIPBOARD_NONE: u32 = 0;
pub const VD_AGENT_CLIPBOARD_UTF8_TEXT: u32 = 1;

#[allow(dead_code)]
pub struct UdscsMsg {
    pub msg_type: u32,
    pub arg1: u32,
    pub arg2: u32,
    pub data: Vec<u8>,
}

pub fn read_msg(stream: &mut UnixStream) -> io::Result<UdscsMsg> {
    let mut hdr = [0u8; HDR_SIZE];
    stream.read_exact(&mut hdr)?;

    let msg_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let arg1 = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let arg2 = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let size = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;

    if size > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "clipboard_limit",
        ));
    }
    let mut data = vec![0u8; size];
    if size > 0 {
        stream.read_exact(&mut data)?;
    }

    Ok(UdscsMsg {
        msg_type,
        arg1,
        arg2,
        data,
    })
}

pub fn send_msg(stream: &UnixStream, msg_type: u32, arg1: u32, arg2: u32, data: &[u8]) {
    if data.len() > MAX_PAYLOAD {
        return;
    }
    let mut buf = Vec::with_capacity(HDR_SIZE + data.len());
    buf.extend_from_slice(&msg_type.to_le_bytes());
    buf.extend_from_slice(&arg1.to_le_bytes());
    buf.extend_from_slice(&arg2.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    let _ = (&*stream).write_all(&buf);
    let _ = (&*stream).flush();
}

#[cfg(test)]
mod tests {
    use super::{
        read_msg, send_msg, MAX_PAYLOAD, VDAGENTD_CLIPBOARD_DATA, VD_AGENT_CLIPBOARD_UTF8_TEXT,
    };
    use std::io::{ErrorKind, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    #[test]
    fn text_round_trip_preserves_utf8() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_msg(
            &sender,
            VDAGENTD_CLIPBOARD_DATA,
            0,
            VD_AGENT_CLIPBOARD_UTF8_TEXT,
            "Città\nOblivion".as_bytes(),
        );
        let value = read_msg(&mut receiver).unwrap();
        assert_eq!(value.msg_type, VDAGENTD_CLIPBOARD_DATA);
        assert_eq!(value.arg1, 0);
        assert_eq!(value.arg2, VD_AGENT_CLIPBOARD_UTF8_TEXT);
        assert_eq!(value.data, "Città\nOblivion".as_bytes());
    }

    #[test]
    fn oversized_header_is_refused_without_reading_its_body() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut header = [0; 16];
        header[12..].copy_from_slice(&u32::MAX.to_le_bytes());
        sender.write_all(&header).unwrap();
        assert_eq!(
            read_msg(&mut receiver).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncated_body_is_not_accepted() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut header = [0; 16];
        header[12..].copy_from_slice(&4u32.to_le_bytes());
        sender.write_all(&header).unwrap();
        sender.write_all(b"ab").unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_msg(&mut receiver).err().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn oversized_outgoing_text_is_not_transmitted() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_msg(
            &sender,
            VDAGENTD_CLIPBOARD_DATA,
            0,
            VD_AGENT_CLIPBOARD_UTF8_TEXT,
            &vec![b'a'; MAX_PAYLOAD + 1],
        );
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_msg(&mut receiver).err().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
