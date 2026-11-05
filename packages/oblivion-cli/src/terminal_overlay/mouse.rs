use oblivion_wire::agent::Size;

const SGR: &[u8] = b"\x1b[<";
const X10: &[u8] = b"\x1b[M";

pub(super) enum Packet {
    Other,
    Pending,
    Complete,
}

pub(super) fn recognized(bytes: &[u8]) -> bool {
    bytes.starts_with(SGR) || bytes.starts_with(X10)
}

pub(super) fn translate(bytes: &[u8], viewport: Size, utf8: bool, output: &mut Vec<u8>) -> Packet {
    if let Some(fields) = bytes.strip_prefix(SGR) {
        // Three u16 fields, two separators and a final M/m. Wait for a
        // fragmented report without accumulating arbitrary escape sequences.
        if fields.len() > 18 {
            return Packet::Other;
        }
        let Some((&end, body)) = fields.split_last() else {
            return Packet::Pending;
        };
        if !matches!(end, b'M' | b'm') {
            return if fields
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b';')
            {
                Packet::Pending
            } else {
                Packet::Other
            };
        }
        if !body
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';')
        {
            return Packet::Other;
        }
        let mut fields = body.split(|byte| *byte == b';');
        let (Some(button), Some(column), Some(row_text), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Packet::Other;
        };
        let number = |value| std::str::from_utf8(value).ok()?.parse::<u16>().ok();
        let (Some(_), Some(column), Some(row)) = (number(button), number(column), number(row_text))
        else {
            return Packet::Other;
        };
        if inside(viewport, column, row) {
            output.extend_from_slice(SGR);
            output.extend_from_slice(&body[..body.len() - row_text.len()]);
            output.extend_from_slice((row - 1).to_string().as_bytes());
            output.push(end);
        }
        return Packet::Complete;
    }

    if let Some(fields) = bytes.strip_prefix(X10) {
        if utf8 {
            return translate_utf8(fields, viewport, output);
        }
        if fields.len() < 3 {
            return Packet::Pending;
        }
        let &[button @ 32..=255, column @ 33..=255, row @ 33..=255] = fields else {
            return Packet::Other;
        };
        if inside(viewport, u16::from(column - 32), u16::from(row - 32)) {
            output.extend_from_slice(X10);
            output.extend_from_slice(&[button, column, row - 1]);
        }
        return Packet::Complete;
    }

    Packet::Other
}

fn translate_utf8(fields: &[u8], viewport: Size, output: &mut Vec<u8>) -> Packet {
    // Mode 1005 keeps the X10 envelope but encodes its three offset values
    // as UTF-8. Valid encoded values occupy at most two bytes each.
    if fields.len() > 6 {
        return Packet::Other;
    }
    let text = match std::str::from_utf8(fields) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => return Packet::Pending,
        Err(_) => return Packet::Other,
    };
    let mut values = text.chars();
    let (Some(button), Some(column), Some(row)) = (values.next(), values.next(), values.next())
    else {
        return Packet::Pending;
    };
    if values.next().is_some()
        || !(' '..='\u{7ff}').contains(&button)
        || !('!'..='\u{7ff}').contains(&column)
        || !('!'..='\u{7ff}').contains(&row)
    {
        return Packet::Other;
    }
    if inside(viewport, column as u16 - 32, row as u16 - 32) {
        output.extend_from_slice(X10);
        output.extend_from_slice(&fields[..fields.len() - row.len_utf8()]);
        let row = char::from_u32(u32::from(row) - 1).expect("remapped UTF-8 mouse row");
        output.extend_from_slice(row.encode_utf8(&mut [0; 4]).as_bytes());
    }
    Packet::Complete
}

fn inside(viewport: Size, column: u16, row: u16) -> bool {
    column > 0 && column <= viewport.cols && row > 1 && row < viewport.rows
}

#[cfg(test)]
mod tests {
    use crate::terminal_overlay::Keys;
    use oblivion_wire::agent::Size;
    use std::time::{Duration, Instant};

    fn feed(keys: &mut Keys, output: &mut Vec<u8>, bytes: &[u8], now: Instant) {
        for &byte in bytes {
            assert!(keys.feed(byte, output, now).is_none());
        }
    }

    #[test]
    fn sgr_mouse_keeps_interior_coordinates_and_drops_both_bars() {
        let now = Instant::now();
        let later = now + Duration::from_millis(100);
        let mut keys = Keys::default();
        keys.set_viewport(Some(Size { rows: 24, cols: 80 }));
        let mut output = Vec::new();
        feed(&mut keys, &mut output, b"\x1b[<0;5;", now);
        keys.expire(&mut output, later);
        assert!(output.is_empty());
        feed(
            &mut keys,
            &mut output,
            b"2M\x1b[<0;5;23m\x1b[<64;5;1M\x1b[<65;5;24M",
            later,
        );
        assert_eq!(output, b"\x1b[<0;5;1M\x1b[<0;5;22m");

        output.clear();
        keys.set_viewport(Some(Size { rows: 12, cols: 80 }));
        feed(
            &mut keys,
            &mut output,
            b"\x1b[<64;5;12M\x1b[<64;5;11M",
            later,
        );
        assert_eq!(output, b"\x1b[<64;5;10M");
    }

    #[test]
    fn x10_mouse_and_bracketed_paste_keep_packet_boundaries() {
        let now = Instant::now();
        let mut keys = Keys::default();
        keys.set_viewport(Some(Size { rows: 24, cols: 80 }));
        let mut output = Vec::new();
        feed(&mut keys, &mut output, b"\x1b[M\x20\x25", now);
        assert!(output.is_empty());
        feed(
            &mut keys,
            &mut output,
            b"\x22\x1b[M\x20\x25\x21\x1b[M\x20\x25\x38",
            now,
        );
        assert_eq!(output, b"\x1b[M\x20\x25\x21");

        output.clear();
        let paste = b"\x1b[200~\x1b[<0;5;1M\x1b[M\x20\x25\x22\x1b[201~";
        feed(&mut keys, &mut output, paste, now);
        assert_eq!(output, paste);

        output.clear();
        keys.set_viewport(None);
        let transparent = b"\x1b[<0;5;1M\x1b[M\x20\x25\x22";
        feed(&mut keys, &mut output, transparent, now);
        assert_eq!(output, transparent);
    }

    #[test]
    fn negotiated_utf8_mouse_remaps_complete_codepoints() {
        let now = Instant::now();
        let mut keys = Keys::default();
        keys.set_viewport(Some(Size {
            rows: 200,
            cols: 200,
        }));
        keys.set_mouse_utf8(true);
        let mut output = Vec::new();
        feed(&mut keys, &mut output, b"\x1b[M \xc2", now);
        feed(&mut keys, &mut output, b"\x82\xc2", now);
        assert!(output.is_empty());
        feed(&mut keys, &mut output, b"\x80x", now);
        assert_eq!(output, b"\x1b[M \xc2\x82\x7fx");

        output.clear();
        feed(
            &mut keys,
            &mut output,
            b"\x1b[M \xc2\x82!\x1b[M \xc2\x82\xc3\xa8",
            now,
        );
        assert!(output.is_empty());
        keys.set_mouse_utf8(false);
        feed(&mut keys, &mut output, b"\x1b[M\x20\xc2\x22", now);
        assert_eq!(output, b"\x1b[M\x20\xc2\x21");
    }
}
