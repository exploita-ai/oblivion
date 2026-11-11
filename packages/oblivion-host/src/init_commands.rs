use oblivion_host::control;
use std::fs::OpenOptions;
use std::io::{Read, Write};

pub(super) fn confirm(word: &str) -> control::Result<bool> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")
        .map_err(|_| "Storage setup requires an interactive terminal")?;
    write!(tty, "Type {word} to confirm, or press Enter to go back: ")?;
    tty.flush()?;
    let mut answer = Vec::new();
    loop {
        let mut byte = [0];
        tty.read_exact(&mut byte)?;
        if matches!(byte[0], b'\r' | b'\n') { break }
        if answer.len() >= 64 { return Err("Storage confirmation is too long".into()) }
        answer.push(byte[0]);
    }
    Ok(answer == word.as_bytes())
}
