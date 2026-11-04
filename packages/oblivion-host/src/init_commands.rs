use oblivion_host::control;
use std::fs::OpenOptions;
use std::io::{Read, Write};

pub fn run(args: &[String]) -> control::Result<i32> {
    let mut reset = false;
    let mut confirmed = false;
    for value in args {
        match value.as_str() {
            "--reset-incomplete" if !reset => reset = true,
            "--confirmed-reset" if !confirmed => confirmed = true,
            _ => return Err("Use oblivion init [--reset-incomplete [--confirmed-reset]]".into()),
        }
    }
    if confirmed && !reset { return Err("--confirmed-reset requires --reset-incomplete".into()); }
    let current = super::status()?;
    if current.app_open { return Err("Lock Oblivion before creating or resetting encrypted storage.".into()); }
    if current.general_present { return Err("Encrypted storage already exists. Run oblivion unlock.".into()); }
    if current.general_incomplete != reset {
        return Err(if current.general_incomplete { "An incomplete storage setup exists. Review it with oblivion init --reset-incomplete." } else { "There is no incomplete storage setup to reset." }.into());
    }
    if reset {
        eprintln!("Only the unfinished app archive is removed. Published encrypted storage is preserved.");
        if !confirmed && !confirm("RESET")? { return Err("Storage reset cancelled. Nothing was changed.".into()); }
        control::request("discard-general-pending", None, &[])?;
        eprintln!("Incomplete setup removed. Run oblivion init to create encrypted storage.");
        return Ok(0);
    }
    eprintln!("Create the managed encrypted archive: {} MiB.", current.general_bytes / 1024 / 1024);
    control::request("init-general", None, &super::new_password("Oblivion password")?)?;
    eprintln!("Encrypted storage created. Run oblivion unlock.");
    Ok(0)
}

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
