use oblivion_host::{control, persistence};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub fn run(args: &[String]) -> control::Result<i32> {
    let mut reset = false;
    let mut reviewed = None;
    let mut values = args.iter();
    while let Some(value) = values.next() {
        match value.as_str() {
            "--reset-incomplete" if !reset => reset = true,
            "--confirmed-plan" if reviewed.is_none() => reviewed = Some(serde_json::from_str::<Option<persistence::Plan>>(values.next().ok_or("Missing confirmed storage plan")?)?),
            _ => return Err("Use oblivion init [--reset-incomplete]".into()),
        }
    }
    let current = super::status()?;
    if current.app_open { return Err("Lock Oblivion before creating or resetting encrypted storage.".into()) }
    if current.general_present { return Err("Encrypted storage already exists. Run oblivion unlock.".into()) }
    let incomplete = current.general_incomplete || current.persistence.as_ref().is_some_and(|state| state.incomplete);
    if incomplete != reset {
        return Err(if incomplete { "An incomplete storage setup exists. Review it with oblivion init --reset-incomplete." } else { "There is no incomplete storage setup to reset." }.into());
    }
    let plan = current.persistence.as_ref().and_then(|state| state.plan.as_ref());
    if let Some(persistence) = &current.persistence {
        if let Some(reason) = &persistence.unavailable { return Err(unavailable(reason).into()) }
        if plan.is_none() { return Err("The live boot medium has no verified storage plan. Oblivion will not write to it.".into()) }
    }
    if let Some(reviewed) = reviewed {
        confirm_plan(reviewed.as_ref(), plan)?;
    } else if reset || plan.is_some() {
        eprintln!("{}", if reset { "Reset incomplete encrypted storage" } else { "Prepare encrypted app storage" });
        if let Some(plan) = plan {
            eprintln!("Boot medium: /dev/{} · total {} MiB", plan.device, plan.disk_bytes / 1024 / 1024);
            eprintln!("Data partition: {} · start {} MiB · capacity {} MiB", plan.partition, plan.start / 2048, plan.sectors / 2048);
            eprintln!("Only the verified app-data partition {} is affected. The live image remains in place.", if reset { "from an unfinished setup" } else { "in unused space" });
        } else { eprintln!("Only the unfinished app archive is removed. Published storage cannot be reset."); }
        if !confirm(if reset { "RESET" } else { "CREATE" })? { return Err("Storage setup cancelled. Nothing was changed.".into()) }
    }
    if reset {
        control::request("discard-general-pending", None, &serde_json::to_vec(&plan)?)?;
        eprintln!("Incomplete setup removed. Run oblivion init to create encrypted storage.");
        return Ok(0);
    }
    let password = super::new_password("Oblivion password")?;
    if let Some(plan) = plan {
        let prepare = persistence::Prepare { plan: plan.clone(), password: Zeroizing::new(String::from_utf8(password.to_vec())?) };
        control::request("prepare-usb", None, &Zeroizing::new(serde_json::to_vec(&prepare)?))?;
    } else { control::request("init-general", None, &password)?; }
    eprintln!("Encrypted storage created. Run oblivion unlock.");
    Ok(0)
}

fn confirm_plan(reviewed: Option<&persistence::Plan>, current: Option<&persistence::Plan>) -> control::Result<()> {
    if reviewed != current { return Err("The storage plan changed. Review the device and free space again before continuing.".into()) }
    Ok(())
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

fn unavailable(reason: &str) -> &'static str {
    match reason {
        "usb_no_free_space" => "Not enough unused space after the live image. Use a larger writable boot medium.",
        "usb_foreign_partitions" | "usb_live_layout_unsupported" | "usb_partition_table_unsupported" => "The boot medium has an unsupported partition layout. Oblivion will not modify it. Use a fresh supported boot medium.",
        _ => "Persistent Live storage requires a writable boot USB or virtio disk containing the Oblivion image. A read-only ISO with an arbitrary second disk is not supported. Use supported writable media.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> persistence::Plan {
        persistence::Plan { device: "vda".into(), identity: "252:0".into(), table: "reviewed-table".into(), disk_bytes: 8 * 1024 * 1024 * 1024, start: 4096000, sectors: 12000000, partition: 5 }
    }
    #[test]
    fn confirmed_plan_cannot_silently_follow_another_device_or_new_geometry() {
        let reviewed = plan();
        assert!(confirm_plan(Some(&reviewed), Some(&reviewed)).is_ok());
        let changed = persistence::Plan { sectors: reviewed.sectors - 2048, ..reviewed.clone() };
        assert!(confirm_plan(Some(&reviewed), Some(&changed)).is_err());
        let changed = persistence::Plan { identity: "252:16".into(), ..reviewed.clone() };
        assert!(confirm_plan(Some(&reviewed), Some(&changed)).is_err());
        assert!(confirm_plan(Some(&reviewed), None).is_err());
        assert!(confirm_plan(None, Some(&reviewed)).is_err());
        assert!(confirm_plan(None, None).is_ok());
    }
}
