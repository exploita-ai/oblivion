#[cfg(target_os = "linux")]
mod runtime;

fn main() {
    if execute().is_err() {
        eprintln!("transfer_failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn execute() -> Result<(), Box<dyn std::error::Error>> {
    use oblivion_transfer::relay;
    use std::time::Duration;
    runtime::harden()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("invalid_arguments".into());
    }
    let budget: u64 = args[0].parse()?;
    if !(1..=3_600_000).contains(&budget) {
        return Err("invalid_deadline".into());
    }
    let source = runtime::inherited(3)?;
    let destination = runtime::inherited(4)?;
    let control = runtime::inherited(5)?;
    // The privileged controller chooses these private QEMU connections. Their
    // kernel-bound process handles remain specific to this VM incarnation.
    let owners = vec![
        relay::peer_process(&source)?,
        relay::peer_process(&destination)?,
    ];
    relay::run(
        source,
        destination,
        control,
        owners,
        Duration::from_millis(budget),
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn execute() -> Result<(), Box<dyn std::error::Error>> {
    // The Mac laboratory tests the relay library with explicit lifetime pipes.
    // This product binary never silently substitutes them for Linux pidfds.
    Err("linux_required".into())
}
