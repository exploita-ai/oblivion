use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub struct Status {
    os: String,
    architecture: &'static str,
    cpu: String,
    pub cores: usize,
    pub memory_total: u64,
    memory_available: u64,
}

pub fn status() -> Status {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let memory = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let value = |key: &str| {
        memory
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name == key)
                    .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
                    .flatten()
            })
            .unwrap_or(0)
            .saturating_mul(1024)
    };
    let os = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.strip_prefix("PRETTY_NAME=")
                .map(|value| value.trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| "Debian GNU/Linux".into());
    let cpu = cpuinfo
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            matches!(key.trim(), "model name" | "Hardware" | "Processor")
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_else(|| std::env::consts::ARCH.into());
    Status {
        os,
        architecture: std::env::consts::ARCH,
        cpu,
        cores: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        memory_total: value("MemTotal"),
        memory_available: value("MemAvailable"),
    }
}
