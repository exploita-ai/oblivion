use oblivion_transport::Transport;
use std::io::{self, Write};
use std::process::{Command, Stdio};

// The immutable ruleset starts with empty selectors. Only this trusted process
// may select an egress route; every update is one atomic nftables transaction.
pub fn configure(transport: &Transport) -> io::Result<()> {
    transport.validate().map_err(io::Error::other)?;
    let mut policy = String::from(include_str!("../guest/firewall.nft"));
    match transport {
        Transport::Tor {} => policy.push_str(
            "add element inet oblivion tor_owners { 1200 }\nadd element inet oblivion tor_connectors { 1201 }\n",
        ),
        Transport::Socks5 { endpoint, .. } => policy.push_str(&format!(
            "add element inet oblivion proxy4 {{ {} . {} }}\n",
            endpoint.ip(), endpoint.port(),
        )),
    }
    apply(&policy)
}

pub fn offline() -> io::Result<()> {
    // Drop established traffic as well, before the established/related rules.
    let policy = include_str!("../guest/firewall.nft")
        .replace("type filter hook input priority filter; policy drop;", "type filter hook input priority filter; policy drop;\n        iifname \"outside0\" drop")
        .replace("type filter hook output priority filter; policy drop;", "type filter hook output priority filter; policy drop;\n        oifname \"outside0\" drop");
    apply(&policy)
}

// This barrier precedes conntrack accepts. The supervisor refuses transport
// policy changes while it is installed; only verified rotation can release it.
pub fn rotation_block() -> io::Result<()> {
    apply("add table inet oblivion_rotation\nflush table inet oblivion_rotation\n\
        add chain inet oblivion_rotation input { type filter hook input priority -20; policy accept; }\n\
        add rule inet oblivion_rotation input iifname \"inside0\" tcp dport 8114 return\n\
        add rule inet oblivion_rotation input iifname \"inside0\" counter drop\n\
        add rule inet oblivion_rotation input iifname \"outside0\" counter drop\n\
        add chain inet oblivion_rotation output { type filter hook output priority -20; policy accept; }\n\
        add rule inet oblivion_rotation output meta skuid { 1201, 1300, 1301, 1302 } counter drop\n\
        add rule inet oblivion_rotation output oifname \"outside0\" counter drop\n")
}

pub fn rotation_tor_only() -> io::Result<()> {
    // Called only after the data plane is joined and Tor has closed its old
    // circuits. Keep the same table throughout; allow only Tor infrastructure.
    apply("flush chain inet oblivion_rotation input\n\
        add rule inet oblivion_rotation input iifname \"inside0\" tcp dport 8114 return\n\
        add rule inet oblivion_rotation input iifname \"inside0\" counter drop\n\
        flush chain inet oblivion_rotation output\n\
        add rule inet oblivion_rotation output meta skuid { 1201, 1300, 1301, 1302 } counter drop\n\
        add rule inet oblivion_rotation output oifname \"outside0\" meta skuid != 1200 counter drop\n")
}

pub fn rotation_release() -> io::Result<()> {
    apply("delete table inet oblivion_rotation\n")
}

pub fn apply(policy: &str) -> io::Result<()> {
    let mut child = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing_policy_input"))?
        .write_all(policy.as_bytes());
    let status = child.wait()?;
    written?;
    if !status.success() {
        return Err(io::Error::other("network_policy_failed"));
    }
    Ok(())
}

pub fn snapshot() -> io::Result<Vec<u8>> {
    let output = Command::new("/usr/sbin/nft")
        .args(["--stateless", "--numeric", "list", "ruleset"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 65536 {
        return Err(io::Error::other("firewall_verification_failed"));
    }
    Ok(output.stdout)
}

pub fn isolated(expected: &[u8]) -> io::Result<bool> {
    Ok(snapshot()? == expected
        && std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() == "0"
        && std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")?.trim() == "1")
}
