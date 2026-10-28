use std::io;

pub fn configure(enabled: bool, published: bool) -> io::Result<Vec<u8>> {
    if published && !enabled {
        return Err(io::Error::other("invalid_onion_policy"));
    }
    let mut policy = String::from(include_str!("../guest/onion/firewall.nft"));
    if enabled {
        policy.push_str("add element inet oblivion tor_owners { 1200 }\n");
    }
    if published {
        policy.push_str("add element inet oblivion file_ports { 8080 }\n");
    }
    crate::network::apply(&policy)?;
    crate::network::snapshot()
}
