//! One owned, isolated ICS network and static controller endpoint, using the
//! current default HCN document shape used by Microsoft WSL. Linux addressing
//! is configured explicitly; no host DNS proxy or guest DHCP client is enabled.
//! Safe gateways and their Tor/SOCKS policy remain inside the controller.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const MAX_PREFIXES: usize = 4096;
const MAX_REPLY: usize = 1024 * 1024;
const PREFIX_LENGTH: u8 = 28;
// NetworkFlags.EnableNonPersistent in Microsoft WSL src/shared/inc/hns_schema.h.
// EnableDns (1) and EnableDhcp (2) are deliberately absent.
const NONPERSISTENT: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    network: u32,
    length: u8,
}

impl Prefix {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, length) = value
            .split_once('/')
            .ok_or(Error("invalid_hcn_ipv4_prefix"))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| Error("invalid_hcn_ipv4_prefix"))?;
        let length: u8 = length
            .parse()
            .map_err(|_| Error("invalid_hcn_ipv4_prefix"))?;
        let prefix = Self::from_address(address, length)?;
        if prefix.network != u32::from(address) || prefix.cidr() != value {
            return Err(Error("invalid_hcn_ipv4_prefix"));
        }
        Ok(prefix)
    }

    /// Windows route/address observations may carry host bits. Normalize those
    /// typed observations; textual HCN CIDRs above must already be canonical.
    pub fn from_address(address: Ipv4Addr, length: u8) -> Result<Self> {
        if length > 32 {
            return Err(Error("invalid_hcn_ipv4_prefix"));
        }
        let mask = if length == 0 {
            0
        } else {
            u32::MAX << (32 - length)
        };
        Ok(Self {
            network: u32::from(address) & mask,
            length,
        })
    }

    pub fn cidr(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.length)
    }
    fn last(self) -> u32 {
        self.network
            | if self.length == 32 {
                0
            } else {
                u32::MAX >> self.length
            }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub runtime_id: String,
    pub network_id: String,
    pub endpoint_id: String,
    pub adapter_id: String,
    pub mac: String,
    pub subnet: String,
    pub ip_address: String,
    pub gateway: String,
    pub prefix_length: u8,
}

impl Attachment {
    pub fn validate(&self, runtime_id: &str) -> Result<()> {
        let identity = Identity::new(runtime_id)?;
        let prefix = Prefix::parse(&self.subnet)?;
        if self.runtime_id != runtime_id
            || self.network_id != identity.network
            || self.endpoint_id != identity.endpoint
            || self.adapter_id != identity.adapter
            || self.mac != identity.mac
            || self.prefix_length != PREFIX_LENGTH
            || prefix.length != PREFIX_LENGTH
            || !private(prefix)
            || self.gateway != Ipv4Addr::from(prefix.network + 1).to_string()
            || self.ip_address != Ipv4Addr::from(prefix.network + 2).to_string()
        {
            return Err(Error("invalid_hcn_attachment"));
        }
        Ok(())
    }

    /// Only the HCS builder appends these validated, secret-free parameters.
    /// RuntimeConfig.command_line never admits caller-supplied network metadata.
    pub fn boot_args(&self) -> String {
        format!(
            "oblivion.runtime-ipv4={}/{} oblivion.runtime-gateway={} oblivion.runtime-mac={}",
            self.ip_address, self.prefix_length, self.gateway, self.mac
        )
    }

    pub fn hcs_mac(&self) -> String {
        self.mac.replace(':', "-")
    }
}

pub struct Plan {
    pub attachment: Attachment,
}

impl Plan {
    pub fn new(runtime_id: &str, occupied: &[Prefix]) -> Result<Self> {
        let identity = Identity::new(runtime_id)?;
        if occupied.len() > MAX_PREFIXES {
            return Err(Error("hcn_prefix_inventory_too_large"));
        }
        // A default route is reachability, not an allocated address range. All
        // more-specific host routes and existing HCN subnets remain exclusions.
        let mut blocked: Vec<_> = occupied
            .iter()
            .filter(|prefix| prefix.length != 0)
            .map(|prefix| (prefix.network as u64, prefix.last() as u64))
            .collect();
        blocked.sort_unstable();
        let pools = private_pools();
        let seed = u16::from_str_radix(&runtime_id[28..], 16)
            .map_err(|_| Error("invalid_hcn_runtime_identity"))? as u64;
        let split = pools[0].network as u64 + seed * 16;
        let ranges = [
            (split, pools[0].last() as u64),
            (pools[0].network as u64, split.saturating_sub(1)),
            (pools[1].network as u64, pools[1].last() as u64),
            (pools[2].network as u64, pools[2].last() as u64),
        ];
        let selected = ranges
            .into_iter()
            .find_map(|(first, last)| free(first, last, &blocked))
            .ok_or(Error("hcn_private_subnet_unavailable"))?;
        let prefix = Prefix {
            network: selected,
            length: PREFIX_LENGTH,
        };
        Ok(Self {
            attachment: Attachment {
                runtime_id: runtime_id.to_owned(),
                network_id: identity.network,
                endpoint_id: identity.endpoint,
                adapter_id: identity.adapter,
                mac: identity.mac,
                subnet: prefix.cidr(),
                gateway: Ipv4Addr::from(selected + 1).to_string(),
                ip_address: Ipv4Addr::from(selected + 2).to_string(),
                prefix_length: PREFIX_LENGTH,
            },
        })
    }

    /// The current WSL HcnCreateNetwork request uses the default document shape,
    /// not a v2 Ipams document: ICS, a separate switch and constrained addresses.
    /// Flags omit DNS and DHCP. Their real Windows behavior remains a platform
    /// qualification gate; a refused constraint never triggers an auto fallback.
    /// https://github.com/microsoft/WSL/blob/master/src/windows/common/NatNetworking.cpp
    /// https://github.com/microsoft/WSL/blob/master/src/shared/inc/hns_schema.h
    pub fn network_json(&self) -> Result<String> {
        self.attachment.validate(&self.attachment.runtime_id)?;
        let document = Network {
            name: format!("Oblivion.{}.network", self.attachment.runtime_id),
            kind: "ICS",
            isolate_switch: true,
            flags: NONPERSISTENT,
            subnets: [Subnet {
                address_prefix: &self.attachment.subnet,
                gateway_address: &self.attachment.gateway,
                ip_subnets: [IpSubnet {
                    ip_address_prefix: &self.attachment.subnet,
                }],
            }],
        };
        serde_json::to_string(&document).map_err(|_| Error("hcn_configuration_encode_failed"))
    }

    /// HNSEndpoint is the flat default HCN shape in WSL's hns_schema.h. Both
    /// object IDs are API arguments, not caller-supplied JSON identity overrides.
    /// Metadata alone does not configure Linux; Debian receives the same static
    /// address, gateway and MAC through the validated boot attachment.
    /// https://github.com/microsoft/WSL/blob/master/src/shared/inc/hns_schema.h
    pub fn endpoint_json(&self) -> Result<String> {
        self.attachment.validate(&self.attachment.runtime_id)?;
        let document = Endpoint {
            name: format!("Oblivion.{}.endpoint", self.attachment.runtime_id),
            virtual_network: &self.attachment.network_id,
            ip_address: &self.attachment.ip_address,
            mac_address: self.attachment.hcs_mac(),
            gateway_address: &self.attachment.gateway,
            prefix_length: PREFIX_LENGTH,
        };
        serde_json::to_string(&document).map_err(|_| Error("hcn_configuration_encode_failed"))
    }

    /// WSL queries HCN with a null query and consumes Subnets/flat endpoint
    /// fields. Provider health fields are not authority: IDs, switch isolation
    /// and all static addresses must still match our original plan exactly.
    /// https://github.com/microsoft/WSL/blob/master/src/windows/common/WslCoreNetworkingSupport.h
    pub fn verify_network_properties(&self, document: &str) -> Result<()> {
        self.attachment.validate(&self.attachment.runtime_id)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Current {
            #[serde(rename = "ID")]
            id: String,
            name: String,
            #[serde(rename = "Type")]
            kind: String,
            isolate_switch: bool,
            flags: u32,
            subnets: Vec<ObservedSubnet>,
            #[serde(default)]
            policies: Vec<serde::de::IgnoredAny>,
            #[serde(default)]
            interface_constraint: InterfaceConstraint,
        }
        let current: Current = decode(document)?;
        if !same_guid(&current.id, &self.attachment.network_id)
            || current.name != format!("Oblivion.{}.network", self.attachment.runtime_id)
            || current.kind != "ICS"
            || !current.isolate_switch
            || current.flags != NONPERSISTENT
            || !current.policies.is_empty()
            || !current.interface_constraint.empty()
            || current.subnets.len() != 1
        {
            return Err(Error("hcn_network_identity_mismatch"));
        }
        let subnet = &current.subnets[0];
        if subnet.address_prefix != self.attachment.subnet
            || subnet.gateway_address != self.attachment.gateway
            || subnet.ip_subnets.len() > 1
            || subnet
                .ip_subnets
                .iter()
                .any(|subnet| subnet.ip_address_prefix != self.attachment.subnet)
        {
            return Err(Error("hcn_network_identity_mismatch"));
        }
        Ok(())
    }

    pub fn verify_endpoint_properties(&self, document: &str) -> Result<()> {
        self.attachment.validate(&self.attachment.runtime_id)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Current {
            #[serde(rename = "ID")]
            id: String,
            name: String,
            virtual_network: String,
            #[serde(rename = "IPAddress")]
            ip_address: String,
            mac_address: String,
            gateway_address: String,
            prefix_length: u8,
            #[serde(default)]
            policies: Vec<serde::de::IgnoredAny>,
            #[serde(default)]
            flags: u32,
            #[serde(default)]
            interface_constraint: InterfaceConstraint,
        }
        let current: Current = decode(document)?;
        if !same_guid(&current.id, &self.attachment.endpoint_id)
            || current.name != format!("Oblivion.{}.endpoint", self.attachment.runtime_id)
            || !same_guid(&current.virtual_network, &self.attachment.network_id)
            || !current
                .mac_address
                .eq_ignore_ascii_case(&self.attachment.hcs_mac())
            || current.flags != 0
            || !current.policies.is_empty()
            || !current.interface_constraint.empty()
            || current.ip_address != self.attachment.ip_address
            || current.prefix_length != PREFIX_LENGTH
            || current.gateway_address != self.attachment.gateway
        {
            return Err(Error("hcn_endpoint_identity_mismatch"));
        }
        Ok(())
    }
}

/// Reservations in the same default HCN Subnets document shape used by WSL.
/// Inspect both the subnet's AddressPrefix and any more-specific IpSubnets;
/// IPv6 cannot overlap our IPv4 pool, but malformed peer CIDRs still refuse it.
pub fn observed_prefixes(document: &str) -> Result<Vec<Prefix>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Current {
        #[serde(default)]
        subnets: Vec<ObservedSubnet>,
    }
    let current: Current = decode(document)?;
    let mut prefixes = Vec::new();
    let mut observed = 0;
    for subnet in current.subnets {
        for value in std::iter::once(subnet.address_prefix).chain(
            subnet
                .ip_subnets
                .into_iter()
                .map(|subnet| subnet.ip_address_prefix),
        ) {
            observed += 1;
            if observed > MAX_PREFIXES {
                return Err(Error("hcn_prefix_inventory_too_large"));
            }
            if value.contains(':') {
                let (address, length) = value
                    .split_once('/')
                    .ok_or(Error("invalid_hcn_ipv4_prefix"))?;
                let address: Ipv6Addr = address
                    .parse()
                    .map_err(|_| Error("invalid_hcn_ipv4_prefix"))?;
                let length: u8 = length
                    .parse()
                    .map_err(|_| Error("invalid_hcn_ipv4_prefix"))?;
                if length > 128 || length != 128 && u128::from(address) & (u128::MAX >> length) != 0
                {
                    return Err(Error("invalid_hcn_ipv4_prefix"));
                }
                continue;
            }
            let prefix = Prefix::parse(&value)?;
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }
    Ok(prefixes)
}

fn decode<T: serde::de::DeserializeOwned>(document: &str) -> Result<T> {
    if document.len() > MAX_REPLY {
        return Err(Error("hcn_reply_too_large"));
    }
    serde_json::from_str(document).map_err(|_| Error("invalid_hcn_properties"))
}

fn same_guid(value: &str, expected: &str) -> bool {
    crate::hcs_model::guid(value)
        .ok()
        .zip(crate::hcs_model::guid(expected).ok())
        .is_some_and(|(value, expected)| value == expected)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ObservedSubnet {
    address_prefix: String,
    #[serde(default)]
    gateway_address: String,
    #[serde(default)]
    ip_subnets: Vec<ObservedIpSubnet>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ObservedIpSubnet {
    ip_address_prefix: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InterfaceConstraint {
    #[serde(default)]
    interface_guid: String,
    #[serde(default)]
    interface_index: u32,
    #[serde(default)]
    interface_media_type: u32,
    #[serde(default)]
    interface_alias: String,
}
impl InterfaceConstraint {
    fn empty(&self) -> bool {
        (self.interface_guid.is_empty()
            || self.interface_guid == "00000000-0000-0000-0000-000000000000")
            && self.interface_index == 0
            && self.interface_media_type == 0
            && self.interface_alias.is_empty()
    }
}

struct Identity {
    network: String,
    endpoint: String,
    adapter: String,
    mac: String,
}
impl Identity {
    fn new(runtime_id: &str) -> Result<Self> {
        if runtime_id.len() != 32
            || !runtime_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error("invalid_hcn_runtime_identity"));
        }
        let value = u128::from_str_radix(runtime_id, 16)
            .map_err(|_| Error("invalid_hcn_runtime_identity"))?;
        if [0, 0x4e, 0x45, 0x41].contains(&value) {
            return Err(Error("invalid_hcn_runtime_identity"));
        }
        // Public role-separated object names, not authentication material. A
        // collision must be refused by Create, never resolved by adopting it.
        let guid = |role| {
            let id = format!("{:032x}", value ^ role);
            format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            )
        };
        Ok(Self {
            network: guid(0x4e),
            endpoint: guid(0x45),
            adapter: guid(0x41),
            mac: format!(
                "02:{}:{}:{}:{}:{}",
                &runtime_id[22..24],
                &runtime_id[24..26],
                &runtime_id[26..28],
                &runtime_id[28..30],
                &runtime_id[30..32]
            ),
        })
    }
}

fn free(mut first: u64, last: u64, blocked: &[(u64, u64)]) -> Option<u32> {
    if first > last {
        return None;
    }
    for (start, end) in blocked {
        if *end < first {
            continue;
        }
        if *start > first + 15 {
            break;
        }
        first = (end + 16) & !15;
        if first + 15 > last {
            return None;
        }
    }
    (first + 15 <= last).then_some(first as u32)
}

fn private_pools() -> [Prefix; 3] {
    [
        Prefix {
            network: u32::from(Ipv4Addr::new(172, 16, 0, 0)),
            length: 12,
        },
        Prefix {
            network: u32::from(Ipv4Addr::new(10, 0, 0, 0)),
            length: 8,
        },
        Prefix {
            network: u32::from(Ipv4Addr::new(192, 168, 0, 0)),
            length: 16,
        },
    ]
}

fn private(prefix: Prefix) -> bool {
    private_pools()
        .iter()
        .any(|pool| pool.network <= prefix.network && prefix.last() <= pool.last())
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Network<'a> {
    name: String,
    #[serde(rename = "Type")]
    kind: &'a str,
    isolate_switch: bool,
    flags: u32,
    subnets: [Subnet<'a>; 1],
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Subnet<'a> {
    address_prefix: &'a str,
    gateway_address: &'a str,
    ip_subnets: [IpSubnet<'a>; 1],
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct IpSubnet<'a> {
    ip_address_prefix: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Endpoint<'a> {
    name: String,
    virtual_network: &'a str,
    #[serde(rename = "IPAddress")]
    ip_address: &'a str,
    mac_address: String,
    gateway_address: &'a str,
    prefix_length: u8,
}

#[cfg(test)]
mod tests {
    use super::{MAX_PREFIXES, MAX_REPLY, Plan, Prefix, observed_prefixes};
    use serde_json::{Value, json};
    use std::net::Ipv4Addr;
    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn owned_isolated_ics_and_flat_endpoint_match_static_guest_without_extra_services() {
        let plan = Plan::new(ID, &[]).unwrap();
        plan.attachment.validate(ID).unwrap();
        let network: Value = serde_json::from_str(&plan.network_json().unwrap()).unwrap();
        let endpoint: Value = serde_json::from_str(&plan.endpoint_json().unwrap()).unwrap();
        assert_eq!(
            network,
            json!({"Name":format!("Oblivion.{ID}.network"),
            "Type":"ICS","IsolateSwitch":true,"Flags":8,"Subnets":[{
                "AddressPrefix":plan.attachment.subnet,"GatewayAddress":plan.attachment.gateway,
                "IpSubnets":[{"IpAddressPrefix":plan.attachment.subnet}]}]})
        );
        assert_eq!(
            endpoint,
            json!({"Name":format!("Oblivion.{ID}.endpoint"),
            "VirtualNetwork":plan.attachment.network_id,"MacAddress":plan.attachment.hcs_mac(),
            "IPAddress":plan.attachment.ip_address,"PrefixLength":28,
            "GatewayAddress":plan.attachment.gateway})
        );
        assert_eq!(
            plan.attachment.boot_args(),
            format!(
                "oblivion.runtime-ipv4={}/28 oblivion.runtime-gateway={} oblivion.runtime-mac={}",
                plan.attachment.ip_address, plan.attachment.gateway, plan.attachment.mac
            )
        );
        assert_ne!(plan.attachment.network_id, plan.attachment.endpoint_id);
        assert_ne!(plan.attachment.adapter_id, plan.attachment.endpoint_id);
        assert!(plan.attachment.mac.starts_with("02:"));
    }

    #[test]
    fn chooses_nonoverlapping_private_prefix_and_does_not_treat_default_route_as_reserved() {
        let first = Plan::new(ID, &[]).unwrap();
        let same = Plan::new(ID, &[Prefix::parse("0.0.0.0/0").unwrap()]).unwrap();
        assert_eq!(first.attachment, same.attachment);
        let occupied = Prefix::parse(&first.attachment.subnet).unwrap();
        let next = Plan::new(ID, &[occupied]).unwrap();
        let chosen = Prefix::parse(&next.attachment.subnet).unwrap();
        assert!(chosen.last() < occupied.network || occupied.last() < chosen.network);
        let other = Plan::new("1123456789abcdef0123456789abcdef", &[occupied, chosen]).unwrap();
        assert_ne!(other.attachment.network_id, first.attachment.network_id);
    }

    #[test]
    fn exhaustive_private_routes_refuse_allocation_without_overwriting_any_network() {
        let blocked = [
            Prefix::parse("172.16.0.0/12").unwrap(),
            Prefix::parse("10.0.0.0/8").unwrap(),
            Prefix::parse("192.168.0.0/16").unwrap(),
        ];
        assert_eq!(
            Plan::new(ID, &blocked).err().unwrap().0,
            "hcn_private_subnet_unavailable"
        );
        assert_eq!(
            Plan::new(ID, &vec![blocked[0]; MAX_PREFIXES + 1])
                .err()
                .unwrap()
                .0,
            "hcn_prefix_inventory_too_large"
        );
    }

    #[test]
    fn prefix_parser_is_canonical_but_native_route_constructor_masks_host_bits() {
        for invalid in [
            "10.0.0.1/24",
            "10.0.0.0/33",
            "10.0.0.0/024",
            "10.0.0.0/-1",
            "::/0",
            "PRIVATE_CANARY",
            "10.0.0.0/24/1",
        ] {
            let error = Prefix::parse(invalid).unwrap_err();
            assert_eq!(error.0, "invalid_hcn_ipv4_prefix");
            assert!(!error.to_string().contains("PRIVATE_CANARY"));
        }
        assert_eq!(
            Prefix::from_address(Ipv4Addr::new(10, 1, 2, 3), 24)
                .unwrap()
                .cidr(),
            "10.1.2.0/24"
        );
        assert_eq!(
            Prefix::parse("255.255.255.255/32").unwrap().last(),
            u32::MAX
        );
    }

    #[test]
    fn attachment_rejects_foreign_identity_public_subnet_reserved_addresses_and_arbitrary_boot_text()
     {
        let original = Plan::new(ID, &[]).unwrap().attachment;
        for field in 0..9 {
            let mut value = original.clone();
            match field {
                0 => value.runtime_id = "a".repeat(32),
                1 => value.network_id = value.endpoint_id.clone(),
                2 => value.endpoint_id = value.adapter_id.clone(),
                3 => value.adapter_id = value.network_id.clone(),
                4 => value.mac = "ff:ff:ff:ff:ff:ff".into(),
                5 => value.subnet = "8.8.8.0/28".into(),
                6 => value.ip_address = value.gateway.clone(),
                7 => value.gateway = "PRIVATE_CANARY".into(),
                _ => value.prefix_length = 24,
            }
            assert_eq!(value.validate(ID).unwrap_err().0, "invalid_hcn_attachment");
        }
        for invalid in [
            "",
            "00000000000000000000000000000000",
            "0123456789ABCDEF0123456789abcdef",
            "PRIVATE_CANARY",
        ] {
            assert_eq!(
                Plan::new(invalid, &[]).err().unwrap().0,
                "invalid_hcn_runtime_identity"
            );
        }
    }

    #[test]
    fn default_queries_refuse_foreign_objects_policies_and_reassigned_addresses() {
        let plan = Plan::new(ID, &[]).unwrap();
        let mut original: Value = serde_json::from_str(&plan.network_json().unwrap()).unwrap();
        original["ID"] = json!(plan.attachment.network_id);
        original["Health"] = json!({"Extra":"provider-field"});
        plan.verify_network_properties(&original.to_string())
            .unwrap();
        let mut without_ip_subnets = original.clone();
        without_ip_subnets["Subnets"][0]
            .as_object_mut()
            .unwrap()
            .remove("IpSubnets");
        plan.verify_network_properties(&without_ip_subnets.to_string())
            .unwrap();
        for (key, value) in [
            ("ID", json!(plan.attachment.endpoint_id)),
            ("Name", json!("Default Switch")),
            ("Type", json!("NAT")),
            ("IsolateSwitch", json!(false)),
            ("Flags", json!(9)),
            ("Policies", json!([{"Type":"PortMapping"}])),
            ("Subnets", json!([])),
            ("InterfaceConstraint", json!({"InterfaceAlias":"Ethernet"})),
        ] {
            let mut current = original.clone();
            current[key] = value;
            assert!(
                plan.verify_network_properties(&current.to_string())
                    .is_err()
            );
        }
        let mut changed = original.clone();
        changed["Subnets"][0]["GatewayAddress"] = json!("10.0.0.1");
        assert!(
            plan.verify_network_properties(&changed.to_string())
                .is_err()
        );
        let mut changed = original.clone();
        changed["Subnets"][0]["IpSubnets"][0]["IpAddressPrefix"] = json!("10.0.0.0/28");
        assert!(
            plan.verify_network_properties(&changed.to_string())
                .is_err()
        );
        let mut original: Value = serde_json::from_str(&plan.endpoint_json().unwrap()).unwrap();
        original["ID"] = json!(plan.attachment.endpoint_id);
        plan.verify_endpoint_properties(&original.to_string())
            .unwrap();
        for (key, value) in [
            ("ID", json!(plan.attachment.network_id)),
            ("Name", json!("other")),
            ("VirtualNetwork", json!(plan.attachment.endpoint_id)),
            ("MacAddress", json!("ff-ff-ff-ff-ff-ff")),
            ("IPAddress", json!(plan.attachment.gateway)),
            ("GatewayAddress", json!(plan.attachment.ip_address)),
            ("PrefixLength", json!(24)),
            ("Policies", json!([{"Type":"PortMapping"}])),
            ("Flags", json!(1)),
            ("InterfaceConstraint", json!({"InterfaceIndex":1})),
        ] {
            let mut current = original.clone();
            current[key] = value;
            assert!(
                plan.verify_endpoint_properties(&current.to_string())
                    .is_err()
            );
        }
        assert_eq!(
            plan.verify_network_properties(&" ".repeat(MAX_REPLY + 1))
                .unwrap_err()
                .0,
            "hcn_reply_too_large"
        );
    }

    #[test]
    fn default_inventory_validates_subnets_and_ip_subnets_including_ipv6() {
        let document = json!({"Subnets":[{"AddressPrefix":"10.0.0.0/24","IpSubnets":[
            {"IpAddressPrefix":"10.0.0.0/24"},{"IpAddressPrefix":"10.0.1.0/24"}]},
            {"AddressPrefix":"fd00::/64","IpSubnets":[{"IpAddressPrefix":"fd01::/64"}]}]});
        assert_eq!(
            observed_prefixes(&document.to_string()).unwrap(),
            [
                Prefix::parse("10.0.0.0/24").unwrap(),
                Prefix::parse("10.0.1.0/24").unwrap()
            ]
        );
        for value in [
            json!({"Subnets":"PRIVATE_CANARY"}),
            json!({"Subnets":[{"AddressPrefix":"PRIVATE_CANARY"}]}),
            json!({"Subnets":[{"AddressPrefix":"10.0.0.0/24","IpSubnets":[{"IpAddressPrefix":"PRIVATE_CANARY"}]}]}),
            json!({"Subnets":[{"AddressPrefix":"fd00::1/64"}]}),
            json!({"Subnets":[{"AddressPrefix":"::/129"}]}),
        ] {
            let error = observed_prefixes(&value.to_string()).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_CANARY"));
        }
        let too_many =
            json!({"Subnets":vec![json!({"AddressPrefix":"10.0.0.0/24"});MAX_PREFIXES+1]});
        assert_eq!(
            observed_prefixes(&too_many.to_string()).unwrap_err().0,
            "hcn_prefix_inventory_too_large"
        );
    }
}
