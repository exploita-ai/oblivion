//! Owned, isolated HCN ICS switch and endpoint. Translation belongs to Windows
//! SharedAccess, not a standalone WinNAT instance or an adopted Default Switch.
//! HCN calls are synchronous and expose no operation handle or documented
//! cancellation API. Run them directly on the owner, with
//! lifetime checks before/after; never detach a mutating timeout worker.
//!
//! Acquisition must precede HCS VM creation. Explicit stop is authorized only
//! after an actual Stopped observation (or rollback before any VM exists). Thus
//! a blocked HCN call cannot authorize an active VM. A service hang is not a
//! fabricated deadline success; Windows qualification must cover that boundary.
use crate::hcs_model;
use crate::network_model::{self, Attachment, MAX_PREFIXES, Plan, Prefix};
use crate::{Error, Result};
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::ptr::{NonNull, null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, HCN_E_ENDPOINT_NOT_FOUND, HCN_E_NETWORK_NOT_FOUND,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::HostComputeNetwork::{
    HcnCloseEndpoint, HcnCloseNetwork, HcnCreateEndpoint, HcnCreateNetwork, HcnDeleteEndpoint,
    HcnDeleteNetwork, HcnEnumerateNetworks, HcnOpenEndpoint, HcnOpenNetwork,
    HcnQueryEndpointProperties, HcnQueryNetworkProperties,
};
use windows_sys::core::{GUID, PWSTR};

const TEXT_LIMIT: usize = 1024 * 1024;

/// Dropping an uncleaned lease preserves its handles until helper exit. It does
/// not implicitly delete host resources while VM state may still be unknown.
#[must_use]
pub struct Lease {
    plan: Plan,
    network: Option<Object>,
    endpoint: Option<Object>,
}

impl Lease {
    pub fn acquire(plan: Plan, check: &dyn Fn() -> Result<()>) -> Result<Self> {
        plan.attachment.validate(&plan.attachment.runtime_id)?;
        let network = guid(&plan.attachment.network_id)?;
        let endpoint = guid(&plan.attachment.endpoint_id)?;
        // Refuse both existing IDs before any mutation. A matching name/schema
        // is not authority to adopt a resource from an earlier invocation.
        for (kind, id) in [(Kind::Network, network), (Kind::Endpoint, endpoint)] {
            check()?;
            let existing = Object::open(kind, &id)?;
            if let Some(mut existing) = existing {
                existing.close()?;
                return Err(Error("hcn_runtime_resources_exist"));
            }
            check()?;
        }
        let mut lease = Self {
            plan,
            network: None,
            endpoint: None,
        };
        let result = (|| {
            check()?;
            lease.network = Some(Object::create_network(
                &network,
                &lease.plan.network_json()?,
            )?);
            check()?;
            let properties = lease
                .network
                .as_ref()
                .expect("created HCN network")
                .query()?;
            lease.plan.verify_network_properties(&properties)?;
            check()?;
            lease.endpoint = Some(Object::create_endpoint(
                lease.network.as_ref().expect("created HCN network"),
                &endpoint,
                &lease.plan.endpoint_json()?,
            )?);
            check()?;
            let properties = lease
                .endpoint
                .as_ref()
                .expect("created HCN endpoint")
                .query()?;
            lease.plan.verify_endpoint_properties(&properties)?;
            check()?;
            Ok(())
        })();
        if let Err(error) = result {
            // No HCS VM exists yet. Rollback remains authorized after parent
            // EOF; cancelling cleanup would strand a partially created network.
            let cleanup = lease.stop(&|| Ok(()));
            return cleanup.and(Err(error));
        }
        Ok(lease)
    }

    pub fn attachment(&self) -> &Attachment {
        &self.plan.attachment
    }

    /// Caller supplies an observed Stopped boundary, never just successful
    /// termination submission. Cleanup may use an unconditional check after
    /// parent EOF because removing these already-owned resources is authorized.
    pub fn stop(&mut self, check: &dyn Fn() -> Result<()>) -> Result<()> {
        for kind in [Kind::Endpoint, Kind::Network] {
            check()?;
            let current = match kind {
                Kind::Endpoint => &self.endpoint,
                Kind::Network => &self.network,
            };
            let Some(object) = current else {
                continue;
            };
            let properties = object.query_optional()?;
            check()?;
            if let Some(properties) = properties {
                match kind {
                    Kind::Endpoint => self.plan.verify_endpoint_properties(&properties)?,
                    Kind::Network => self.plan.verify_network_properties(&properties)?,
                }
                check()?;
                object.delete()?;
                check()?;
            }
            // Delete returning S_OK is not the proof of absence.
            if let Some(mut still_present) = Object::open(kind, &object.id)? {
                still_present.close()?;
                return Err(Error("hcn_network_cleanup_unconfirmed"));
            }
            check()?;
            let object = match kind {
                Kind::Endpoint => self.endpoint.take(),
                Kind::Network => self.network.take(),
            };
            if let Some(mut object) = object {
                object.close()?;
            }
            check()?;
        }
        Ok(())
    }

    pub fn retain_until_exit(self) {
        std::mem::forget(self);
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(object) = self.endpoint.take() {
            std::mem::forget(object);
        }
        if let Some(object) = self.network.take() {
            std::mem::forget(object);
        }
    }
}

/// Read-only host routes plus HCN address spaces; no external reachability or
/// IP-check request and no adoption/modification of an existing host network.
pub fn inventory(check: &dyn Fn() -> Result<()>) -> Result<Vec<Prefix>> {
    check()?;
    let mut prefixes = routes()?;
    check()?;
    let mut networks = Text(null_mut());
    let mut error = Text(null_mut());
    // The default HCN schema is the same flat switch/endpoint format used by
    // Microsoft's WSL ICS path; there is one model and no v2 query fallback.
    let result = unsafe { HcnEnumerateNetworks(null(), &mut networks.0, &mut error.0) };
    if result != 0 {
        return Err(Error("hcn_network_inventory_failed"));
    }
    check()?;
    let ids: Vec<String> = serde_json::from_str(&networks.string()?)
        .map_err(|_| Error("hcn_network_inventory_failed"))?;
    if ids.len() > MAX_PREFIXES {
        return Err(Error("hcn_prefix_inventory_too_large"));
    }
    for id in ids {
        let id = guid(&id)?;
        check()?;
        // Concurrent removal is an absence observation, not a reason to adopt
        // or recreate any of the other runtime's resources.
        let Some(mut network) = Object::open(Kind::Network, &id)? else {
            continue;
        };
        check()?;
        let properties = network.query();
        let closed = network.close();
        let observed = network_model::observed_prefixes(&properties?)?;
        closed?;
        check()?;
        if prefixes.len() + observed.len() > MAX_PREFIXES {
            return Err(Error("hcn_prefix_inventory_too_large"));
        }
        prefixes.extend(observed);
    }
    Ok(prefixes)
}

#[derive(Clone, Copy)]
enum Kind {
    Network,
    Endpoint,
}

struct Object {
    handle: Option<NonNull<c_void>>,
    kind: Kind,
    id: GUID,
}

impl Object {
    fn open(kind: Kind, id: &GUID) -> Result<Option<Self>> {
        let mut handle = null_mut();
        let mut error = Text(null_mut());
        let result = unsafe {
            match kind {
                Kind::Network => HcnOpenNetwork(id, &mut handle, &mut error.0),
                Kind::Endpoint => HcnOpenEndpoint(id, &mut handle, &mut error.0),
            }
        };
        let object = NonNull::new(handle).map(|handle| Self {
            handle: Some(handle),
            kind,
            id: *id,
        });
        if result == missing(kind) && object.is_none() {
            return Ok(None);
        }
        if result != 0 {
            // Only S_OK established a usable context. Contradictory failure
            // output is neither an absence proof nor authority to close it.
            if let Some(object) = object {
                std::mem::forget(object);
            }
            return Err(Error("hcn_object_query_failed"));
        }
        object.map(Some).ok_or(Error("hcn_object_query_failed"))
    }

    fn create_network(id: &GUID, settings: &str) -> Result<Self> {
        let mut handle = null_mut();
        let mut error = Text(null_mut());
        let settings = wide(settings);
        let result = unsafe { HcnCreateNetwork(id, settings.as_ptr(), &mut handle, &mut error.0) };
        Self::created(Kind::Network, id, handle, result)
    }

    fn create_endpoint(network: &Self, id: &GUID, settings: &str) -> Result<Self> {
        let mut handle = null_mut();
        let mut error = Text(null_mut());
        let settings = wide(settings);
        let result = unsafe {
            HcnCreateEndpoint(
                network.raw()?,
                id,
                settings.as_ptr(),
                &mut handle,
                &mut error.0,
            )
        };
        Self::created(Kind::Endpoint, id, handle, result)
    }

    fn created(kind: Kind, id: &GUID, handle: *mut c_void, result: i32) -> Result<Self> {
        let object = NonNull::new(handle).map(|handle| Self {
            handle: Some(handle),
            kind,
            id: *id,
        });
        if result != 0 {
            // The API did not confirm creation. A returned context is not a
            // capability to adopt/delete a pre-existing or uncertain object.
            if let Some(object) = object {
                std::mem::forget(object);
            }
            return Err(Error("hcn_network_creation_unconfirmed"));
        }
        object.ok_or(Error("hcn_network_creation_unconfirmed"))
    }

    fn raw(&self) -> Result<*mut c_void> {
        self.handle
            .map(NonNull::as_ptr)
            .ok_or(Error("hcn_object_closed"))
    }

    fn query(&self) -> Result<String> {
        self.query_optional()?
            .ok_or(Error("hcn_owned_object_missing"))
    }

    fn query_optional(&self) -> Result<Option<String>> {
        let mut properties = Text(null_mut());
        let mut error = Text(null_mut());
        let result = unsafe {
            match self.kind {
                Kind::Network => {
                    HcnQueryNetworkProperties(self.raw()?, null(), &mut properties.0, &mut error.0)
                }
                Kind::Endpoint => {
                    HcnQueryEndpointProperties(self.raw()?, null(), &mut properties.0, &mut error.0)
                }
            }
        };
        if result == missing(self.kind) {
            return Ok(None);
        }
        if result != 0 {
            return Err(Error("hcn_object_query_failed"));
        }
        Ok(Some(properties.string()?))
    }

    fn delete(&self) -> Result<()> {
        let mut error = Text(null_mut());
        let result = unsafe {
            match self.kind {
                Kind::Network => HcnDeleteNetwork(&self.id, &mut error.0),
                Kind::Endpoint => HcnDeleteEndpoint(&self.id, &mut error.0),
            }
        };
        if result != 0 {
            return Err(Error("hcn_network_cleanup_unconfirmed"));
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        let result = unsafe {
            match self.kind {
                Kind::Network => HcnCloseNetwork(handle.as_ptr()),
                Kind::Endpoint => HcnCloseEndpoint(handle.as_ptr()),
            }
        };
        // A failed close has an uncertain context lifetime. Never retry the
        // same opaque pointer; the remaining native context lives until exit.
        if result != 0 {
            return Err(Error("hcn_handle_close_unconfirmed"));
        }
        Ok(())
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn missing(kind: Kind) -> i32 {
    match kind {
        Kind::Network => HCN_E_NETWORK_NOT_FOUND,
        Kind::Endpoint => HCN_E_ENDPOINT_NOT_FOUND,
    }
}

struct Text(PWSTR);
impl Text {
    fn string(&self) -> Result<String> {
        if self.0.is_null() {
            return Err(Error("invalid_hcn_response"));
        }
        let length = (0..TEXT_LIMIT / 2)
            .find(|index| unsafe { *self.0.add(*index) == 0 })
            .ok_or(Error("hcn_response_too_large"))?;
        String::from_utf16(unsafe { std::slice::from_raw_parts(self.0, length) })
            .map_err(|_| Error("invalid_hcn_response"))
    }
}
impl Drop for Text {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
}

struct RouteTable(*mut MIB_IPFORWARD_TABLE2);
impl Drop for RouteTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
}

fn routes() -> Result<Vec<Prefix>> {
    let mut table = RouteTable(null_mut());
    let result = unsafe { GetIpForwardTable2(AF_INET, &mut table.0) };
    if result == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    if result != 0 || table.0.is_null() {
        return Err(Error("hcn_route_inventory_failed"));
    }
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > MAX_PREFIXES {
        return Err(Error("hcn_prefix_inventory_too_large"));
    }
    // Address the SDK field, not sizeof(NumEntries): the ABI has alignment
    // padding before its flexible array of MIB_IPFORWARD_ROW2 records.
    let first = unsafe { std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>() };
    unsafe { std::slice::from_raw_parts(first, count) }
        .iter()
        .map(|row| {
            if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET {
                return Err(Error("hcn_route_inventory_failed"));
            }
            let address = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b };
            Prefix::from_address(
                Ipv4Addr::new(address.s_b1, address.s_b2, address.s_b3, address.s_b4),
                row.DestinationPrefix.PrefixLength,
            )
        })
        .collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn guid(value: &str) -> Result<GUID> {
    let value = hcs_model::guid(value).map_err(|_| Error("invalid_hcn_guid"))?;
    Ok(GUID {
        data1: (value >> 96) as u32,
        data2: (value >> 80) as u16,
        data3: (value >> 64) as u16,
        data4: (value as u64).to_be_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Lease, inventory};
    use crate::Error;
    use crate::network_model::Plan;

    #[test]
    fn revoked_lifetime_never_enters_an_hcn_or_route_call() {
        let denied = || Err(Error("supervisor_lifetime_lost"));
        assert_eq!(
            inventory(&denied).err(),
            Some(Error("supervisor_lifetime_lost"))
        );
        let plan = Plan::new("0123456789abcdef0123456789abcdef", &[]).unwrap();
        assert_eq!(
            Lease::acquire(plan, &denied).err(),
            Some(Error("supervisor_lifetime_lost"))
        );
    }
}
