//! Owned HCS handles only: recovery can stop exactly a recorded generation,
//! never adopt or start a system opened by ID.
//! Async API admission is never treated as operation completion.
use crate::hcs_model::{self, MAX_REPLY_BYTES};
use crate::{Error, Result};
use std::ptr;
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    GENERIC_ALL, HCS_E_OPERATION_TIMEOUT, HCS_E_SYSTEM_NOT_FOUND, LocalFree,
};
use windows_sys::Win32::System::HostComputeSystem::{
    HCS_OPERATION, HCS_SYSTEM, HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem,
    HcsCreateOperation, HcsEnumerateComputeSystems, HcsGetComputeSystemProperties,
    HcsGetServiceProperties, HcsOpenComputeSystem, HcsShutDownComputeSystem, HcsStartComputeSystem,
    HcsTerminateComputeSystem, HcsWaitForOperationResult,
};
use windows_sys::core::{GUID, HRESULT, PWSTR};

pub use crate::hcs_model::{Capabilities, Schema, State};

pub struct Status {
    pub state: State,
    /// This is HCS RuntimeId, not the caller's compute-system ID.
    pub runtime_id: Option<GUID>,
}

pub fn capabilities() -> Result<Capabilities> {
    // The two official WSL query shapes deliberately have distinct response
    // schemas; a failed processor query cannot silently mean nested support.
    let basic = service_properties(r#"{"PropertyTypes":["Basic"]}"#)?;
    let processors = service_properties(r#"{"PropertyQueries":{"ProcessorCapabilities":{}}}"#)?;
    Capabilities::parse(&basic, &processors)
}

pub struct Machine {
    handle: HCS_SYSTEM,
    id: String,
    owner: String,
}

impl Machine {
    pub fn create(
        id: &str,
        owner: &str,
        configuration: &str,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        hcs_model::creation(configuration, id, owner)?;
        require_absent(id, deadline, check)?;
        check()?;
        remaining(deadline)?;
        let operation = Operation::new()?;
        let id_wide = wide(id)?;
        let configuration = wide(configuration)?;
        let mut handle = ptr::null_mut();
        let admitted = unsafe {
            HcsCreateComputeSystem(
                id_wide.as_ptr(),
                configuration.as_ptr(),
                operation.0,
                ptr::null(),
                &mut handle,
            )
        };
        // Own even an error-path handle immediately. The generated configuration
        // sets ShouldTerminateOnLastHandleClosed, including create timeouts.
        let machine = (!handle.is_null()).then(|| Self {
            handle,
            id: id.to_owned(),
            owner: owner.to_owned(),
        });
        if admitted < 0 {
            return Err(Error("hcs_create_failed"));
        }
        let machine = machine.ok_or(Error("hcs_create_handle_missing"))?;
        operation.wait(deadline, check, "hcs_create_failed")?;
        machine.state(deadline, check)?;
        Ok(machine)
    }

    pub fn start(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<()> {
        self.change(deadline, check, HcsStartComputeSystem, "hcs_start_failed")
    }

    pub fn shutdown(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<()> {
        self.change(
            deadline,
            check,
            HcsShutDownComputeSystem,
            "hcs_shutdown_failed",
        )
    }

    pub fn terminate(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<()> {
        self.change(
            deadline,
            check,
            HcsTerminateComputeSystem,
            "hcs_terminate_failed",
        )
    }

    pub fn state(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<Status> {
        check()?;
        remaining(deadline)?;
        let operation = Operation::new()?;
        if unsafe { HcsGetComputeSystemProperties(self.handle, operation.0, ptr::null()) } < 0 {
            return Err(Error("hcs_properties_failed"));
        }
        let document = operation
            .wait(deadline, check, "hcs_properties_failed")?
            .ok_or(Error("hcs_properties_missing"))?;
        let properties = hcs_model::Properties::parse(&document, &self.id, &self.owner)?;
        Ok(Status {
            state: properties.state,
            runtime_id: properties.runtime_id.map(GUID::from_u128),
        })
    }

    /// An ephemeral system may disappear before its retained handle can return
    /// Properties. Only an exact scoped inventory may prove that alternative.
    pub fn stopped(&self, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<bool> {
        match self.state(deadline, check) {
            Ok(status) => Ok(status.state == State::Stopped),
            Err(Error("hcs_properties_failed" | "hcs_properties_missing")) => {
                let current = hcs_model::Properties::inventory(
                    &inventory(&self.id, deadline, check)?,
                    &self.id,
                    &self.owner,
                )?;
                Ok(current.is_none_or(|properties| properties.state == State::Stopped))
            }
            Err(error) => Err(error),
        }
    }

    fn change(
        &self,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
        change: unsafe extern "system" fn(HCS_SYSTEM, HCS_OPERATION, *const u16) -> HRESULT,
        failure: &'static str,
    ) -> Result<()> {
        check()?;
        remaining(deadline)?;
        let operation = Operation::new()?;
        if unsafe { change(self.handle, operation.0, ptr::null()) } < 0 {
            return Err(Error(failure));
        }
        operation.wait(deadline, check, failure)?;
        Ok(())
    }
}

/// Call before grants/network creation too. The check inside Machine::create
/// closes the ordinary collision window; an AlreadyExists result is never an
/// invitation to open or adopt that system.
pub fn require_absent(id: &str, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<()> {
    if !hcs_model::absent(&inventory(id, deadline, check)?, id)? {
        return Err(Error("hcs_system_already_exists"));
    }
    Ok(())
}

/// Stop only a generation authorized by the durable resource receipt. HCS
/// Owner is a client marker, not an authentication secret: the caller must
/// hold the installation's private receipt lock throughout this operation.
pub fn reconcile(
    id: &str,
    expected_owner: &str,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    hcs_model::validate_owner(id, expected_owner)?;
    let Some(observed) =
        hcs_model::Properties::inventory(&inventory(id, deadline, check)?, id, expected_owner)?
    else {
        return Ok(());
    };
    match observed.state {
        State::Stopped => return Ok(()),
        State::Created | State::Running | State::Paused => {}
        _ => return Err(Error("hcs_recovery_state_unconfirmed")),
    }

    check()?;
    remaining(deadline)?;
    let id_wide = wide(id)?;
    let mut handle = ptr::null_mut();
    // The HCS API currently requires GENERIC_ALL, not a guessed access mask:
    // https://learn.microsoft.com/virtualization/api/hcs/reference/hcsopencomputesystem
    let result = unsafe { HcsOpenComputeSystem(id_wide.as_ptr(), GENERIC_ALL, &mut handle) };
    let machine = (!handle.is_null()).then(|| Machine {
        handle,
        id: id.to_owned(),
        owner: expected_owner.to_owned(),
    });
    check()?;
    if result == HCS_E_SYSTEM_NOT_FOUND && machine.is_none() {
        // A failed open alone is not absence. Confirm the scoped inventory
        // after the failure rather than overlooking a changed generation.
        return require_absent(id, deadline, check);
    }
    if result < 0 {
        return Err(Error("hcs_recovery_open_failed"));
    }
    let machine = machine.ok_or(Error("hcs_recovery_handle_missing"))?;
    let current = machine.state(deadline, check)?;
    match current.state {
        State::Stopped => return Ok(()),
        State::Created | State::Running | State::Paused => {}
        _ => return Err(Error("hcs_recovery_state_unconfirmed")),
    }
    // A successful terminate admission/completion is not a stopped proof.
    // Even an error may race an already-completed stop, so query afterwards.
    let terminated = machine.terminate(deadline, check);
    loop {
        check()?;
        remaining(deadline)?;
        if machine.stopped(deadline, check)? {
            return Ok(());
        }
        terminated?;
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn inventory(id: &str, deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<String> {
    // SystemQuery.Ids returns an array of Properties; Owner is deliberately
    // not a filter because a foreign VM with this ID must block creation.
    // https://learn.microsoft.com/virtualization/api/hcs/schemareference#systemquery
    check()?;
    remaining(deadline)?;
    let query = wide(&hcs_model::system_query(id)?)?;
    let operation = Operation::new()?;
    if unsafe { HcsEnumerateComputeSystems(query.as_ptr(), operation.0) } < 0 {
        return Err(Error("hcs_inventory_failed"));
    }
    operation
        .wait(deadline, check, "hcs_inventory_failed")?
        .ok_or(Error("hcs_inventory_missing"))
}

impl Drop for Machine {
    fn drop(&mut self) {
        unsafe { HcsCloseComputeSystem(self.handle) };
    }
}

struct Operation(HCS_OPERATION);
impl Operation {
    fn new() -> Result<Self> {
        let operation = unsafe { HcsCreateOperation(ptr::null(), None) };
        if operation.is_null() {
            return Err(Error("hcs_operation_unavailable"));
        }
        Ok(Self(operation))
    }

    fn wait(
        &self,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
        failure: &'static str,
    ) -> Result<Option<String>> {
        loop {
            check()?;
            let timeout = remaining(deadline)?.min(100);
            let mut document = ptr::null_mut();
            let result = unsafe { HcsWaitForOperationResult(self.0, timeout, &mut document) };
            // Every poll may supply an allocation, including error/timeout or a
            // completed operation whose authority was just revoked by check().
            let document = Document(document);
            check()?;
            if result == HCS_E_OPERATION_TIMEOUT {
                // Keep the same operation handle until completion, revocation
                // or the caller's real deadline. A timed-out wait never means
                // the compute system stopped or that its operation was cancelled.
                continue;
            }
            if result != 0 {
                return Err(Error(failure));
            }
            return document.read();
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        unsafe { HcsCloseOperation(self.0) };
    }
}

struct Document(PWSTR);
impl Document {
    fn read(&self) -> Result<Option<String>> {
        if self.0.is_null() {
            return Ok(None);
        }
        for length in 0..MAX_REPLY_BYTES / 2 {
            if unsafe { self.0.add(length).read() } == 0 {
                let value = unsafe { std::slice::from_raw_parts(self.0, length) };
                let value = String::from_utf16(value).map_err(|_| Error("invalid_hcs_reply"))?;
                if value.len() > MAX_REPLY_BYTES {
                    return Err(Error("hcs_reply_too_large"));
                }
                return Ok(Some(value));
            }
        }
        Err(Error("hcs_reply_too_large"))
    }
}
impl Drop for Document {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

fn service_properties(query: &str) -> Result<String> {
    let query = wide(query)?;
    let mut document = ptr::null_mut();
    let result = unsafe { HcsGetServiceProperties(query.as_ptr(), &mut document) };
    let document = Document(document);
    if result < 0 {
        return Err(Error("hcs_capabilities_unavailable"));
    }
    document.read()?.ok_or(Error("hcs_capabilities_missing"))
}

fn remaining(deadline: Instant) -> Result<u32> {
    let duration = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Error("hcs_operation_timeout"))?;
    // Round upward to avoid converting a positive remainder to a zero wait;
    // never use the reserved INFINITE value.
    Ok(duration
        .as_millis()
        .saturating_add(u128::from(duration.subsec_nanos() % 1_000_000 != 0))
        .min(u128::from(u32::MAX - 1)) as u32)
}

fn wide(value: &str) -> Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(Error("invalid_hcs_input"));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}
