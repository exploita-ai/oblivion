//! Per-owner, demand-start Windows service. Only the installed privileged
//! helper is executed; lifecycle requests never supply an executable or VM JSON.
use crate::files::Executable;
use crate::private::{self, Pipe};
use crate::security::{self, Identity};
use crate::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DISABLED,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SERVICE_SPECIFIC_ERROR, GetLastError, NO_ERROR, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, QueryServiceStatusEx,
    RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_STOP, SERVICE_CHANGE_CONFIG,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DISABLED,
    SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

pub fn name(owner: &Identity) -> Result<String> {
    if matches!(owner.sid(), "S-1-5-18" | "S-1-5-32-544") {
        return Err(Error("broker_user_owner_required"));
    }
    Ok(format!("Oblivion.{}", owner.sid()))
}

/// Install/update runs with SCM administrator rights. A concurrent Start may
/// refuse the operation; a running service is never overwritten or stopped here.
pub fn install(owner: &Identity, helper: &Path) -> Result<()> {
    let owner_name = name(owner)?;
    let helper = helper.to_str().ok_or(Error("broker_helper_path_invalid"))?;
    let executable = Executable::open(helper, &Identity::administrators()?)?;
    executable.verify()?;
    let command = wide(&format!("\"{helper}\" broker --owner {}", owner.sid()));
    let manager = manager(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT)?;
    let service_name = wide(&owner_name);
    let created = unsafe {
        CreateServiceW(
            manager.0,
            service_name.as_ptr(),
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS
                | SERVICE_QUERY_CONFIG
                | SERVICE_CHANGE_CONFIG
                | WRITE_DAC
                | WRITE_OWNER
                | READ_CONTROL,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    let service = if created.is_null() {
        if unsafe { GetLastError() } != ERROR_SERVICE_EXISTS {
            return Err(Error("broker_service_install_failed"));
        }
        let service = open(
            &manager,
            owner,
            SERVICE_QUERY_STATUS
                | SERVICE_QUERY_CONFIG
                | SERVICE_CHANGE_CONFIG
                | WRITE_DAC
                | WRITE_OWNER,
        )?
        .ok_or(Error("broker_service_missing"))?;
        security::service_permissions(service.0, owner)?;
        if configuration(&service, owner)? != SERVICE_DISABLED {
            return Err(Error("broker_service_quiescence_required"));
        }
        if observe(&service)?.dwCurrentState != SERVICE_STOPPED {
            return Err(Error("broker_service_in_use"));
        }
        executable.verify()?;
        if unsafe {
            ChangeServiceConfigW(
                service.0,
                SERVICE_NO_CHANGE,
                SERVICE_DEMAND_START,
                SERVICE_NO_CHANGE,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } == 0
        {
            return Err(Error("broker_service_update_failed"));
        }
        service
    } else {
        Service(created)
    };
    let descriptor = owner.service_descriptor()?;
    if unsafe {
        SetServiceObjectSecurity(
            service.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    } == 0
    {
        return Err(Error("broker_service_permissions_failed"));
    }
    security::service_permissions(service.0, owner)?;
    executable.verify()?;
    Ok(())
}

pub struct Server {
    service: Service,
    process: OwnedHandle,
    pid: u32,
    owner: Identity,
}
impl Server {
    pub fn connect(&self, stop: Arc<AtomicBool>, deadline: Instant) -> Result<Pipe> {
        check(&stop, deadline)?;
        let current = observe(&self.service)?;
        if current.dwCurrentState != SERVICE_RUNNING
            || current.dwProcessId != self.pid
            || unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err(Error("broker_service_changed"));
        }
        let name = wide(&crate::broker_pipe::name(&self.owner)?);
        let pipe = loop {
            match private::connect_control(&name, &self.owner, &stop, deadline) {
                Ok(pipe) => break pipe,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => {
                    check(&stop, deadline)?;
                    let current = observe(&self.service)?;
                    if current.dwCurrentState != SERVICE_RUNNING || current.dwProcessId != self.pid
                    {
                        return Err(Error("broker_service_changed"));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err(Error("broker_connect_failed")),
            }
        };
        pipe.verify_server_process(&self.process)
            .map_err(|_| Error("untrusted_broker_service"))?;
        check(&stop, deadline)?;
        Ok(pipe)
    }
}

pub fn ensure_running(
    owner: &Identity,
    stop: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Server> {
    name(owner)?;
    let manager = manager(SC_MANAGER_CONNECT)?;
    let service = open(
        &manager,
        owner,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | READ_CONTROL,
    )?
    .ok_or(Error("broker_not_installed"))?;
    security::service_permissions(service.0, owner)?;
    if configuration(&service, owner)? == SERVICE_DISABLED {
        return Err(Error("broker_service_maintenance"));
    }
    let mut attempted = false;
    loop {
        check(&stop, deadline)?;
        let status = observe(&service)?;
        match status.dwCurrentState {
            SERVICE_STOPPED => {
                if attempted {
                    return Err(Error("broker_service_start_failed"));
                }
                attempted = true;
                if unsafe { StartServiceW(service.0, 0, null()) } == 0
                    && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
                {
                    return Err(Error(
                        if unsafe { GetLastError() } == ERROR_SERVICE_DISABLED {
                            "broker_service_maintenance"
                        } else {
                            "broker_service_start_failed"
                        },
                    ));
                }
            }
            SERVICE_START_PENDING => {}
            SERVICE_RUNNING => {
                if status.dwProcessId == 0 {
                    return Err(Error("broker_service_identity_unavailable"));
                }
                let process = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                        0,
                        status.dwProcessId,
                    )
                };
                if process.is_null() {
                    return Err(Error("broker_service_identity_unavailable"));
                }
                let process = unsafe { OwnedHandle::from_raw_handle(process) };
                let confirm = observe(&service)?;
                if confirm.dwCurrentState != SERVICE_RUNNING
                    || confirm.dwProcessId != status.dwProcessId
                    || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
                {
                    return Err(Error("broker_service_changed"));
                }
                return Ok(Server {
                    service,
                    process,
                    pid: status.dwProcessId,
                    owner: owner.clone(),
                });
            }
            _ => return Err(Error("broker_service_in_transition")),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Caller must already hold the runtime's exclusive observed-Stopped guard.
/// Ordinary users have no SERVICE_STOP or CHANGE_CONFIG rights.
pub fn quiesce(owner: &Identity, stop: Arc<AtomicBool>, deadline: Instant) -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let Some(service) = open(
        &manager,
        owner,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG,
    )?
    else {
        return Ok(());
    };
    security::service_permissions(service.0, owner)?;
    configuration(&service, owner)?;
    // A user may still poll ensure_running during maintenance. Disable demand
    // starts while the caller retains its observed-Stopped runtime guard.
    if unsafe {
        ChangeServiceConfigW(
            service.0,
            SERVICE_NO_CHANGE,
            SERVICE_DISABLED,
            SERVICE_NO_CHANGE,
            null(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            null(),
        )
    } == 0
    {
        return Err(Error("broker_service_disable_failed"));
    }
    loop {
        check(&stop, deadline)?;
        match observe(&service)?.dwCurrentState {
            SERVICE_STOPPED => return Ok(()),
            SERVICE_RUNNING => {
                let mut status = SERVICE_STATUS::default();
                if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0
                    && !matches!(
                        unsafe { GetLastError() },
                        ERROR_SERVICE_NOT_ACTIVE | ERROR_SERVICE_CANNOT_ACCEPT_CTRL
                    )
                {
                    return Err(Error("broker_service_stop_failed"));
                }
            }
            SERVICE_START_PENDING | SERVICE_STOP_PENDING => {}
            _ => return Err(Error("broker_service_in_transition")),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn remove(owner: &Identity) -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let Some(service) = open(
        &manager,
        owner,
        DELETE | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    )?
    else {
        return Ok(());
    };
    security::service_permissions(service.0, owner)?;
    if configuration(&service, owner)? != SERVICE_DISABLED {
        return Err(Error("broker_service_quiescence_required"));
    }
    if observe(&service)?.dwCurrentState != SERVICE_STOPPED {
        return Err(Error("broker_service_in_use"));
    }
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(Error("broker_service_remove_failed"));
    }
    Ok(())
}

fn manager(access: u32) -> Result<Service> {
    let manager = unsafe { OpenSCManagerW(null(), null(), access) };
    if manager.is_null() {
        return Err(Error("broker_service_access_denied"));
    }
    Ok(Service(manager))
}
fn open(manager: &Service, owner: &Identity, access: u32) -> Result<Option<Service>> {
    let service = unsafe {
        OpenServiceW(
            manager.0,
            wide(&name(owner)?).as_ptr(),
            access | READ_CONTROL,
        )
    };
    if service.is_null() {
        if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        return Err(Error("broker_service_access_denied"));
    }
    Ok(Some(Service(service)))
}
fn observe(service: &Service) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(Error("broker_service_observation_failed"));
    }
    Ok(status)
}
fn configuration(service: &Service, owner: &Identity) -> Result<u32> {
    let mut needed = 0;
    unsafe {
        QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<QUERY_SERVICE_CONFIGW>() as u32 || needed > 65536 {
        return Err(Error("broker_service_configuration_invalid"));
    }
    let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe { QueryServiceConfigW(service.0, data.as_mut_ptr().cast(), needed, &mut needed) } == 0
    {
        return Err(Error("broker_service_configuration_unavailable"));
    }
    let config = unsafe { &*data.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || !matches!(config.dwStartType, SERVICE_DEMAND_START | SERVICE_DISABLED)
        || text(config.lpServiceStartName)?.to_ascii_lowercase() != "localsystem"
    {
        return Err(Error("broker_service_configuration_invalid"));
    }
    let command = text(config.lpBinaryPathName)?;
    let _helper = command
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix(&format!("\" broker --owner {}", owner.sid())))
        .filter(|path| crate::config::drive_file(path))
        .ok_or(Error("broker_service_configuration_invalid"))?;
    Ok(config.dwStartType)
}
fn text(pointer: *const u16) -> Result<String> {
    if pointer.is_null() {
        return Err(Error("broker_service_configuration_invalid"));
    }
    let length = (0..32768)
        .find(|index| unsafe { *pointer.add(*index) == 0 })
        .ok_or(Error("broker_service_configuration_invalid"))?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(|_| Error("broker_service_configuration_invalid"))
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn check(stop: &AtomicBool, deadline: Instant) -> Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(Error("broker_cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error("broker_timeout"));
    }
    Ok(())
}

type Callback = fn(Identity, Arc<AtomicBool>) -> Result<()>;
struct Dispatch {
    owner: Identity,
    callback: Callback,
    stop: Arc<AtomicBool>,
    state: Mutex<Option<ServiceState>>,
    result: Mutex<Option<Error>>,
}
struct ServiceState {
    handle: usize,
    status: SERVICE_STATUS,
}
static DISPATCH: OnceLock<Dispatch> = OnceLock::new();

pub fn dispatch(owner: Identity, callback: Callback) -> Result<()> {
    name(&owner)?;
    security::require_system_process(unsafe { GetCurrentProcess() })?;
    let service_name = wide(&name(&owner)?);
    DISPATCH
        .set(Dispatch {
            owner,
            callback,
            stop: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
            result: Mutex::new(None),
        })
        .map_err(|_| Error("broker_service_already_dispatched"))?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(Error("broker_service_dispatch_failed"));
    }
    let result = DISPATCH
        .get()
        .ok_or(Error("broker_service_dispatch_failed"))?
        .result
        .lock()
        .map_err(|_| Error("broker_service_state_failed"))?;
    result.map_or(Ok(()), Err)
}
unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let Some(context) = DISPATCH.get() else {
        return;
    };
    let Ok(service_name) = name(&context.owner) else {
        return;
    };
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(wide(&service_name).as_ptr(), Some(service_control), null())
    };
    if handle.is_null() {
        if let Ok(mut error) = context.result.lock() {
            *error = Some(Error("broker_service_handler_failed"));
        }
        return;
    }
    if let Ok(mut state) = context.state.lock() {
        *state = Some(ServiceState {
            handle: handle as usize,
            status: SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                ..SERVICE_STATUS::default()
            },
        });
    }
    let result = (|| {
        report(SERVICE_START_PENDING, 0)?;
        security::expose_broker_process(&context.owner)?;
        report(SERVICE_RUNNING, 0)?;
        (context.callback)(context.owner.clone(), Arc::clone(&context.stop))
    })();
    if let Err(error) = result {
        if let Ok(mut stored) = context.result.lock() {
            *stored = Some(error);
        }
    }
    let _ = report(
        SERVICE_STOPPED,
        if result.is_ok() {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
    );
}
unsafe extern "system" fn service_control(
    control: u32,
    _: u32,
    _: *mut core::ffi::c_void,
    _: *mut core::ffi::c_void,
) -> u32 {
    let Some(context) = DISPATCH.get() else {
        return 1;
    };
    if control == SERVICE_CONTROL_STOP {
        context.stop.store(true, Ordering::Release);
        let _ = report(SERVICE_STOP_PENDING, 0);
    } else if control == SERVICE_CONTROL_INTERROGATE {
        if let Ok(state) = context.state.lock() {
            if let Some(state) = state.as_ref() {
                unsafe {
                    SetServiceStatus(state.handle as _, &state.status);
                }
            }
        }
    }
    NO_ERROR
}
fn report(phase: u32, exit: u32) -> Result<()> {
    let context = DISPATCH.get().ok_or(Error("broker_service_state_failed"))?;
    let mut state = context
        .state
        .lock()
        .map_err(|_| Error("broker_service_state_failed"))?;
    let state = state.as_mut().ok_or(Error("broker_service_state_failed"))?;
    if state.status.dwCurrentState == SERVICE_STOPPED && phase == SERVICE_STOP_PENDING {
        return Ok(());
    }
    state.status.dwCurrentState = phase;
    state.status.dwControlsAccepted = if phase == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP
    } else {
        0
    };
    state.status.dwWin32ExitCode = exit;
    state.status.dwServiceSpecificExitCode = u32::from(exit != 0);
    state.status.dwCheckPoint = if matches!(phase, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
        1
    } else {
        0
    };
    state.status.dwWaitHint = if matches!(phase, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
        390000
    } else {
        0
    };
    if unsafe { SetServiceStatus(state.handle as _, &state.status) } == 0 {
        return Err(Error("broker_service_state_failed"));
    }
    Ok(())
}
