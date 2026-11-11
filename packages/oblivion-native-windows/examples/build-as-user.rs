//! CI-only launcher for the Windows development builder.
#[cfg(all(windows, target_arch = "x86_64"))]
fn main() {
    match windows::run() {
        Ok(code) => std::process::exit(code as i32),
        Err(error) => {
            eprintln!("build-as-user: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {
    eprintln!("build-as-user requires Windows x64");
    std::process::exit(1);
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows {
    use oblivion_native_windows::security::Identity;
    use std::fs::File;
    use std::io;
    use std::mem::{size_of, size_of_val};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_ALL, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
        GetSecurityDescriptorDacl, GetTokenInformation, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
        SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
        TokenDefaultDacl, TokenOwner, TokenUser, WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
        GetProcessWindowStation, GetThreadDesktop, HDESK, HWINSTA, SetProcessWindowStation,
        SetThreadDesktop,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateProcessAsUserW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThreadId, GetExitCodeProcess,
        INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::CWF_CREATE_ONLY;

    pub fn run() -> Result<u32, Box<dyn std::error::Error>> {
        let mut args = std::env::args_os().skip(1);
        let executable = args
            .next()
            .ok_or("Expected absolute pwsh.exe path and encoded command")?;
        let encoded = args
            .next()
            .ok_or("Expected a Base64 UTF-16LE encoded command")?;
        if args.next().is_some() {
            return Err("Expected exactly two arguments".into());
        }
        let executable = executable.to_str().ok_or("Invalid PowerShell path")?;
        let path = Path::new(executable);
        if !path.is_absolute()
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("pwsh.exe"))
            || !path.is_file()
            || executable.contains(['"', '\0'])
        {
            return Err("Expected an absolute path to pwsh.exe".into());
        }
        let encoded = encoded.to_str().ok_or("Invalid encoded command")?;
        let data = encoded.trim_end_matches('=');
        let padding = encoded.len() - data.len();
        if data.is_empty()
            || encoded.len() % 4 != 0
            || padding > 2
            || (encoded.len() / 4 * 3 - padding) % 2 != 0
            || !data
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        {
            return Err("Expected a Base64 UTF-16LE encoded command".into());
        }
        let mut command: Vec<u16> =
            format!("\"{executable}\" -NoProfile -NonInteractive -EncodedCommand {encoded}")
                .encode_utf16()
                .chain([0])
                .collect();
        if command.len() > 32_767 {
            return Err("PowerShell command exceeds the Windows command line limit".into());
        }
        let executable: Vec<u16> = executable.encode_utf16().chain([0]).collect();
        let token = restricted_token()?;
        Ok(launch(&token, &executable, &mut command)?)
    }

    fn restricted_token() -> io::Result<OwnedHandle> {
        let mut original = null_mut();
        require(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                    &mut original,
                ) != 0
            },
            "Open process token",
        )?;
        let original = unsafe { OwnedHandle::from_raw_handle(original) };
        let mut administrator = [0u32; SECURITY_MAX_SID_SIZE as usize / size_of::<u32>()];
        let mut sid_size = size_of_val(&administrator) as u32;
        let disabled = SID_AND_ATTRIBUTES {
            Sid: administrator.as_mut_ptr().cast(),
            Attributes: 0,
        };
        require(
            unsafe {
                CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    null_mut(),
                    disabled.Sid,
                    &mut sid_size,
                ) != 0
            },
            "Read Administrators SID",
        )?;
        let mut restricted = null_mut();
        require(
            unsafe {
                CreateRestrictedToken(
                    original.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    1,
                    &disabled,
                    0,
                    null(),
                    0,
                    null(),
                    &mut restricted,
                ) != 0
            },
            "Create restricted primary token",
        )?;
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        // TOKEN_USER plus its SID fits in this aligned buffer. Keep it alive
        // until SetTokenInformation copies the SID to the restricted token.
        let mut user = [0usize; 16];
        let mut length = 0;
        require(
            unsafe {
                GetTokenInformation(
                    restricted.as_raw_handle(),
                    TokenUser,
                    user.as_mut_ptr().cast(),
                    size_of_val(&user) as u32,
                    &mut length,
                ) != 0
            },
            "Read restricted user SID",
        )?;
        let owner = TOKEN_OWNER {
            Owner: unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid },
        };
        require(
            unsafe {
                SetTokenInformation(
                    restricted.as_raw_handle(),
                    TokenOwner,
                    (&owner as *const TOKEN_OWNER).cast(),
                    size_of::<TOKEN_OWNER>() as u32,
                ) != 0
            },
            "Set restricted token owner",
        )?;
        // TokenOwner and TokenDefaultDacl are independent. New process/thread
        // and synchronization objects must remain usable without Administrators.
        let descriptor = Identity::current()
            .and_then(|identity| identity.descriptor())
            .map_err(io::Error::other)?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = TOKEN_DEFAULT_DACL::default();
        require(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut dacl.DefaultDacl,
                    &mut defaulted,
                ) != 0
            },
            "Read caller default DACL",
        )?;
        if present == 0 || dacl.DefaultDacl.is_null() {
            return Err(io::Error::other("Caller default DACL is missing"));
        }
        require(
            unsafe {
                SetTokenInformation(
                    restricted.as_raw_handle(),
                    TokenDefaultDacl,
                    (&dacl as *const TOKEN_DEFAULT_DACL).cast(),
                    size_of::<TOKEN_DEFAULT_DACL>() as u32,
                ) != 0
            },
            "Set restricted token default DACL",
        )?;
        Ok(restricted)
    }

    fn launch(token: &OwnedHandle, executable: &[u16], command: &mut [u16]) -> io::Result<u32> {
        let mut desktop = PrivateDesktop::create()?;
        let input = File::open("NUL")?;
        let stdin = inheritable(input.as_raw_handle())?;
        let stdout = inheritable(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })?;
        let stderr = inheritable(unsafe { GetStdHandle(STD_ERROR_HANDLE) })?;
        let handles = [
            stdin.as_raw_handle(),
            stdout.as_raw_handle(),
            stderr.as_raw_handle(),
        ];
        let mut size = 0;
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        if size == 0 || size > 64 * 1024 {
            return Err(io::Error::other(
                "Windows process attribute size is invalid",
            ));
        }
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let attributes = storage.as_mut_ptr().cast();
        require(
            unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) != 0 },
            "Initialize child handle list",
        )?;
        let attributes = Attributes(attributes);
        // Limit handle inheritance to CI logs and the null input handle.
        require(
            unsafe {
                UpdateProcThreadAttribute(
                    attributes.0,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of_val(&handles),
                    null_mut(),
                    null(),
                ) != 0
            },
            "Set child handle list",
        )?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.StartupInfo.lpDesktop = desktop.name.as_mut_ptr();
        startup.lpAttributeList = attributes.0;
        let mut child = PROCESS_INFORMATION::default();
        require(
            unsafe {
                CreateProcessAsUserW(
                    token.as_raw_handle(),
                    executable.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    null(),
                    null(),
                    &startup.StartupInfo,
                    &mut child,
                ) != 0
            },
            "Start PowerShell with restricted token",
        )?;
        eprintln!(
            "build-as-user: CreateProcessAsUser succeeded, child PID {}",
            child.dwProcessId
        );
        let process = unsafe { OwnedHandle::from_raw_handle(child.hProcess) };
        drop(unsafe { OwnedHandle::from_raw_handle(child.hThread) });
        drop(attributes);
        drop((stdin, stdout, stderr));
        require(
            unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) == WAIT_OBJECT_0 },
            "Wait for restricted PowerShell",
        )?;
        let mut code = 0;
        require(
            unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) != 0 },
            "Read restricted PowerShell exit code",
        )?;
        eprintln!("build-as-user: restricted PowerShell exited with {code:#010x}");
        Ok(code)
    }

    // A hosted runner's station can depend on its enabled Administrators SID.
    // Give USER32 a separate noninteractive station and desktop whose explicit
    // DACL admits the unchanged caller SID, without changing the runner's ACLs.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
    struct PrivateDesktop {
        desktop: HDESK,
        station: HWINSTA,
        name: Vec<u16>,
    }

    impl PrivateDesktop {
        fn create() -> io::Result<Self> {
            let descriptor = Identity::current()
                .and_then(|identity| identity.descriptor())
                .map_err(io::Error::other)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let station = format!(
                "OblivionBuild-{}-{:032x}",
                std::process::id(),
                u128::from_le_bytes(random)
            );
            let name = format!("{station}\\build")
                .encode_utf16()
                .chain([0])
                .collect();
            let station: Vec<u16> = station.encode_utf16().chain([0]).collect();
            let original = unsafe { GetProcessWindowStation() };
            require(!original.is_null(), "Read runner window station")?;
            let original_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
            require(!original_desktop.is_null(), "Read runner desktop")?;
            let station = unsafe {
                CreateWindowStationW(station.as_ptr(), CWF_CREATE_ONLY, GENERIC_ALL, &attributes)
            };
            require(!station.is_null(), "Create private build window station")?;
            let mut result = Self {
                desktop: null_mut(),
                station,
                name,
            };
            require(
                unsafe { SetProcessWindowStation(result.station) != 0 },
                "Select private build window station",
            )?;
            result.desktop = unsafe {
                CreateDesktopW(
                    windows_sys::core::w!("build"),
                    null(),
                    null(),
                    0,
                    GENERIC_ALL,
                    &attributes,
                )
            };
            // Preserve the create error before restoring the process station.
            let created = require(!result.desktop.is_null(), "Create private build desktop");
            require(
                unsafe { SetProcessWindowStation(original) != 0 },
                "Restore runner window station",
            )?;
            require(
                unsafe { SetThreadDesktop(original_desktop) != 0 },
                "Restore runner desktop",
            )?;
            created?;
            Ok(result)
        }
    }

    impl Drop for PrivateDesktop {
        fn drop(&mut self) {
            unsafe {
                if !self.desktop.is_null() {
                    CloseDesktop(self.desktop);
                }
                CloseWindowStation(self.station);
            }
        }
    }

    struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);

    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }

    fn inheritable(handle: HANDLE) -> io::Result<OwnedHandle> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("Runner standard handle is unavailable"));
        }
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = null_mut();
        require(
            unsafe {
                DuplicateHandle(
                    process,
                    handle,
                    process,
                    &mut duplicate,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                ) != 0
            },
            "Copy runner standard handle",
        )?;
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
    }

    fn require(success: bool, operation: &str) -> io::Result<()> {
        if success {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        Err(io::Error::other(format!("{operation}: {error}")))
    }
}
