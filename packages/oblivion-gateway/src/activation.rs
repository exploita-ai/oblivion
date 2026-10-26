use std::io;

pub fn harden() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::other("arguments_denied"));
    }
    // Check inherited FDs before Tokio can allocate its own descriptors. Taking
    // ownership of an absent FD after runtime startup could close its poller.
    for (fd, control) in [(3, true), (4, false)] {
        let mut kind = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut address_length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
            || kind != libc::SOCK_STREAM
            || unsafe {
                libc::getsockname(
                    fd,
                    (&mut address as *mut libc::sockaddr_storage).cast(),
                    &mut address_length,
                )
            } != 0
            || (control && address.ss_family as i32 != libc::AF_UNIX)
            || (!control && ![libc::AF_INET, libc::AF_INET6].contains(&(address.ss_family as i32)))
            || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
        {
            return Err(io::Error::other("invalid_descriptors"));
        }
        // Darwin exposes the constant but rejects SO_ACCEPTCONN. The Mac lab
        // still validates socket type/family; production is Linux-only.
        #[cfg(target_os = "linux")]
        if !control {
            let mut accepting = 0;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    (&mut accepting as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
                || accepting == 0
            {
                return Err(io::Error::other("listener_required"));
            }
        }
    }
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } != 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::umask(0o077) };
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } == 0
            || std::fs::read_to_string("/proc/swaps")?.lines().count() != 1
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        {
            return Err(io::Error::other("isolation_required"));
        }
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || (!cfg!(feature = "lab-emulation") && peer.uid != 0)
        {
            return Err(io::Error::other("controller_required"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    if !cfg!(feature = "lab-emulation") {
        return Err(io::Error::other("linux_required"));
    }
    Ok(())
}
