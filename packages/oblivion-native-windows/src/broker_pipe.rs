//! Broker IPC shares the owned local pipe implementation. Authentication uses
//! the kernel client token, after a bounded frame read and before its dispatch.
use crate::private::{Endpoint, Pipe, Purpose};
use crate::security::Identity;
use crate::{Error, Result};

pub fn name(owner: &Identity) -> Result<String> {
    crate::scm::name(owner)?;
    Ok(format!(r"\\.\pipe\oblivion.{}.broker", owner.sid()))
}
pub fn bind(owner: &Identity) -> Result<Endpoint> {
    if Identity::current()?.sid() != "S-1-5-18" {
        return Err(Error("broker_system_process_required"));
    }
    Endpoint::bind_for(&name(owner)?, Purpose::Broker, owner)
}
pub fn authenticate(pipe: &Pipe, owner: &Identity) -> Result<()> {
    pipe.authenticate_client(owner)
}

#[cfg(test)]
mod tests {
    use super::authenticate;
    use crate::client::Channel;
    use crate::private::Purpose;
    use crate::private::tests::{connected_pair, receive};
    use crate::security::Identity;
    use std::io::Write;
    use std::ptr::null_mut;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, GetLastError};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    #[test]
    fn kernel_pipe_token_binds_the_read_message_to_the_exact_owner_and_always_reverts() {
        let (_endpoint, mut server, client) = connected_pair(Purpose::Control);
        let mut client = Channel::new(
            client,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(3),
        );
        client.write_all(b"bounded request").unwrap();
        client.flush().unwrap();
        assert_eq!(receive(&mut server, 15), b"bounded request");
        let owner = Identity::current().unwrap();
        authenticate(&server, &owner).unwrap();
        let wrong = Identity::from_sid("S-1-5-21-1-2-3-1001").unwrap();
        assert!(authenticate(&server, &wrong).is_err());
        assert!(client.authenticate_broker(&owner).is_err());
        let mut token = null_mut();
        assert_eq!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
    }
}
