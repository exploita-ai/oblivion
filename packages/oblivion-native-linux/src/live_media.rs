//! Receive the exclusive, read-only block descriptor from the Live broker.
use crate::{Error, Result};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// The caller owns the privileged broker process and its private socketpair.
/// This function admits only the exact single-descriptor reply.
pub fn receive(socket: &UnixStream, deadline: Instant) -> Result<File> {
    let file = receive_descriptor(socket, deadline)?;
    verify_block(&file)?;
    Ok(file)
}

fn receive_descriptor(socket: &UnixStream, deadline: Instant) -> Result<File> {
    let mut marker = 0u8;
    let mut data = libc::iovec {
        iov_base: (&mut marker as *mut u8).cast(),
        iov_len: 1,
    };
    let mut ancillary = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut data;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary);
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Error("live_media_broker_timeout"))?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|_| Error("live_media_socket_failed"))?;
    let mut descriptors = Vec::new();
    let mut valid = true;
    unsafe {
        if libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) != 1 {
            return Err(Error("live_media_descriptor_unavailable"));
        }
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
                let count = bytes / std::mem::size_of::<libc::c_int>();
                let fds = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(fds.add(index).read_unaligned()));
                }
            } else {
                valid = false;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if !valid
        || marker != b'M'
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || descriptors.len() != 1
    {
        return Err(Error("invalid_live_media_descriptor"));
    }
    Ok(File::from(descriptors.remove(0)))
}

fn verify_block(file: &File) -> Result<()> {
    let info = file
        .metadata()
        .map_err(|_| Error("invalid_live_media_descriptor"))?;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if !info.file_type().is_block_device()
        || flags < 0
        || flags & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        || !crate::config::data_size(file).is_ok_and(|bytes| bytes > 0)
    {
        return Err(Error("invalid_live_media_descriptor"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn send(socket: &UnixStream, marker: u8, fds: &[libc::c_int]) {
        let mut data = libc::iovec {
            iov_base: (&marker as *const u8).cast_mut().cast(),
            iov_len: 1,
        };
        let mut ancillary = [0usize; 8];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        let bytes = std::mem::size_of_val(fds);
        unsafe {
            message.msg_controllen = libc::CMSG_SPACE(bytes as _) as usize;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(bytes as _) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                bytes,
            );
            assert_eq!(libc::sendmsg(socket.as_raw_fd(), &message, 0), 1);
        }
    }

    #[test]
    fn imports_one_cloexec_descriptor_and_rejects_nonblock_media() {
        let (receiver, sender) = UnixStream::pair().unwrap();
        let source = File::open("/dev/null").unwrap();
        send(&sender, b'M', &[source.as_raw_fd()]);
        let file = receive_descriptor(&receiver, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) },
            libc::FD_CLOEXEC
        );
        assert_eq!(
            verify_block(&file).unwrap_err().0,
            "invalid_live_media_descriptor"
        );
    }

    #[test]
    fn rejects_extra_descriptors_and_wrong_marker() {
        let source = File::open("/dev/null").unwrap();
        for (marker, count) in [(b'M', 2), (b'F', 1)] {
            let (receiver, sender) = UnixStream::pair().unwrap();
            send(&sender, marker, &vec![source.as_raw_fd(); count]);
            assert_eq!(
                receive(&receiver, Instant::now() + Duration::from_secs(1))
                    .unwrap_err()
                    .0,
                "invalid_live_media_descriptor"
            );
        }
    }
}
