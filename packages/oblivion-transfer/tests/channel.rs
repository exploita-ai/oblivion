use oblivion_transfer::channel::Channel;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn channel(stream: UnixStream, budget: Duration) -> Channel {
    Channel::new(File::from(OwnedFd::from(stream)), budget).unwrap()
}

#[test]
fn fragmented_duplex_exchange_uses_the_same_descriptor() {
    let (stream, peer) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut peer = channel(peer, Duration::from_secs(5));
        for byte in b"copy-ready" {
            peer.write_all(&[*byte]).unwrap();
            let mut response = [0];
            peer.read_exact(&mut response).unwrap();
            assert_eq!(response, [*byte]);
        }
    });
    let mut stream = channel(stream, Duration::from_secs(5));
    for byte in b"copy-ready" {
        let mut received = [0];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, [*byte]);
        stream.write_all(&received).unwrap();
    }
    worker.join().unwrap();
}

#[test]
fn continuous_progress_cannot_extend_the_deadline() {
    let (stream, peer) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut peer = channel(peer, Duration::from_secs(5));
        let mut byte = [0];
        while peer.read_exact(&mut byte).is_ok() {
            if peer.write_all(&byte).is_err() {
                break;
            }
        }
    });
    let mut stream = channel(stream, Duration::from_millis(100));
    let mut byte = [0];
    let error = loop {
        if let Err(error) = stream
            .write_all(b"x")
            .and_then(|()| stream.read_exact(&mut byte))
        {
            break error;
        }
        assert_eq!(&byte, b"x");
    };
    drop(stream);
    worker.join().unwrap();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[test]
fn incomplete_read_and_blocked_write_expire() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"x").unwrap();
    let mut bytes = [0; 2];
    assert_eq!(
        channel(stream, Duration::from_millis(50))
            .read_exact(&mut bytes)
            .unwrap_err()
            .kind(),
        ErrorKind::TimedOut
    );
    assert_eq!(bytes[0], b'x');
    let (stream, _peer) = UnixStream::pair().unwrap();
    assert_eq!(
        channel(stream, Duration::from_millis(50))
            .write_all(&vec![0; 4 * 1024 * 1024])
            .unwrap_err()
            .kind(),
        ErrorKind::TimedOut
    );
}

#[test]
fn eof_is_distinct_and_an_expired_channel_does_not_read_buffered_content() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"x").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let next = stream.try_clone().unwrap();
    let mut byte = [0];
    assert_eq!(
        channel(stream, Duration::ZERO)
            .read_exact(&mut byte)
            .unwrap_err()
            .kind(),
        ErrorKind::TimedOut
    );
    let mut next = channel(next, Duration::from_secs(5));
    next.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    assert_eq!(
        next.read_exact(&mut byte).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
}

#[test]
fn inherited_pipes_work_and_regular_storage_files_are_not_channels() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let reader = unsafe { File::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    let mut reader = Channel::new(reader, Duration::from_secs(5)).unwrap();
    let mut writer = Channel::new(writer, Duration::from_secs(5)).unwrap();
    writer.write_all(b"pipe").unwrap();
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"pipe");
    assert!(Channel::new(File::open("Cargo.toml").unwrap(), Duration::from_secs(5)).is_err());
}

#[test]
fn revocation_wins_over_buffered_data_and_ready_writes() {
    for close in [false, true] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let (watch, mut owner) = UnixStream::pair().unwrap();
        let mut stream = channel(stream, Duration::from_secs(5));
        stream.watch(watch.into());
        peer.write_all(b"data").unwrap();
        if !close {
            owner.write_all(b"cancel").unwrap();
        }
        drop(owner);
        assert_eq!(
            stream.read(&mut [0; 1]).unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.write(b"data").unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.flush().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    }
}

#[test]
fn owner_closure_interrupts_a_blocked_writer() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let (watch, owner) = UnixStream::pair().unwrap();
    let mut stream = channel(stream, Duration::from_secs(5));
    stream.watch(watch.into());
    let worker = std::thread::spawn(move || stream.write_all(&vec![0; 4 * 1024 * 1024]));
    // Observing actual data establishes that the operation started. No timing
    // sleep or speed assertion is needed to trigger the cancellation.
    peer.read_exact(&mut [0; 1]).unwrap();
    drop(owner);
    assert_eq!(
        worker.join().unwrap().unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );
}
