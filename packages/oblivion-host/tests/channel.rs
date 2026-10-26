use oblivion_host::channel::Channel;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[test]
fn fragmented_bidirectional_exchange_completes() {
    let (stream, peer) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut channel = Channel::new(&peer, Duration::from_secs(5));
        for byte in b"token\n" {
            channel.write_all(&[*byte]).unwrap();
            let mut ack = [0];
            channel.read_exact(&mut ack).unwrap();
            assert_eq!(ack, [*byte]);
        }
        channel.write_all(b"ready\n").unwrap();
    });
    let mut channel = Channel::new(&stream, Duration::from_secs(5));
    for byte in b"token\n" {
        let mut received = [0];
        channel.read_exact(&mut received).unwrap();
        assert_eq!(received, [*byte]);
        channel.write_all(&received).unwrap();
    }
    let mut ready = [0; 6];
    channel.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready\n");
    worker.join().unwrap();
}

#[test]
fn continued_progress_does_not_renew_the_exchange() {
    let (stream, peer) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        // This longer deadline is a watchdog; a broken client cannot hang the test.
        let mut channel = Channel::new(&peer, Duration::from_secs(5));
        let mut byte = [0];
        while channel.read_exact(&mut byte).is_ok() {
            if channel.write_all(&byte).is_err() {
                break;
            }
        }
    });
    let mut channel = Channel::new(&stream, Duration::from_millis(200));
    let mut byte = [0];
    let error = loop {
        if let Err(error) = channel
            .write_all(b"x")
            .and_then(|()| channel.read_exact(&mut byte))
        {
            break error;
        }
        assert_eq!(&byte, b"x");
    };
    stream.shutdown(Shutdown::Both).unwrap();
    worker.join().unwrap();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[test]
fn partial_read_expires_and_a_new_exchange_has_its_own_budget() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"t").unwrap();
    let mut ready = [0; 6];
    let error = Channel::new(&stream, Duration::from_millis(100))
        .read_exact(&mut ready)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(ready[0], b't');
    peer.write_all(b"ready\n").unwrap();
    Channel::new(&stream, Duration::from_secs(5))
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready\n");
}

#[test]
fn a_peer_that_does_not_drain_cannot_block_a_write_forever() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let error = Channel::new(&stream, Duration::from_millis(100))
        .write_all(&vec![0; 16 * 1024 * 1024])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[test]
fn expired_exchange_does_not_consume_buffered_bytes_and_eof_stays_distinct() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"x").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut byte = [0];
    assert_eq!(
        Channel::new(&stream, Duration::ZERO)
            .read_exact(&mut byte)
            .unwrap_err()
            .kind(),
        ErrorKind::TimedOut
    );
    let mut channel = Channel::new(&stream, Duration::from_secs(5));
    channel.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    assert_eq!(
        channel.read_exact(&mut byte).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
}

#[cfg(target_os = "linux")]
#[test]
fn full_unix_listener_backlog_expires_before_a_protocol_exchange() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;
    let path = std::env::temp_dir().join(format!("oblivion-connect-{}.sock", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let first = UnixStream::connect(&path).unwrap();
    let error = oblivion_host::channel::connect(&path, Duration::from_millis(25)).unwrap_err();
    assert!(matches!(
        error.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EINPROGRESS)
    ));
    drop(listener.accept().unwrap());
    drop(first);
    let mut next = oblivion_host::channel::connect(&path, Duration::from_secs(5)).unwrap();
    let (peer, _) = listener.accept().unwrap();
    next.write_all(b"ready").unwrap();
    let mut bytes = [0; 5];
    Channel::new(&peer, Duration::from_secs(5))
        .read_exact(&mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"ready");
    drop((next, peer, listener));
    std::fs::remove_file(path).unwrap();
}
