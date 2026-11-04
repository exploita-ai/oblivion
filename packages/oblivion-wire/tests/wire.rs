use oblivion_wire::{agent, control, frame};
use std::io::{self, Read};

#[test]
fn control_headers_keep_the_existing_local_and_native_wire_bytes() {
    let request = control::Request {
        expected_session: None,
        operation: control::Operation::Status,
        secret_len: 0,
        session: None,
        slot: 0_u8,
    };
    let local =
        br#"{"expected_session":null,"operation":"status","secret_len":0,"session":null,"slot":0}"#;
    let native = br#"{"expected_session":null,"operation":"status","secret_len":0,"session":null,"slot":0,"version":1}"#;
    assert_eq!(serde_json::to_vec(&request).unwrap(), local);
    assert_eq!(
        serde_json::to_vec(&control::NativeRequest::new(&request)).unwrap(),
        native
    );
    let mut bytes = Vec::new();
    frame::write(&mut bytes, native, 1..=control::HEADER_LIMIT).unwrap();
    assert_eq!(&bytes[..4], &[0, 0, 0, 97]);
    assert_eq!(&bytes[4..], native);
    let decoded: control::Request<u8> = serde_json::from_slice(local).unwrap();
    assert_eq!(decoded.operation, control::Operation::Status);
    assert_eq!(decoded.slot, 0);
}

#[test]
fn secret_bytes_and_native_versions_never_enter_local_control_headers() {
    let base = serde_json::json!({"operation":"unlock", "session":null, "secret_len":70000});
    let request: control::Request<u8> = serde_json::from_value(base.clone()).unwrap();
    assert_eq!(request.secret_len, 70000);
    assert_eq!(request.slot, 0);
    for name in ["password", "secret", "version", "path", "owner"] {
        let mut value = base.clone();
        value[name] = "unexpected synthetic payload".into();
        assert!(serde_json::from_value::<control::Request<u8>>(value).is_err());
    }
    for operation in [
        "open-agent-child",
        "start-child-agent",
        "child-start-close",
        "unknown",
    ] {
        assert!(control::Operation::parse(operation).is_err());
    }
    let response: control::Response =
        serde_json::from_slice(br#"{"ok":false,"output":"","error":"operation_rejected"}"#)
            .unwrap();
    assert!(!response.ok);
    assert_eq!(response.error.as_deref(), Some("operation_rejected"));
    assert_eq!(
        serde_json::to_vec(&control::Response {
            ok: true,
            output: "done",
            error: None
        })
        .unwrap(),
        br#"{"ok":true,"output":"done","error":null}"#
    );
}

struct Fragmented<'a>(&'a [u8]);
impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let limit = output.len().min(1);
        self.0.read(&mut output[..limit])
    }
}

#[test]
fn binary_agent_frames_preserve_kinds_payloads_empty_eof_and_fragmentation() {
    let mut bytes = Vec::new();
    agent::write_frame(&mut bytes, 0, &[0, 255, b'\n']).unwrap();
    agent::write_frame(&mut bytes, 5, &[]).unwrap();
    agent::write_frame(&mut bytes, 3, &[0, 24, 0, 80]).unwrap();
    assert_eq!(
        bytes,
        [
            0, 0, 0, 0, 3, 0, 255, b'\n', 5, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 24, 0, 80
        ]
    );
    let mut input = Fragmented(&bytes);
    assert_eq!(
        agent::read_frame(&mut input).unwrap(),
        (0, vec![0, 255, b'\n'])
    );
    assert_eq!(agent::read_frame(&mut input).unwrap(), (5, vec![]));
    assert_eq!(
        agent::read_frame(&mut input).unwrap(),
        (3, vec![0, 24, 0, 80])
    );
    assert!(
        matches!(agent::read_frame(&mut input), Err(frame::Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn bounded_frames_reject_lengths_before_payload_io_and_never_partially_emit_rejections() {
    for length in [0_u32, control::HEADER_LIMIT as u32 + 1, u32::MAX] {
        let bytes = length.to_be_bytes();
        assert!(matches!(
            frame::read(&mut bytes.as_slice(), 1..=control::HEADER_LIMIT),
            Err(frame::Error::InvalidLength)
        ));
    }
    let bytes = [0, 0, 0, 2, b'x'];
    assert!(
        matches!(frame::read(&mut bytes.as_slice(), 1..=control::HEADER_LIMIT), Err(frame::Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
    let mut output = Vec::new();
    assert!(matches!(
        agent::write_frame(&mut output, 0, &vec![0; agent::LIMIT + 1]),
        Err(frame::Error::InvalidLength)
    ));
    assert!(output.is_empty());
    assert!(matches!(
        agent::read_frame(&mut [0, 0, 1, 0, 1].as_slice()),
        Err(frame::Error::InvalidLength)
    ));
    let payload = vec![42; agent::LIMIT];
    agent::write_frame(&mut output, 1, &payload).unwrap();
    assert_eq!(
        agent::read_frame(&mut output.as_slice()).unwrap(),
        (1, payload)
    );
    assert!(agent::Size { rows: 24, cols: 80 }.valid());
    assert!(!agent::Size { rows: 0, cols: 80 }.valid());
    assert!(
        !agent::Size {
            rows: 24,
            cols: 1001
        }
        .valid()
    );
}
