use oblivion_wire::control::{HEADER_LIMIT, Operation, RESPONSE_LIMIT, Request, Response};
use oblivion_wire::control_client::{Error, Framing, read_response, write_request};
use oblivion_wire::frame;
use std::io::{Cursor, Read};

fn request() -> Request<u8> {
    Request {
        expected_session: Some("1".repeat(32)),
        operation: Operation::Unlock,
        secret_len: 4,
        session: None,
        slot: 0,
    }
}

fn response(value: &Response, framing: Framing) -> Vec<u8> {
    let json = serde_json::to_vec(value).unwrap();
    if framing == Framing::Local {
        return json;
    }
    let mut bytes = Vec::new();
    frame::write(&mut bytes, &json, 1..=RESPONSE_LIMIT).unwrap();
    bytes
}

#[test]
fn both_request_headers_preserve_their_schema_and_keep_secret_bytes_separate() {
    for framing in [Framing::Local, Framing::Native] {
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request(), b"s\0ec", framing).unwrap();
        let mut reader = Cursor::new(bytes);
        let header = frame::read(&mut reader, 1..=HEADER_LIMIT).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["operation"], "unlock");
        assert_eq!(header["secret_len"], 4);
        assert_eq!(header["slot"], 0);
        assert_eq!(header["expected_session"], "1".repeat(32));
        assert_eq!(
            header.get("version").and_then(serde_json::Value::as_u64),
            if framing == Framing::Native {
                Some(1)
            } else {
                None
            }
        );
        assert_eq!(
            header.as_object().unwrap().len(),
            if framing == Framing::Native { 6 } else { 5 }
        );
        let mut secret = Vec::new();
        reader.read_to_end(&mut secret).unwrap();
        assert_eq!(secret, b"s\0ec");
    }
}

#[test]
fn invalid_request_lengths_fail_before_releasing_header_or_secret() {
    for framing in [Framing::Local, Framing::Native] {
        let mut bytes = Vec::new();
        assert!(matches!(
            write_request(&mut bytes, &request(), b"short", framing),
            Err(Error::SecretLengthMismatch)
        ));
        assert!(bytes.is_empty());
        let mut oversized = request();
        oversized.session = Some("x".repeat(HEADER_LIMIT));
        assert!(write_request(&mut bytes, &oversized, b"s\0ec", framing).is_err());
        assert!(bytes.is_empty());
    }
}

#[test]
fn native_response_reads_exactly_one_frame_and_preserves_the_attached_stream() {
    let value = Response {
        ok: true,
        output: "client".into(),
        error: None,
    };
    let mut bytes = response(&value, Framing::Native);
    bytes.extend_from_slice(b"next-agent-frame");
    let mut reader = Cursor::new(bytes);
    assert_eq!(
        read_response(&mut reader, Framing::Native).unwrap(),
        "client"
    );
    let mut remaining = String::new();
    reader.read_to_string(&mut remaining).unwrap();
    assert_eq!(remaining, "next-agent-frame");
    assert_eq!(
        read_response(
            &mut Cursor::new(response(&value, Framing::Local)),
            Framing::Local
        )
        .unwrap(),
        "client"
    );
    assert!(
        read_response(
            &mut Cursor::new(response(&value, Framing::Local)),
            Framing::Native
        )
        .is_err()
    );
    assert!(
        read_response(
            &mut Cursor::new(response(&value, Framing::Native)),
            Framing::Local
        )
        .is_err()
    );
}

#[test]
fn rejected_responses_surface_only_the_existing_static_error_vocabulary() {
    for framing in [Framing::Local, Framing::Native] {
        for (error, expected) in [
            (Some("safe_busy"), "safe_busy"),
            (Some(""), ""),
            (None, "operation_rejected"),
            (Some("provider secret\nprivate-path"), "operation_rejected"),
            (Some("UPPERCASE"), "operation_rejected"),
        ] {
            let value = Response {
                ok: false,
                output: "secret response content".into(),
                error: error.map(str::to_owned),
            };
            let error =
                read_response(&mut Cursor::new(response(&value, framing)), framing).unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(!format!("{error:?}").contains("secret"));
        }
        let value = Response {
            ok: false,
            output: String::new(),
            error: Some("a".repeat(81)),
        };
        assert_eq!(
            read_response(&mut Cursor::new(response(&value, framing)), framing)
                .unwrap_err()
                .to_string(),
            "operation_rejected"
        );
    }
}

#[test]
fn malformed_and_oversized_responses_do_not_trigger_a_framing_fallback() {
    for length in [0, RESPONSE_LIMIT + 1] {
        assert!(matches!(
            read_response(
                &mut Cursor::new((length as u32).to_be_bytes()),
                Framing::Native
            ),
            Err(Error::InvalidResponseLength)
        ));
    }
    assert!(matches!(
        read_response(
            &mut Cursor::new(vec![b' '; RESPONSE_LIMIT + 1]),
            Framing::Local
        ),
        Err(Error::ResponseTooLarge)
    ));
    let mut truncated = 12u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(b"{}");
    assert!(matches!(
        read_response(&mut Cursor::new(truncated), Framing::Native),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        read_response(
            &mut Cursor::new(br#"{"ok":true,"output":"x","error":null,"unknown":1}"#),
            Framing::Local
        ),
        Err(Error::InvalidResponse)
    ));
}

#[test]
fn codec_failures_do_not_retain_serde_diagnostics_or_peer_canaries() {
    struct InvalidSlot;
    impl serde::Serialize for InvalidSlot {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("PRIVATE_CANARY_SERIALIZE"))
        }
    }
    for framing in [Framing::Local, Framing::Native] {
        for json in [
            br#"{"ok":true,"output":"","error":null,"PRIVATE_CANARY_FIELD":false}"#.as_slice(),
            br#"{"ok":"PRIVATE_CANARY_VALUE","output":"","error":null}"#.as_slice(),
        ] {
            let mut bytes = Vec::new();
            if framing == Framing::Local {
                bytes.extend_from_slice(json);
            } else {
                frame::write(&mut bytes, json, 1..=RESPONSE_LIMIT).unwrap();
            }
            let error = read_response(&mut Cursor::new(bytes), framing).unwrap_err();
            assert_eq!(error.to_string(), "invalid_control_response");
            assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
            assert!(std::error::Error::source(&error).is_none());
        }
        let request = Request {
            operation: Operation::Status,
            expected_session: None,
            session: None,
            slot: InvalidSlot,
            secret_len: 0,
        };
        let mut writer = Vec::new();
        let error = write_request(&mut writer, &request, &[], framing).unwrap_err();
        assert_eq!(error.to_string(), "invalid_control_request");
        assert!(!format!("{error:?}").contains("PRIVATE_CANARY"));
        assert!(std::error::Error::source(&error).is_none());
        assert!(writer.is_empty());
    }
}

#[test]
fn boxed_transport_error_preserves_the_original_io_error_and_inner_identity() {
    #[derive(Debug)]
    struct TransportFailure(u8);
    impl std::fmt::Display for TransportFailure {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            output.write_str("test_transport_failure")
        }
    }
    impl std::error::Error for TransportFailure {}
    let cause = Box::new(TransportFailure(7));
    let identity = &*cause as *const TransportFailure;
    let cause: Box<dyn std::error::Error + Send + Sync> = cause;
    let error = std::io::Error::new(std::io::ErrorKind::TimedOut, cause);
    let boxed = Error::Io(error).into_boxed();
    let error = boxed.downcast::<std::io::Error>().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<TransportFailure>()
            .unwrap()
            .0,
        7
    );
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<TransportFailure>()
            .unwrap() as *const _,
        identity
    );
}
