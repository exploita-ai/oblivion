use oblivion_wire::agent::{self, Command, Decoder, Launch, Size};
use std::io::{self, Read};

struct Ready<'a>(&'a [u8]);
impl Read for Ready<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.0.read(output)
    }
}

#[test]
fn shared_decoder_keeps_partial_frame_state_at_every_byte_boundary() {
    let mut bytes = vec![];
    agent::write_frame(&mut bytes, 1, &[0, 255, b'\n']).unwrap();
    agent::write_frame(&mut bytes, 4, &7i32.to_be_bytes()).unwrap();
    agent::write_frame(&mut bytes, agent::RELAY_FAILURE_KIND, &[]).unwrap();
    for split in 0..8 {
        let mut decoder = Decoder::default();
        assert!(decoder.read(&mut Ready(&bytes[..split])).unwrap().is_none());
        let mut rest = Ready(&bytes[split..]);
        assert_eq!(
            decoder.read(&mut rest).unwrap(),
            Some((1, vec![0, 255, b'\n']))
        );
        assert_eq!(
            decoder.read(&mut rest).unwrap(),
            Some((4, 7i32.to_be_bytes().to_vec()))
        );
        assert_eq!(decoder.read(&mut rest).unwrap(), Some((agent::RELAY_FAILURE_KIND, vec![])));
        assert!(decoder.read(&mut rest).unwrap().is_none());
    }
    assert_eq!(
        agent::read_frame(&mut bytes.as_slice()).unwrap(),
        (1, vec![0, 255, b'\n'])
    );
    let mut decoder = Decoder::default();
    assert!(decoder.read(&mut [1, 0, 1, 0, 1].as_slice()).is_err());
}

#[test]
fn native_launch_shape_preserves_opaque_arguments_and_workspace_size() {
    let launch = Launch {
        agent: "codex".into(),
        argv: vec!["--resume".into(), "$(literal) a b".into(), "".into()],
        terminal: None,
        managed: None,
    };
    let mut bytes = vec![];
    Command::Agent(&launch).write(&mut bytes).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"kind":"agent","agent":"codex","argv":["--resume","$(literal) a b",""],"terminal":null,"managed":null})
    );
    bytes.clear();
    Command::Workspace {
        terminal: Size { rows: 24, cols: 80 },
    }
    .write(&mut bytes)
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes[4..]).unwrap(),
        serde_json::json!({"kind":"workspace","terminal":{"rows":24,"cols":80}})
    );
}
