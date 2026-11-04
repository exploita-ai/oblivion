use oblivion_host::agent::{Command, Size};

#[test]
fn human_workspace_has_no_agent_or_executable_argument_authority() {
    let mut bytes = Vec::new();
    Command::Workspace {
        terminal: Size { rows: 24, cols: 80 },
    }
    .write(&mut bytes)
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
    assert_eq!(
        value,
        serde_json::json!({ "kind": "workspace", "terminal": { "rows": 24, "cols": 80 } })
    );
    assert_eq!(
        u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
        bytes.len() - 4
    );
    for terminal in [
        Size { rows: 0, cols: 80 },
        Size {
            rows: 24,
            cols: 1001,
        },
    ] {
        let mut bytes = Vec::new();
        assert!(Command::Workspace { terminal }.write(&mut bytes).is_err());
        assert!(bytes.is_empty());
    }
}
