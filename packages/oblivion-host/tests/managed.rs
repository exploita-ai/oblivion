use oblivion_host::{agent,managed};
use zeroize::Zeroizing;

fn value() -> managed::Info {
    managed::Info { job_id:"a".repeat(32),request_id:"b".repeat(32),agent:"codex".into(),state:managed::State::Queued,native_chat_id:None,reason:None }
}
#[test]
fn normal_launch_preserves_arguments_with_explicit_no_managed_job() {
    let request = agent::Launch { agent:"codex".into(),argv:vec!["--resume".into(),"quoted $task; not shell".into()],terminal:None,managed:None };
    let mut frame = Vec::new(); request.write(&mut frame).unwrap();
    let encoded: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
    assert_eq!(u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize, frame.len()-4);
    assert!(encoded.get("managed").is_some_and(serde_json::Value::is_null));
    assert_eq!(encoded["kind"], "agent");
    assert_eq!(encoded["argv"][1], "quoted $task; not shell");
}
#[test]
fn managed_launch_cannot_choose_argv_tty_or_an_unbounded_task() {
    let mut request = agent::Launch { agent:"claude".into(),argv:vec![],terminal:None,managed:Some(managed::Command::Start {
        job_id:"a".repeat(32),request_id:"b".repeat(32),task:Zeroizing::new("explicit task".into())
    }) };
    assert!(request.validate().is_ok());
    request.argv.push("--dangerously-skip-permissions".into());
    assert!(request.validate().is_err()); request.argv.clear();
    request.terminal=Some(agent::Size {rows:24,cols:80}); assert!(request.validate().is_err());
    request.terminal=None;
    request.managed=Some(managed::Command::Start { job_id:"a".repeat(32),request_id:"b".repeat(32),task:Zeroizing::new("x".repeat(16385)) });
    assert!(request.validate().is_err());
    for input in [r#"{"operation":"inspect","job_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/etc/passwd"}"#,
        r#"{"operation":"start","job_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","task":"task","argv":["id"]}"#] {
        assert!(serde_json::from_str::<managed::Command>(input).is_err());
    }
}
#[test]
fn metadata_rejects_non_native_ids_unknown_payloads_and_false_terminal_reasons() {
    let mut info=value(); assert!(info.valid());
    info.native_chat_id=Some("api key or arbitrary text".into()); assert!(!info.valid());
    info.native_chat_id=Some("12345678-1234-4234-8234-123456789abc".into()); assert!(info.valid());
    info.state=managed::State::Completed; info.reason=Some(managed::Reason::NeedsAuth); assert!(!info.valid());
    info.state=managed::State::Failed; assert!(info.valid());
    let mut json=serde_json::to_value(info).unwrap(); json["output"]="private task output".into();
    assert!(serde_json::from_value::<managed::Info>(json).is_err());
    assert!(serde_json::from_str::<managed::Event>(r#"{"kind":"status","info":{},"task":"private"}"#).is_err());
}
