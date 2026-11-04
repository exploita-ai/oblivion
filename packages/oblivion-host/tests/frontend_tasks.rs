mod frontend_support;
use frontend_support::{Fixture, RunTerminal, SAFE, accept, read, receive, reply, state};
use oblivion_cli::child_task;
use oblivion_host::scope;
use oblivion_wire::control::Operation;
use serde_json::{Value, json};

const REQUEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn saved() -> Value {
    json!({"version":1,"safe_id":SAFE,"agent":"claude","request_id":REQUEST,
        "attempt_request_id":null,"attempts":0,"attempt_limit":16,"phase":"not-started",
        "job":null,"can_start":true,"can_retry":false,"can_cancel":false,"blocked":null})
}

#[test]
fn shared_task_start_uses_real_private_adapter_and_preserves_safe_and_request_scope() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &state().to_string(), None);
        for operation in [
            Operation::ChildTaskStatus,
            Operation::PinSafe,
            Operation::StartAgent,
            Operation::ChildTaskStart,
        ] {
            let mut stream = accept(&listener);
            let (request, secret) = receive(&mut stream);
            assert_eq!(request.operation, operation);
            assert_eq!(request.slot.index(), 4);
            assert_eq!(request.expected_session.as_deref(), Some(SAFE));
            assert!(request.session.is_none());
            match operation {
                Operation::ChildTaskStatus => {
                    assert!(secret.is_empty());
                    reply(&mut stream, &saved().to_string(), None);
                }
                Operation::ChildTaskStart => {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&secret).unwrap(),
                        json!({"request_id":REQUEST})
                    );
                    let mut running = saved();
                    running["attempt_request_id"] = json!(REQUEST);
                    running["attempts"] = json!(1);
                    running["phase"] = json!("submitted");
                    running["can_start"] = json!(false);
                    running["can_cancel"] = json!(true);
                    running["job"] = json!({"job_id":"cccccccccccccccccccccccccccccccc","request_id":REQUEST,
                        "agent":"claude","state":"running","native_chat_id":null,"reason":null});
                    reply(&mut stream, &running.to_string(), None);
                }
                _ => {
                    assert!(secret.is_empty());
                    reply(&mut stream, "", None);
                }
            }
        }
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command =
        child_task::parse(&["start", "GB", "--request", REQUEST, "--json"].map(str::to_owned))
            .unwrap();
    let mut output = vec![];
    assert_eq!(
        child_task::execute(&mut terminal, command, &mut output).unwrap(),
        0
    );
    let response: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(response["request_id"], REQUEST);
    assert_eq!(response["job"]["state"], "running");
    assert!(terminal.prompts.is_empty());
    assert!(terminal.attached.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}

#[test]
fn explicit_task_review_uses_real_private_adapter_without_starting_an_agent() {
    let (fixture, listener) = Fixture::new();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        assert_eq!(read(&mut stream).operation, Operation::Status);
        reply(&mut stream, &state().to_string(), None);
        let mut stream = accept(&listener);
        let request = read(&mut stream);
        assert_eq!(request.operation, Operation::ChildTaskReview);
        assert_eq!(request.slot.index(), 4);
        assert_eq!(request.expected_session.as_deref(), Some(SAFE));
        assert!(request.session.is_none());
        reply(
            &mut stream,
            &json!({"status":saved(),"task":"Review only\n\u{1b}[2J日本語"}).to_string(),
            None,
        );
    });
    let mut terminal = RunTerminal::new(&fixture.path);
    let command = child_task::parse(&["review", "GB"].map(str::to_owned)).unwrap();
    let mut output = vec![];
    child_task::execute(&mut terminal, command, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Review only\n\\u{1b}[2J日本語"));
    assert!(!output.contains('\u{1b}'));
    assert!(terminal.prompts.is_empty());
    assert!(terminal.attached.is_empty());
    assert_eq!(scope::current().index(), 0);
    server.join().unwrap();
}
