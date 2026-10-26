use super::{Fixture, KEY, Observed, TOKEN, reply};
use bytes::Bytes;
use serde_json::{Value, json};
use std::fs::{self, DirBuilder};
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;

const MARKER: &str = "OBLIVION_ADAPTER_CANARY_94ab";

// These tests require a compiled Oblivion CLI, not a second implementation of
// the adapter. The swap-free VM fixture runs both explicitly, with state in RAM.
#[tokio::test]
#[ignore = "requires OBLIVION_ADAPTER_BIN pointing to the compiled privacy CLI"]
async fn compiled_adapter_streams_tools_and_resumes() {
    let workspace = Workspace::new("roundtrip");
    fs::write(workspace.0.join("context.txt"), format!("{MARKER}_CONTEXT")).unwrap();
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut session = None::<String>;
    for resumed in [false, true] {
        let mut command = workspace.command(&fixture);
        if let Some(session) = &session {
            command.args(["--session", session]);
        } else {
            command.arg("--file").arg(workspace.0.join("context.txt"));
        }
        command.arg(if resumed {
            "Resume the synthetic conversation"
        } else {
            "Read and update the synthetic document"
        });
        let output = command.output();
        tokio::pin!(output);
        let mut called = 0;
        let mut completed = 0;
        let output = timeout(Duration::from_secs(180), async {
            loop {
                tokio::select! {
                    output = &mut output => break output.unwrap(),
                    observed = fixture.observed.recv() => {
                        let observed = observed.unwrap();
                        inspect(&observed);
                        let chat = has_tools(&observed);
                        if chat {
                            let history = observed.body["messages"].to_string();
                            assert!(history.contains(&format!("{MARKER}_CONTEXT")));
                            if resumed {
                                assert!(history.contains(&format!("{MARKER}_REPLY")));
                            }
                            let tool = observed.body["messages"].as_array().unwrap().iter()
                                .any(|message| message["role"] == "tool" && message["content"].to_string().contains(&format!("{MARKER}_CONTEXT")));
                            let chunks = reply(observed, 200, vec![("content-type", "text/event-stream")]);
                            if !tool {
                                assert!(!resumed);
                                called += 1;
                                let arguments = json!({"command":format!("printf %s {MARKER}_DOCUMENT > document.txt; cat context.txt")}).to_string();
                                let split = arguments.len() / 2;
                                delta(&chunks, json!({"role":"assistant","tool_calls":[{"index":0,"id":"call_adapter","type":"function","function":{"name":"shell","arguments":&arguments[..split]}}]}), None).await;
                                delta(&chunks, json!({"tool_calls":[{"index":0,"function":{"arguments":&arguments[split..]}}]}), None).await;
                                finish(chunks, "tool_calls").await;
                            } else {
                                completed += 1;
                                assert_eq!(fs::read_to_string(workspace.0.join("document.txt")).unwrap(), format!("{MARKER}_DOCUMENT"));
                                delta(&chunks, json!({"role":"assistant","reasoning_content":"Synthetic reasoning."}), None).await;
                                delta(&chunks, json!({"content":MARKER}), None).await;
                                delta(&chunks, json!({"content":if resumed { "_RESUMED" } else { "_REPLY" }}), None).await;
                                finish(chunks, "stop").await;
                            }
                        } else {
                            // Title/background requests use the same real adapter and broker.
                            let chunks = reply(observed, 200, vec![("content-type", "text/event-stream")]);
                            delta(&chunks, json!({"role":"assistant","content":"Synthetic conversation"}), None).await;
                            finish(chunks, "stop").await;
                        }
                    }
                }
            }
        }).await.expect("compiled adapter deadline");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stderr}\n{stdout}");
        assert!(!stdout.contains(KEY) && !stdout.contains(TOKEN));
        assert!(!stderr.contains(KEY) && !stderr.contains(TOKEN));
        assert!(
            stdout.contains(&format!(
                "{MARKER}{}",
                if resumed { "_RESUMED" } else { "_REPLY" }
            )),
            "{stdout}"
        );
        let events = stdout
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            !events.iter().any(|event| event["type"] == "error"),
            "{stdout}"
        );
        assert_eq!(called, usize::from(!resumed));
        assert_eq!(completed, 1);
        let id = events.last().unwrap()["sessionID"]
            .as_str()
            .unwrap()
            .to_owned();
        if let Some(session) = &session {
            assert_eq!(session, &id);
        }
        session = Some(id);
        workspace.inspect();
    }
    while let Ok((host, port, role, token)) = fixture.sockets.try_recv() {
        assert_eq!(
            (host.as_str(), port, role.as_str(), token.as_str()),
            ("api.abliteration.ai", 443, "oblivion-api", TOKEN)
        );
    }
    assert!(fixture.attempts.load(Ordering::SeqCst) >= 3);
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "requires OBLIVION_ADAPTER_BIN pointing to the compiled privacy CLI"]
async fn compiled_adapter_observes_revocation_of_active_stream() {
    let workspace = Workspace::new("revocation");
    let mut fixture = Fixture::new(true, TOKEN).await;
    let mut command = workspace.command(&fixture);
    command.arg("Synthetic response to interrupt");
    let mut child = command.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut stderr = child.stderr.take().unwrap();
    let errors = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    });
    let mut stdout = Vec::new();
    let mut streaming = None;
    let ended = timeout(Duration::from_secs(180), async {
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    let line = line.unwrap().expect("adapter exited before streaming");
                    let event: Value = serde_json::from_str(&line).unwrap();
                    stdout.push(line);
                    // The adapter emits step-start on the first LLM output. No
                    // finish, DONE or provider EOF has been sent for this request.
                    if event["type"] == "step_start" {
                        break streaming.take().expect("step started without provider data");
                    }
                    assert_ne!(event["type"], "error", "{event}");
                }
                observed = fixture.observed.recv() => {
                    let observed = observed.unwrap();
                    inspect(&observed);
                    let chat = has_tools(&observed);
                    let ended = observed.ended.clone();
                    let chunks = reply(observed, 200, vec![("content-type", "text/event-stream")]);
                    delta(&chunks, json!({"role":"assistant","content":"Synthetic open response"}), None).await;
                    if chat {
                        assert!(streaming.is_none());
                        streaming = Some((ended, chunks));
                    } else {
                        finish(chunks, "stop").await;
                    }
                }
            }
        }
    }).await.expect("adapter stream admission deadline");
    fixture.stop().await;
    timeout(Duration::from_secs(10), ended.0.cancelled())
        .await
        .unwrap();
    assert!(ended.1.is_closed());
    timeout(Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            stdout.push(line);
        }
        child.wait().await.unwrap();
    })
    .await
    .expect("adapter revocation deadline");
    let stdout = stdout.join("\n");
    let stderr = errors.await.unwrap();
    assert!(!stdout.contains(KEY) && !stdout.contains(TOKEN));
    assert!(!stderr.contains(KEY) && !stderr.contains(TOKEN));
    assert!(
        stdout
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|event| event["type"] == "error"),
        "{stderr}\n{stdout}"
    );
    assert!(
        tokio::net::TcpStream::connect(fixture.address)
            .await
            .is_err()
    );
    workspace.inspect();
}

fn inspect(observed: &Observed) {
    assert_eq!(observed.uri, "/v1/chat/completions");
    assert_eq!(observed.headers["authorization"], format!("Bearer {KEY}"));
    assert_eq!(observed.headers["host"], "api.abliteration.ai");
    assert_eq!(observed.body["stream"], true);
    assert_eq!(observed.body["model"], "abliterated-model");
    assert!(!observed.body.to_string().contains(TOKEN));
    assert!(!observed.body.to_string().contains(KEY));
}

fn has_tools(observed: &Observed) -> bool {
    observed.body["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty())
}

async fn delta(chunks: &mpsc::Sender<Bytes>, delta: Value, finish: Option<&str>) {
    let chunk = json!({"id":"chatcmpl-oblivion-adapter","object":"chat.completion.chunk","created":1,"model":"abliterated-model",
        "choices":[{"index":0,"delta":delta,"finish_reason":finish}]});
    chunks
        .send(Bytes::from(format!("data: {chunk}\n\n")))
        .await
        .unwrap();
}

async fn finish(chunks: mpsc::Sender<Bytes>, reason: &str) {
    delta(&chunks, json!({}), Some(reason)).await;
    let usage = json!({"id":"chatcmpl-oblivion-adapter","object":"chat.completion.chunk","created":1,"model":"abliterated-model","choices":[],
        "usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}});
    chunks
        .send(Bytes::from(format!("data: {usage}\n\ndata: [DONE]\n\n")))
        .await
        .unwrap();
}

struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("oblivion-adapter-{name}-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        for directory in ["home", "state", "data", "config", "cache", "tmp"] {
            fs::create_dir(path.join(directory)).unwrap();
        }
        Self(path)
    }

    fn command(&self, fixture: &Fixture) -> Command {
        let mut command = Command::new(
            std::env::var_os("OBLIVION_ADAPTER_BIN").expect("compiled privacy CLI required"),
        );
        command.args(["run", "--standalone", "--auto", "--format", "json"])
            .current_dir(&self.0).env_clear()
            .env("PATH", "/usr/bin:/bin").env("HOME", self.0.join("home"))
            .env("XDG_STATE_HOME", self.0.join("state")).env("XDG_DATA_HOME", self.0.join("data"))
            .env("XDG_CONFIG_HOME", self.0.join("config")).env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("TMPDIR", self.0.join("tmp")).env("ABLIT_KEY", TOKEN)
            .env("OPENCODE_DISABLE_FILEWATCHER", "true").env("OPENCODE_DISABLE_FFF", "true")
            .env("OPENCODE_CONFIG_CONTENT", json!({"model":"abliteration-ai/abliterated-model","snapshots":false,
                "providers":{"abliteration-ai":{"settings":{"baseURL":format!("http://{}/v1",fixture.address)}}}}).to_string())
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        command
    }

    fn inspect(&self) {
        let mut directories = vec![self.0.clone()];
        while let Some(path) = directories.pop() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    directories.push(entry.path());
                    continue;
                }
                if !entry.file_type().unwrap().is_file() {
                    continue;
                }
                assert!(
                    !["log", "heapsnapshot", "cpuprofile"].contains(
                        &entry
                            .path()
                            .extension()
                            .and_then(|value| value.to_str())
                            .unwrap_or("")
                    )
                );
                let mut file = fs::File::open(entry.path()).unwrap();
                let mut bytes = [0; 65536];
                let mut tail = Vec::new();
                loop {
                    let size = file.read(&mut bytes).unwrap();
                    if size == 0 {
                        break;
                    }
                    tail.extend_from_slice(&bytes[..size]);
                    for secret in [KEY, TOKEN] {
                        assert!(
                            !tail
                                .windows(secret.len())
                                .any(|part| part == secret.as_bytes())
                        );
                    }
                    tail = tail[tail.len().saturating_sub(128)..].to_vec();
                }
            }
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
