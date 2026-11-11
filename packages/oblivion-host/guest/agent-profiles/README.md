# Official agent privacy defaults

`agent.sh` sources the selected profile after selecting the Safe's encrypted
home, state and configuration directories. Each profile disables optional
telemetry and seeds native configuration only when that file is absent. Agent
arguments are passed unchanged. Existing configuration remains user-owned.

The wrapper then executes the official binary. Each client owns its
native conversations in the encrypted Safe; there is no shared chat catalog,
history watcher, prompt-admission hook or cross-agent replication. Separate
clients in the same Safe share files, while native resume IDs remain scoped
to the agent that created them. Agent and Workspace services retain their
systemd cgroups so closing the Safe can stop their processes and backends.

An explicitly launched OpenCode2 client enters a separate transient systemd
scope before its profile and native entrypoint run. The scope retains elected
servers after their first client exits, including servers replaced by native
restart, and stops before the Safe's vault. It preserves the caller's PTY,
cwd and argv; the fixed sudo handoff has `!use_pty` and drops back to UID1000.
TERM/HUP on the attachment relay revokes that client process group while an
elected server in a separate session remains available to other clients.
The full scope/cgroup and shutdown ordering still require a real systemd/VM
qualification; SIGKILL/OOM of the relay is not proof of client revocation.

Managed OpenCode tasks instead use their fixed `run --standalone` command and
the same native profile/entrypoint within the original managed-service cgroup.
Their exclusive backend does not acquire the interactive persistent scope.
Native SIGINT requests a session interrupt; forced client death alone does not
prove that backend shutdown has finished. Cancellation after forced kill and
native execution recovery remain qualification gates before promising complete
job cancellation. `tests/opencode-native.py` tests two real pinned TUIs and
session metadata after server restart offline; it does not make a provider
request or qualify a complete conversation, encrypted Safe reboot or cgroups.

Codex defaults disable analytics, feedback and each log, metrics and trace
exporter. Explicit OTLP exporters otherwise work independently of the analytics
switch. [Codex configuration reference](https://developers.openai.com/codex/config-reference/).

The machine profile also disables automatic daemon startup. The daemon pins a
second copy of the installed Codex package in the Safe, which can crowd out
chat history and workspace files on a small Safe. The user profile and native
CLI can still select daemon mode.
[Codex daemon configuration](https://learn.chatgpt.com/docs/environments/network-file-systems#2-stop-codex-on-every-host).

Claude defaults disable nonessential traffic, surveys, feedback submission,
error reports, optional exporters and automatic official marketplace installs.
The initial settings also disable the WebFetch preflight, which otherwise sends
the requested hostname to Anthropic separately from fetching the page.
[Claude data usage](https://code.claude.com/docs/en/data-usage) ·
[Claude monitoring](https://code.claude.com/docs/en/monitoring-usage).

OpenCode 2 defaults disable update checks. The profile removes inherited OTLP
endpoints so its optional exporter is inactive. There is no invented
`OPENCODE_DISABLE_TELEMETRY` setting.
[OpenCode configuration](https://opencode.ai/v2/docs/config) ·
[OpenCode 2.0.1 observability implementation](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/util/src/observability/otlp.ts).

The common profile disables OpenTelemetry exporters and removes inherited
collector addresses and credentials. It keeps provider authentication intact.
Native client settings and code can change with upstream releases, so client
versions and these profiles must be qualified together with a traffic capture.
Provider login and inference remain functional network traffic. The gateway
can deny a dedicated telemetry hostname, while telemetry on a shared provider
HTTPS origin requires the client's own setting to distinguish its purpose.

These are launch defaults. A user with root access inside their Safe can
change application configuration or invoke a client directly. The VM's enforced
Tor/SOCKS5 path and prohibition of direct egress remain the controller boundary.

## Child Safe authentication

SafeAdmin can transfer only the requested agent's compatible identity through
its private channel. Codex API keys and native `at-` personal access tokens,
Claude API keys and separately provisioned `setup-token` credentials, and
selected standard OpenCode2 API-key integrations have dedicated adapters.
The child gets a separate native credential store. Native homes, histories,
MCP configuration, hooks and plugins are never cloned.

Ordinary rotating OAuth caches are refused. A missing, ambiguous or unsupported
identity leaves the task waiting for authentication. Oblivion never changes a
subscription login into API billing automatically. Custom endpoints and auth
commands need an explicit adapter; the initial implementation refuses them.
Per-launch configuration overrides, project-local profiles and user provider
plugins are also refused when their effective routing cannot be qualified.
OpenCode2 additionally requires an explicit default model in its own config,
so the delegated key cannot select a different provider accidentally.

Installation runs before the child has a network device. Codex and Claude use
their current native identity storage formats. OpenCode2 briefly serves its
public 2.0.1 key-connect API on private loopback; a transient identity-only
catalog registers the known built-in integration without inventing inference
models or fetching remote metadata. The source of that metadata is the
[pinned upstream snapshot](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/core/src/models-dev/snapshot.txt).
The subprocess is stopped and reaped before the helper returns. Its configured
model still needs to exist in the normal native catalog when execution starts.

`tests/credential-delegation.py` exercises synthetic stores and first-launch
profile preservation. `tests/credential-native.py` qualifies the pinned native
clients inside a Linux network namespace with no external connection: native
auth readers, real OpenCode key import, idempotence, native config loading and
profile preservation. It makes no inference or authenticated provider request.

## Dedicated collector enforcement

The gateway additionally denies these exact collector hosts on every port,
including in Open Internet and when a user rule would allow the destination.

| Client | Collector | Purpose and evidence |
| --- | --- | --- |
| Codex 0.159.2 | `ab.chatgpt.com` | Built-in metrics exporter in the [pinned source](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/otel/src/config.rs). |
| Codex 0.159.2 | `o33249.ingest.us.sentry.io` | Feedback uploader in the [pinned source](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/feedback/src/lib.rs). |
| Claude Code 2.1.302 | `http-intake.logs.us5.datadoghq.com` | Logging intake hostname embedded in the verified official release binary. |
| Claude Code 2.1.302 | `o1158394.ingest.us.sentry.io` | Error reporting hostname embedded in the verified official release binary. |

The Claude hostnames were inspected in the package selected by
`script/oblivion/install-agents.json`. The vendor documents the metrics and error
reporting channels separately. [Claude data usage](https://code.claude.com/docs/en/data-usage).

OpenCode 2 has no fixed default collector in the inspected source. Its optional
OTLP destinations are removed by the launch profile. Provider traffic to
`chatgpt.com` and `api.anthropic.com` remains available because those HTTPS
origins carry functional requests as well. The gateway cannot identify the
purpose of an encrypted request on a shared origin. Disabling those client
channels remains the launch profile's responsibility.
