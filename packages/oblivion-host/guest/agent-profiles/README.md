# Official agent privacy defaults

`agent.sh` sources the selected profile after selecting the Safe's encrypted
home, state and configuration directories. Each profile disables optional
telemetry and seeds native configuration only when that file is absent. Agent
arguments are passed unchanged. Existing configuration remains user-owned.

Codex defaults disable analytics, feedback and each log, metrics and trace
exporter. Explicit OTLP exporters otherwise work independently of the analytics
switch. [Codex configuration reference](https://developers.openai.com/codex/config-reference/).

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
[OpenCode observability implementation](../../../util/src/observability/otlp.ts).

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
