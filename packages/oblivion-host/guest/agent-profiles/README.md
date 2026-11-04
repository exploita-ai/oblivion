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
