# Providers and official clients

Oblivion 1.0 runs unmodified Codex, Claude Code and OpenCode 2 in a Safe. Provider
configuration and authentication belong to the chosen client. There is no
Oblivion-specific model API adapter or central provider-key broker.

Authenticate inside the Safe using the client's supported login or API-key
flow. A desktop profile is not mounted or copied into the guest. Profiles,
refresh tokens, client databases and API keys saved by the client live inside
that Safe's encrypted volume. Two agents in the same Safe can access data
permitted by that guest's user account; different Safes have separate filesystems.

The client communicates through its Safe's Tor or configured SOCKS5 gateway.
Open Internet is the default access policy; Strict and Offline remain explicit
Safe-wide choices. A provider may refuse Tor exits, require interactive login,
reject credentials or impose its own account conditions. Oblivion must report
that error without switching to a direct connection or another transport.

Tor conceals the original network address from the destination when correctly
routed, but it does not conceal the provider account or the request content from
the provider. End-to-end HTTPS validation remains enabled. Oblivion does not
intercept TLS to read or rewrite arbitrary model requests.

Client telemetry settings are configured for the pinned clients, and verified
dedicated collector domains are denied ahead of user rules. This is not a claim
that all telemetry can be identified: traffic to a collector sharing the model
API's encrypted destination cannot be distinguished by a hostname-only gateway.

Agent versions and package integrity values are recorded in
[install-agents.json](../script/oblivion/install-agents.json). Provider terms,
account restrictions and billing remain those of the native clients. See
[NOTICE](../NOTICE) for licensing boundaries.

Local inference, Ollama endpoint integration and managed model downloads are
explicitly deferred until after Oblivion 1.0. See the
[roadmap](oblivion1.0-roadmap.md) for that later work.
