# Providers and official clients

Oblivion 1.0 runs unmodified Codex, Claude Code and OpenCode 2 in a Safe. Provider
configuration and authentication belong to the chosen client. There is no
Oblivion-specific model API adapter or central provider-key broker.

Authenticate inside the Safe using the client's supported login or API-key
flow. A desktop profile is not mounted or copied into the guest. Profiles,
refresh tokens, client databases and API keys saved by the client live inside
that Safe's encrypted volume. Two agents in the same Safe can access data
permitted by that guest's user account; different Safes have separate filesystems.

For the first ChatGPT login in Codex, choose **Sign in with Device Code** in the
native client and open the displayed link in a browser outside the Safe, for
example on your desktop or phone. Browser login uses a `localhost:1455` callback
inside the Safe; opening its URL on the physical computer does not connect that
callback to the guest. Device Code uses the client's supported headless flow
when enabled for your account. An OpenAI API key remains a separate native login
choice with its own billing. See the [pinned Codex login implementation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/tui/src/onboarding/auth.rs).

The explicit CLI login can use the same named Safe:

```sh
oblivion run --name work codex login --device-auth
oblivion run --safe work codex
```

After closing it, use `oblivion run --safe work codex resume --last` to reopen
that Safe and continue its latest native Codex conversation. Oblivion forwards
the client arguments unchanged and does not forward an OAuth callback port.

Agent-created children have a controller-managed startup path. It exports only
the requested client's supported credential from the parent, seals it to the
family, child and creation request while booting, installs it in the child's
native store while offline, then starts the saved task. Parent authority is
checked throughout. Missing, ambiguous or unsupported authentication leaves the
task waiting for authentication; it does not start anonymously. No whole home,
agent profile, conversation store, cache or desktop login is copied.

| Client | Credential-only adapters in the current source | Explicit limits |
| --- | --- | --- |
| Codex | OpenAI API key or a separately provisioned Codex Access Token | Ordinary ChatGPT OAuth caches are not cloned. Access Tokens represent a ChatGPT Business/Enterprise workspace; they are not Platform API keys. Custom routing is rejected by this adapter. |
| Claude Code | Anthropic API key or a separately provisioned `claude setup-token` credential | Ordinary `/login` refresh caches are not cloned. Mixed identities, custom routing and authentication helpers need a separate supported adapter. |
| OpenCode 2 | Selected active API key for a supported built-in integration, including `abliteration-ai`, with an explicit model | OAuth, custom provider routing, ambiguous selection and provider-specific forms are not delegated. Installation uses the pinned native key-connect API on private loopback without provider access. |

These adapters cover known default native profiles. Per-launch routing/settings
overrides, native project configuration and unqualified provider plugins are
refused rather than treated as equivalent to a default provider. This limits
credential delegation; ordinary `oblivion run` still forwards native arguments.

These are source adapters, not a qualification of real-provider login, expiry
or account policy. Subscription delegation may require one-time provisioning
before children can start without another login. See the official
[Codex Access Token](https://learn.chatgpt.com/docs/enterprise/access-tokens),
[Codex concurrent-authentication limits](https://learn.chatgpt.com/docs/auth/ci-cd-auth)
and [Claude long-lived token](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token)
documentation. No subscription is silently replaced with API billing. Native
login remains the fallback; universal managed-OAuth delegation is still an open
requirement.

Delegation does not make a provider account anonymous or narrow its permissions.
Expiry, refresh, logout and simultaneous parent/child use require real-provider
tests before a credential form is declared supported. Delegated secrets remain
excluded from portable Share data, task text, public status and MCP responses;
personal encrypted volume backups may still contain saved credentials.

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
