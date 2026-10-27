# Remote inference providers

Oblivion's local encryption and its provider boundary solve different
problems. The selected service must receive every prompt, attached document,
tool result and generated response required for inference. Tor or SOCKS5 can
change the network path; neither makes that content secret from the provider.

“Zero retention” below summarizes published provider policies. It is not a
property Oblivion can independently verify, and policies may change after an
image is released. Review the linked source before submitting sensitive data.

## Abliteration.ai

- **Integration:** native provider support.
- **Endpoint policy:** the production gateway grants only the selected
  Abliteration endpoint for the chat opening.
- **Published handling:** its
  [data-handling policy](https://abliteration.ai/data-handling) says core API
  prompts, completions and images are processed in memory, are not stored and
  are not used for training. Operational telemetry and billing metadata are
  retained.
- **Boundary:** optional web search or fetch is outside the core API's stated
  zero-retention boundary.
- **Account:** the provider's published privacy material describes retained
  account/billing records and third-party payment processing.

## Refuseless

- **Integration:** OpenAI-compatible adapter with a fixed provider gateway.
- **Endpoint policy:** only the configured Refuseless API endpoint is granted
  for the opening.
- **Published handling:** its [privacy policy](https://refuseless.com/privacy)
  says prompts and outputs are not saved or used for training.
- **Boundary:** Refuseless may route requests to third-party model providers and
  states that it cannot guarantee every upstream retention policy.
- **Account and payment:** its [pricing page](https://refuseless.com/pricing)
  lists card and cryptocurrency payment options. Its public policy does not
  state an unconditional no-KYC guarantee, so Oblivion does not make one.

## OpenRouter

- **Integration:** OpenCode's native OpenRouter adapter.
- **Mandatory routing:** the Oblivion gateway overwrites each request with
  `zdr: true`, `data_collection: deny` and `allow_fallbacks: false`.
- **Fail-closed behavior:** a model with no endpoint eligible for the requested
  policy fails instead of falling back to a weaker route.
- **Published handling:** OpenRouter documents
  [zero-data-retention routing at endpoint level](https://openrouter.ai/docs/guides/features/zdr).
- **Boundary:** OpenRouter and the selected upstream still process the request.
  ZDR does not automatically cover optional server-side tools or plugins;
  Oblivion does not enable those provider features.

## Credential and routing boundary

The provider is selected for a chat opening. The production gateway allowlists
that provider's endpoint, keeps the real API key inside the gateway VM and gives
the session only a revocable local capability plus the provider identifier.
Closing the session revokes the opening-specific grant.

Provider or client-supplied routing fields cannot weaken the mandatory
OpenRouter ZDR policy. Oblivion never silently falls back to a direct host
connection or an unreviewed provider. A routing failure is visible to the user
and the request stops.

## Before choosing a provider

Check the provider's current policy, jurisdiction, account requirements,
upstream routing and optional tool behavior. Do not infer that a provider is
anonymous, no-KYC or zero-retention solely because it accepts cryptocurrency or
exposes an OpenAI-compatible API.
