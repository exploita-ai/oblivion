# Oblivion architecture

This document describes the intended security boundaries of Oblivion. It is a
design description, not a claim that the current beta image is secure.

## System boundary

Oblivion is a dedicated Debian live image, not a desktop application installed
on the user's normal operating system. The image contains a deliberately small
set of Debian packages plus the Oblivion host services and an OpenCode-derived
coding agent.

```text
physical machine
└── read-only live system
    ├── tmpfs runtime
    ├── encrypted general vault
    ├── Oblivion manager
    ├── egress gateway VM
    └── one active session
        ├── independent encrypted volume
        └── isolated session VM
```

The live host owns boot, display, input, encrypted-volume lifecycle and VM
lifecycle. A session VM owns the agent process and the session filesystem. The
gateway VM is the only supported network path for a chat session.

## Persistent state

The general LUKS2 vault stores host preferences, Wi-Fi configuration and saved
provider credentials. Each persistent session uses a separate LUKS2 volume and
password. A session contains its chats, workspace, imported files and the
agent's session-local state.

Only one session volume and one session VM may be open at a time. Locking a
session stops its VM, revokes runtime credentials, closes its encrypted volume
and clears the per-opening API-key override.

Ephemeral mode does not unlock or intentionally modify the general vault. Its
state lives in RAM and is discarded on shutdown. Runtime directories and
temporary files in both modes are placed on tmpfs where possible; this reduces
disk residue but does not protect plaintext while the machine is running.

## Session modes

Opening Documents starts an offline session VM with no virtual network device,
provider credential or agent process. The host receives bounded directory
metadata and file-transfer messages; it does not mount the session filesystem.

Starting a chat stops the offline VM and starts the chat VM against the already
unlocked volume. Chats inside one session share `workspace` and `imports`, but
not another session's volume. Switching between Chat and Documents while a
chat is running changes the view, not the isolation boundary.

External media is handled through explicit import and export flows. The source
or destination is exposed only to the dedicated transfer endpoint. Paths are
validated against the permitted roots and transfers use manifests and content
hashes.

## Network model

The host may have an Internet connection for Wi-Fi, time and gateway setup. A
chat session must not receive a direct host-network interface. Its egress is
routed through the gateway VM using either Tor or an explicitly configured
SOCKS5 proxy. There is no intended direct fallback.

The UI distinguishes three facts:

- whether the host has connectivity;
- whether Tor or SOCKS5 is ready for the active session;
- whether direct session access was verified as blocked.

A selected transport is not considered ready until the controller observes a
working gateway and its isolation checks. Oblivion does not contact a public
"what is my IP" service automatically.

## Credentials

Saved API keys are encrypted in the general vault. The selected key is passed
to the chat runtime only for the current opening. It is not copied into the
session's durable configuration. Documents mode receives no provider key.

Development images can expose SSH and diagnostic facilities. Release images
must omit them. Test certificates and credentials in the repository are
synthetic fixtures and must never be trusted by a production image.

## Trust and limitations

Oblivion currently trusts the physical machine, firmware, live kernel,
Oblivion host services, virtualization stack and cryptographic implementation.
An attacker controlling those layers can observe an unlocked session.

Cloud mode is not air-gapped: prompts, selected files, tool output and model
responses are visible to the configured provider. Tor hides the source network
from the provider; it does not hide submitted content. A planned local
inference engine is required for fully offline model execution.

See [SECURITY.md](../SECURITY.md) for the threat model and disclosure process.
