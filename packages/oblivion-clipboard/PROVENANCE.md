# Clipboard adapter

Derived from [wayland-vdagent](https://github.com/v-dermichev/wayland-vdagent)
at commit `9191ec6a82d9712a81d5c86d6e5cf5daa21af2b9` (0.3.4). Upstream declares
the MIT license in its README; original file hashes are in `upstream.json`.
The original Wayland dispatchers and SPICE daemon protocol are reused.

Oblivion removes file transfer, host-requested display changes and image
formats. Only UTF-8 clipboard text is served, bounded to 256 KiB. Payloads are
requested lazily when an application pastes. The adapter runs alongside Foot,
as the display user, with no session filesystem, network or provider key.
The session's terminal escapes remain filtered by the trusted manager.

The separate Debian `spice-vdagentd` broker owns the hypervisor's virtio port;
no QEMU guest-agent, remote-execution service or shared folder is enabled.
Runtime output and histories are disabled and state is confined to RAM.
