# Official client notices

These files are the unchanged upstream notices for the client versions in
`../install-agents.json`. That lock records each file's source URL and SHA-256.
The image installer checks them before downloading any client, preserves the
complete official npm package, and installs the notices under
`/usr/share/doc/oblivion-agents/<client>/` in the Safe image.

Codex is Apache-2.0; OpenCode2 is MIT. Claude Code has its own terms and is not
covered by Oblivion's MIT license. Anthropic's documented product integration
conditions require the original client, preserved native authentication,
users' own credentials and direct provider billing, with no usage resale or
intermediation. See the exact URLs and conditions in the lock and the installed
`distribution.json`. Provider authentication remains the native client's flow.

`/usr/lib/oblivion/build-evidence.json` identifies only the clients and
architecture actually installed, their verified upstream archive integrity,
executable hashes, required notice hashes and additional upstream notices.
The original lock is retained separately in this documentation directory.
Hash verification establishes which bytes were delivered; it does not record
legal acceptance or establish compliance with every applicable term. The
installer does not claim that this inventory is an exhaustive license audit
of all code compiled into an upstream executable.
