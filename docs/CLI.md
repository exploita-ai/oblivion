# Oblivion CLI

`oblivion` opens the manager. Use `oblivion --help` for the commands available
in your installation and `oblivion --version` for the installed version. In
the examples below, `research` is a Safe name. Commands that select an existing
Safe also accept its full ID from `oblivion safes`.

## Storage and Safes

| Command | What it does |
| --- | --- |
| `oblivion init` | Create the encrypted archive and leave it locked. |
| `oblivion init --reset-incomplete` | Review and discard an unfinished archive setup. Published storage is preserved. |
| `oblivion unlock` or `oblivion unlock --read-only` | Open an existing encrypted archive in the chosen mode. |
| `oblivion ephemeral` | Enter RAM-only mode. Closing an ephemeral Safe discards its contents. |
| `oblivion safes` | List Safe names, full IDs and current modes. |
| `oblivion status --json` | Read the controller's current state. |
| `oblivion safe open research` | Open the Safe offline for Files. |
| `oblivion safe rename research "Field notes"` | Change the Safe's display name. |
| `oblivion safe grow research 4096` | Increase a closed persistent Safe to 4096 MiB. |
| `oblivion close research` | Close and lock one Safe. |
| `oblivion lock` | Close all Safes and lock the archive. |

An agent-created Safe can hold a saved task. Open the Safe, then use
`oblivion safe task status SAFE` or `oblivion safe task review SAFE`. Replace
`status` with `start`, `retry`, or `cancel` to control the task. Each action
supports `--json`. For start, retry or cancel, `--request ID` binds the action
to a specific creation request. Task review can print the saved task text.

Close the Safes in the affected family before changing its password. Use
`oblivion safe password preview SAFE --json` to review the members, then
`oblivion safe password SAFE` to apply the change. After interruption, inspect
`oblivion safe password status --json` before choosing `oblivion safe password
recover TRANSACTION --complete` or `--rollback`. [Family passwords and recovery](PASSWORDS.md)

## Run an agent

```sh
oblivion run --name research codex
oblivion run --safe research codex resume --last
oblivion run --ephemeral --policy offline opencode2
oblivion shell --safe research
```

The supported agents are `codex`, `claude`, and `opencode2`. Put Oblivion's
options before the agent name. Arguments after it go unchanged to the client
inside the Safe. `--name` creates a new persistent Safe and `--safe` selects an
existing one. A plain `oblivion run codex` opens a new Safe and guides archive
setup if needed. Lock Oblivion before switching from an open persistent
archive to ephemeral mode. Authenticate inside each Safe using the agent's
own login flow. [Provider setup](PROVIDERS.md)

`shell` opens the Safe's tmux Workspace. Use `--policy offline` to set the
Safe's policy to Offline before opening the Workspace. In an interactive agent
or Workspace, **F7** opens Files and **F9** opens Network. **Esc** returns to the
running client. The manager's **Ctrl+Q** locks Oblivion. In tmux, **Ctrl+B**
then **?** lists its native shortcuts.

## Network and automatic lock

```sh
oblivion network status --safe research --json
oblivion network set --safe research --tor
oblivion network set --safe research --policy strict
oblivion proxy add office
oblivion proxy list --json
oblivion network set --safe research --proxy-profile office
oblivion proxy remove office
oblivion settings idle --json
oblivion settings idle --safe-minutes 15 --host-minutes 30
```

Each Safe defaults to Tor and the `open-internet` policy. `strict` requires
allow rules and `offline` blocks agent network access. To choose a transport
or policy on launch, put `--tor`, `-x socks5h://HOST:PORT`,
`--proxy-profile NAME`, or `--policy MODE` before the agent. Use `network set`
to change one setting at a time on an already open Safe. Tor and SOCKS5 carry
TCP traffic without direct fallback.

`proxy add NAME` prompts privately for a SOCKS5 URL. If a URL is supplied on
the command line, it can end up in shell history. A username with the password
omitted triggers a private password prompt. Removing a saved profile leaves
active Safe connections unchanged.

Setting an idle timer to `0` disables that timer. A timer omitted from an
update keeps its current value. Idle locking closes active agent sessions.

## Files

Open the Safe before browsing or copying. An export destination must be an
existing local directory.

```sh
oblivion safe open research
oblivion files import --safe research --source ./project
oblivion files list --safe research workspace/project --json
oblivion files export --safe research --path workspace/project --destination ./exports
oblivion files transfers --safe research --destination ./exports --json
oblivion files status --safe research --operation OPERATION --destination ./exports --json
```

Repeat `--source` or `--path` to select several items and give the collection a
`--name`. Copies normally show a manifest for approval. Use `--yes` only when
intentionally approving an unattended local copy. Copies can take an explicit
`--operation ID`. After an interruption, inspect the outcome with `files status`
first. Use `files recover` or `files discard` with the same Safe, operation ID
and, for local exports, the original `--destination`. Recovery can publish a
fully verified copy. Discard removes only incomplete staging.

The following options are specific to the Live profile. Get the device ID
with `runtime live-media --json`. Sources are relative to the selected USB.

```sh
oblivion runtime live-media --json
oblivion files import --safe research --usb DEVICE --source path/on/usb
oblivion files export --safe research --usb DEVICE --path workspace/project
oblivion files transfers --safe research --usb DEVICE --json
```

USB export requires approval and creates its own operation directory. Use
`--usb DEVICE` with `files status`, `files recover` or `files discard` to
inspect or manage USB export records. [Live controls and USB recovery](LIVE.md)

## Personal backup and Share

Unlock writable storage and close the Safe or Safes you want to export.

| Purpose | Export | Import |
| --- | --- | --- |
| Personal backup with original identity, native state and saved logins | `oblivion backup export --safe research ./research.luks` | `oblivion backup import ./research.luks` |
| Portable Share with new Safe identities and provider credential stores excluded | `oblivion share export --safe research ./research.oblivion-share` | `oblivion share import ./research.oblivion-share` |

For a personal backup, retain the original Safe password. Use `oblivion backup
status --json` to inspect an interrupted copy, `oblivion backup finish
TRANSACTION` to finish a verified import, and `oblivion backup discard
TRANSACTION` to discard incomplete staging. [Personal backup and recovery](BACKUPS.md)

Share also supports `share export --branch SAFE FILE` and `share export --all
FILE`. Select content with `--path`, `--chat`, `--exclude`, `--exclude-chat`, or
`--no-chats` as applicable to the export scope. Review messages and documents
for any secrets they may contain. Use `--include-settings` on an all-Safes
export and `--apply-settings` at import if you want to transfer idle timers.
Use `oblivion share imports --json` to inspect imports and `oblivion share
discard TRANSACTION` to remove incomplete staging. [Share selection and recovery](SHARING.md)

## Runtime maintenance

- `oblivion runtime start`, `stop`, and `recover` manage the protected runtime.
- `oblivion runtime install-bundle BUNDLE` installs a desktop bundle. Use
  `runtime update BUNDLE` for updates. The standalone macOS/Linux profile also
  exposes `runtime install BUNDLE` and `runtime deploy BUNDLE`. APT-managed
  desktop installs use the package manager for installation and updates.
- On standalone desktop installations, `oblivion runtime gc` removes verified
  obsolete software and `oblivion runtime uninstall` removes managed software
  while preserving encrypted data. Stop the runtime first.
- On Live, `oblivion runtime choose-storage` lets you select a different
  storage mode after closing active work and stopping the controller.

**Permanent removal on standalone macOS, Linux and Windows installations.**
`oblivion runtime atomic` requires the runtime to be stopped and an interactive
review. Confirming permanently removes the owned application installation and
its encrypted archive, including all Safes. External backups, exports and
snapshots remain separate copies.

On Windows, run the command from the matching verified bundle outside the
installation directory so Windows can remove the installed executable. See the
[Windows Atomic instructions](WINDOWS.md#permanent-removal-with-atomic).

On macOS and Linux, if removal is interrupted, run `runtime atomic` again
from the launcher path shown by the command. If the launcher was already
removed, reinstall with the matching bundle to finish the last cleanup step
and start with fresh storage.

See the installation guides for platform prerequisites and current acceptance.
[Desktop bundles](DESKTOP.md) · [Windows](WINDOWS.md) · [Debian packages](DEBIAN.md) · [Live](LIVE.md)
