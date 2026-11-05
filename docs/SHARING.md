# Share and recovery

Share moves selected files and conversations to another Oblivion installation.
It creates a portable package encrypted with a separate sharing passphrase.
The receiver creates new Safes and uses their own provider accounts. This is
different from a personal disk backup, which can contain saved provider logins.

The CLI and manager paths described here are implemented in the current 1.0
source, with one workflow for Unix and Windows launchers. They still require
Windows execution and acceptance between two installed candidates; old
0.x images do not contain this workflow.

## Export

Unlock writable encrypted storage and close every Safe included in the export.
Unrelated Safes can remain open. Choose one of:

```sh
oblivion share export --safe research research.oblivion-share
oblivion share export --branch research family.oblivion-share
oblivion share export --all collection.oblivion-share
```

`--branch` includes the selected Safe and its descendants. `--all` includes all
persistent Safes and the application automatic-lock timers. No proxy passwords
or provider profiles enter the package. Export refuses an existing output file.

By default Share includes `workspace`, `imports` and supported native
conversations. Each conversation reopens in the agent that created it. Source
login files, client configuration and native database blobs are not copied.
OpenCode native transfers are imported on its next explicit launch, rather
than executing a client in the offline maintenance VM.
Native forks and reverts can depend on saved prefixes from other conversations.
Share includes required native history dependencies and identifies that inclusion
in review. It preserves physical transcript bytes instead of rewriting signed
reasoning, tool records or byte offsets. Required document paths must also be
selected for export; missing attachments or unsupported records stop the
operation instead of producing an incomplete conversation. Credential files
remain excluded; messages and documents themselves can still contain secrets.

Narrow the selection or exclude items shown during review:

```sh
oblivion share export --safe research project.oblivion-share \
  --path workspace/project --exclude workspace/project/private --no-chats

oblivion share export --safe research discussion.oblivion-share \
  --chat 11111111-1111-4111-8111-111111111111
```

`--chat` selects conversations from a single Safe using the opaque UUID
references shown by Share review, rather than a client-native ID. These are
export selections, not a shared chat catalog. `--exclude-chat UUID` can
exclude conversations from any export. Known credential-store paths are always
rejected. Suspected secrets in arbitrary files or conversation content are
excluded by default and reported for review; explicit `--include-sensitive PATH`
or `--include-sensitive-chat UUID` can include those candidates. Scanning is
bounded and best effort: review the selected content yourself before sharing.

The source Safes are opened one at a time in offline maintenance VMs, without
agents, network devices or the writable sudo overlay. Oblivion first reviews
every source, then asks for `SHARE` and a separate passphrase of at least 16
characters. During encryption it reopens each source and refuses content that
changed after review. The desktop writes ciphertext from the first byte and
publishes the output only after successful verification and source cleanup.
Do not change or reopen the selected Safes during this operation.

One export authorization lasts at most an hour. It can open only its fixed
source set and cannot start agents. Closing the client, locking Oblivion or
expiry revokes that authorization. Titles and relationships are encrypted;
the age format, KDF parameters and ciphertext size remain observable.
Automatic-lock timers still apply: unattended output or transfer traffic does
not keep Oblivion unlocked. Review those timers before a long export or import.

## Import

On the receiving installation, unlock writable encrypted storage:

```sh
oblivion share import research.oblivion-share
```

Enter the sharing passphrase. Review the destination titles, disk capacities and
transport requirements, then confirm `IMPORT` and choose a new password for the
imported Safes. That password applies to this imported collection; each tree
gets a fresh family, each Safe a new identity and encryption key. Name conflicts
receive a visible ` (imported)` suffix. Existing Safes are never overwritten.

Each destination is prepared offline and kept outside the visible catalog.
Publication is one atomic collection operation after all payload hashes and the
final age authentication chunk pass. A complete first Safe remains unpublished
if a later Safe or the final authentication check fails.

Imported Safes start offline. Source proxy labels can describe setup still
needed, but proxy secrets and provider logins are not imported. Configure the
transport and authenticate with your own account before using a cloud model.
Imported conversations and documents may themselves contain information the
sender chose to share. Installed packages, shell history, caches, temporary
files and source client profiles are not copied.

Application settings remain unchanged unless explicitly selected:

```sh
oblivion share import collection.oblivion-share --apply-settings
```

Only the shared automatic-lock timers are currently portable. They are applied
after successful Safe publication. Exit code `2` means the Safes were imported
but those optional settings could not be applied: change Settings manually;
do not import again. Exit code `130` indicates cancellation.

## Interrupted imports

Inspect import transactions without publishing or resuming them:

```sh
oblivion share imports
oblivion share imports --json
```

The manager exposes the same list in `Settings → Share imports`, with a review
page before invoking the explicit discard confirmation. Committed imports are
inspect-only. A failed or stale status read disables discard actions until a
fresh result is available.

`Pending` means unpublished staging. `Recovery required` means the stored import
cannot continue under its current authority or needs inspection. `Imported`
records the committed collection. Locking or restarting Oblivion does not grant
an old client permission to resume a pending import.

To remove an incomplete transaction, first stop its active import client, then:

```sh
oblivion share discard TRANSACTION_ID
```

Read the confirmation and type `DISCARD`. This operation refuses committed
collections, active maintenance VMs and unknown staged data that it cannot
identify safely. It cannot remove personal Safes. Retry an import only after
checking its outcome; a lost success response does not mean publication failed.

Share uses the existing explicit file-transfer paths for delivery. Qualification
of large packages over public Tor/OnionShare is separate from local Share
verification.

The current native adapters retain separate ownership for the export signal
and each source stream. Revoking or dropping the export owner stops source I/O;
only the common workflow decides release, import finish and export end. Local
input/output authorities are shared with personal backups, while Share keeps
its distinct passphrase-encrypted container and credential-exclusion policy.
The Windows fixtures are currently compiled evidence, not installed acceptance.
