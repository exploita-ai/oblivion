# Personal encrypted backups

A personal backup is the complete LUKS volume of one persistent Safe. It keeps
the original Safe identity, family, data key, native chats, installed software
and any credentials saved inside that Safe. Keep the original Safe password.
Use [Share](SHARING.md) to create portable copies with new identities and keys
while excluding native provider credentials.

In the manager, select the source in **Safes**, then open **Settings → Personal
backups**. Create backup, restore and transfer recovery are separate actions.
The review shows the chosen local path and the complete-volume credential
policy before the CLI requests any password. Transfer history uses actual
controller records; interrupted commands must be inspected before retrying.

Unlock writable Oblivion storage and close the source Safe, then run:

```sh
oblivion backup export --safe GB ./GB.luks
```

The CLI requests the Safe password privately. A maintenance VM checkpoints the
current metadata without a network interface, agent process or writable sudo
overlay. The controller then copies the closed encrypted volume. The computer
receives ciphertext through a transaction-bound stream, never a mounted Safe
filesystem or an open file descriptor into the general archive. Hashes and a
receipt are checked before publishing the chosen output without overwriting an
existing file. Other Safes remain independent; the source cannot open or grow
while its copy lease is active.

On another installation, unlock writable Oblivion storage and run:

```sh
oblivion backup import ./GB.luks
```

After the verified copy, enter the original Safe password. Restore verifies the
current volume identity and checkpoint, including a child task's authenticated
context without requiring its mother. Publication preserves the original Safe
ID and refuses an existing identity. The restored Safe starts Offline. This is
recovery of the same Safe, not a way to run two separately keyed copies.

Inspect uncertain outcomes before repeating an operation:

```sh
oblivion backup status --json
oblivion backup finish TRANSACTION
oblivion backup discard TRANSACTION
```

`finish` is for an already verified import in the same unlocked Oblivion opening,
for example after an incorrect password; it does not recopy the volume. A lost
reply is reconciled through status rather than automatically restoring again.
After lock or restart, old authority cannot publish a pending import. Discard
removes only an identifiable incomplete transaction after its owners stop;
committed Safes are never discarded through this command.

Lock stops and reaps copy workers before releasing the general archive. An
interrupted output can leave an encrypted partial file in the chosen external
directory. It is not a confirmed backup. This path has local stream, filesystem
and process-revocation fixtures. A headless Apple Silicon test restored a 2 GiB
backup into a separate archive with the original Safe ID, password, file and
OpenCode 2 history. It used a diagnostic controller image; release-image
qualification remains open. A restore writes a complete volume, so when using
the native launcher, leave enough free space on the disk backing its VM.

The current Unix and Windows command adapters use one backup workflow for
preflight, password entry, copy receipts, controller reconciliation and restore.
Native filesystem endpoints pin only the chosen ciphertext file and output
directory. The output is private and published without replacing an existing
file, only after the controller confirms its copy. No source path crosses the
attachment: the manifest always names the one fixed encrypted-volume payload.

A backup attachment ends through data-channel EOF, unlike a Files/agent
attachment with an explicit client release. Closing that channel is not proof
of a successful backup; the workflow checks the controller's outcome separately.
Windows source, output and transport compilation is distinct from execution on
Windows and an installed Hyper-V backup/restore round trip, which remain open.
