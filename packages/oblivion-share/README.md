# Oblivion Share

Portable Safe data encrypted with a separate sharing passphrase. This library
uses the standard age format and the existing Oblivion transfer manifest and
payload verifier. It never opens a source filesystem or mounts a Safe.

The application supplies guest streams containing only approved `workspace`,
`imports` and a `history/chats.jsonl` archive of the selected native conversations.
That transfer file is not a shared live conversation catalog. Known credential-store
paths are rejected by the shared transfer validator. Full home directories,
provider profiles, proxy secrets and installed-system overlays are not portable
roots. Content scanning happens before approval in the guest and cannot promise
that arbitrary messages or files contain no secrets.

## Container and publication

The encrypted age payload contains `OBSHARE1`, bounded versioned package
metadata, a manifest and verified payload per Safe, then `OBSHEND1`. Package IDs
are local to the package; imports allocate new local Safe identities and keys.
Relationships and approved provenance can be carried without source credentials.
The manifest hash and sizes bind each payload to the reviewed selection.

Encryption uses age passphrase encryption with scrypt `log2(N)=18`, `r=8`
(approximately 256 MiB). Import refuses work factors above that bound. Secrets
use age's secrecy types; package metadata is encrypted, including titles and
relations. The outer age header necessarily exposes the encryption format and
KDF parameters. Output file size also remains observable.

`Source::complete` acknowledges the exact verified transfer receipt; sources
may wait for that acknowledgement rather than EOF. Encryption success requires
age's final `finish`, after which the application can publish its exclusive
ciphertext staging file without replacing an existing destination.

`Import` writes only into unpublished, newly allocated Safes. It must not
publish data from `begin` or `finish_safe`. Every file hash, transfer terminator,
container terminator and the final age authentication chunk must pass before
`decrypt` returns `Verified`. Only the caller holding that proof can proceed to
publication. A failure calls `abort`; failed cleanup is reported distinctly.
A complete earlier Safe in a multi-Safe package is still staging until the
entire package authenticates.

The library does not run clients or import native credentials. The guest
[native-history adapter](../oblivion-history/README.md) validates each pinned
client's records and restores them for that same client. Native reasoning and
signatures retain their original format; unsupported records and relationships
are disclosed as omissions in review.

## Verification

From this package:

```sh
cargo test --locked --release --test container
```

The integration suite exercises real selection streams, multiple Safes,
relationships, UTF-8 names, binary payloads, passphrase encryption, corruption,
truncation and failed authentication without publication. It does not qualify
controller hotplug, power-loss recovery or end-to-end import between machines.
