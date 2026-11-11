# Desktop bundle manifests

The common version-2 `oblivion-desktop` manifest for desktop bundles. Unix and
Windows targets use one canonical identity, inventory and
runtime binding. Platform adapters own filesystem access, permissions, hashes
and installation; this crate performs no I/O.

`Manifest::decode` checks the bounded manifest, its canonical SHA-256 identity,
source/platform binding and required files. Paths have portable lexical rules;
Windows inventories also reject reserved names and case aliases in files and
parent directories. `Binding` identifies the three immutable controller boot
assets. Unknown formats are rejected without a migration or alternate reader.

Every manifest requires a `channel` and its canonical ASCII `product_version`
(at most 64 bytes): `dev` uses `X.Y.Z~devN.sha12`, `rc` uses `X.Y.Z~rcN`, and
`stable` uses `X.Y.Z`. Version components are decimal without leading zeroes;
`N` starts at 1 and `sha12` is exactly 12 lowercase hexadecimal characters.
The channel is part of the canonical identity. Version 1 and its
`development_only` field are rejected.

Checksums pair source and artifacts. They do not establish release signatures,
hardware support or permission to redistribute an agent.

From this package directory:

```sh
cargo test --locked
cargo check --locked --all-targets --target x86_64-pc-windows-msvc
```
