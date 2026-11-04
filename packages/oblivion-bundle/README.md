# Desktop bundle manifests

The common, current-format `oblivion-desktop` manifest for development desktop
bundles. Unix and Windows targets use one canonical identity, inventory and
runtime binding. Platform adapters own filesystem access, permissions, hashes
and installation; this crate performs no I/O.

`Manifest::decode` checks the bounded manifest, its canonical SHA-256 identity,
source/platform binding and required files. Paths have portable lexical rules;
Windows inventories also reject reserved names and case aliases in files and
parent directories. `Binding` identifies the three immutable controller boot
assets. Unknown formats are rejected without a migration or alternate reader.

Checksums pair source and artifacts. They do not establish release signatures,
hardware support or permission to redistribute an agent.

From this package directory:

```sh
cargo test --locked
cargo check --locked --all-targets --target x86_64-pc-windows-msvc
```
