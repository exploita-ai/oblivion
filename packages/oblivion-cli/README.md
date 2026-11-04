# Portable Oblivion CLI syntax

The native launcher uses this single parser for `oblivion run` options and SOCKS5
URLs. It performs no terminal, filesystem, network, VM or authentication I/O.
The Windows frontend can consume the same parser without reproducing its grammar.
Name validity, Safe selection and authorization remain at their owning domain
boundary; a parsed request does not grant access or mean a named Safe exists.

Options stop at `codex`, `claude` or `opencode2`. All subsequent UTF-8 strings are
passed unchanged, including empty strings and options with the same spelling as
Oblivion's. The parser neither splits commands nor expands shell expressions.
An omitted transport/policy remains omitted rather than changing an existing Safe.

SOCKS5 URLs accept the existing literal IPv4/port syntax and optional percent-
encoded credentials. Both `socks5://` and `socks5h://` use the existing transport;
no destination DNS lookup occurs here. A username without `:PASSWORD` returns a
typed `NeedsPassword` request. The platform frontend prompts privately, then
completes and validates it. Secret-bearing requests have no Debug implementation;
decoded buffers and credential values use zeroizing storage, and errors are
static strings without the supplied URL. Explicit credentials supplied in argv
still follow the desktop shell/process trust boundary; parsing cannot erase
those original OS arguments.

From this directory:

```sh
cargo test --locked
cargo check --locked --lib --target x86_64-pc-windows-msvc
```

This is a portable parsing boundary, not an implemented Windows CLI or VM backend.
