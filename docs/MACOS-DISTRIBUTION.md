# macOS command-line installation

Oblivion's macOS distribution uses the native command-line installer. Developer
ID signing and notarization are optional distribution improvements, not required
to qualify this CLI installation path. Neither the bootstrap nor native installer
removes quarantine, changes Gatekeeper policy or grants itself privileges.

## Publication status

The bootstrap is being prepared on the development branch. It is not yet
available from `main`, and the RC2 release is a draft. Do not describe the
commands below as a published installation service until the source and release
assets are public. The published beta is intentionally rejected by this 1.0
installer; there is no beta migration or compatibility path.

The intended command **after publication** is:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/exploita-ai/oblivion/main/install.sh | bash
```

It selects GitHub's latest published stable release and accepts only 1.x tags.
To select an immutable release explicitly, use a bootstrap from that tag:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/exploita-ai/oblivion/v1.0.0/install.sh \
  | bash -s -- --version v1.0.0
```

For an RC, use its exact public tag with `--version v1.0.0-rc.N`. A draft or
missing asset produces an error before installation. The script does not read
GitHub credentials or attempt to access draft releases. For source review or
local development, run `bash install.sh --help`; a downloaded script can also
be inspected before running it with `bash install.sh --version TAG`.

## What the bootstrap does

`install.sh` supports native macOS Apple Silicon with macOS 15 or newer. It uses
the system Bash 3.2, curl, tar and shasum. It does not require Bun, Python, jq,
Homebrew, sudo or an Apple developer account.

It downloads the exact release's Mac TAR and SHA-256 sidecar from the fixed
`exploita-ai/oblivion` GitHub release origin over HTTPS. When the release uses
split delivery, it downloads the ordered raw parts, verifies each part and the
reconstructed TAR, and then checks archive paths and entry types. Checksums
identify bytes from that release; they are not publisher signatures.

Extraction occurs in a private temporary directory. Only the expected bundle
root, regular files and directories are accepted. The bootstrap then runs the
bundle's existing `install.sh`; the native launcher validates the manifest,
complete inventory and hardware capabilities and owns installation, activation
and current-format recovery. Missing nested virtualization remains a native
preflight error. The bootstrap cleans its temporary downloads on exit.

The command is installed at `~/.local/bin/oblivion`. No shell startup file is
edited automatically. If that directory is absent from `PATH`, invoke the full
path or add it through your normal shell configuration. Existing unrelated
commands, incompatible stored formats and another installation's runtime are
handled by the native installer's existing refusal rules.

## Qualification

Test the actual published download, verification, installation, launch, update
and removal paths with disposable state. Running `--help`, fixture tests or
opening the manager preview does not qualify an installed bundle. Record the
exact source and artifact digests in [the acceptance matrix](ACCEPTANCE.md),
including the common privacy, provider, persistence and recovery requirements.

If Developer ID signing is added later, sign native components before computing
the bundle inventory. Signing changes bytes and requires a new candidate and
applicable tests. Notarization and Gatekeeper behavior must then be verified on
the delivered artifact; no signature or notarization is currently claimed.
