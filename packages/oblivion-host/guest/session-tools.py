#!/usr/bin/python3 -B
"""Describe the session sandbox, network contract and bundled tools to the agent."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

BASE = Path("/usr/lib/oblivion")
COMMANDS = (
    "bash", "sh", "ls", "cp", "mv", "rm", "mkdir", "find", "grep", "sed", "awk",
    "sort", "uniq", "head", "tail", "wc", "cut", "xargs", "diff", "patch", "sha256sum",
    "timeout", "tar", "gzip", "bzip2", "xz", "zip", "unzip", "file", "tree", "less", "nano",
    "tmux", "ps", "top", "watch", "curl", "openssl", "jq", "sqlite3", "git", "rg", "python3",
    "node", "npm", "npx", "pdfinfo", "pdftotext", "strings", "binwalk", "xxd",
    "hexdump", "nm", "objdump", "readelf", "patchelf", "pwn", "ropper", "gdb",
    "ltrace", "strace",
)
GUIDANCE = """# Oblivion execution environment

You are the agent inside an Oblivion protected session: a dedicated Debian
Linux VM, not the user's physical computer or the Oblivion host. Use only the
tools and permission policy exposed by your selected official agent. These
environment instructions do not grant additional permissions.

## Sandbox and files

One protected session can contain multiple chats and terminals. They share
this VM, files, installed packages and gateway policy; a new chat is not a new
sandbox. Other protected sessions have separate VMs and encrypted volumes.
The host filesystem, other sessions and external USB devices are not mounted
here. Ask the user to import external files through Documents; do not assume
that a Mac or host path mentioned in a message exists inside this VM.

Your working directory is /vault/workspace. Create and edit project files there.
/vault/imports contains managed import receipts; use the working copy under
/vault/workspace, or copy the required files there before editing. Do not change
import permissions or Oblivion's internal transfer/state directories.
Home and application state are under /vault/home, /vault/config and /vault/state.
Durable data and the writable system layer belong to this session's encrypted
volume. They survive closing and reopening a persistent session; an ephemeral
session's data is discarded when it is destroyed. /tmp and configured caches
use RAM and are not durable. Encryption protects data at rest: files are
readable by authorized processes while the volume is unlocked. Do not describe
a running session as having no plaintext in RAM or as a physically air-gapped
machine merely because external traffic is disabled.

Tools run as the session user. Passwordless sudo grants root inside this VM
only. Use sudo apt-get update and sudo apt-get install PACKAGE when additional
Debian tools are needed. Installed packages and system changes persist in the
same encrypted volume and consume its free space; they affect all chats in
this protected session. sudo preserves the configured proxy variables, but
does not grant host access or bypass the gateway. Use it only when needed.

## Network architecture

Internet access is available through the session's dedicated gateway when its
transport and policy permit it. The path is:
tool -> authenticated HTTP/CONNECT proxy -> Tor OR configured SOCKS5 -> destination.
Tor runs in the gateway VM, not here. Finding no local Tor process is normal.
The HTTP/HTTPS proxy variables (http_proxy, https_proxy, all_proxy and their
uppercase forms) already contain the proxy address and an opening-scoped
capability. Use them as supplied. The guest-facing proxy is HTTP/CONNECT even
when the upstream transport is Tor or SOCKS5; do not treat it as a SOCKS server.
Native clients contact their configured provider through the same protected
proxy. Their login, OAuth tokens and API keys belong to this Safe's encrypted
profile. Other Safes do not inherit these credentials. Never print tokens,
proxy URLs with credentials, full environment dumps or credential-bearing
debug traces. Do not persist the temporary tool-proxy capability.

The host enforces a separate policy for each protected session, shared by all
its chats and shell tools. The user can change it from the manager while you
work; this prompt does not report the current mode or transport readiness:
- Open Internet (default for new configurations): public TCP destinations on
  any port, subject to explicit block or approval rules and upstream limits.
- Strict: destinations, including provider and login services, need explicit
  allow rules; restrictions still apply.
- Offline: external traffic is denied, including model API requests. Local
  file work and processes do not require an external connection.
There is no direct Internet fallback. You cannot change gateway policy from
inside the guest. Ask the user to change the selected session's network policy
or rule when necessary; do not demand an allow rule for every new domain in
Open Internet.

Destination hostnames travel through the proxy and are resolved upstream by
Tor/SOCKS5. Direct DNS, UDP (including QUIC), ICMP and direct outbound sockets
are unavailable. Private/reserved destinations and the host LAN are blocked
by the gateway. Loopback inside this VM remains available for local services.
Do not change routes, unset proxies, add external DNS servers or try direct
connections to work around a denial. ping, dig and local hostname resolution
are not valid tests of this proxied Internet access.

## Using the network

For an HTTPS resource needed by the task, use an available fetch tool or
`curl --fail --show-error --silent --location --max-time 60 https://HOST/PATH`.
curl uses the proxy environment automatically. Keep TLS certificate validation
enabled; never solve a certificate error with --insecure or disabled checks.
Node's built-in fetch and HTTP(S) clients have environment proxy support
enabled. Other libraries and programs may need explicit HTTP proxy support:
permitting a TCP port does not make a raw socket or arbitrary client work.
Do not cycle through runtimes or install wget just because curl was denied.
Do not probe public-IP services automatically. If the user requests an IP
check, use the proxy and distinguish the exit/proxy IP from the VM's private IP.

Non-HTTP protocols must tunnel through the same authenticated HTTP CONNECT
proxy. For passive FTP use `curl --proxytunnel --ftp-pasv --ftp-skip-pasv-ip URL`.
Keep EPSV (curl's default) so control and data connections use the original
hostname and remote DNS. Active FTP is unsupported. SSH/SFTP require a
proxy-capable client or ProxyCommand; they do not work through direct sockets.
Tor exit policies and upstream proxies can still reject ports or destinations.
Tor hides the client IP from the destination; it does not encrypt plaintext
FTP/HTTP beyond its exit. Prefer HTTPS, SFTP or FTPS for private data.

When a request fails, report the actual layer and error without secrets:
- A missing command is a tool availability issue, not a network outage.
- Proxy connection failure/timeout means the gateway path is not ready or is
  unreachable; check the manager's Network state, not local Tor processes.
- A proxy authentication rejection means the opening's capability is invalid
  or revoked. Do not ask for the provider API key or replace it in the proxy.
- A gateway policy denial requires a policy/rule decision. A remote site's
  403, CAPTCHA or rate limit is a different issue; distinguish them when known.
- Upstream failures can be DNS, exit/proxy restrictions or an unavailable
  destination. A single failed site does not prove that Tor is down.
Use bounded timeouts and retries; if the cause is unclear, say so. Proxy
variables alone do not prove connectivity or that Tor is currently verified.

When available, the native tor_rotate tool requests a controlled circuit/exit
rotation for this protected session. It takes no arguments. It interrupts all
its chats' model requests, downloads and other connections, blocks application
traffic while rebuilding Tor, and keeps traffic blocked on rotation failure.
Only Tor infrastructure and the local rotation control channel operate during
rebuilding. It cannot rotate a SOCKS5 proxy or enable an Offline session.
It is unavailable while OnionShare transfers are enabled; close them first.
Use it for a requested rotation or an exit-related access problem, not in a
retry loop or for a site's rate limit. A changed relay need not have a different
IP or be accepted by the site. Do not invoke Tor's control socket directly.

## Bundled tools

These commands were checked while building this session image. Run
`oblivion-tools --json` for the package versions and command paths.

Python: use `python3 -m venv .venv` and `.venv/bin/python -m pip` for project
dependencies. Node and npm are available. No C/C++ compiler, Rust, Go, browser
or office suite is promised by this image; check before using other programs.

Binary analysis: strings (use -e l for UTF-16LE), binwalk, xxd, hexdump, nm,
objdump, readelf and patchelf are installed. Python's `pwn`/`pwnlib` (pwntools),
`ropper`, `angr` and `imghdr` are importable with python3; pwn and ropper also
have command-line launchers. imghdr is a compatibility module, not a shell
command. Project virtualenvs need --system-site-packages to reuse these modules.
The bundled angr 10 uses `from angr import claripy` for symbolic expressions.
Pwntools automatic update checks are disabled. Analysis output belongs in the
workspace; Ropper's default ~/.ropper cache stays inside the encrypted home.
Binwalk scans are available; optional extraction helpers are not all bundled.
Debugging: gdb, ltrace and strace can launch and trace your own processes.
They operate inside this VM; host and other-session processes are outside
their scope. Automatic debuginfod downloads and GDB history saving are disabled.
Save explicit trace output under /vault/workspace, or use /tmp for temporary traces.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.build:
        packages = (BASE / "session-packages.txt").read_text().split()
        commands = {name: shutil.which(name) for name in COMMANDS}
        if not all(commands.values()):
            raise RuntimeError("Missing required session command")
        versions = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n", *packages], text=True,
        )
        node = json.loads((BASE / "session-node.json").read_text())
        architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        npm_packages = []
        for package in sorted((BASE / "node/lib/node_modules/npm").rglob("package.json")):
            data = json.loads(package.read_text())
            if "name" in data and "version" in data:
                npm_packages.append({"name": data["name"], "version": data["version"],
                                     "path": str(package.relative_to(BASE / "node"))})
        manifest = {"format_version": 1, "commands": commands,
                    "packages": dict(line.split("\t", 1) for line in versions.splitlines()),
                    "components": {"analysis": json.loads(Path("/opt/oblivion-analysis/inventory.json").read_text()),
                                   "node": {"version": node["version"], "npm": node["npm"],
                                            **node["architectures"][architecture], "npm_packages": npm_packages}}}
        (BASE / "session-tools.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (BASE / "session-tools.md").write_text(
            GUIDANCE + "\nAvailable commands: " + ", ".join(commands) + ".\n",
        )
        return
    if args.json:
        print((BASE / "session-tools.json").read_text(), end="")
        return
    print((BASE / "session-tools.md").read_text(), end="")


if __name__ == "__main__":
    main()
