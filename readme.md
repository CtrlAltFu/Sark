# sark — Kali Tools MCP Server

Lightweight, spec-compliant MCP server that exposes a handful of common Kali tools over a **streamable HTTP MCP** endpoint so LM Studio (or other MCP-aware clients) can call them programmatically.

> **Dangerous by design.** This server executes system binaries. Read the **Security** section carefully before running.

---

# What this repository contains
`sark.py` — single-file Python MCP server that wraps common Kali tools (nmap, gobuster, dirb, nikto, sqlmap, hydra, john, wpscan, enum4linux) and a generic `exec_cmd` tool. It uses `fastmcp` to expose those functions over an MCP HTTP endpoint.

---

# Requirements

- Python 3.10+ (tested with modern 3.x)
- `fastmcp` Python package:
```bash
pip install fastmcp
```
- The Kali tools you intend to run must be installed and in your `PATH` (e.g., `nmap`, `gobuster`, `nikto`, `sqlmap`, `hydra`, `john`, `wpscan`, `enum4linux`).

---

# Quick start

1. Install requirements (pip, tools as needed):
```bash
# default Kali pip repository doesn't include fastmcp
python -m venv .venv
pip install fastmcp
# install system packages as required (nmap, gobuster, ...), e.g. apt on Debian/Ubuntu:
# sudo apt install nmap gobuster nikto sqlmap hydra john wpscan enum4linux
```

2. Run the server (binds to localhost by default):
```bash
HOST=127.0.0.1 PORT=8765 python3 sark.py
```

You should see:
```
[kali-mcp] serving on 127.0.0.1:8765 at /mcp
[kali-mcp] WARNING: no allowlist set (all commands permitted)
```

---

# Environment variables

- `HOST` — interface to bind (default `127.0.0.1`). **Prefer `127.0.0.1`** unless you understand network risks.
- `PORT` — port to listen on (default `8765`).
- `ALLOWED_COMMAND_PREFIXES` — comma separated prefixes to restrict allowed commands (example: `nmap,gobuster,nikto`). When set, only commands whose text begins with one of the prefixes are allowed.

Example allowlist:
```bash
ALLOWED_COMMAND_PREFIXES="nmap,gobuster,nikto" HOST=127.0.0.1 python3 sark.py
# prints: [kali-mcp] allowed commands: nmap, gobuster, nikto
```

> If `ALLOWED_COMMAND_PREFIXES` is not set the server will allow any command — **highly unsafe**.

---

# LM Studio integration

Add (or edit) the `mcp.json` entry in LM Studio to point to this service:

```json
{
  "kali-tools": {
    "url": "http://127.0.0.1:8765/mcp",
    "timeout": 120000
  }
}
```

LM Studio will then be able to call MCP tools exposed by `sark.py`.

---

# Exposed tools (API)

All tools are decorated with `@mcp.tool()` and exposed via MCP. Function signatures (Python) and short descriptions:

- `exec_cmd(cmd: str, shell: bool=False) -> str`  
  Run an arbitrary shell command. Use with extreme care.

- `nmap_scan(target: str, scan_type: str="-sV", ports: str="", additional_args: str="-T4 -Pn") -> str`  
  Runs `nmap`.

- `gobuster(url: str, mode: str="dir", wordlist: str="/usr/share/wordlists/dirb/common.txt", additional_args: str="") -> str`  
  Runs `gobuster`.

- `dirb(url: str, wordlist: str="/usr/share/wordlists/dirb/common.txt", additional_args: str="") -> str`  
  Runs `dirb`.

- `nikto(target: str, additional_args: str="") -> str`  
  Runs `nikto`.

- `sqlmap(url: str, data: str="", additional_args: str="") -> str`  
  Runs `sqlmap` (batch mode).

- `hydra(target: str, service: str, username: str="", username_file: str="", password: str="", password_file: str="", additional_args: str="") -> str`  
  Runs `hydra` for brute forcing.

- `john(hash_file: str, wordlist: str="/usr/share/wordlists/rockyou.txt", format: str="", additional_args: str="") -> str`  
  Runs `john` (John the Ripper).

- `wpscan(url: str, additional_args: str="") -> str`  
  Runs `wpscan`.

- `enum4linux(target: str, additional_args: str="-a") -> str`  
  Runs `enum4linux`.

Each tool returns the combined STDOUT/STDERR and the return code (or an error message) as a string.

---

# Examples

Run server (only allow nmap and gobuster):
```bash
ALLOWED_COMMAND_PREFIXES="nmap,gobuster" HOST=127.0.0.1 PORT=8765 python3 sark.py
```

From an MCP client (LM Studio will handle this for you) — example conceptual `curl` usage is shown for demonstration only (LM Studio speaks MCP; a raw HTTP call may not be equivalent to a proper MCP client):

```bash
# This is illustrative — LM Studio does the MCP protocol work for you.
curl -X POST http://127.0.0.1:8765/mcp \
  -H "Content-Type: application/json" \
  -d '{ "method": "nmap_scan", "params": ["127.0.0.1", "-sV", "", "-T4 -Pn"] }'
```

> Use LM Studio's built-in MCP client instead of crafting raw HTTP calls unless you know the MCP framing expected by your client.

---

# Implementation notes

- The server uses `subprocess.run()` to execute commands. When `shell=True` is used by the `exec_cmd` wrapper, `/bin/bash` is used as the shell.
- Commands are tokenized using `shlex.split()` unless `shell=True`.
- The allowlist check is a simple prefix check (`cmd.strip().startswith(prefix)`); tune to your needs if you require more granular controls.
- Outputs are returned as plain text: stdout, optional stderr, and `[rc=<returncode>]`. Errors/timeouts are returned as human readable strings.

---

# Security & Hardening (read carefully)

This server **executes arbitrary system commands**. If misconfigured or exposed it can lead to full system compromise.

Recommendations:
- Bind to `127.0.0.1` and firewall the port. Do **not** expose this service to untrusted networks.
- Use `ALLOWED_COMMAND_PREFIXES` to limit which command prefixes are permitted. Example: `ALLOWED_COMMAND_PREFIXES="nmap,gobuster,nikto"`.
- Run as a non-privileged user (never `root`).
- Consider additional sandboxing: containers, chroot, seccomp, AppArmor, or similar.
- Keep attack surface minimal: only install the tools you need, maintain proper system updates.
- Consider logging, audit trails, and rate limiting if exposing to multiple clients.
- If you need remote access, use an authenticated, encrypted tunnel (SSH port forwarding, VPN) — do not bind to `0.0.0.0` publicly.

---

# Service (systemd) example

Example systemd unit (run as `kaliuser`, adjust paths):
```ini
[Unit]
Description=Kali MCP Server (sark)
After=network.target

[Service]
User=kaliuser
WorkingDirectory=/opt/kali-mcp
Environment=HOST=127.0.0.1
Environment=PORT=8765
Environment=ALLOWED_COMMAND_PREFIXES=nmap,gobuster,nikto
ExecStart=/usr/bin/python3 /opt/kali-mcp/sark.py
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

---

# Troubleshooting

- If tools return `command not found` errors: ensure the binary is installed and on the PATH for the user running the process.
- If commands hang: the `_run()` helper enforces a default timeout (300s). You can adjust usage or modify the server.
- If LM Studio cannot connect: verify HOST/PORT and that LM Studio `mcp.json` URL matches `http://<HOST>:<PORT>/mcp`.

---

# Extending

- Add new `@mcp.tool()` functions to wrap additional binaries.
- Improve allowlist checking (e.g., whitelist full command templates or validate arguments).
- Add authentication/authorization if exposing beyond localhost.
- Add structured JSON responses (currently returns plain text strings).

---

# License & Disclaimer

This code is provided as-is for convenience. Use at your own risk. The author is not responsible for misuse or damage resulting from running this software. Carefully evaluate security implications before use.

---
