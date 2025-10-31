#!/usr/bin/env python3
"""
sark.py
A spec-compliant MCP server exposing Kali tools over Streamable HTTP for LM Studio.

Requires:
  pip install fastmcp

Run:
  HOST=127.0.0.1 PORT=8765 python3 sark.py
Then set in LM Studio's mcp.json:
  "kali-tools": { "url": "http://127.0.0.1:8765/mcp", "timeout": 120000 }

Security:
  This can execute system tools. Prefer HOST=127.0.0.1 or firewall it.
"""

import os, shlex, subprocess
from typing import Optional
from fastmcp import FastMCP, tools

HOST = os.getenv("HOST", "127.0.0.1")  # bind local by default
PORT = int(os.getenv("PORT", "8765"))
ALLOW = os.getenv("ALLOWED_COMMAND_PREFIXES")  # e.g. "nmap,gobuster,nikto"
ALLOW_LIST = [p.strip() for p in ALLOW.split(",")] if ALLOW else None

mcp = FastMCP("Kali Tools")

def _allowed(cmd: str) -> bool:
    if not ALLOW_LIST:
        return True
    return any(cmd.strip().startswith(p) for p in ALLOW_LIST)

def _run(cmd: str, shell: bool=False, timeout: Optional[int]=300) -> str:
    if not _allowed(cmd):
        return f"[blocked] command not allowed by server policy: {cmd}"
    try:
        if shell:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, executable="/bin/bash")
        else:
            p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        out = p.stdout or ""
        err = p.stderr or ""
        rc  = p.returncode
        return (out + (("\nSTDERR:\n" + err) if err else "") + f"\n[rc={rc}]").strip()
    except subprocess.TimeoutExpired:
        return "[error] command timed out"
    except Exception as e:
        return f"[error] {e}"

@mcp.tool()
def exec_cmd(cmd: str, shell: bool=False) -> str:
    """Run an arbitrary shell command. Use carefully.
    Args:
      cmd: Full command line (e.g., 'id', 'uname -a')
      shell: If true, runs through /bin/bash.
    """
    return _run(cmd, shell=shell)

@mcp.tool()
def nmap_scan(target: str, scan_type: str="-sV", ports: str="", additional_args: str="-T4 -Pn") -> str:
    """Run nmap.
    Args:
      target: host/IP, e.g. 127.0.0.1
      scan_type: e.g. -sV or -sCV
      ports: '22,80' or '1-1024'
      additional_args: extra flags
    """
    cmd = f"nmap {scan_type}" + (f" -p {ports}" if ports else "") + (f" {additional_args}" if additional_args else "") + f" {target}"
    return _run(cmd)

@mcp.tool()
def gobuster(url: str, mode: str="dir", wordlist: str="/usr/share/wordlists/dirb/common.txt", additional_args: str="") -> str:
    """Run gobuster."""
    cmd = f"gobuster {mode} -u {url} -w {wordlist}" + (f" {additional_args}" if additional_args else "")
    return _run(cmd)

@mcp.tool()
def dirb(url: str, wordlist: str="/usr/share/wordlists/dirb/common.txt", additional_args: str="") -> str:
    """Run dirb."""
    cmd = f"dirb {url} {wordlist}" + (f" {additional_args}" if additional_args else "")
    return _run(cmd)

@mcp.tool()
def nikto(target: str, additional_args: str="") -> str:
    """Run nikto."""
    cmd = f"nikto -h {target}" + (f" {additional_args}" if additional_args else "")
    return _run(cmd)

@mcp.tool()
def sqlmap(url: str, data: str="", additional_args: str="") -> str:
    """Run sqlmap (batch mode)."""
    cmd = f"sqlmap -u {shlex.quote(url)} --batch" + (f" --data={shlex.quote(data)}" if data else "") + (f" {additional_args}" if additional_args else "")
    return _run(cmd)

@mcp.tool()
def hydra(target: str, service: str, username: str="", username_file: str="", password: str="", password_file: str="", additional_args: str="") -> str:
    """Run hydra brute-force."""
    cmd = "hydra -t 4"
    cmd += f" -l {shlex.quote(username)}" if username else (f" -L {shlex.quote(username_file)}" if username_file else "")
    cmd += f" -p {shlex.quote(password)}" if password else (f" -P {shlex.quote(password_file)}" if password_file else "")
    cmd += f" {additional_args}" if additional_args else ""
    cmd += f" {shlex.quote(target)} {shlex.quote(service)}"
    return _run(cmd)

@mcp.tool()
def john(hash_file: str, wordlist: str="/usr/share/wordlists/rockyou.txt", format: str="", additional_args: str="") -> str:
    """Run john the ripper."""
    cmd = "john" + (f" --format={format}" if format else "") + (f" --wordlist={shlex.quote(wordlist)}" if wordlist else "") + (f" {additional_args}" if additional_args else "") + f" {shlex.quote(hash_file)}"
    return _run(cmd)

@mcp.tool()
def wpscan(url: str, additional_args: str="") -> str:
    """Run wpscan."""
    cmd = f"wpscan --url {shlex.quote(url)}" + (f" {additional_args}" if additional_args else "")
    return _run(cmd)

@mcp.tool()
def enum4linux(target: str, additional_args: str="-a") -> str:
    """Run enum4linux."""
    cmd = f"enum4linux {additional_args} {shlex.quote(target)}"
    return _run(cmd)

if __name__ == "__main__":
    print(f"[kali-mcp] serving on {HOST}:{PORT} at /mcp")
    if ALLOW_LIST:
        print(f"[kali-mcp] allowed commands: {', '.join(ALLOW_LIST)}")
    else:
        print("[kali-mcp] WARNING: no allowlist set (all commands permitted)")
    # Streamable HTTP transport with a single endpoint that LM Studio can consume.
    mcp.run(transport="http", host=HOST, port=PORT, path="/mcp")
