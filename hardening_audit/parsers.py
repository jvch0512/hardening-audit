"""Parsers for the config formats we audit. Pure functions over text, so they are trivial to test."""
from __future__ import annotations

import re


def parse_sshd(text: str) -> dict[str, str]:
    """sshd uses the FIRST occurrence of a keyword (outside Match blocks), so we do the same.
    Keywords are case-insensitive and are returned lower-cased."""
    out: dict[str, str] = {}
    in_match = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\s+|=", line, maxsplit=1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            in_match = True
            continue
        if in_match:
            continue
        out.setdefault(key, val.strip('"'))
    return out


def parse_sysctl(text: str) -> dict[str, str]:
    """Later settings win, like the real sysctl loader."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_passwd(text: str) -> list[dict]:
    users = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 7:
            users.append({"name": f[0], "uid": int(f[2]) if f[2].isdigit() else -1, "shell": f[6]})
    return users


def parse_shadow(text: str) -> list[dict]:
    return [{"name": f[0], "hash": f[1]} for f in (l.split(":") for l in text.splitlines()) if len(f) >= 2]


def parse_dpkg_status(text: str) -> set[str]:
    """Names of installed packages from /var/lib/dpkg/status."""
    installed = set()
    for block in text.split("\n\n"):
        name = status = None
        for line in block.splitlines():
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].strip()
        if name and status and status.endswith("installed") and "not-installed" not in status and "deinstall" not in status:
            installed.add(name)
    return installed
