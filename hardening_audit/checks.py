from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import parsers

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class Result:
    id: str
    title: str
    category: str
    severity: str                 # high | medium | low
    status: str
    evidence: str = ""
    fix: dict = field(default_factory=dict)   # {"kind": ..., ...} consumed by the playbook generator


class Host:
    """Read-only view of a Linux host rooted at `root` ('/' for the live system, a fixture dir for tests)."""

    def __init__(self, root: str | Path = "/"):
        self.root = Path(root)

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def read(self, p: str) -> str | None:
        try:
            return self.path(p).read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return None

    def mode(self, p: str) -> int | None:
        try:
            return stat.S_IMODE(os.stat(self.path(p)).st_mode)
        except (FileNotFoundError, PermissionError):
            return None

    def sshd(self) -> dict[str, str] | None:
        text = self.read("/etc/ssh/sshd_config")
        if text is None:
            return None
        merged = text
        d = self.path("/etc/ssh/sshd_config.d")
        if d.is_dir():  # sshd processes Include files first, so drop-ins take precedence
            merged = "\n".join(f.read_text(errors="replace") for f in sorted(d.glob("*.conf"))) + "\n" + text
        return parsers.parse_sshd(merged)

    def sysctl(self) -> dict[str, str]:
        text = ""
        d = self.path("/etc/sysctl.d")
        if d.is_dir():
            text += "\n".join(f.read_text(errors="replace") for f in sorted(d.glob("*.conf"))) + "\n"
        text += self.read("/etc/sysctl.conf") or ""
        return parsers.parse_sysctl(text)

    def packages(self) -> set[str] | None:
        t = self.read("/var/lib/dpkg/status")
        return None if t is None else parsers.parse_dpkg_status(t)


def _ssh(host: Host, id_: str, title: str, key: str, ok, want: str, severity: str, default: str | None = None) -> Result:
    cfg = host.sshd()
    if cfg is None:
        return Result(id_, title, "SSH", severity, SKIP, "sshd_config not found")
    val = cfg.get(key.lower(), default)
    shown = val if val is not None else "(not set)"
    status = PASS if val is not None and ok(val) else FAIL
    return Result(id_, title, "SSH", severity, status, f"{key} = {shown}", {"kind": "sshd", "key": key, "value": want})


def _sysctl(host: Host, id_: str, title: str, key: str, want: str, severity: str) -> Result:
    val = host.sysctl().get(key)
    return Result(id_, title, "Kernel/network", severity, PASS if val == want else FAIL,
                  f"{key} = {val if val is not None else '(not configured)'}", {"kind": "sysctl", "key": key, "value": want})


def _mode_at_most(host: Host, id_: str, title: str, p: str, max_mode: int, severity: str) -> Result:
    m = host.mode(p)
    if m is None:
        return Result(id_, title, "Files", severity, SKIP, f"{p} not found")
    ok = (m & ~max_mode) == 0           # no permission bit beyond what is allowed
    return Result(id_, title, "Files", severity, PASS if ok else FAIL, f"{p} mode {m:04o}, allowed {max_mode:04o} or stricter",
                  {"kind": "file", "path": p, "mode": f"{max_mode:04o}"})


def run_checks(host: Host) -> list[Result]:
    r: list[Result] = []
    r.append(_ssh(host, "SSH-01", "Root login over SSH is disabled", "PermitRootLogin", lambda v: v.lower() == "no", "no", "high"))
    r.append(_ssh(host, "SSH-02", "Password authentication is disabled (keys only)", "PasswordAuthentication", lambda v: v.lower() == "no", "no", "high", default="yes"))
    r.append(_ssh(host, "SSH-03", "Empty passwords are rejected", "PermitEmptyPasswords", lambda v: v.lower() == "no", "no", "high", default="no"))
    r.append(_ssh(host, "SSH-04", "MaxAuthTries is 4 or lower", "MaxAuthTries", lambda v: v.isdigit() and int(v) <= 4, "4", "medium", default="6"))
    r.append(_ssh(host, "SSH-05", "X11 forwarding is disabled", "X11Forwarding", lambda v: v.lower() == "no", "no", "low", default="no"))
    r.append(_ssh(host, "SSH-06", "LoginGraceTime is 60 seconds or lower", "LoginGraceTime", lambda v: v.isdigit() and 0 < int(v) <= 60, "60", "low", default="120"))

    passwd = host.read("/etc/passwd")
    if passwd is None:
        r.append(Result("ACC-01", "Only root has UID 0", "Accounts", "high", SKIP, "/etc/passwd not found"))
    else:
        extra = [u["name"] for u in parsers.parse_passwd(passwd) if u["uid"] == 0 and u["name"] != "root"]
        r.append(Result("ACC-01", "Only root has UID 0", "Accounts", "high", FAIL if extra else PASS,
                        f"extra UID 0 accounts: {', '.join(extra)}" if extra else "only root", {"kind": "manual", "note": "Review and remove or renumber the extra UID 0 accounts."}))

    shadow = host.read("/etc/shadow")
    if shadow is None:
        r.append(Result("ACC-02", "No account has an empty password", "Accounts", "high", SKIP, "/etc/shadow not readable"))
    else:
        empty = [u["name"] for u in parsers.parse_shadow(shadow) if u["hash"] == ""]
        r.append(Result("ACC-02", "No account has an empty password", "Accounts", "high", FAIL if empty else PASS,
                        f"empty password: {', '.join(empty)}" if empty else "none", {"kind": "manual", "note": "Lock or set a password for: " + ", ".join(empty)} if empty else {}))

    r.append(_mode_at_most(host, "FS-01", "/etc/passwd is not writable by group/others", "/etc/passwd", 0o644, "medium"))
    r.append(_mode_at_most(host, "FS-02", "/etc/shadow is not readable by others", "/etc/shadow", 0o640, "high"))
    r.append(_mode_at_most(host, "FS-03", "sshd_config is not accessible by group/others", "/etc/ssh/sshd_config", 0o600, "medium"))

    r.append(_sysctl(host, "NET-01", "IP forwarding is disabled", "net.ipv4.ip_forward", "0", "medium"))
    r.append(_sysctl(host, "NET-02", "TCP SYN cookies are enabled", "net.ipv4.tcp_syncookies", "1", "medium"))
    r.append(_sysctl(host, "NET-03", "ICMP redirects are not accepted", "net.ipv4.conf.all.accept_redirects", "0", "medium"))
    r.append(_sysctl(host, "KRN-01", "ASLR is fully enabled", "kernel.randomize_va_space", "2", "high"))

    pkgs = host.packages()
    if pkgs is None:
        r.append(Result("PKG-01", "Legacy clear-text services are not installed", "Packages", "high", SKIP, "dpkg status not found"))
        r.append(Result("LOG-01", "An audit or logging daemon is installed", "Logging", "medium", SKIP, "dpkg status not found"))
    else:
        legacy = sorted(pkgs & {"telnetd", "telnet-server", "rsh-server", "rsh-redone-server", "talkd", "tftpd", "xinetd"})
        r.append(Result("PKG-01", "Legacy clear-text services are not installed", "Packages", "high", FAIL if legacy else PASS,
                        f"installed: {', '.join(legacy)}" if legacy else "none", {"kind": "packages_absent", "names": legacy}))
        logging = sorted(pkgs & {"auditd", "rsyslog", "syslog-ng"})
        r.append(Result("LOG-01", "An audit or logging daemon is installed", "Logging", "medium", PASS if logging else FAIL,
                        f"found: {', '.join(logging)}" if logging else "none of auditd, rsyslog, syslog-ng", {"kind": "packages_present", "names": ["auditd"]}))
    return r


def score(results: list[Result]) -> float:
    w = {"high": 3, "medium": 2, "low": 1}
    scored = [x for x in results if x.status != SKIP]
    total = sum(w[x.severity] for x in scored)
    return round(100 * sum(w[x.severity] for x in scored if x.status == PASS) / total, 1) if total else 0.0
