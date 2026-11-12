"""Builds a deliberately insecure fake host so the tool can be demonstrated safely without root."""
from __future__ import annotations

import os
from pathlib import Path


def build_insecure_host(root: Path) -> Path:
    def w(p: str, text: str, mode: int = 0o644):
        f = root / p.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        os.chmod(f, mode)

    w("/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 10\nX11Forwarding yes\n", 0o644)
    w("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    w("/etc/shadow", "root:$6$abc:19000:0:99999:7:::\nalice::19000:0:99999:7:::\n", 0o644)
    w("/etc/sysctl.conf", "net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 0\n")
    w("/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\n\nPackage: telnetd\nStatus: install ok installed\n")
    return root
