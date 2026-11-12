import os
from pathlib import Path

import pytest
import yaml

from hardening_audit import parsers
from hardening_audit.checks import FAIL, PASS, SKIP, Host, run_checks, score
from hardening_audit.cli import main
from hardening_audit.demo import build_insecure_host
from hardening_audit.remediate import build_playbook


def secure_host(root: Path) -> Path:
    def w(p, text, mode=0o644):
        f = root / p.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        os.chmod(f, mode)
    w("/etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\nX11Forwarding no\nLoginGraceTime 30\n", 0o600)
    w("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    w("/etc/shadow", "root:$6$x:19000:0:99999:7:::\nalice:$6$y:19000:0:99999:7:::\n", 0o640)
    w("/etc/sysctl.conf", "net.ipv4.ip_forward = 0\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_redirects = 0\nkernel.randomize_va_space = 2\n")
    w("/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\n\nPackage: auditd\nStatus: install ok installed\n")
    return root


def by_id(results):
    return {r.id: r for r in results}


def test_sshd_first_occurrence_wins_and_match_ignored():
    cfg = parsers.parse_sshd("PermitRootLogin no\nPermitRootLogin yes\nMatch User bob\n  PasswordAuthentication yes\n")
    assert cfg["permitrootlogin"] == "no" and "passwordauthentication" not in cfg


def test_sshd_equals_and_comments():
    assert parsers.parse_sshd("MaxAuthTries=3 # fast\n")["maxauthtries"] == "3"


def test_sysctl_last_wins():
    assert parsers.parse_sysctl("a = 1\n# c\na = 2\n")["a"] == "2"


def test_dpkg_status_ignores_removed():
    t = "Package: a\nStatus: install ok installed\n\nPackage: b\nStatus: deinstall ok config-files\n"
    assert parsers.parse_dpkg_status(t) == {"a"}


def test_secure_host_scores_100(tmp_path):
    res = run_checks(Host(secure_host(tmp_path)))
    assert all(r.status == PASS for r in res), [(r.id, r.evidence) for r in res if r.status != PASS]
    assert score(res) == 100.0


def test_insecure_host_fails_expected_checks(tmp_path):
    res = by_id(run_checks(Host(build_insecure_host(tmp_path))))
    for cid in ("SSH-01", "SSH-02", "SSH-04", "ACC-01", "ACC-02", "FS-02", "NET-01", "KRN-01", "PKG-01"):
        assert res[cid].status == FAIL, cid
    assert "toor" in res["ACC-01"].evidence and "alice" in res["ACC-02"].evidence and "telnetd" in res["PKG-01"].evidence


def test_empty_host_skips_instead_of_failing_falsely(tmp_path):
    res = run_checks(Host(tmp_path))
    assert any(r.status == SKIP for r in res)
    assert by_id(res)["SSH-01"].status == SKIP


def test_dropin_overrides_main_config(tmp_path):
    root = secure_host(tmp_path)
    (root / "etc/ssh/sshd_config.d").mkdir()
    (root / "etc/ssh/sshd_config.d/50-bad.conf").write_text("PermitRootLogin yes\n")
    assert by_id(run_checks(Host(root)))["SSH-01"].status == FAIL


def test_playbook_is_valid_yaml_with_expected_modules(tmp_path):
    results = run_checks(Host(build_insecure_host(tmp_path)))
    text, manual = build_playbook(results)
    play = yaml.safe_load(text)
    mods = {k for t in play[0]["tasks"] for k in t if k.startswith("ansible.")}
    assert {"ansible.builtin.lineinfile", "ansible.posix.sysctl", "ansible.builtin.file", "ansible.builtin.apt"} <= mods
    assert {m.id for m in manual} == {"ACC-01", "ACC-02"}
    assert all("validate" in t["ansible.builtin.lineinfile"] for t in play[0]["tasks"] if "ansible.builtin.lineinfile" in t)


def test_cli_demo_and_gate(tmp_path, capsys):
    pb = tmp_path / "fix.yml"
    assert main(["--demo", "--playbook", str(pb), "--min-score", "90"]) == 2
    assert "Score:" in capsys.readouterr().out and pb.exists()
    assert main(["--root", str(secure_host(tmp_path / "ok")), "--min-score", "90"]) == 0
