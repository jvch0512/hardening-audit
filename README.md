# hardening-audit

A **read-only Linux hardening audit** that turns findings into an **Ansible remediation playbook**. It checks SSH, accounts, file permissions, kernel/network settings and installed packages, scores the host by severity and tells you exactly what to change.

It never modifies the system it audits. Fixes are emitted as a playbook you can review, run with `--check --diff` and commit.

## Why it is built this way

* **Rooted host abstraction**: every check reads files through a `Host(root)` object. On a live server `root` is `/`; in tests it is a temp directory built to look like a secure or insecure server. That makes 100% of the logic testable without root, containers or mocks.
* **Faithful parsing**: sshd uses the *first* occurrence of a keyword and ignores `Match` blocks for global settings, `sshd_config.d` drop-ins take precedence, and sysctl uses the *last* value. These details are where naive audit scripts give wrong answers, and each is covered by a test.
* **Honest results**: if a file does not exist (for example the host is not Debian-based) the check is `SKIP`, not a false `FAIL`, and skipped checks do not count toward the score.
* **Severity-weighted score** (high 3, medium 2, low 1) with a `--min-score` gate for CI.

## Checks (16)

| Area | Examples |
|---|---|
| SSH | root login, password auth, empty passwords, MaxAuthTries, X11 forwarding, LoginGraceTime |
| Accounts | extra UID 0 accounts, empty password hashes |
| Files | permissions of `/etc/passwd`, `/etc/shadow`, `sshd_config` |
| Kernel/network | IP forwarding, SYN cookies, ICMP redirects, ASLR |
| Packages | telnet/rsh/tftp/xinetd absent, audit or logging daemon present |

## Quick start

```bash
pip install -e .

hardening-audit --demo                         # audit a built-in insecure fake host, safe anywhere
hardening-audit --demo --playbook fix.yml      # also generate the Ansible playbook
sudo hardening-audit --format html > audit.html   # audit the live machine (root needed for /etc/shadow)
hardening-audit --root /mnt/disk-image --min-score 80   # audit a mounted image, fail CI below 80
```

Demo output:

```
[FAIL] SSH-01  high   Root login over SSH is disabled  (PermitRootLogin = yes)
[FAIL] ACC-01  high   Only root has UID 0  (extra UID 0 accounts: toor)
[FAIL] FS-02   high   /etc/shadow is not readable by others  (/etc/shadow mode 0644, allowed 0640 or stricter)
...
Score: 12.5%  |  pass 2  fail 15  skipped 0
```

The generated playbook uses `lineinfile` with `validate: sshd -t` (so a bad edit cannot lock you out), `ansible.posix.sysctl`, `file` and `apt`. Checks that need human judgment (extra UID 0 accounts, empty passwords) are listed as manual follow-ups in the playbook header instead of being "fixed" blindly.

## Limitations

* Sysctl checks read the **configured** values in `/etc/sysctl.conf` and `/etc/sysctl.d`, not the live kernel state
* Package checks currently understand Debian/Ubuntu (`dpkg`); other distributions are skipped
* The SSH service name in the handler is `ssh` (Debian/Ubuntu); on RHEL-family systems change it to `sshd`
* The playbook is generated and YAML-validated in tests, but is not executed against a real host in CI. Always run it with `--check --diff` first
* These are CIS-inspired checks, not an official CIS benchmark implementation

## Development

```bash
pip install -e .[dev] && pytest -q
```

## License

MIT
