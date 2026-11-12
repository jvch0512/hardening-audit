from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import demo, report
from .checks import FAIL, Host, run_checks, score
from .remediate import build_playbook


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hardening-audit", description="Read-only Linux hardening audit with Ansible remediation output.")
    p.add_argument("--root", default="/", help="filesystem root to audit (default: the live system)")
    p.add_argument("--demo", action="store_true", help="audit a built-in insecure fake host instead")
    p.add_argument("--format", choices=["text", "json", "html"], default="text")
    p.add_argument("--playbook", help="write an Ansible remediation playbook for failed checks to this path")
    p.add_argument("--min-score", type=float, help="exit with code 2 when the score is below this value")
    args = p.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        root = demo.build_insecure_host(Path(tmp)) if args.demo else Path(args.root)
        results = run_checks(Host(root))

    out = {"text": report.to_text, "json": report.to_json, "html": report.to_html}[args.format](results)
    sys.stdout.write(out)

    if args.playbook:
        text, manual = build_playbook(results)
        Path(args.playbook).write_text(text, encoding="utf-8")
        print(f"\nPlaybook written to {args.playbook} ({sum(1 for r in results if r.status == FAIL) - len(manual)} automated tasks, {len(manual)} manual).", file=sys.stderr)

    if args.min_score is not None and score(results) < args.min_score:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
