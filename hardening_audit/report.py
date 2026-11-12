from __future__ import annotations

import json
from html import escape

from .checks import FAIL, PASS, SKIP, Result, score


def to_text(results: list[Result]) -> str:
    L = []
    for r in results:
        mark = {"PASS": "[ ok ]", "FAIL": "[FAIL]", "SKIP": "[skip]"}[r.status]
        L.append(f"{mark} {r.id:<7} {r.severity:<6} {r.title}  ({r.evidence})")
    c = {s: sum(1 for r in results if r.status == s) for s in (PASS, FAIL, SKIP)}
    L.append(f"\nScore: {score(results)}%  |  pass {c[PASS]}  fail {c[FAIL]}  skipped {c[SKIP]}")
    return "\n".join(L) + "\n"


def to_json(results: list[Result]) -> str:
    return json.dumps({"score": score(results), "results": [r.__dict__ for r in results]}, indent=2)


def to_html(results: list[Result]) -> str:
    col = {PASS: "#15803d", FAIL: "#b91c1c", SKIP: "#6b7280"}
    rows = "".join(
        f"<tr><td style='color:{col[r.status]};font-weight:600'>{r.status}</td><td>{r.id}</td><td>{r.severity}</td>"
        f"<td>{escape(r.title)}</td><td><code>{escape(r.evidence)}</code></td></tr>" for r in results)
    return (f"<!doctype html><meta charset='utf-8'><title>Hardening audit</title>"
            "<style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse;width:100%}"
            "td,th{border-bottom:1px solid #eee;padding:.4rem .6rem;text-align:left}</style>"
            f"<h1>Hardening audit: {score(results)}%</h1>"
            f"<table><tr><th>Status</th><th>ID</th><th>Severity</th><th>Check</th><th>Evidence</th></tr>{rows}</table>")
