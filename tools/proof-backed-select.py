#!/usr/bin/env python3
"""Select PROOF-BACKED rows from a workspace queue_proof_hard_close.json for
auto-staging into submission drafts.

A row is proof-backed iff closeout_status == "proved" AND proof_counted is True
(the only verdict tools/queue-proof-hard-close.py counts as genuine proof).
blocked / blocked_with_obligation / missing_evidence / disproved / killed rows
are excluded by construction.

Emits TSV to stdout: <row_id>\t<impact_contract_id>\t<title>, one proof-backed
row per line. On a genuinely-clean workspace (0 proof-backed) it emits nothing and
exits 0 - so the auto-stage bridge NEVER manufactures a draft. Read-only.

Schema: auditooor.proof_backed_select.v1
"""
from __future__ import annotations

import json
import sys


def _row_id(r: dict) -> str:
    for k in ("evidence_candidate_id", "row_id", "candidate_id", "lead_id", "id"):
        v = r.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def select(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        # Unreadable / absent -> treat as 0 proof-backed (no-op), never crash the
        # staging pipeline.
        print(f"[proof-backed-select] cannot read {path}: {exc}", file=sys.stderr)
        return 0
    rows = doc.get("rows") if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    if not isinstance(rows, list):
        rows = []
    n = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("closeout_status") == "proved" and r.get("proof_counted") is True:
            rid = _row_id(r)
            if not rid:
                continue
            icid = str(r.get("impact_contract_id") or "").strip()
            title = str(r.get("impact_assertion") or r.get("title") or "").strip()
            title = title.replace("\t", " ").replace("\n", " ").replace("\r", " ")
            print(f"{rid}\t{icid}\t{title}")
            n += 1
    print(f"[proof-backed-select] {n} proof-backed row(s)", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: proof-backed-select.py <queue_proof_hard_close.json>", file=sys.stderr)
        return 2
    return select(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
