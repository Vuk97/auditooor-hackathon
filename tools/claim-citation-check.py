#!/usr/bin/env python3
"""claim-citation-check.py - R-CODE-CITED detector.

Operator directive (2026-07-04): everything must be verified against actual
IN-SCOPE code at exact file:line + reasoning - no assumptions, "no bullshit".
The universal parent of R76 (the code_excerpt must be a verbatim substring of real
source) and R-ADVERSARIAL-CONFIG (no benign-config assumption): EVERY load-bearing
claim in a verdict / finding / refutation must be grounded in a cited file:line.

This checker flags the EGREGIOUS under-citation case: a terminal verdict whose
`reason` makes >= 2 load-bearing claims (guard / reachability / scope / impact /
config / dedup / math) but cites ZERO in-scope file:line anywhere (reason text OR
the sidecar's file_line field). A reason full of "it's validated / guarded / out
of scope / capped" with no code reference is a pure narrative assertion, not a
verified verdict. Deliberately conservative (claims>=2 AND citations==0) to stay
low-false-positive; the load-bearing enforcement is the Section 15-EVIDENCE brief
directive, this is the safety net.

Verdicts:
  pass-claims-cited              - no under-cited verdict
  warn-claims-undercited         - >=1 flagged (advisory; rc 0)
  fail-claims-undercited         - >=1 flagged AND strict (rc 1)

STRICT: AUDITOOOR_CLAIM_CITATION_STRICT in {1,true,yes} hard-fails; advisory-first
otherwise (a NEW gate; the operator may later graduate it default-on-under-L37).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.claim_citation_check.v1"
_STRICT_ENV = "AUDITOOOR_CLAIM_CITATION_STRICT"

# A verdict that asserts a terminal conclusion (positive OR negative) - both a KILL
# and a CONFIRMED make load-bearing claims that must be code-grounded.
_TERMINAL_RE = re.compile(
    r"\b(kill|killed|refute[d]?|not[-\s]?fileable|no[-\s]?finding|confirmed|"
    r"fileable|applies_to_target|ruled[-\s]?out|answered)\b", re.IGNORECASE)

# Load-bearing CLAIM markers - each such phrase is an assertion about code behaviour
# that must be backed by a file:line.
_CLAIM_RE = re.compile(
    r"("
    r"guard(?:ed|s)?\b|validat(?:ed|es|ion)|check(?:ed|s)\b|gated?\b|nonreentrant"
    r"|onlyrole|only[-\s]?owner|require[ds]?\b|assert\w*"
    r"|(?:un)?reachable|callable|attacker[-\s]?control|entry[-\s]?point"
    r"|out[-\s]?of[-\s]?scope|in[-\s]?scope|privileged|vendored|permissionless"
    r"|capped?\b|bounded|recoverable|reverts?\b|prevented|foreclos\w+|cannot\b|no\s+net"
    r"|overflow|underflow|rounding|truncat\w+|div(?:ision|ide)"
    r"|immutable|hardcoded|admin[-\s]?only|dedup|duplicate|same\s+root|same\s+mechanism"
    r")", re.IGNORECASE)

# An in-scope file:line citation: <name>.<ext>:<digits>  or  <name>.<ext>#L<digits>
_CITATION_RE = re.compile(
    r"[\w./-]+\.(?:sol|go|rs|move|cairo|vy|py|ts|js|yul|circom|nr|fe)\b\s*[:#]\s*L?\d+",
    re.IGNORECASE)

_MIN_CLAIMS = 2  # need at least this many claims before under-citation is meaningful


def _iter_sidecars(ws: Path):
    a = ws / ".auditooor"
    for sub in ("hacker_question_verdicts", "hunt_findings_sidecars"):
        d = a / sub
        if not d.is_dir():
            continue
        for fp in sorted(d.glob("*.json")):
            try:
                rec = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if isinstance(rec, dict):
                yield str(fp), rec
    lv = a / "lead_verdicts.jsonl"
    if lv.is_file():
        for line in lv.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield f"{lv}::{rec.get('lead') or rec.get('lead_id') or '?'}", rec


def scan(ws: Path) -> dict:
    flagged, scanned = [], 0
    for src, rec in _iter_sidecars(ws):
        verdict = str(rec.get("verdict") or rec.get("state")
                      or rec.get("applies_to_target") or "")
        if not _TERMINAL_RE.search(verdict):
            continue
        reason = " ".join(str(rec.get(k) or "") for k in (
            "reason", "reasoning", "rationale", "justification", "kill_reason",
            "note", "notes", "result", "refutation"))
        if isinstance(rec.get("reasons"), list):
            reason += " " + " ".join(str(x) for x in rec["reasons"])
        if not reason.strip():
            continue
        scanned += 1
        n_claims = len(_CLAIM_RE.findall(reason))
        # citations in the reason PLUS the sidecar's own file_line field(s).
        cite_blob = reason + " " + " ".join(
            str(rec.get(k) or "") for k in ("file_line", "file", "source_refs"))
        n_cites = len(_CITATION_RE.findall(cite_blob))
        if n_claims >= _MIN_CLAIMS and n_cites == 0:
            flagged.append({"source": src, "verdict": verdict[:40],
                            "claims": n_claims, "citations": n_cites})
    return {"scanned": scanned, "flagged": flagged}


def _strict() -> bool:
    return os.environ.get(_STRICT_ENV, "").strip().lower() in ("1", "true", "yes")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="R-CODE-CITED detector")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser()
    res = scan(ws)
    strict = _strict()
    n = len(res["flagged"])
    verdict = ("pass-claims-cited" if n == 0
               else "fail-claims-undercited" if strict
               else "warn-claims-undercited")
    out = {"schema": SCHEMA, "verdict": verdict, "strict": strict,
           "strict_env": _STRICT_ENV, "scanned": res["scanned"],
           "flagged_count": n, "flagged": res["flagged"][:100]}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"[R-CODE-CITED] verdict={verdict} scanned={res['scanned']} flagged={n}")
        for f in res["flagged"][:25]:
            print(f"    - {f['source']} [{f['verdict']}] "
                  f"claims={f['claims']} citations={f['citations']}")
        if n and not strict:
            print("  (advisory: a terminal verdict asserting guard/scope/impact claims "
                  "with ZERO in-scope file:line is a narrative assertion - re-ground "
                  "every claim in exact in-scope code.)")
    return 1 if verdict.startswith("fail") else 0


if __name__ == "__main__":
    sys.exit(main())
