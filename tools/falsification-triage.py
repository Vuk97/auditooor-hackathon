#!/usr/bin/env python3
"""Falsification-triage prefilter: when a coverage-guided invariant fuzz harness
FALSIFIES a property, decide CHEAPLY - before spending a verification agent -
whether it re-discovers a documented KNOWN / ACKNOWLEDGED / OOS issue.

WHY (SSV loop 2026-06-23): an over-constrained invariant (asserting unconditional
solvency the protocol never promises) falsified on the *acknowledged* delayed-
liquidation bad-debt. Confirming that cost a full 500k campaign + a 154k-token
verification agent to re-derive "this is the Quantstamp/known-issue (e)". R47
tooling existed but only fires at PASTE-READY time, and the known-issues lived only
in an operator's memory + prose in prior_audits/ - so nothing caught it at
FALSIFICATION time. This tool closes that gap on EVERY workspace:

  1. reads a structured per-workspace registry .auditooor/known_issues.json
     (schema auditooor.known_issues.v1) - the durable home for documented OOS /
     acknowledged issues (replaces tribal memory);
  2. matches a falsified invariant (by name-hint + keyword overlap) against the
     registry AND a cheap keyword scan of prior_audits/*.txt;
  3. emits a disposition so the loop routes a known-issue rediscovery to a CHEAP
     "confirm extension-distinct or dispose (R47/R45)" check instead of a full
     paste-ready verification agent.

ADVISORY, never auto-dismiss: R47 still requires an explicit extension-distinct
judgment for a HIGH match (the new manifestation could be genuinely distinct). The
value is focusing/short-circuiting the agent, not skipping the judgment for novel
work. A `candidate-novel` disposition means "spend the full verification agent".
Generic across any workspace + language.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.falsification_triage.v1"


def _norm_tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", str(s).lower()))


def load_registry(ws: Path) -> dict:
    p = ws / ".auditooor" / "known_issues.json"
    if not p.is_file():
        return {"issues": [], "_absent": True}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"issues": [], "_absent": True}


def _score_issue(issue: dict, inv: str, kw: set[str]) -> tuple[float, list[str]]:
    """Confidence in [0,1] that the falsification matches this known issue, with
    the matched evidence tokens."""
    reasons: list[str] = []
    inv_l = (inv or "").lower()
    hint_hit = False
    for hint in issue.get("invariant_hints", []):
        if hint and hint.lower() in inv_l:
            hint_hit = True
            reasons.append(f"invariant-hint '{hint}'")
    # keyword overlap between the falsification and the issue's keywords
    issue_kw = set()
    for k in issue.get("keywords", []):
        issue_kw |= _norm_tokens(k)
    overlap = kw & issue_kw
    if overlap:
        reasons.append("keywords:" + ",".join(sorted(overlap)[:6]))
    # Combine evidence: an issue matched by BOTH an invariant-hint AND keyword
    # overlap outranks one matched by a single (possibly broad) signal - so the
    # most-corroborated known issue sorts first, not whichever shares a generic word.
    if hint_hit and overlap:
        score = min(0.8 + 0.03 * len(overlap), 0.97)
    elif hint_hit:
        score = 0.8
    elif overlap:
        score = min(0.3 + 0.12 * len(overlap), 0.75)
    else:
        score = 0.0
    return score, reasons


def _prior_audit_hits(ws: Path, kw: set[str]) -> list[str]:
    """Cheap keyword co-occurrence scan of prior_audits/*.txt|*.md - a falsification
    whose keywords cluster in a prior audit doc is likely a re-manifestation."""
    pa = ws / "prior_audits"
    hits: list[str] = []
    if not pa.is_dir() or not kw:
        return hits
    strong = {k for k in kw if len(k) >= 5}  # avoid noise words
    for f in list(pa.rglob("*.txt")) + list(pa.rglob("*.md")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        present = {k for k in strong if k in text}
        if len(present) >= 3:
            hits.append(f"{f.name}: {','.join(sorted(present)[:6])}")
    return hits[:5]


def triage(ws: Path, invariant: str, keywords: set[str]) -> dict:
    reg = load_registry(ws)
    matches = []
    for issue in reg.get("issues", []):
        sc, reasons = _score_issue(issue, invariant, keywords)
        if sc > 0:
            matches.append({
                "id": issue.get("id"),
                "title": issue.get("title"),
                "status": issue.get("status"),
                "rule": issue.get("rule"),
                "cite": issue.get("source") or issue.get("cite"),
                "confidence": round(sc, 2),
                "evidence": reasons,
            })
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    prior = _prior_audit_hits(ws, keywords)
    top = matches[0]["confidence"] if matches else 0.0
    if top >= 0.7 or (matches and prior):
        disp = "known-issue-rediscovery"
        guidance = ("Route to a CHEAP extension-distinct confirm (R47/R45/R53): the "
                    "falsification matches a documented known/acknowledged issue. Do "
                    "NOT spawn a full paste-ready verification agent unless you can "
                    "state an extension-distinct argument. Likely OOS / not fileable.")
    elif matches or prior:
        disp = "possible-known-issue"
        guidance = ("Partial match to a known issue - spend a FOCUSED verification "
                    "agent primed with the cited issue, tasked to decide same-issue "
                    "vs extension-distinct (cheaper than a cold investigation).")
    else:
        disp = "candidate-novel"
        guidance = ("No known-issue match - spend the full adversarial verification "
                    "agent (real-entrypoint, realistic amounts, R40/R44).")
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "invariant": invariant,
        "disposition": disp,
        "guidance": guidance,
        "registry_present": not reg.get("_absent"),
        "matches": matches,
        "prior_audit_hits": prior,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--invariant", required=True, help="falsified invariant name")
    ap.add_argument("--keywords", default="",
                    help="comma-separated keywords from the call sequence / modules")
    ap.add_argument("--log", default=None,
                    help="optional echidna/medusa log to auto-extract action_/module keywords")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()

    kw = _norm_tokens(args.keywords.replace(",", " "))
    kw |= _norm_tokens(args.invariant)
    if args.log:
        try:
            text = Path(args.log).read_text(encoding="utf-8", errors="replace")
            for m in re.findall(r"action_([a-z_]+)", text):
                kw |= _norm_tokens(m)
        except OSError:
            pass

    rep = triage(ws, args.invariant, kw)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[falsification-triage] {rep['disposition']} (invariant={args.invariant})")
        for m in rep["matches"][:4]:
            print(f"    match {m['id']} conf={m['confidence']} [{m['status']}] {m['cite']}")
            print(f"          {', '.join(m['evidence'])}")
        for h in rep["prior_audit_hits"]:
            print(f"    prior_audit: {h}")
        print(f"  -> {rep['guidance']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
