#!/usr/bin/env python3
"""anomaly-escalation-guard.py - block a NOT-a-bug / down-tier verdict that rests on
an UNEXPLAINED anomaly the analysis itself admitted it could not resolve.

Operator-caught 2026-07-01 (strata MIN_SHARES): a verify worker dispositioned a
permanent-freeze finding NOT-FILEABLE (bounded-dust, LOW) while its own PoC log said
the reverting check trips ~10x above the threshold - which it called "logically
impossible unless totalSupply() returns something else" and then closed with "I've
spent enough cycles on the exact constant." That is an R80 evidence-honesty
violation: severity/fileability was decided ON TOP OF an unexplained mechanism. An
unexplained anomaly can hide a bigger bug (proportional freeze vs fixed dust); the
honest move is escalate-for-root-cause, NOT close.

THE GATE (anti-false-NEGATIVE for the FINDING direction): if a finding/disposition
carries BOTH (a) a self-admitted "I could not explain this" signal about the
mechanism/magnitude AND (b) a CLOSING verdict (not-fileable / refuted / down-tier /
"not a bug"), it FLAGS `escalate-for-root-cause` - the close is blocked until the
anomaly is resolved (or an explicit rebuttal states where it was resolved). A close
with NO admitted anomaly passes; an admission with NO close (an open finding that
honestly flags a loose end) passes.

Override: `anomaly-escalation-rebuttal: <where the anomaly was actually root-caused>`
(visible line or HTML comment, <=200 chars; per-gate operator approval).

Schema: auditooor.anomaly_escalation_guard.v1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_ID = "auditooor.anomaly_escalation_guard.v1"

# Self-admitted "I could not explain / this contradicts my model" signals. Matched
# case-insensitively. These are the tells that the author does NOT understand the
# mechanism their verdict rests on.
_ANOMALY_MARKERS = [
    r"logically impossible",
    r"(?:makes|make) no sense",
    r"does ?n[o']t make sense",
    r"(?:can ?not|can'?t|could ?n[o']?t|couldn'?t|unable to)\s+(?:explain|reconcile|root[- ]?cause|figure out|understand)",
    r"(?:i am|i'?m)\s+suspicious",
    r"(?:un|not )explained",
    r"unexplained anomaly",
    r"contradicts?\b.{0,40}\b(?:model|claim|expect|math)",
    r"spent enough cycles",
    r"(?:exact|precise) (?:constant|magnitude|value|number)\s+(?:does ?n[o']t|doesn'?t)\s+(?:matter|change)",
    r"(?:secondary|does ?n[o']t matter)\b.{0,40}\bmagnitude",
    r"surprising",
    r"impossible unless",
    r"\b10x\b.{0,40}\b(?:discrepancy|unexplained|factor)",
    r"why (?:does|is|would).{0,60}\b(?:revert|trip|fail)",
    r"something (?:else|is) (?:burning|minting|off|wrong)",
    r"give[ns]? up",
]
_ANOMALY_RE = re.compile("|".join(f"(?:{m})" for m in _ANOMALY_MARKERS), re.IGNORECASE)

# A CLOSING / down-tier verdict on the finding.
_CLOSE_MARKERS = [
    r"not[- ]?fileable",
    r"\brefuted\b",
    r"not a (?:bug|finding|vuln)",
    r"\bcleared\b",
    r"bounded[- ]?dust",
    r"below (?:every|the).{0,30}\b(?:floor|tier|threshold)",
    r"honest tier\s*[:=]?\s*low",
    r"\bLOW\b(?:\s|$|[.,)])",
    r"disposition_type\W+(?:not-fileable|refuted|known)",
    r"accepted design (?:tradeoff|choice)",
]
_CLOSE_RE = re.compile("|".join(f"(?:{m})" for m in _CLOSE_MARKERS), re.IGNORECASE)

_REBUTTAL_RE = re.compile(
    r"anomaly-escalation-rebuttal\s*:\s*([^\n>]{1,200})", re.IGNORECASE
)


def evaluate(text: str) -> dict:
    out = {"schema_id": SCHEMA_ID, "verdict": None, "anomaly_hits": [],
           "close_hits": [], "reasons": []}
    if not text:
        out["verdict"] = "pass-empty"
        return out
    anomaly = [m.group(0).strip() for m in _ANOMALY_RE.finditer(text)]
    close = [m.group(0).strip() for m in _CLOSE_RE.finditer(text)]
    out["anomaly_hits"] = sorted(set(anomaly))[:8]
    out["close_hits"] = sorted(set(close))[:8]
    rebut = _REBUTTAL_RE.search(text)

    if anomaly and close:
        if rebut:
            out["verdict"] = "pass-rebuttal"
            out["reasons"].append(f"anomaly-escalation-rebuttal: {rebut.group(1).strip()}")
            return out
        out["verdict"] = "flag-escalate-for-root-cause"
        out["reasons"].append(
            "the verdict CLOSES the finding (" + ", ".join(out["close_hits"][:3]) +
            ") while ADMITTING an unexplained anomaly (" + ", ".join(out["anomaly_hits"][:3]) +
            ") - R80: a not-a-bug / down-tier disposition must NOT rest on a mechanism the "
            "analysis could not explain. Root-cause the anomaly first (it may hide a larger "
            "impact, e.g. proportional vs fixed-dust freeze), or add an "
            "`anomaly-escalation-rebuttal:` citing where it was resolved.")
        return out
    if anomaly:
        out["verdict"] = "pass-anomaly-but-open"
        out["reasons"].append("admits a loose end but does NOT close the finding - fine "
                              "(an honest open flag). Escalate/resolve when closing.")
        return out
    out["verdict"] = "pass-no-unexplained-close"
    out["reasons"].append("no self-admitted unexplained anomaly tied to a closing verdict")
    return out


def _permits(v: str) -> bool:
    return v.startswith("pass")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--finding", help="path to a finding .md / disposition / worker report")
    ap.add_argument("--text", help="inline text instead of --finding")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.finding:
        try:
            text = Path(args.finding).expanduser().read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[anomaly-escalation-guard] ERROR reading finding: {e}", file=sys.stderr)
            return 2
    else:
        text = args.text or sys.stdin.read()
    res = evaluate(text)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[anomaly-escalation-guard] verdict={res['verdict']}")
        for r in res["reasons"]:
            print(f"  - {r}")
        if res["anomaly_hits"]:
            print(f"  anomaly-signals: {res['anomaly_hits']}")
    return 0 if _permits(res["verdict"]) else 1


if __name__ == "__main__":
    sys.exit(main())
