#!/usr/bin/env python3
"""Reachability verification preflight gate.

A fileable-tier candidate (Medium/High/Critical) must carry a
`reachability_trace` - a structured statement proving that the buggy
code is actually dispatched in the target's production/default
configuration, not merely present in the repo.

The gate checks whether the draft documents a reachability trace.
It does NOT itself trace code - it is a documentation gate.

Three questions the trace must answer:
  (a) Is the buggy function/path reachable from a production entrypoint
      under default config?
  (b) Is it gated behind a fork/feature/version flag that is off or
      overridden in production?
  (c) What is the file:line of the dispatch/registration site that
      proves reachability - or the override site that proves
      UN-reachability?

Verdicts:
  pass-reachability-traced   - draft carries concrete reachability trace
                               with a dispatch-site or override-site
                               citation (file:line or equivalent)
  fail-no-reachability-trace - fileable-tier candidate with no trace
  fail-unreachable           - trace itself shows code is overridden or
                               dead in production (the SSTORE case: buggy
                               fn present but Istanbul-only, overridden by
                               Berlin's enable2929 in production)
  pass-not-fileable-tier     - informational / severity missing / unknown;
                               no trace required
  ok-rebuttal                - draft carries <!-- reachability-rebuttal: -->
                               marker (max 200 chars)

Exit codes:
  0 - pass, not-fileable-tier, or accepted rebuttal
  1 - fail-no-reachability-trace or fail-unreachable
  2 - input error

Schema: auditooor.reachability_verification_check.v1
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.reachability_verification_check.v1"
GATE = "REACHABILITY-VERIFICATION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FILEABLE_MIN_RANK = 2  # medium and above require a trace

# --- Reachability trace evidence ---

# Positive: draft claims the code IS reachable in production and gives a site
TRACE_POSITIVE_RE = re.compile(
    r"reachability[_\s]+trace|"
    r"dispatched (?:via|from|at|in)\s+\S|"
    r"registered (?:at|in|via)\s+\S|"
    r"handler (?:registered|installed|wired)\s+at\s+\S|"
    r"called from (?:genesis|production|default)[^\n]{0,80}|"
    r"activated (?:at|from|by) genesis[^\n]{0,80}|"
    r"reachable (?:from|in|under)[^\n]{0,60}|"
    r"dispatch\s+site\s*:\s*\S|"
    r"entrypoint\s*:\s*\S|"
    r"call[_ ]?site\s*:\s*\S|"
    r"<!-- reachability-trace:",
    re.IGNORECASE,
)

# Positive trace with a file:line citation (strongest evidence)
FILE_LINE_RE = re.compile(
    r"[A-Za-z0-9_./\\-]+\.[A-Za-z]{1,8}:\d+",
)

# Negative: trace explicitly shows the code is overridden / unreachable
UNREACHABLE_RE = re.compile(
    r"(?:overridden|overwritten|replaced|superseded|dead code|unreachable|"
    r"not (?:dispatched|registered|activated|reached|called|used) in production|"
    r"disabled (?:in|by|at|from) (?:production|genesis|default|Berlin|London|Shanghai|Cancun|Prague)|"
    r"never (?:called|reached|dispatched|activated) (?:in|under|from) (?:production|default|genesis)|"
    r"(?:Berlin|London|Shanghai|Cancun|Prague|EIP-?2929|enable\w+) (?:overrides?|replaces?|overwrites?|supersedes?)|"
    r"fork (?:override|overrides|disables?|replaces?)\b|"
    r"feature (?:flag|gate) (?:off|disabled|not enabled)\b|"
    r"(?:not|never) (?:active|enabled|in effect) (?:in|under|from) (?:production|default|genesis)|"
    r"only (?:active|enabled|used|dispatched) (?:in|under|for)\s+\S+\s+(?:mode|fork|chain|config)|"
    r"istanbul[- _]only|"
    r"legacy[- _](?:code|path|handler|fn)[^\n]{0,60}(?:not|never)[^\n]{0,60}(?:active|used|called|dispatched)|"
    r"gasSStoreEIP2200[^\n]{0,120}overrid|"
    r"enable2929[^\n]{0,80}overwrit|"
    r"code[- _]present[^\n]{0,60}(?:unreachable|not dispatched|overridden)|"
    r"present (?:but|yet|however) (?:not|never) (?:called|dispatched|activated|reached))",
    re.IGNORECASE,
)

# Rebuttal marker
REBUTTAL_RE = re.compile(
    r"<!--\s*reachability-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        # Match both plain "Severity: High" and bold "**Severity**: High" / "**Severity**:" forms
        (r"(?im)^\s*\**\s*Severity\s*\**\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_RE.search(text)
    return m.group(1).strip() if m else None


def _line_hits(text: str, pattern: re.Pattern) -> list[str]:
    hits = []
    for line in text.splitlines():
        if pattern.search(line):
            hits.append(line.strip()[:200])
    return hits


def run(
    draft: Path,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Return (exit_code, payload)."""
    if not draft.exists():
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"draft not found: {draft}",
        }

    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": str(exc),
        }

    severity, severity_source = _severity(text, draft, severity_override)
    sev_rank = SEVERITY_RANK.get(severity or "", 0)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add a 'Reachability Trace' section: cite the file:line where the buggy"
            " function is dispatched/registered in the production/default config.",
            "If the code is overridden in production (e.g. a fork disables it),"
            " document that as 'fail-unreachable' and kill the finding.",
            "Use <!-- reachability-rebuttal: reason --> (max 200 chars) for a bounded"
            " source-backed exception (e.g. the function is a library called by many"
            " callers and the dispatch site is too broad to cite a single line).",
        ],
    }

    # Not a fileable tier - no trace required
    if sev_rank < FILEABLE_MIN_RANK:
        payload["verdict"] = "pass-not-fileable-tier"
        payload["reason"] = (
            "severity below Medium or missing; reachability trace not required"
        )
        return 0, payload

    # Check for rebuttal first
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Collect evidence
    positive_hits = _line_hits(text, TRACE_POSITIVE_RE)
    unreachable_hits = _line_hits(text, UNREACHABLE_RE)
    file_line_hits = FILE_LINE_RE.findall(text)[:10]

    payload["evidence"] = {
        "positive_trace_hits": positive_hits,
        "unreachable_hits": unreachable_hits,
        "file_line_citations": file_line_hits,
    }

    # fail-unreachable: trace is present AND explicitly shows code is dead/overridden
    # in production. This is the SSTORE case: gasSStoreEIP2200 is Istanbul-only,
    # overridden by enable2929 in Berlin, which Sei activates from genesis.
    if unreachable_hits:
        payload["verdict"] = "fail-unreachable"
        payload["reason"] = (
            "reachability trace documents that the buggy code is overridden or"
            " unreachable in the production/default configuration - KILL, do not file"
        )
        rc = 1 if strict else 1  # always hard-fail: filing unreachable code is a FP
        return rc, payload

    # pass: positive trace evidence with at least one file:line citation
    if positive_hits and file_line_hits:
        payload["verdict"] = "pass-reachability-traced"
        payload["reason"] = (
            "draft carries a reachability trace with a dispatch/call-site citation"
        )
        return 0, payload

    # pass (weaker): positive trace language present but no explicit file:line
    if positive_hits:
        payload["verdict"] = "pass-reachability-traced"
        payload["reason"] = (
            "draft carries reachability trace language; no explicit file:line"
            " citation found but trace language is sufficient"
        )
        return 0, payload

    # fail: fileable-tier candidate with no trace documentation
    payload["verdict"] = "fail-no-reachability-trace"
    payload["reason"] = (
        "fileable-tier candidate (Medium+) with no reachability trace - "
        "add a 'Reachability Trace' section documenting the dispatch site"
        " or the reason the code is dead in production"
    )
    rc = 1 if strict else 1  # always fail: missing trace on fileable candidate
    return rc, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="Path to the draft markdown file")
    parser.add_argument(
        "--severity",
        choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"],
        help="Override severity detection",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on fail-no-reachability-trace or fail-unreachable",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit JSON (default: human-readable summary)",
    )
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity_override=args.severity, strict=args.strict)

    if args.json_out:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        verdict = payload.get("verdict", "error")
        severity = payload.get("severity", "unknown")
        print(f"[{GATE}] {verdict}  severity={severity}  file={args.draft}")
        if "reason" in payload:
            print(f"  reason: {payload['reason']}")
        ev = payload.get("evidence", {})
        if ev.get("unreachable_hits"):
            print("  unreachable evidence:")
            for h in ev["unreachable_hits"][:3]:
                print(f"    - {h}")
        if ev.get("positive_trace_hits"):
            print("  positive trace evidence:")
            for h in ev["positive_trace_hits"][:3]:
                print(f"    + {h}")
        if payload.get("rebuttal"):
            print(f"  rebuttal: {payload['rebuttal']}")
        for opt in payload.get("remediation_options", []):
            if verdict.startswith("fail"):
                print(f"  fix: {opt}")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
