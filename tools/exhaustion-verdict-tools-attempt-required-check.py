#!/usr/bin/env python3
# r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE registered via tools/agent-pathspec-register.py (this exact file path declared in the pathspec; top-level agent_id field updated to match this lane).
"""exhaustion-verdict-tools-attempt-required-check.py - Gap #37 gate.

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py

A lane that claims "EXHAUSTED" / "GENUINELY-EXHAUSTED" /
"NEGATIVE-CLOSED-EXHAUSTED" /
"NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE" (Gap #48) /
"HUNT-DONE" must prove it actually attempted the depth-analysis tools
listed below, OR justified-skipped each via an entry in the workspace's
depth_tools_log.jsonl.

Note (Gap #48): the WITH-OBSERVATION-FOR-EXISTING-BUNDLE variant is an
exhaustive negation for "new draft N+1" with a fold-in candidate logged
for an existing bundle. The verdict is still EXHAUSTION-class for
gate-attempt purposes: the lane is required to demonstrate it tried the
depth-tool surface before concluding the surface is exhausted.

Required tool families (each must show evidence-of-attempt OR justified-
skip in the log; rebuttals on individual rows are accepted):

  - orient-prefilter
  - hacker-mcp (callable via vault_hacker_brief_for_lane*)
  - audit-deep
  - foundry-fuzz-1m
  - halmos
  - differential-fuzz
  - symbolic-exec (mythril OR manticore)
  - rule14-deep (triager-amend-asymmetry deep integration)

Verdicts
--------
  pass-no-exhaustion-verdict          : lane file lacks exhaustion-class verdict.
  pass-all-tools-attempted            : every required family has a log row.
  ok-rebuttal                         : <!-- gap37-rebuttal: <reason> --> accepted.
  fail-exhaustion-tools-incomplete    : exhausted verdict claimed but >=1
                                        required family lacks any log row
                                        AND no rebuttal present.
  error                               : tool-side error.

CLI
---
    <lane_results.md>                 Lane results file claiming a verdict.
    --workspace <ws>                  Workspace whose log to inspect.
    [--log <path>]                    Override log path (default
                                      <ws>/.auditooor/depth_tools_log.jsonl).
    [--strict]                        Treat any "ERROR" log status as
                                      missing evidence.
    [--json]                          Emit machine-readable JSON.

Override marker (gap37-rebuttal)
--------------------------------
Visible bounded line `gap37-rebuttal: <reason>` (<=200 chars) OR
`<!-- gap37-rebuttal: <reason> -->`. Empty or oversized reason is
ignored; the original fail verdict stands.

Schema: auditooor.gap37_exhaustion_verdict_tools_attempt.v1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.gap37_exhaustion_verdict_tools_attempt.v1"
TOOL_NAME = "exhaustion-verdict-tools-attempt-required-check"
LOG_FILENAME = "depth_tools_log.jsonl"
LOG_DIR = ".auditooor"

# Verdicts.
V_PASS_NO_EXHAUSTION = "pass-no-exhaustion-verdict"
V_PASS_ALL_TOOLS = "pass-all-tools-attempted"
V_OK_REBUTTAL = "ok-rebuttal"
V_FAIL_INCOMPLETE = "fail-exhaustion-tools-incomplete"
V_ERROR = "error"

# Required tool families. Each entry maps the canonical family name to a
# tuple of accepted log-row "tool" values that satisfy the family.
REQUIRED_TOOL_FAMILIES: dict[str, tuple[str, ...]] = {
    "orient-prefilter": ("orient-prefilter", "orient_prefilter"),
    "hacker-mcp": (
        "hacker-mcp",
        "hacker_mcp",
        "vault_hacker_brief_for_lane",
        "vault_hacker_brief_for_lane_v2",
        "vault_hacker_brief_for_lane_v3",
        "hackerman",
    ),
    "audit-deep": ("audit-deep", "audit_deep", "audit-deep.sh"),
    "foundry-fuzz-1m": ("foundry-fuzz-1m", "foundry_fuzz_1m", "foundry-fuzz"),
    "halmos": ("halmos",),
    "differential-fuzz": ("differential-fuzz", "differential_fuzz"),
    "symbolic-exec": ("mythril", "manticore", "symbolic-exec", "symbolic_exec"),
    "rule14-deep": ("rule14-deep-integrate", "rule14_deep_integrate", "triager-amend-asymmetry"),
}

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION
# Exhaustion-verdict trigger phrases (case-insensitive).
#
# Gap #48 (codified 2026-05-26): the WITH-OBSERVATION-FOR-EXISTING-BUNDLE
# form is an exhaustion-class verdict (the lane closed the surface; the
# incremental observation is fold-in candidate only). The
# "negative-closed-with-observation" prefix triggers the depth-tool
# attempt requirement just like the other exhaustion-class verdicts.
# STRONG triggers: unambiguous exhaustion-class VERDICT tokens. These are
# hyphenated / verdict-form strings that do not occur in ordinary prose, so a
# plain substring match anywhere is safe.
EXHAUSTION_TRIGGERS_STRONG = [
    "genuinely-exhausted",
    "negative-closed-exhausted",
    "negative-closed-with-observation",
    "hunt-done",
    "hunt-exhausted",
    "salvage-exhausted",
    "exhaustion-confirmed",
]

# WEAK triggers: common-English words / loose phrases that are ALSO used in
# ordinary impact prose (e.g. "once the reserves are exhausted", "gas
# exhausted", "the queue is exhausted"). A bare substring match here false-fires
# the Gap #37 gate on findings that merely describe resource exhaustion rather
# than claim a HUNT-EXHAUSTED verdict (observed NUVA 2026-07-04: a Medium
# griefing finding tripped Check #109 on "once reserves are exhausted").
# These only count when they appear in a VERDICT CONTEXT - see
# _weak_trigger_in_verdict_context().
EXHAUSTION_TRIGGERS_WEAK = [
    "exhausted",
    "genuinely exhausted",
    "negative closed exhausted",
    "negative closed with observation",
    "hunt done",
    "exhaustion verdict",
]

# Backwards-compat alias (some external callers / tests import this name).
EXHAUSTION_TRIGGERS = EXHAUSTION_TRIGGERS_STRONG + EXHAUSTION_TRIGGERS_WEAK

# A weak trigger only counts as an exhaustion-class verdict when it sits in a
# verdict context: a "verdict"/"status"/"disposition"/"outcome" label within a
# small window, or an explicit VERDICT:/STATUS: line. This keeps the gate firing
# on real "VERDICT: EXHAUSTED" lane results while ignoring ordinary prose.
_VERDICT_CONTEXT_RE = re.compile(
    r"(verdict|status|disposition|outcome|conclusion)\b", re.IGNORECASE
)

REBUTTAL_PATTERNS = [
    re.compile(r"<!--\s*gap37-rebuttal\s*:\s*([^\n>]+?)\s*-->", re.IGNORECASE),
    re.compile(r"^\s*gap37-rebuttal\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
]

MAX_REBUTTAL_LEN = 200

# Statuses that count as evidence-of-attempt.
EVIDENCE_STATUSES = {"PASS", "FAIL", "SKIPPED"}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _weak_trigger_in_verdict_context(low: str, idx: int, triglen: int) -> bool:
    """A weak trigger counts only if a verdict-context word sits nearby.

    Window: 60 chars before the trigger through 20 chars after it. This catches
    "VERDICT: EXHAUSTED", "status: hunt done", "disposition = exhausted" while
    excluding ordinary prose like "once the reserves are exhausted".
    """
    start = max(0, idx - 60)
    end = min(len(low), idx + triglen + 20)
    return _VERDICT_CONTEXT_RE.search(low[start:end]) is not None


def _detect_exhaustion_verdict(text: str) -> tuple[bool, str]:
    low = text.lower()
    # Strong (unambiguous verdict-form) triggers: match anywhere.
    for trig in EXHAUSTION_TRIGGERS_STRONG:
        idx = low.find(trig)
        if idx >= 0:
            start = max(0, idx - 40)
            end = min(len(text), idx + len(trig) + 40)
            return True, text[start:end].strip()
    # Weak (common-English) triggers: only in a verdict context.
    for trig in EXHAUSTION_TRIGGERS_WEAK:
        search_from = 0
        while True:
            idx = low.find(trig, search_from)
            if idx < 0:
                break
            if _weak_trigger_in_verdict_context(low, idx, len(trig)):
                start = max(0, idx - 40)
                end = min(len(text), idx + len(trig) + 40)
                return True, text[start:end].strip()
            search_from = idx + len(trig)
    return False, ""


def _detect_rebuttal(text: str) -> str:
    for rx in REBUTTAL_PATTERNS:
        for m in rx.finditer(text):
            reason = m.group(1).strip()
            if 0 < len(reason) <= MAX_REBUTTAL_LEN:
                return reason
    return ""


def _load_log(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


# r36-rebuttal: bugfix-inventory-claude-20260610
def _family_satisfied(
    family: str, accepted_tools: tuple[str, ...], rows: list[dict[str, Any]], strict: bool
) -> tuple[bool, dict[str, Any]]:
    """Return (satisfied, evidence_summary)."""
    matched = [r for r in rows if r.get("tool", "") in accepted_tools]
    if strict:
        matched = [r for r in matched if r.get("status") in EVIDENCE_STATUSES and r.get("status") != "ERROR"]
    else:
        matched = [r for r in matched if r.get("status") in EVIDENCE_STATUSES]
    # A SKIPPED row whose skip_reason starts with "target-not-applicable:" means the
    # tool was invoked with a directory/wrong-target rather than a real applicable
    # source file. This does NOT constitute evidence-of-attempt: the operator must
    # supply an explicit file-level target for the tool to be genuinely attempted.
    matched = [
        r for r in matched
        if not r.get("skip_reason", "").startswith("target-not-applicable:")
    ]
    summary = {
        "family": family,
        "accepted_tools": list(accepted_tools),
        "matched_count": len(matched),
        "latest_status": matched[-1].get("status") if matched else "",
        "latest_skip_reason": matched[-1].get("skip_reason", "") if matched else "",
        "latest_timestamp": matched[-1].get("timestamp_utc", "") if matched else "",
    }
    return (len(matched) > 0), summary


def evaluate(lane_path: Path, workspace: Path, log_path: Path, strict: bool) -> dict[str, Any]:
    if not lane_path.exists():
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_ERROR,
            "reason": f"lane results file not found: {lane_path}",
            "evidence": {},
        }
    text = _read_text(lane_path)
    has_exhaustion, excerpt = _detect_exhaustion_verdict(text)
    if not has_exhaustion:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_PASS_NO_EXHAUSTION,
            "reason": "lane results do not claim an exhaustion-class verdict",
            "evidence": {"trigger_excerpt": ""},
        }
    rebuttal = _detect_rebuttal(text)
    rows = _load_log(log_path)
    family_results: list[dict[str, Any]] = []
    missing_families: list[str] = []
    for family, accepted_tools in REQUIRED_TOOL_FAMILIES.items():
        satisfied, summary = _family_satisfied(family, accepted_tools, rows, strict)
        family_results.append({**summary, "satisfied": satisfied})
        if not satisfied:
            missing_families.append(family)

    evidence = {
        "trigger_excerpt": excerpt,
        "log_path": str(log_path),
        "log_row_count": len(rows),
        "family_results": family_results,
        "missing_families": missing_families,
        "rebuttal_reason": rebuttal,
    }

    if not missing_families:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_PASS_ALL_TOOLS,
            "reason": "every required depth-tool family has evidence-of-attempt in the log",
            "evidence": evidence,
        }
    if rebuttal:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_OK_REBUTTAL,
            "reason": f"gap37-rebuttal accepted: {rebuttal}",
            "evidence": evidence,
        }
    return {
        "schema": SCHEMA_VERSION,
        "verdict": V_FAIL_INCOMPLETE,
        "reason": (
            "exhaustion verdict claimed but the following depth-tool families lack "
            "evidence-of-attempt in "
            + str(log_path)
            + ": "
            + ", ".join(missing_families)
            + ". Run tools/depth-tools-orchestrator.py for each missing family OR "
            "add <!-- gap37-rebuttal: <reason up to 200 chars> -->."
        ),
        "evidence": evidence,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__.split("\n")[0])
    p.add_argument("lane_results", help="Path to the lane results .md file.")
    p.add_argument("--workspace", required=True, help="Workspace root.")
    p.add_argument("--log", default="", help="Override path to depth_tools_log.jsonl.")
    p.add_argument("--strict", action="store_true",
                   help="Treat ERROR-status log rows as missing evidence.")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    lane_path = Path(args.lane_results).expanduser().resolve()
    workspace = Path(args.workspace).expanduser().resolve()
    log_path = (
        Path(args.log).expanduser().resolve()
        if args.log
        else (workspace / LOG_DIR / LOG_FILENAME)
    )
    result = evaluate(lane_path, workspace, log_path, args.strict)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result['verdict']}")
        print(f"reason : {result['reason']}")
        ev = result.get("evidence", {})
        if ev.get("missing_families"):
            print("missing-families: " + ", ".join(ev["missing_families"]))
        if ev.get("log_row_count") is not None:
            print(f"log: {ev.get('log_path','')} ({ev.get('log_row_count')} rows)")
    if result["verdict"] in {V_PASS_NO_EXHAUSTION, V_PASS_ALL_TOOLS, V_OK_REBUTTAL}:
        return 0
    if result["verdict"] == V_FAIL_INCOMPLETE:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
