#!/usr/bin/env python3
"""Rule 29 Commitment-Point-vs-Validation-Gap preflight (Check #92).

# Rule 29: this tool emits no corpus record.

GENERAL RULE - applies to any HIGH+ draft referencing cooperative /
multi-party-exit / commitment-point protocol patterns (Spark cooperative-exit,
Lightning HTLC, Curve gauge-vote, ERC-4626 multi-party redemption, etc.).

When a draft is at HIGH+ severity AND contains multi-party-exit or
commitment-point trigger phrases, it MUST include a
"Commitment & Protection Analysis" section before promotion to
paste_ready/ or filed/.

The section must enumerate THREE things:

  (a) Commitment point: cite file:line where funds become irrecoverable for
      the victim. Distinguish reversible state transitions (user can cancel)
      from irreversible commits (out-of-protocol path required to recover).

  (b) Validation gap class: state whether the gap is POST-commit (creates a
      NEW attack surface that only fires AFTER irreversible commit, typically
      Critical/High) or PRE-commit (exposes an existing risk that the user is
      already entering knowingly, typically Medium-or-drop).

  (c) Protection cardinality: enumerate ALL independent guards between the bug
      and the impact. If N>1 fully-covering guards exist, walk back severity
      or drop. If the gap is the SOLE protection, the severity claim is
      stronger.

Fail-closed for HIGH+ drafts that contain multi-party-exit trigger phrases but:
  - have no "Commitment & Protection Analysis" section -> fail-no-analysis-section
  - name no commitment-point file:line citation -> fail-no-commitment-point-citation
  - state no gap class (POST-commit vs PRE-commit) -> fail-no-gap-class
  - enumerate no protection cardinality -> fail-no-protection-cardinality

Verdict vocabulary:
  pass-out-of-scope              - severity below HIGH or missing
  pass-not-multi-party           - no multi-party / commitment-point trigger phrases
  pass-commitment-analysis-complete - all three fields present
  ok-rebuttal                    - valid r29-rebuttal marker present
  fail-no-analysis-section       - trigger present but no analysis section at all
  fail-no-commitment-point-citation - section present but no file:line commitment point
  fail-no-gap-class              - section present but no POST-commit / PRE-commit declaration
  fail-no-protection-cardinality - section present but no protection cardinality field
  error                          - input error

Exit codes:
  0 - pass, out-of-scope, pass-not-multi-party, or accepted rebuttal
  1 - Rule 29 violation (with --strict always 1; without --strict emits fail verdict but rc=0)
  2 - input error

Schema: auditooor.r29_commitment_vs_validation.v1

Empirical anchor: Spark LEAD 1 closed as spam because the paste-ready did not
tabulate (a)-(c) in a single section, leaving room for the triager to misread
the actor model as user-error rather than sender-attacks-receiver.
watch_chain.go:842-862 txid-equality match is the SOLE protection between
attacker's unrelated-txid and the irreversible tweakKeysForCoopExit commit at
watch_chain.go:1309.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r29_commitment_vs_validation.v1"
GATE = "R29-COMMITMENT-VS-VALIDATION-GAP"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200

# ---------------------------------------------------------------------------
# Multi-party / commitment-point trigger patterns
# (env-extendable via AUDITOOOR_R29_TRIGGER_PATTERNS)
# ---------------------------------------------------------------------------
DEFAULT_TRIGGER_PATTERNS: list[str] = [
    r"cooperative[- ]?exit",
    r"coop[- ]?exit",
    r"multi[- ]?party[- ]?exit",
    r"\b2[- ]of[- ]2\b",
    r"\bM[- ]of[- ]N\b",
    r"escrow[- ]?release",
    r"commitment[- ]?point",
    r"irreversible[- ]?commit",
    r"state[- ]transition[- ]past[- ]cancel",
    r"claim[- ]?window",
    r"withdrawal[- ]?window",
    r"redeem[- ]?path",
    r"htlc\b",
    r"lightning[- ]channel",
    r"force[- ]?close",
    r"cooperative[- ]?close",
    r"time[- ]?lock(?:ed)?",
    r"swap[- ]out",
    r"atomic[- ]swap",
    r"state[- ]channel",
    r"exit[- ]window",
    r"cancel[- ]window",
]


def _build_trigger_re() -> re.Pattern[str]:
    extras_raw = os.environ.get("AUDITOOOR_R29_TRIGGER_PATTERNS", "")
    extra_pats = [p.strip() for p in extras_raw.splitlines() if p.strip()]
    all_pats = DEFAULT_TRIGGER_PATTERNS + extra_pats
    combined = "|".join(f"(?:{p})" for p in all_pats)
    return re.compile(combined, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Analysis section header
# ---------------------------------------------------------------------------
ANALYSIS_SECTION_RE = re.compile(
    r"(?im)^#{0,6}\s*commitment\s+(?:&|and)\s+protection\s+analysis\s*:?\s*$"
    r"|^[-*]?\s*commitment\s+(?:&|and)\s+protection\s+analysis\s*:"
    r"|commitment\s+(?:&|and)\s+protection\s+analysis\s*\n",
)

# ---------------------------------------------------------------------------
# Field (a): commitment point - file:line or equivalent citation
# ---------------------------------------------------------------------------
COMMITMENT_POINT_RE = re.compile(
    r"(?im)"
    # Explicit field label
    r"(?:commitment[- ]?point|irreversible[- ]?commit(?:ment)?)\s*:"
    r"|"
    # file:line pattern anywhere in analysis context
    r"[a-zA-Z0-9_/\-]+\.[a-z]{1,6}:\d+"
    r"|"
    # Named function/struct anchor with "commit" semantics
    r"(?:tweakKeys|MarkReceiversClaimPending|SetStatus|lockFunds|"
    r"finalizeExit|processExit|claimExpired|executeWithdraw|"
    r"settleTrade|finalizeTransfer|commit\b)[^\n]*"
    r"(?:\bat\b|\(|:)\s*\n?"
    r".*?(?:\w+\.(?:go|rs|sol|ts|py|move):\d+)",
    re.IGNORECASE | re.DOTALL,
)

# Simpler single-line commitment point field marker
COMMITMENT_POINT_LABEL_RE = re.compile(
    r"(?im)"
    r"^\s*[-*]?\s*\(a\)|"
    r"^\s*[-*]?\s*commitment[- ]?point\s*:"
    r"|^\s*[-*]?\s*irreversible[- ]?commit\s*:",
)

FILE_LINE_RE = re.compile(r"[a-zA-Z0-9_/\-.]+\.[a-z]{1,6}:\d+")

# ---------------------------------------------------------------------------
# Field (b): validation gap class (POST-commit vs PRE-commit)
# ---------------------------------------------------------------------------
GAP_CLASS_RE = re.compile(
    r"(?im)"
    r"(?:post[- ]?commit|pre[- ]?commit)[^.]*"
    r"(?:attack[- ]surface|gap|fires?|exposure|validation|surface|class)"
    r"|"
    r"(?:gap|validation[- ]gap)[^.]*"
    r"(?:post[- ]?commit|pre[- ]?commit)"
    r"|"
    r"(?:fires?|occurs?|fires?[- ]only)[^.]*after[^.]*irreversible"
    r"|"
    r"(?:new[- ]attack[- ]surface|attack[- ]surface[- ]created)[^.]*after"
    r"|"
    r"^\s*[-*]?\s*\(b\)"
    r"|^\s*[-*]?\s*validation[- ]?gap[- ]?class\s*:"
    r"|POST[- ]commit\b|PRE[- ]commit\b",
)

# ---------------------------------------------------------------------------
# Field (c): protection cardinality
# ---------------------------------------------------------------------------
PROTECTION_CARDINALITY_RE = re.compile(
    r"(?im)"
    r"(?:sole|only|single|one)[^.]*(?:guard|protection|check|defense|barrier)"
    r"|"
    r"(?:guard|protection|check|defense|barrier)[^.]*(?:sole|only|single|one)"
    r"|"
    r"N\s*(?:=|>|>=)\s*[0-9]"
    r"|"
    r"(?:[0-9]+|no|zero)\s+(?:independent\s+)?(?:guard|protection|check)s?"
    r"|"
    r"protection\s+cardinality"
    r"|"
    r"fully[- ]covering[- ]guard"
    r"|"
    r"independent[- ]guard"
    r"|"
    r"^\s*[-*]?\s*\(c\)"
    r"|^\s*[-*]?\s*protection[- ]?cardinality\s*:",
)

# ---------------------------------------------------------------------------
# Override / rebuttal
# ---------------------------------------------------------------------------
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r29-rebuttal\s*:\s*(.{1,300}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_INLINE_RE = re.compile(
    r"(?im)^r29-rebuttal\s*:\s*(.{1,300}?)$",
)


def _parse_rebuttal(text: str) -> str | None:
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_INLINE_RE.search(text)
    if not m:
        return None
    reason = m.group(1).strip()
    if not reason or len(reason) > REBUTTAL_MAX_CHARS:
        return None
    return reason


# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------
SEVERITY_LINE_RE = re.compile(
    r"(?im)"
    r"^\s*[*-]?\s*[*_]*\s*severity\s*[*_]*\s*:\s*([a-z]+)"
    r"|^\s*##\s*Severity\s*\n\s*([a-z]+)"
    r"|\*\*severity\*\*\s*:\s*([a-z]+)",
)


def _detect_severity(text: str, cli_severity: str) -> str:
    if cli_severity != "auto":
        return cli_severity.lower()
    m = SEVERITY_LINE_RE.search(text)
    if m:
        val = (m.group(1) or m.group(2) or m.group(3) or "").lower().strip()
        if val in SEVERITY_RANK:
            return val
    return "unknown"


def _is_in_scope(severity: str) -> bool:
    """Only HIGH and CRITICAL are in-scope for R29."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]


# ---------------------------------------------------------------------------
# Section extraction helper
# ---------------------------------------------------------------------------
def _extract_analysis_section(text: str) -> str | None:
    """Return text from the analysis section header to the next ## header."""
    m = ANALYSIS_SECTION_RE.search(text)
    if not m:
        return None
    start = m.end()
    # find next major heading
    next_heading = re.search(r"(?m)^#{1,4}\s+\w", text[start:])
    if next_heading:
        return text[start : start + next_heading.start()]
    return text[start:]


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------
def check(draft_path: Path, severity_cli: str, strict: bool) -> dict[str, Any]:
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"verdict": "error", "reason": str(exc), "gate": GATE, "schema": SCHEMA_VERSION}

    severity = _detect_severity(text, severity_cli)

    # --- Rebuttal check (before everything else) ---
    rebuttal = _parse_rebuttal(text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"r29-rebuttal accepted: {rebuttal}",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
            "severity": severity,
        }

    # --- Scope check: only HIGH+ ---
    if not _is_in_scope(severity):
        return {
            "verdict": "pass-out-of-scope",
            "reason": f"Severity '{severity}' is below HIGH; R29 does not apply.",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
            "severity": severity,
        }

    # --- Trigger check ---
    trigger_re = _build_trigger_re()
    if not trigger_re.search(text):
        return {
            "verdict": "pass-not-multi-party",
            "reason": "No multi-party exit / commitment-point trigger phrases found.",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
            "severity": severity,
        }

    # --- Analysis section check ---
    section = _extract_analysis_section(text)
    if section is None:
        verdict = "fail-no-analysis-section"
        reason = (
            "Trigger phrases present but no 'Commitment & Protection Analysis' section found. "
            "Add the section with (a) commitment point, (b) gap class, (c) protection cardinality."
        )
        return _result(verdict, reason, severity, strict)

    # --- Field (a): commitment point ---
    has_commitment_point = bool(
        COMMITMENT_POINT_LABEL_RE.search(section) or FILE_LINE_RE.search(section)
    )
    if not has_commitment_point:
        verdict = "fail-no-commitment-point-citation"
        reason = (
            "'Commitment & Protection Analysis' section found but no file:line commitment-point "
            "citation. Add (a) Commitment point: <file:line where funds become irrecoverable>."
        )
        return _result(verdict, reason, severity, strict)

    # --- Field (b): gap class ---
    has_gap_class = bool(GAP_CLASS_RE.search(section))
    if not has_gap_class:
        verdict = "fail-no-gap-class"
        reason = (
            "No POST-commit / PRE-commit gap class declaration found in the analysis section. "
            "Add (b) Validation gap class: POST-commit (new attack surface) or PRE-commit "
            "(existing risk user is entering knowingly)."
        )
        return _result(verdict, reason, severity, strict)

    # --- Field (c): protection cardinality ---
    has_cardinality = bool(PROTECTION_CARDINALITY_RE.search(section))
    if not has_cardinality:
        verdict = "fail-no-protection-cardinality"
        reason = (
            "No protection cardinality statement found in the analysis section. "
            "Add (c) Protection cardinality: enumerate all independent guards; "
            "if sole protection state so explicitly."
        )
        return _result(verdict, reason, severity, strict)

    return {
        "verdict": "pass-commitment-analysis-complete",
        "reason": "Commitment & Protection Analysis section present with all three fields (a/b/c).",
        "gate": GATE,
        "schema": SCHEMA_VERSION,
        "severity": severity,
        "commitment_point_found": True,
        "gap_class_found": True,
        "protection_cardinality_found": True,
    }


def _result(verdict: str, reason: str, severity: str, strict: bool) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "reason": reason,
        "gate": GATE,
        "schema": SCHEMA_VERSION,
        "severity": severity,
        "strict": strict,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rule 29 Commitment-Point-vs-Validation-Gap preflight check",
    )
    parser.add_argument("draft", type=Path, help="Path to draft .md file")
    parser.add_argument(
        "--severity",
        choices=["auto", "low", "medium", "high", "critical"],
        default="auto",
        help="Override severity detection (default: auto)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on any fail verdict (default: emits fail verdict but exits 0)",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Emit result as JSON",
    )
    args = parser.parse_args()

    if not args.draft.exists():
        err = {"verdict": "error", "reason": f"File not found: {args.draft}", "gate": GATE, "schema": SCHEMA_VERSION}
        if args.json_out:
            print(json.dumps(err))
        else:
            print(f"ERROR: {err['reason']}", file=sys.stderr)
        return 2

    result = check(args.draft, args.severity, args.strict)

    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        verdict = result["verdict"]
        reason = result.get("reason", "")
        print(f"[{GATE}] {verdict}: {reason}")

    verdict = result["verdict"]
    if verdict == "error":
        return 2
    if verdict.startswith("fail"):
        return 1 if args.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
