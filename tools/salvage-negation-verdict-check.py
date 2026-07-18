#!/usr/bin/env python3
# r36-rebuttal: lane-gap37b-salvage-negation registered via tools/agent-pathspec-register.py (this exact file path declared in the pathspec).
"""salvage-negation-verdict-check.py - Gap #37b gate.

Companion to Gap #37 (Check #109, tools-attempt-required). Gap #37
catches missing tool-attempt evidence under EXHAUSTION-class verdicts;
Gap #37b enforces that the verdict prose ITSELF frames the negation
exhaustively when an exhaustion-class / salvage-class / drop-class
conclusion is declared.

Empirical anchor (operator pushback 2026-05-26): the orchestrator
declared findings "salvageable" / "exhausted" / "drop" three times when
the rigorous answer required explicit negation framing
(NOT-SALVAGEABLE-CONFIRMED, DROP-CONFIRMED, EXHAUSTION-CONFIRMED) backed
by an explicit list of tools/paths attempted that did NOT yield, AND a
"What would flip this" clause naming the new evidence (artifact, call
site, predicate) that would re-open the verdict.

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py declaring this file at .auditooor/agent_pathspec.json
Required negation framing (each verdict needs all three):

1. Explicit negation framing TOKEN. One of:
   - NOT-SALVAGEABLE-CONFIRMED
   - DROP-CONFIRMED
   - EXHAUSTION-CONFIRMED
   - KILLED-CONFIRMED
   - NEGATIVE-CLOSED
   - NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE
     (Gap #48, codified 2026-05-26): an incremental observation that is
     symmetric to a previously-staged bundle, has R60-unreachable
     status, and is a fold-in candidate pending operator authorization
     (per L34 v2 the lane MAY NOT auto-stage). The lane's negation is
     exhaustive for "new draft N+1"; the observation is logged for
     bundle fold-in only. Empirical anchor: HUNT-SMT-1 (2026-05-26)
     CHECK-7 `Bytes.reverse(bytes memory)` empty-input underflow at
     `src/solidity-merkle-trees/src/trie/Bytes.sol:226`, symmetric to
     staged `smt-library-latent-defects-LOW` Defect A.

2. "Negation evidence" section listing AT LEAST 3 specific paths
   attempted that did NOT yield, one line per path, in the shape
   "<tool / approach>: <one-line reason>". Examples:
   - "Halmos: timeout at depth 7"
   - "Foundry 1M fuzz: 0 counterexamples"
   - "differential vs reference impl: bit-equal"

3. "What would flip this" section naming the SPECIFIC new evidence
   (artifact, call site, predicate) that would re-open the verdict.

When the framing token is
``NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE``, the verdict
SHOULD additionally include an ``Observation`` block of the shape::

    observation:
      finding_class: <class>
      symmetric_to: <existing draft slug>
      file_line: <src:line>
      reachability: 0 in-tree callers (R60 unreachable)
      fold_in_candidate: yes / pending-operator-authorization
      L34_v2_status: NEW_DRAFT_NOT_STAGED / FOLD_IN_PENDING_OP_AUTH

The observation block is structural prose; the gate does not parse
its sub-fields beyond confirming the new framing token is present.

Verdicts
--------
  pass-out-of-scope             : file path outside the trigger surface.
  pass-no-verdict-language      : body lacks salvage / exhaustion / drop
                                  verdict phrasing.
  pass-negation-framing-complete: all three required elements present.
  ok-rebuttal                   : <!-- gap37b-rebuttal: <reason> --> or
                                  visible `gap37b-rebuttal: <reason>`.
  fail-no-negation-token        : verdict prose present, framing token
                                  absent.
  fail-no-negation-evidence-list: token present, <3 negation-evidence
                                  rows.
  fail-no-flip-clause           : token + evidence present, no
                                  "What would flip this" clause.
  error                         : tool-side error.

CLI
---
    <verdict.md>                  Verdict / report file to inspect.
    [--strict]                    Treat soft-pass as fail (currently
                                  unused; reserved for future tightening).
    [--json]                      Emit machine-readable JSON.

Override marker (gap37b-rebuttal)
---------------------------------
Visible bounded line `gap37b-rebuttal: <reason>` (<=200 chars) OR
`<!-- gap37b-rebuttal: <reason> -->`. Empty or oversized reason is
ignored; the original fail verdict stands.

Trigger surface
---------------
Any file path matching:
  - reports/v3_iter_*/lane_*/results.md
  - agent_outputs/**/results.md
  - submissions/**/_killed/**/*.md

Other paths skip with `pass-out-of-scope`.

Schema: auditooor.gap37b_salvage_negation_verdict.v1
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.gap37b_salvage_negation_verdict.v1"
TOOL_NAME = "salvage-negation-verdict-check"

# Verdicts.
V_PASS_OOS = "pass-out-of-scope"
V_PASS_NO_VERDICT = "pass-no-verdict-language"
V_PASS_COMPLETE = "pass-negation-framing-complete"
V_OK_REBUTTAL = "ok-rebuttal"
V_FAIL_NO_TOKEN = "fail-no-negation-token"
V_FAIL_NO_EVIDENCE = "fail-no-negation-evidence-list"
V_FAIL_NO_FLIP = "fail-no-flip-clause"
V_ERROR = "error"

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py
# Verdict-language trigger phrases (case-insensitive). Presence of ANY
# triggers the gate; absence routes to pass-no-verdict-language.
#
# Gap #48 (codified 2026-05-26): "negative-closed-with-observation" is
# added so a lane that uses ONLY the new framing token (without
# salvage/drop/exhausted prose) still trips the gate. Without this
# trigger the gate would route to pass-no-verdict-language and skip
# the framing requirement entirely.
VERDICT_TRIGGERS = [
    "salvageable",
    "not salvageable",
    "non-salvageable",
    "non salvageable",
    "salvage",
    "exhausted",
    "exhaustion",
    "drop",
    "dropped",
    "killed",
    "no further work",
    "no path forward",
    "closeout",
    "negative-closed-with-observation",
    "negative closed with observation",
]

# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py
# Explicit framing tokens. Case-sensitive when uppercased; we match
# upper-case canonical forms to keep the token visually distinctive.
#
# Gap #48 (codified 2026-05-26): adds
# NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE for incremental
# observations that are symmetric to an already-staged bundle, are
# R60-unreachable in production, and remain fold-in candidates pending
# operator authorization (per L34 v2). The token is matched BEFORE
# the bare "NEGATIVE-CLOSED" entry so the more-specific form wins when
# both substrings would otherwise match.
NEGATION_TOKENS = [
    "NOT-SALVAGEABLE-CONFIRMED",
    "DROP-CONFIRMED",
    "EXHAUSTION-CONFIRMED",
    "KILLED-CONFIRMED",
    "NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE",
    "NEGATIVE-CLOSED",
]

# "Negation evidence" section header patterns (case-insensitive).
NEGATION_EVIDENCE_HEADERS = [
    re.compile(r"^\s*#{1,6}\s*negation\s+evidence", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*negation\s+evidence\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*\*\*\s*negation\s+evidence\s*\*\*", re.IGNORECASE | re.MULTILINE),
]

# "What would flip this" clause patterns (case-insensitive). We accept
# common natural-language variants so authors are not forced into one
# exact phrasing.
FLIP_CLAUSE_HEADERS = [
    re.compile(r"^\s*#{1,6}\s*what\s+would\s+flip\s+this", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*what\s+would\s+flip\s+this\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*\*\*\s*what\s+would\s+flip\s+this\s*\*\*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*#{1,6}\s*what\s+would\s+re-?open\s+this", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*#{1,6}\s*flip\s+conditions?", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*flip\s+conditions?\s*:", re.IGNORECASE | re.MULTILINE),
]

REBUTTAL_PATTERNS = [
    re.compile(r"<!--\s*gap37b-rebuttal\s*:\s*([^\n>]+?)\s*-->", re.IGNORECASE),
    re.compile(r"^\s*gap37b-rebuttal\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
]

MAX_REBUTTAL_LEN = 200

MIN_NEGATION_EVIDENCE_ROWS = 3

# Trigger-surface glob patterns (matched against the absolute / posix
# path string). Any match -> in-scope. No match -> pass-out-of-scope.
TRIGGER_SURFACE_GLOBS = [
    "*/reports/v3_iter_*/lane_*/results.md",
    "*/agent_outputs/*/results.md",
    "*/agent_outputs/*/*/results.md",
    "*/agent_outputs/*/*/*/results.md",
    "*/submissions/*/_killed/*/*.md",
    "*/submissions/*/_killed/*.md",
    "*/submissions/_killed/*/*.md",
    "*/submissions/_killed/*.md",
]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _path_in_trigger_surface(path: Path) -> bool:
    p = path.as_posix()
    for glob in TRIGGER_SURFACE_GLOBS:
        if fnmatch.fnmatch(p, glob):
            return True
    # Catch deeper nesting under agent_outputs via membership test.
    if "/agent_outputs/" in p and p.endswith("/results.md"):
        return True
    if "/_killed/" in p and p.endswith(".md"):
        return True
    return False


def _detect_verdict_language(text: str) -> tuple[bool, str]:
    low = text.lower()
    for trig in VERDICT_TRIGGERS:
        idx = low.find(trig)
        if idx >= 0:
            start = max(0, idx - 40)
            end = min(len(text), idx + len(trig) + 40)
            return True, text[start:end].strip()
    return False, ""


def _detect_negation_token(text: str) -> str:
    for token in NEGATION_TOKENS:
        if token in text:
            return token
    return ""


def _find_section_block(text: str, header_patterns: list[re.Pattern[str]]) -> tuple[int, int]:
    """Return (start_idx, end_idx) of the first matching section's BODY.

    end_idx is the start of the next top-level header (#, ##) or end of
    file. start_idx is just after the header line.
    """
    earliest: tuple[int, int] | None = None
    for rx in header_patterns:
        m = rx.search(text)
        if not m:
            continue
        body_start = text.find("\n", m.end())
        if body_start < 0:
            body_start = m.end()
        else:
            body_start += 1
        if earliest is None or m.start() < earliest[0]:
            earliest = (m.start(), body_start)
    if earliest is None:
        return (-1, -1)
    body_start = earliest[1]
    # End at next markdown header at top of a line (any level), or EOF.
    next_hdr = re.search(r"^\s*#{1,6}\s+\S", text[body_start:], re.MULTILINE)
    if next_hdr:
        body_end = body_start + next_hdr.start()
    else:
        body_end = len(text)
    return (body_start, body_end)


def _count_negation_evidence_rows(text: str) -> tuple[int, list[str]]:
    start, end = _find_section_block(text, NEGATION_EVIDENCE_HEADERS)
    if start < 0:
        return 0, []
    body = text[start:end]
    rows: list[str] = []
    # Accept lines that look like a bullet or numbered entry containing
    # a colon (e.g. "- Halmos: timeout at depth 7", "* Foundry 1M fuzz:
    # 0 counterexamples", "1. differential vs reference impl: bit-equal").
    row_re = re.compile(
        r"^\s*(?:[-*+]|\d+[.)])\s+(.{2,}?:\s*\S.{1,})$",
        re.MULTILINE,
    )
    for m in row_re.finditer(body):
        line = m.group(1).strip()
        if line:
            rows.append(line)
    return len(rows), rows


def _has_flip_clause(text: str) -> bool:
    start, end = _find_section_block(text, FLIP_CLAUSE_HEADERS)
    if start < 0:
        return False
    body = text[start:end].strip()
    return len(body) > 0


def _detect_rebuttal(text: str) -> str:
    for rx in REBUTTAL_PATTERNS:
        for m in rx.finditer(text):
            reason = m.group(1).strip()
            if 0 < len(reason) <= MAX_REBUTTAL_LEN:
                return reason
    return ""


def evaluate(verdict_path: Path, strict: bool) -> dict[str, Any]:
    if not verdict_path.exists():
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_ERROR,
            "reason": f"verdict file not found: {verdict_path}",
            "evidence": {},
        }
    if not _path_in_trigger_surface(verdict_path):
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_PASS_OOS,
            "reason": (
                "path outside trigger surface (reports/v3_iter_*/lane_*/results.md, "
                "agent_outputs/**/results.md, submissions/**/_killed/**/*.md)"
            ),
            "evidence": {"path": str(verdict_path)},
        }
    text = _read_text(verdict_path)
    has_verdict, excerpt = _detect_verdict_language(text)
    if not has_verdict:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_PASS_NO_VERDICT,
            "reason": "body lacks salvage / exhaustion / drop verdict phrasing",
            "evidence": {"path": str(verdict_path)},
        }
    token = _detect_negation_token(text)
    row_count, rows = _count_negation_evidence_rows(text)
    has_flip = _has_flip_clause(text)
    rebuttal = _detect_rebuttal(text)

    evidence = {
        "path": str(verdict_path),
        "trigger_excerpt": excerpt,
        "negation_token": token,
        "negation_evidence_row_count": row_count,
        "negation_evidence_rows": rows[:10],
        "min_negation_evidence_rows": MIN_NEGATION_EVIDENCE_ROWS,
        "has_flip_clause": has_flip,
        "rebuttal_reason": rebuttal,
        "strict": strict,
    }

    if token and row_count >= MIN_NEGATION_EVIDENCE_ROWS and has_flip:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_PASS_COMPLETE,
            "reason": (
                f"negation framing complete: token={token}, "
                f"evidence_rows={row_count}, flip_clause=yes"
            ),
            "evidence": evidence,
        }

    if not token:
        if rebuttal:
            return {
                "schema": SCHEMA_VERSION,
                "verdict": V_OK_REBUTTAL,
                "reason": f"gap37b-rebuttal accepted: {rebuttal}",
                "evidence": evidence,
            }
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_FAIL_NO_TOKEN,
            "reason": (
                "verdict-language present but no explicit negation token "
                f"({', '.join(NEGATION_TOKENS)}) found. Add one of these "
                "tokens to the verdict line, OR add "
                "<!-- gap37b-rebuttal: <reason up to 200 chars> -->."
            ),
            "evidence": evidence,
        }

    if row_count < MIN_NEGATION_EVIDENCE_ROWS:
        if rebuttal:
            return {
                "schema": SCHEMA_VERSION,
                "verdict": V_OK_REBUTTAL,
                "reason": f"gap37b-rebuttal accepted: {rebuttal}",
                "evidence": evidence,
            }
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_FAIL_NO_EVIDENCE,
            "reason": (
                f"negation token={token} present but \"Negation evidence\" "
                f"section has {row_count} rows (minimum {MIN_NEGATION_EVIDENCE_ROWS}). "
                "Add bullet rows of the shape '- <tool/approach>: <one-line reason>' "
                "(e.g. 'Halmos: timeout at depth 7', 'Foundry 1M fuzz: 0 counterexamples'), "
                "OR add <!-- gap37b-rebuttal: <reason up to 200 chars> -->."
            ),
            "evidence": evidence,
        }

    # Token and evidence present, flip missing.
    if rebuttal:
        return {
            "schema": SCHEMA_VERSION,
            "verdict": V_OK_REBUTTAL,
            "reason": f"gap37b-rebuttal accepted: {rebuttal}",
            "evidence": evidence,
        }
    return {
        "schema": SCHEMA_VERSION,
        "verdict": V_FAIL_NO_FLIP,
        "reason": (
            f"negation token={token} and evidence rows={row_count} present, "
            "but no \"What would flip this\" clause found. Add a section "
            "naming the specific new evidence (artifact, callsite, predicate) "
            "that would re-open the verdict, OR add "
            "<!-- gap37b-rebuttal: <reason up to 200 chars> -->."
        ),
        "evidence": evidence,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__.split("\n")[0])
    p.add_argument("verdict", help="Path to the verdict / report .md file.")
    p.add_argument("--strict", action="store_true",
                   help="Reserved for future tightening (currently no effect).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    verdict_path = Path(args.verdict).expanduser().resolve()
    result = evaluate(verdict_path, args.strict)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result['verdict']}")
        print(f"reason : {result['reason']}")
        ev = result.get("evidence", {})
        if ev.get("negation_token"):
            print(f"token  : {ev['negation_token']}")
        if ev.get("negation_evidence_row_count") is not None:
            print(
                f"evidence-rows: {ev.get('negation_evidence_row_count')} "
                f"(min {ev.get('min_negation_evidence_rows')})"
            )
        if "has_flip_clause" in ev:
            print(f"flip-clause: {ev.get('has_flip_clause')}")
    if result["verdict"] in {V_PASS_OOS, V_PASS_NO_VERDICT, V_PASS_COMPLETE, V_OK_REBUTTAL}:
        return 0
    if result["verdict"] in {V_FAIL_NO_TOKEN, V_FAIL_NO_EVIDENCE, V_FAIL_NO_FLIP}:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
