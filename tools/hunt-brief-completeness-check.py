#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# r36-rebuttal: lane PR9a-1 registered in .auditooor/agent_pathspec.json agents[]
"""hunt-brief-completeness-check.py - PR9a-1 hunt-brief completeness gate.

# PR9a-1: this tool emits no corpus record.

A dispatched HUNT-class worker brief (hunt / drill / comp / fuzz /
opposed-trace-harness / escalation) MUST carry five completeness pillars
before the worker is allowed to start. Without them the worker (a) skips
MCP recall and re-derives known dead-ends, (b) freestyles a shallow pass
instead of running the canonical full-pipeline hunt, (c) ignores the
capability-adoption requirements (brain-prime + per-function hacker
questions) that the orchestrator already paid to compute, (d) attacks
without knowing which guards it must traverse or bypass, or (e) re-runs
audit stages the pipeline already completed.

This gate is the sibling of ``hunt-brief-full-tier-coverage-check.py``
(G13.2, which enforces the SEVERITY.md tier surface). G13.2 answers "did
the brief enumerate every fileable tier"; THIS gate answers "did the brief
carry the MCP-first recall block, the canonical hunt-definition + skip-set,
the capability-adoption requirements, the defense surface, and the
full-audit results".

The five pillars (each maps to a distinct fail verdict):

  (a) MCP-FIRST RECALL block. The brief must direct the worker to call,
      at minimum, ``vault_resume_context``, ``vault_brain_prime_context``,
      and ``vault_known_dead_ends`` before any source read. Missing ->
      ``fail-no-mcp-first-block``.

  (b) Canonical HUNT-DEFINITION + SKIP-SET. The brief must state that a
      hunt is the FULL pipeline (not a shallow/partial pass) AND direct
      the worker to consult the dedup skip-set (``hunt_skip_set.json`` /
      ``vault_known_dead_ends`` / ``vault_originality_context``) FIRST.
      Missing -> ``fail-no-hunt-definition-skip-set``.

  (c) CAPABILITY-ADOPTION requirements (ADD-D). The brief must require
      the worker to consume the brain-prime context AND the per-function
      hacker-questions (``vault_brain_prime_context`` /
      ``vault_per_function_hunter_brief`` / ``vault_hacker_questions`` /
      the per-function hunting-questions section). Missing ->
      ``fail-no-capability-adoption``.

  (d) DEFENSE SURFACE section (Section 15r). The brief must include the
      "## Section 15r - Defense Surface" header (or an acceptable
      equivalent) so the worker knows the guards/modifiers that exist in
      the audit-pin tree and must enumerate them for R57. A section
      header with "(none found)" text satisfies this pillar because it
      signals that the enrichment ran but found nothing - the worker must
      not skip the enumeration just because no guards were detected.
      Missing -> ``fail-no-defense-surface-section``.

  (e) FULL-AUDIT RESULTS section (Section 15s). The brief must include
      the "## Section 15s - Full-Audit Results" header (or an acceptable
      equivalent) so the worker consults what the audit pipeline already
      found before starting a new pass. Missing ->
      ``fail-no-full-audit-results-section``.

Fires ONLY for hunt-class lane types; other lanes pass with
``pass-not-hunt-lane``.

Verdicts:
  pass-not-hunt-lane                  - lane is not hunt-class (gate does not apply)
  pass-complete                       - all five pillars present
  ok-rebuttal                         - bounded pr9a-rebuttal accepted
  fail-no-mcp-first-block             - pillar (a) missing
  fail-no-hunt-definition-skip-set    - pillar (b) missing
  fail-no-capability-adoption         - pillar (c) missing
  fail-no-defense-surface-section     - pillar (d) missing
  fail-no-full-audit-results-section  - pillar (e) missing
  error                               - input / IO error

When multiple pillars are missing the verdict reports the first missing
pillar in (a)->(b)->(c)->(d)->(e) order; the JSON ``missing_pillars``
list carries every missing pillar so the operator sees the full picture.

Exit codes:
  0 - pass-complete / ok-rebuttal / pass-not-hunt-lane
  1 - any fail-* verdict
  2 - error

Override marker: visible bounded line ``pr9a-rebuttal: <reason>``
(<=200 chars) OR HTML-comment form ``<!-- pr9a-rebuttal: <reason> -->``.
An empty or oversized reason is ignored; the original fail verdict stands.

Valid rebuttal anchors for pillars (d)/(e): workspace has no in-scope
source tree yet (greenfield engagement before first ``make audit`` run);
the brief is a stub/skeleton-only brief that will be enriched by
spawn-worker.sh before dispatch (spawn-worker.sh adds the sections).

Schema: ``auditooor.pr9a_hunt_brief_completeness.v1``.

Tests: tools/tests/test_hunt_brief_completeness_check.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.pr9a_hunt_brief_completeness.v1"

# Hunt-class lane types this gate applies to. Mirrors the G13.2 set so the
# two completeness gates fire on the same lanes.
HUNT_CLASS_LANE_TYPES = frozenset(
    {"hunt", "drill", "comp", "fuzz", "opposed-trace-harness", "escalation"}
)

# Override marker (visible bounded line OR HTML comment form).
_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?pr9a-rebuttal:\s*(?P<reason>[^\n>]+?)\s*(?:-->)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_REBUTTAL_MAX_LEN = 200

# ---------------------------------------------------------------------------
# Pillar detectors. Each pillar requires >=1 strong signal from its group.
# The MCP-recall pillars additionally require the three named callables so a
# generic "call MCP" sentence cannot satisfy pillar (a).
# ---------------------------------------------------------------------------

# Pillar (a): MCP-FIRST recall block. Required callables (all three).
_MCP_FIRST_REQUIRED_CALLABLES: Tuple[str, ...] = (
    "vault_resume_context",
    "vault_brain_prime_context",
    "vault_known_dead_ends",
)
# A header/intent signal that an MCP-first block exists at all.
_MCP_FIRST_BLOCK_PATTERNS: Tuple[str, ...] = (
    r"mcp[- _]first",
    r"mcp recall",
    r"first action",
    r"before any (?:source read|code|worker)",
    r"layer 1",
    r"recall block",
)

# Pillar (b): canonical hunt-definition + skip-set.
_HUNT_DEFINITION_PATTERNS: Tuple[str, ...] = (
    r"a hunt is the full pipeline",
    r"hunt is the full pipeline",
    r"full pipeline \(dedup",
    r"canonical hunt definition",
    r"not a hunt",
    r"shallow/partial/repeated pass",
    r"rejected by hunt-completeness",
)
_SKIP_SET_PATTERNS: Tuple[str, ...] = (
    r"hunt_skip_set\.json",
    r"skip[- ]set",
    r"dedup-first",
    r"hunt-dedup-load",
    r"known_dead_ends",
    r"vault_originality_context",
)

# Pillar (c): capability-adoption (ADD-D): brain-prime + per-function
# hacker-questions. Require >=1 brain-prime signal AND >=1 hacker-question
# signal.
_BRAIN_PRIME_PATTERNS: Tuple[str, ...] = (
    r"brain[- _]prime",
    r"vault_brain_prime_context",
)
_HACKER_QUESTION_PATTERNS: Tuple[str, ...] = (
    r"hacker[- ]question",
    r"hacker_question",
    r"vault_hacker_questions",
    r"vault_per_function_hunter_brief",
    r"per-function hunting-questions",
    r"per-function hunter brief",
)

# Pillar (d): Defense Surface section (Section 15r). The dispatch enrichment
# adds "## Section 15r - Defense Surface (traverse/bypass these)" to every
# hunt-class brief. A "(none found)" form also passes - it signals the
# enrichment ran but found no guards, which is valid (the worker must still
# enumerate them explicitly as "none"). Require >=1 signal.
_DEFENSE_SURFACE_PATTERNS: Tuple[str, ...] = (
    r"Section 15r",
    r"Defense Surface",
    r"defense surface \(traverse",
    r"traverse/bypass these",
    r"guards?/modifier",
    r"present guards",
    r"R57 protection-module dir",
)

# Pillar (e): Full-Audit Results section (Section 15s). The dispatch
# enrichment adds "## Section 15s - Full-Audit Results (what the audit
# already found)" to every hunt-class brief. Require >=1 signal.
_FULL_AUDIT_RESULTS_PATTERNS: Tuple[str, ...] = (
    r"Section 15s",
    r"Full-Audit Results",
    r"full-audit results",
    r"what the audit already found",
    r"audit pipeline already",
    r"Detector clusters \(engage_report",
    r"engage_report\.md.*already",
)


def _any_match(text: str, patterns: Tuple[str, ...]) -> List[str]:
    """Return the list of patterns (verbatim) that matched in ``text``."""
    hits: List[str] = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat)
    return hits


def _all_callables_present(text: str, callables: Tuple[str, ...]) -> List[str]:
    """Return the list of callables MISSING from ``text``."""
    lower = text.lower()
    return [c for c in callables if c.lower() not in lower]


def parse_rebuttal(text: str) -> Optional[str]:
    """Return a non-empty, in-bounds pr9a-rebuttal reason, else None."""
    for m in _REBUTTAL_RE.finditer(text or ""):
        reason = (m.group("reason") or "").strip()
        # Strip a trailing HTML-comment close that the non-greedy group can
        # leave when the visible-line form is used inside a comment.
        reason = reason.rstrip("->").strip()
        if reason and len(reason) <= _REBUTTAL_MAX_LEN:
            return reason
    return None


def evaluate_brief(
    brief_text: str,
    *,
    lane_type: Optional[str],
) -> Dict[str, Any]:
    """Evaluate a (post-enrichment) hunt brief for the five pillars.

    Returns a stable result dict carrying the schema, verdict, the list of
    missing pillars, the per-pillar match evidence, and a human-readable
    detail line. Pure string analysis - no filesystem access.
    """
    result: Dict[str, Any] = {
        "schema": SCHEMA,
        "lane_type": lane_type,
        "verdict": None,
        "missing_pillars": [],
        "pillar_evidence": {},
        "rebuttal": None,
        "detail": "",
    }

    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in HUNT_CLASS_LANE_TYPES:
        result["verdict"] = "pass-not-hunt-lane"
        result["detail"] = (
            f"lane_type={lane_type!r} is not hunt-class; gate does not apply"
        )
        return result

    text = brief_text or ""

    # --- Pillar (a): MCP-FIRST recall block. ---
    mcp_block_hits = _any_match(text, _MCP_FIRST_BLOCK_PATTERNS)
    mcp_missing_callables = _all_callables_present(
        text, _MCP_FIRST_REQUIRED_CALLABLES
    )
    pillar_a_ok = bool(mcp_block_hits) and not mcp_missing_callables
    result["pillar_evidence"]["mcp_first"] = {
        "block_signal_hits": mcp_block_hits,
        "missing_required_callables": mcp_missing_callables,
        "ok": pillar_a_ok,
    }

    # --- Pillar (b): hunt-definition + skip-set. ---
    hunt_def_hits = _any_match(text, _HUNT_DEFINITION_PATTERNS)
    skip_set_hits = _any_match(text, _SKIP_SET_PATTERNS)
    pillar_b_ok = bool(hunt_def_hits) and bool(skip_set_hits)
    result["pillar_evidence"]["hunt_definition_skip_set"] = {
        "hunt_definition_hits": hunt_def_hits,
        "skip_set_hits": skip_set_hits,
        "ok": pillar_b_ok,
    }

    # --- Pillar (c): capability-adoption (brain-prime + hacker-questions). ---
    brain_prime_hits = _any_match(text, _BRAIN_PRIME_PATTERNS)
    hacker_q_hits = _any_match(text, _HACKER_QUESTION_PATTERNS)
    pillar_c_ok = bool(brain_prime_hits) and bool(hacker_q_hits)
    result["pillar_evidence"]["capability_adoption"] = {
        "brain_prime_hits": brain_prime_hits,
        "hacker_question_hits": hacker_q_hits,
        "ok": pillar_c_ok,
    }

    # --- Pillar (d): Defense Surface section (Section 15r). ---
    defense_surface_hits = _any_match(text, _DEFENSE_SURFACE_PATTERNS)
    pillar_d_ok = bool(defense_surface_hits)
    result["pillar_evidence"]["defense_surface"] = {
        "hits": defense_surface_hits,
        "ok": pillar_d_ok,
    }

    # --- Pillar (e): Full-Audit Results section (Section 15s). ---
    full_audit_hits = _any_match(text, _FULL_AUDIT_RESULTS_PATTERNS)
    pillar_e_ok = bool(full_audit_hits)
    result["pillar_evidence"]["full_audit_results"] = {
        "hits": full_audit_hits,
        "ok": pillar_e_ok,
    }

    missing: List[str] = []
    if not pillar_a_ok:
        missing.append("mcp-first-block")
    if not pillar_b_ok:
        missing.append("hunt-definition-skip-set")
    if not pillar_c_ok:
        missing.append("capability-adoption")
    if not pillar_d_ok:
        missing.append("defense-surface-section")
    if not pillar_e_ok:
        missing.append("full-audit-results-section")
    result["missing_pillars"] = missing

    if not missing:
        result["verdict"] = "pass-complete"
        result["detail"] = "all five hunt-brief completeness pillars present"
        return result

    # A rebuttal overrides a fail verdict only.
    rebuttal = parse_rebuttal(text)
    if rebuttal is not None:
        result["verdict"] = "ok-rebuttal"
        result["rebuttal"] = rebuttal
        result["detail"] = (
            f"pr9a-rebuttal accepted ({len(missing)} pillar(s) missing): "
            + ", ".join(missing)
        )
        return result

    # First-missing-pillar -> verdict (priority a -> b -> c -> d -> e).
    if "mcp-first-block" in missing:
        result["verdict"] = "fail-no-mcp-first-block"
        if mcp_missing_callables:
            result["detail"] = (
                "MCP-first recall block missing required callable(s): "
                + ", ".join(mcp_missing_callables)
            )
        else:
            result["detail"] = (
                "no MCP-first recall block header/intent signal in brief"
            )
    elif "hunt-definition-skip-set" in missing:
        result["verdict"] = "fail-no-hunt-definition-skip-set"
        miss_parts = []
        if not hunt_def_hits:
            miss_parts.append("canonical hunt-definition")
        if not skip_set_hits:
            miss_parts.append("skip-set/dedup-first directive")
        result["detail"] = "missing: " + ", ".join(miss_parts)
    elif "capability-adoption" in missing:
        result["verdict"] = "fail-no-capability-adoption"
        miss_parts = []
        if not brain_prime_hits:
            miss_parts.append("brain-prime adoption")
        if not hacker_q_hits:
            miss_parts.append("per-function hacker-questions adoption")
        result["detail"] = "missing: " + ", ".join(miss_parts)
    elif "defense-surface-section" in missing:
        result["verdict"] = "fail-no-defense-surface-section"
        result["detail"] = (
            "Section 15r (Defense Surface) not present in brief; "
            "dispatch enrichment must inject it before worker dispatch"
        )
    else:
        result["verdict"] = "fail-no-full-audit-results-section"
        result["detail"] = (
            "Section 15s (Full-Audit Results) not present in brief; "
            "dispatch enrichment must inject it before worker dispatch"
        )

    return result


def _verdict_exit_code(verdict: Optional[str]) -> int:
    if verdict in ("pass-complete", "ok-rebuttal", "pass-not-hunt-lane"):
        return 0
    if verdict == "error":
        return 2
    return 1


def _read_brief(args: argparse.Namespace) -> str:
    if getattr(args, "brief", None) is not None:
        return args.brief
    if getattr(args, "prompt_file", None):
        path = args.prompt_file
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit(
        "[hunt-brief-completeness-check] ERROR: no brief source - pass "
        "--prompt-file, --brief, or pipe via stdin."
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunt-brief-completeness-check",
        description=(
            "PR9a-1 hunt-brief completeness gate. Fail-closed for hunt-class "
            "lanes whose (post-enrichment) brief lacks the MCP-first recall "
            "block, the canonical hunt-definition + skip-set, or the "
            "capability-adoption (brain-prime + per-function hacker "
            "questions) requirements."
        ),
    )
    p.add_argument(
        "--prompt-file",
        default=None,
        help="Path to the brief file to check (or --brief / stdin).",
    )
    p.add_argument(
        "--brief",
        default=None,
        help="Raw brief text (alternative to --prompt-file / stdin).",
    )
    p.add_argument(
        "--lane-type",
        default=None,
        help=(
            "Lane type. The gate only fires for hunt-class lanes "
            "(hunt / drill / comp / fuzz / opposed-trace-harness / "
            "escalation); all others pass with pass-not-hunt-lane."
        ),
    )
    p.add_argument(
        "--lane-id",
        default=None,
        help="Optional lane id (echoed into the JSON report for audit).",
    )
    p.add_argument(
        "--workspace",
        default=None,
        help="Optional workspace path (echoed into the JSON report).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the full JSON report to stdout.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        brief_text = _read_brief(args)
    except (OSError, SystemExit) as exc:
        report = {
            "schema": SCHEMA,
            "verdict": "error",
            "detail": str(exc),
        }
        if getattr(args, "json", False):
            print(json.dumps(report, sort_keys=True))
        else:
            sys.stderr.write(f"[hunt-brief-completeness-check] {exc}\n")
        return 2

    result = evaluate_brief(brief_text, lane_type=args.lane_type)
    if args.lane_id is not None:
        result["lane_id"] = args.lane_id
    if args.workspace is not None:
        result["workspace"] = args.workspace

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        sys.stderr.write(
            f"[hunt-brief-completeness-check] verdict={result['verdict']} "
            f"lane_type={result.get('lane_type')} "
            f"missing={result.get('missing_pillars')} "
            f"detail={result.get('detail')}\n"
        )

    return _verdict_exit_code(result.get("verdict"))


if __name__ == "__main__":
    raise SystemExit(main())
