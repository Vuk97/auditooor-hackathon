#!/usr/bin/env python3
"""audit-question-burndown.py — classify worker verdicts in spark_hunt_loop_state.

Sister of `tools/memory-gap-analyzer.py` shape: load state, classify each
`pending_commits[]` entry against the L17 3-axis verdict rubric, emit a
ranked burndown table + a re-spawn queue suggestion. No LLM calls.

Verdict-shape classification (L17 3-axis):

  * HOLDS with invariant cite        -> accepted_holds
  * HOLDS without invariant cite     -> respawn_holds_no_invariant
  * NEEDS-BUILD                      -> needs_build_queued
                                        (verifier checks queued_leads[]
                                        absorption; flags if no matching
                                        lead row exists)
  * DROP-justified / DROP-justified-(a)/(b)/(c) / GENUINE_DROP
                                     -> drop_justified
  * DROP without (a)/(b)/(c) tag     -> respawn_drop_no_justification
  * NEGATIVE / no verdict_shape      -> respawn_no_verdict
                                        (legacy entries pre-W2 schema; spawn
                                        a re-tag lane to backfill)

Heuristic FP/FN risks (declared, not silenced):

  * Legacy pending_commits[] from iter<12 use `verdict` field, not
    `verdict_shape`. We treat `verdict=NEGATIVE` + non-empty `note` as
    drop_justified IF the note contains a (a)/(b)/(c) marker, else
    respawn_no_verdict. FP risk: a NEGATIVE entry with a clean kill
    rationale embedded in `note` may match neither (a)/(b)/(c) literal
    nor "rubric" keywords -> false respawn flag. FN risk: a HOLDS row
    with no `verdict_shape` field is silently classified accepted only
    if the legacy `verdict` was set; a missing-both row is respawn_no_verdict.

  * "Invariant cite" detection is keyword-based (looks for tokens like
    "invariant", "RFC ", "spec", "L30", "L31", "rubric verbatim",
    "audit-pin", a SHA-shaped hex). FP risk: keyword match in commit_msg
    that is not actually an invariant cite. FN risk: invariant stated as
    English prose without any of the trigger tokens.

  * NEEDS-BUILD verifier: a NEEDS-BUILD entry is "absorbed" if its
    `lane` substring appears in any state.queued_leads[].id. FP risk:
    lane-naming drift (H7 vs H7-stale-dkg-state-retention). FN risk:
    queued lead may use a different stem than the worker's lane label.

CLI:
    tools/audit-question-burndown.py
    tools/audit-question-burndown.py --workspace ~/audits/spark
    tools/audit-question-burndown.py --state-file path/to/state.json
    tools/audit-question-burndown.py --json
    tools/audit-question-burndown.py --json --quiet      # suppress stderr banner

Exit codes:
    0 — analysis complete (re-spawn flags are informational, not errors)
    2 — state file not found / unreadable
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "auditooor.audit_question_burndown.v1"
DEFAULT_WORKSPACE = pathlib.Path("~/audits/spark").expanduser()
DEFAULT_STATE_REL = pathlib.Path(".auditooor") / "spark_hunt_loop_state.json"

# Tokens that, if present anywhere in the entry's text fields, count as
# an "invariant cite" (justifying a HOLDS verdict).
INVARIANT_TOKENS = (
    "invariant",
    "rfc ",
    "rfc9591",
    "rfc 9591",
    "spec",
    "rubric verbatim",
    "rubric-verbatim",
    "verbatim crit-",
    "verbatim high-",
    "audit-pin",
    "l30",
    "l31",
    "sp-",
    "in pin",
    "merge-base",
)

# (a)/(b)/(c) drop-justification markers per build-or-drop rule.
DROP_JUSTIFICATION_MARKERS = (
    "(a)",
    "(b)",
    "(c)",
    "class-a",
    "class-b",
    "class-c",
    "drop-(a)",
    "drop-(b)",
    "drop-(c)",
    "build-or-drop",
    "rubric-match",
    "no rubric verbatim",
    "no rubric-verbatim",
    "no rubric",
    "non-mainnet",
    "oos",
    "out-of-scope",
    "out of scope",
    "design-correct",
    "by-design",
    "intentional",
    "dead code",
    "no in-tree",
    "zero in-tree",
    "shallow clone",
    "shallow-clone",
)

SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b")

# Classification labels (canonical strings used in --json output).
CLS_ACCEPTED = "accepted_holds"
CLS_NEEDS_BUILD = "needs_build_queued"
CLS_DROP_OK = "drop_justified"
CLS_RESPAWN_HOLDS = "respawn_holds_no_invariant"
CLS_RESPAWN_DROP = "respawn_drop_no_justification"
CLS_RESPAWN_NO_VERDICT = "respawn_no_verdict"

ALL_CLS = (
    CLS_ACCEPTED,
    CLS_NEEDS_BUILD,
    CLS_DROP_OK,
    CLS_RESPAWN_HOLDS,
    CLS_RESPAWN_DROP,
    CLS_RESPAWN_NO_VERDICT,
)


def _entry_text_blob(entry: Dict[str, Any]) -> str:
    """Concatenate all text-shaped fields into a lowercased haystack."""
    parts: List[str] = []
    for k in (
        "verdict",
        "verdict_shape",
        "note",
        "rationale",
        "subject",
        "commit_msg_oneline",
        "build_evidence",
        "tests",
        "kind",
    ):
        v = entry.get(k)
        if isinstance(v, str):
            parts.append(v)
    arts = entry.get("artifacts") or []
    if isinstance(arts, list):
        parts.extend(str(a) for a in arts)
    return "\n".join(parts).lower()


def _has_invariant_cite(blob: str) -> bool:
    if any(tok in blob for tok in INVARIANT_TOKENS):
        return True
    # SHA-shape (commit cite) counts as a structural invariant cite when
    # paired with at least 1 audit-domain word.
    if SHA_RE.search(blob) and any(
        w in blob for w in ("commit", "pin", "fix", "fork", "anchor", "merge-base")
    ):
        return True
    return False


def _has_drop_justification(blob: str) -> bool:
    return any(m in blob for m in DROP_JUSTIFICATION_MARKERS)


def _normalize_shape(entry: Dict[str, Any]) -> str:
    """Return a canonical verdict_shape string for the entry.

    Prefers the explicit `verdict_shape` field (W2 schema). Falls back to
    legacy `verdict` field for pre-iter12 rows. Returns "" if neither
    field is set.
    """
    vs = entry.get("verdict_shape")
    if isinstance(vs, str) and vs.strip():
        return vs.strip()
    legacy = entry.get("verdict")
    if isinstance(legacy, str) and legacy.strip():
        return legacy.strip()
    return ""


def _is_holds(shape: str) -> bool:
    s = shape.upper()
    return s == "HOLDS" or s.startswith("HOLDS")


def _is_needs_build(shape: str) -> bool:
    s = shape.upper().replace("_", "-")
    return s == "NEEDS-BUILD" or s.startswith("NEEDS-BUILD")


def _is_drop(shape: str) -> bool:
    s = shape.upper().replace("_", "-")
    return s.startswith("DROP") or s == "GENUINE-DROP"


def _is_negative(shape: str) -> bool:
    return shape.upper() == "NEGATIVE"


def _lane_absorbed_in_queued_leads(lane: str, queued_leads: List[Any]) -> bool:
    """Return True if any queued_leads[].id contains the lane label."""
    if not lane:
        return False
    needle = lane.lower()
    for ql in queued_leads or []:
        if isinstance(ql, dict):
            for k in ("id", "lane", "label", "title"):
                v = ql.get(k)
                if isinstance(v, str) and needle in v.lower():
                    return True
        elif isinstance(ql, str) and needle in ql.lower():
            return True
    return False


def classify_entry(
    entry: Dict[str, Any], queued_leads: List[Any]
) -> Tuple[str, bool, str]:
    """Return (classification, re_spawn_flag, reason)."""
    shape = _normalize_shape(entry)
    blob = _entry_text_blob(entry)
    lane = str(entry.get("lane") or "")

    if not shape:
        return (
            CLS_RESPAWN_NO_VERDICT,
            True,
            "no verdict / verdict_shape field — pre-W2 schema row needs re-tag",
        )

    if _is_holds(shape):
        if _has_invariant_cite(blob):
            return (CLS_ACCEPTED, False, "HOLDS with invariant/pin/RFC cite")
        return (
            CLS_RESPAWN_HOLDS,
            True,
            "HOLDS without invariant cite — respawn with stronger brief asking "
            "for invariant/pin/RFC reference",
        )

    if _is_needs_build(shape):
        absorbed = _lane_absorbed_in_queued_leads(lane, queued_leads)
        if absorbed:
            return (
                CLS_NEEDS_BUILD,
                False,
                f"NEEDS-BUILD absorbed by queued_leads[] (lane={lane})",
            )
        return (
            CLS_NEEDS_BUILD,
            True,
            f"NEEDS-BUILD with no matching queued_leads[] entry for lane={lane} "
            "— spawn build lane",
        )

    if _is_drop(shape):
        if _has_drop_justification(blob):
            return (CLS_DROP_OK, False, "DROP with (a)/(b)/(c) justification cite")
        return (
            CLS_RESPAWN_DROP,
            True,
            "DROP without (a)/(b)/(c) justification — respawn with stronger "
            "brief demanding rubric-match-or-class-tag",
        )

    if _is_negative(shape):
        # Legacy NEGATIVE: treat as DROP. Re-spawn unless note carries a
        # rubric / (a)(b)(c) / token.
        if _has_drop_justification(blob):
            return (
                CLS_DROP_OK,
                False,
                "legacy NEGATIVE with drop-justification keywords in note",
            )
        return (
            CLS_RESPAWN_NO_VERDICT,
            True,
            "legacy NEGATIVE without justification keywords — respawn with "
            "L17 3-axis verdict shape",
        )

    # Unknown shape
    return (
        CLS_RESPAWN_NO_VERDICT,
        True,
        f"unrecognized verdict_shape={shape!r} — respawn with canonical schema",
    )


def load_state(state_path: pathlib.Path) -> Dict[str, Any]:
    if not state_path.is_file():
        raise SystemExit(
            f"[audit-question-burndown] state file not found: {state_path}"
        )
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"[audit-question-burndown] cannot parse {state_path}: {e}"
        )


def build_rows(state: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (rows, respawn_queue)."""
    pending = state.get("pending_commits") or []
    queued_leads = state.get("queued_leads") or []

    rows: List[Dict[str, Any]] = []
    respawn_queue: List[Dict[str, Any]] = []

    for entry in pending:
        if not isinstance(entry, dict):
            continue
        shape = _normalize_shape(entry)
        cls, respawn, reason = classify_entry(entry, queued_leads)
        lane = entry.get("lane") or ""
        it = entry.get("iter")
        if it is None:
            it = entry.get("iteration")
        row = {
            "lane": lane,
            "iter": it,
            "verdict_shape": shape or "(missing)",
            "classification": cls,
            "re_spawn_flag": respawn,
            "reason": reason,
        }
        rows.append(row)
        if respawn:
            respawn_queue.append(
                {
                    "lane": lane,
                    "iter": it,
                    "verdict_shape": shape or "(missing)",
                    "classification": cls,
                    "respawn_reason": reason,
                }
            )

    return rows, respawn_queue


def render_human(
    rows: List[Dict[str, Any]],
    respawn_queue: List[Dict[str, Any]],
    workspace: pathlib.Path,
    state_path: pathlib.Path,
) -> str:
    out: List[str] = []
    out.append(f"# Audit-question burndown — {workspace}")
    out.append("")
    out.append(f"State file: `{state_path}`")
    out.append(f"Total pending_commits: {len(rows)}")
    out.append("")

    counts = Counter(r["classification"] for r in rows)
    out.append("## Classification summary")
    out.append("")
    for cls in ALL_CLS:
        out.append(f"- {cls}: {counts.get(cls, 0)}")
    out.append("")

    out.append("## Burndown table")
    out.append("")
    out.append("| lane | iter | verdict_shape | classification | re_spawn | reason |")
    out.append("|------|------|---------------|----------------|----------|--------|")
    for r in rows:
        flag = "YES" if r["re_spawn_flag"] else "no"
        reason = (r["reason"] or "").replace("|", "\\|")
        if len(reason) > 80:
            reason = reason[:77] + "..."
        out.append(
            f"| `{r['lane'] or '(none)'}` | {r['iter']!s} | "
            f"`{r['verdict_shape']}` | {r['classification']} | {flag} | {reason} |"
        )
    out.append("")

    out.append("## Re-spawn queue")
    out.append("")
    if not respawn_queue:
        out.append("_(empty — all pending_commits[] have acceptable verdict shapes)_")
    else:
        for q in respawn_queue:
            out.append(
                f"- **{q['lane'] or '(none)'}** (iter {q['iter']}) "
                f"verdict_shape=`{q['verdict_shape']}` "
                f"-> {q['classification']}: {q['respawn_reason']}"
            )
    out.append("")

    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--workspace",
        type=pathlib.Path,
        default=DEFAULT_WORKSPACE,
        help=f"workspace path (default: {DEFAULT_WORKSPACE})",
    )
    parser.add_argument(
        "--state-file",
        type=pathlib.Path,
        default=None,
        help="explicit path to spark_hunt_loop_state.json (overrides --workspace)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine JSON")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress stderr banner on empty input"
    )
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser()
    state_path = (
        args.state_file.expanduser()
        if args.state_file is not None
        else workspace / DEFAULT_STATE_REL
    )

    state = load_state(state_path)
    rows, respawn_queue = build_rows(state)
    counts = Counter(r["classification"] for r in rows)

    if args.json:
        payload = {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "state_file": str(state_path),
            "total_pending": len(rows),
            "by_classification": {cls: counts.get(cls, 0) for cls in ALL_CLS},
            "rows": rows,
            "respawn_queue": respawn_queue,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if len(rows) == 0 and not args.quiet:
        sys.stderr.write(
            f"[audit-question-burndown] {state_path} has zero pending_commits[]\n"
        )

    print(render_human(rows, respawn_queue, workspace, state_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
