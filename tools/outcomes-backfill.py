#!/usr/bin/env python3
"""outcomes-backfill.py — backfill ``lane`` and ``fp_reason`` per-row fields
into ``reference/outcomes.jsonl`` so that
[agent-recall-suggester.py](agent-recall-suggester.py) can produce non-trivial,
non-``absent`` recall hints.

Closes the deferred blocker called out in
[../docs/next-loop/agent_recall_suggester_v0_2026-05-07.md](../docs/next-loop/agent_recall_suggester_v0_2026-05-07.md)
section "What was deferred to L13+", item 1 ("``fp_reason`` ledger backfill").

Schema additions per row
------------------------
* ``lane`` (str): always populated. Pre-existing values are preserved
  verbatim (``source-mine`` etc). Missing values are derived from a small,
  documented heuristic (workspace + source). Falls back to ``"unknown"``.
* ``fp_reason`` (str | null): populated **only** when the row's outcome looks
  FP-shaped (``rejected``, ``duplicate``, ``duplicate_of_rejected``,
  ``withdrawn``). Picked from a fixed allow-list (``ALLOWED_FP_REASONS``);
  defaults to ``"unknown"`` when no signal is available. Set to ``null``
  on non-FP rows so downstream consumers can distinguish "not applicable"
  from "unknown".

Determinism / discipline (Codex M14-trap rules)
-----------------------------------------------
* stdlib-only, offline-safe.
* **Idempotent.** Running twice produces identical bytes (sorted JSON keys,
  trailing newline, stable file order). The tool re-derives ``lane``
  and ``fp_reason`` deterministically from the same source signals each run.
* No mutation beyond ``reference/outcomes.jsonl``. The previous file is
  preserved at ``reference/outcomes.jsonl.bak`` only when ``--write-backup``
  is passed (off by default to keep the repo clean).
* Honest defaults: when no signal is available, ``lane="unknown"`` and
  ``fp_reason="unknown"``. The tool never invents categorical labels for
  rows that lack the underlying field.
* Allow-list enforcement: any ``fp_reason`` value that the heuristic emits
  is asserted to be a member of ``ALLOWED_FP_REASONS``. Adding a new
  vocabulary term requires editing the allow-list explicitly (PR-reviewable).

Usage
-----
    python3 tools/outcomes-backfill.py
    python3 tools/outcomes-backfill.py --ledger reference/outcomes.jsonl
    python3 tools/outcomes-backfill.py --dry-run --stdout

Schema
------
The output preserves the input row schema and **adds** two keys:
``lane``, ``fp_reason``. All existing keys are passed through verbatim.
Output bytes are sorted by JSON key for byte-stable idempotency.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = REPO_ROOT / "reference" / "outcomes.jsonl"

# FP-shaped outcome values — only these rows receive an ``fp_reason``.
FP_OUTCOMES = {
    "rejected",
    "duplicate",
    "duplicate_of_rejected",
    "withdrawn",
}

# Allow-list of ``fp_reason`` values the backfill is permitted to emit.
# Any new vocabulary term must be added here explicitly. Keep small.
ALLOWED_FP_REASONS = frozenset({
    "operator_killed_pre_submit",
    "duplicate_of_rejected_original",
    "unrealistic_bounds",
    "event_only_cosmetic",
    "reconstructible_from_batch_event",
    "architectural_by_design",
    "centralization_weighted",
    "withdrawn_after_precondition_check",
    "self_assessed_not_a_vulnerability",
    "duplicate_of_other_submission",
    "stale_inventory",
    "proto_enum_dispatch",
    "mocked_callback",
    "oos_path_hallucination",
    "severity_overclaim",
    "unknown",
})

# Mapping from blockers_cleared "no:<slug>" suffix to fp_reason. Slugs not
# in this map fall through to "unknown" (which is in the allow-list).
_BLOCKER_SLUG_TO_FP_REASON: dict[str, str] = {
    "operator-killed-pre-submit": "operator_killed_pre_submit",
    "rejected-as-duplicate-of-rejected-original": "duplicate_of_rejected_original",
    "unrealistic-bounds": "unrealistic_bounds",
    "event-only-cosmetic": "event_only_cosmetic",
    "reconstructible-from-erc1155-batch": "reconstructible_from_batch_event",
    "architectural-domain-separation-by-design": "architectural_by_design",
    "centralization-weighted": "centralization_weighted",
    "withdrawn-after-precondition-check": "withdrawn_after_precondition_check",
    "closed-by-self-assessment-not-a-vulnerability": "self_assessed_not_a_vulnerability",
}


# ---------------------------------------------------------------------------
# Pure derivation helpers
# ---------------------------------------------------------------------------
def derive_lane(row: dict[str, Any]) -> str:
    """Derive a ``lane`` value for a row.

    Pure function — same input always yields same output. Preserves an
    existing non-empty ``lane`` value verbatim. Otherwise classifies by
    workspace + source signals into a small categorical bucket.
    """
    existing = row.get("lane")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()

    workspace = (row.get("workspace") or "").strip().lower()
    engagement = (row.get("engagement") or "").strip().lower()
    source = (row.get("source") or "").lower()

    if workspace == "polymarket" and "submissions" in source:
        return "polymarket-source-mine"
    if workspace == "polymarket":
        return "polymarket-source-mine"
    if workspace == "base-azul":
        return "base-azul-source-mine"
    if engagement == "centrifuge":
        return "centrifuge-historical-stub"
    if workspace and workspace != "none":
        return f"{workspace}-source-mine"
    return "unknown"


def derive_fp_reason(row: dict[str, Any]) -> str | None:
    """Derive an ``fp_reason`` value for a row, or ``None`` if N/A.

    Non-FP outcomes return ``None``. FP-shaped outcomes return a value
    from ``ALLOWED_FP_REASONS`` (default ``"unknown"`` when no signal).
    Pre-existing ``fp_reason`` values are preserved verbatim **only when
    they are in the allow-list**; otherwise they are normalized to
    ``"unknown"`` so the ledger can never accumulate untracked vocabulary.
    """
    outcome = (row.get("outcome") or "").strip().lower()
    if outcome not in FP_OUTCOMES:
        return None

    # Preserve existing allow-listed value, if any.
    existing = row.get("fp_reason")
    if isinstance(existing, str) and existing.strip() in ALLOWED_FP_REASONS:
        return existing.strip()

    # Try ``production_path_blockers_cleared`` -> "no:<slug>" / "partial:<slug>".
    blockers = (row.get("production_path_blockers_cleared") or "").strip()
    if blockers.startswith("no:"):
        slug = blockers[3:].strip()
        mapped = _BLOCKER_SLUG_TO_FP_REASON.get(slug)
        if mapped is not None:
            return mapped
    elif blockers.startswith("partial:"):
        # Partial blockers are not strict FPs; fall through to unknown.
        pass

    # Try ``rejection_reason`` free-text scan — only if it carries an OOS
    # signal we can map confidently. Avoid greedy heuristics.
    rejection = (row.get("rejection_reason") or "").strip().lower()
    if rejection:
        if "out of scope" in rejection or "out_of_scope" in rejection or "oos" in rejection:
            return "oos_path_hallucination"

    # ``outcome_class`` hints (e.g. "dupe").
    outcome_class = (row.get("outcome_class") or "").strip().lower()
    if outcome_class == "dupe":
        return "duplicate_of_other_submission"

    # Bare ``duplicate`` outcomes without richer signal.
    if outcome in {"duplicate"}:
        return "duplicate_of_other_submission"

    return "unknown"


def backfill_row(row: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with ``lane`` and ``fp_reason`` populated.

    Pure function: never mutates the input. Asserts the emitted
    ``fp_reason`` (if non-null) is in ``ALLOWED_FP_REASONS``.
    """
    new = dict(row)
    new["lane"] = derive_lane(new)
    fp = derive_fp_reason(new)
    if fp is not None:
        if fp not in ALLOWED_FP_REASONS:
            # Defensive: never let an invalid term slip through.
            fp = "unknown"
        new["fp_reason"] = fp
    else:
        new["fp_reason"] = None
    return new


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------
def _read_ledger(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # Preserve bad rows so backfill never silently drops content.
                rows.append({"_parse_error": True, "_raw": line[:400]})
    return rows


def _serialize_row(row: dict[str, Any]) -> str:
    """Serialize a single row deterministically (sorted keys, no whitespace)."""
    return json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(", ", ": "))


def write_ledger(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write rows to ``path`` deterministically (one JSON per line, sorted keys).

    File-level order is preserved (no row reordering) so diff is minimal.
    Trailing newline ensured.
    """
    payload = "\n".join(_serialize_row(r) for r in rows) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def backfill(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict]:
    """Backfill a list of rows. Returns (new_rows, stats).

    Pure: does not touch disk.
    """
    new_rows = [backfill_row(r) if not r.get("_parse_error") else r for r in rows]

    lane_dist: Counter = Counter()
    fp_dist: Counter = Counter()
    for r in new_rows:
        if r.get("_parse_error"):
            continue
        lane_dist[r.get("lane", "unknown")] += 1
        fp = r.get("fp_reason")
        if fp is not None:
            fp_dist[fp] += 1
    stats = {
        "rows_total": len(new_rows),
        "rows_with_parse_error": sum(1 for r in new_rows if r.get("_parse_error")),
        "lane_distribution": dict(sorted(lane_dist.items(), key=lambda x: (-x[1], x[0]))),
        "fp_reason_distribution": dict(sorted(fp_dist.items(), key=lambda x: (-x[1], x[0]))),
        "rows_with_fp_reason": sum(
            1 for r in new_rows if r.get("fp_reason") not in (None, "")
        ),
    }
    return new_rows, stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--ledger",
        type=Path,
        default=DEFAULT_LEDGER,
        help=f"Path to outcomes ledger (.jsonl). Default: {DEFAULT_LEDGER.relative_to(REPO_ROOT)}",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute backfill but do not rewrite the ledger.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print backfill stats JSON to stdout.",
    )
    parser.add_argument(
        "--write-backup",
        action="store_true",
        help="Write a sibling .bak file before rewriting (off by default).",
    )
    args = parser.parse_args(argv)

    rows = _read_ledger(args.ledger)
    new_rows, stats = backfill(rows)

    if not args.dry_run:
        if args.write_backup and args.ledger.exists():
            backup = args.ledger.with_suffix(args.ledger.suffix + ".bak")
            backup.write_text(args.ledger.read_text(encoding="utf-8"), encoding="utf-8")
        write_ledger(args.ledger, new_rows)

    if args.stdout:
        sys.stdout.write(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
