#!/usr/bin/env python3
"""derived-artifact-size-budget.py - J3e: Derived-artifact size discipline gate.

Scans generated/derived sidecar artifacts under a configurable root directory,
measures each artifact's size, and checks it against per-artifact and total
repository-derived budgets.

Background
----------
J3e (HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19): Full extraction must not create
unreviewable monoliths. The predicate sidecar is already about 77.8 MB before
recursive parity. Sharded layouts (e.g. exploit_predicates.d/) are handled
gracefully - the sharded directory is measured as a unit via its manifest.
This tool enforces the budget gate only; it does NOT delete or rewrite sidecars.

Acceptance criteria:
- No generated sidecar exceeds the configured size budget.
- GitHub push warnings (files >=50 MB, hard limit 100 MB) are treated as
  closeout blockers in strict mode.
- MCP callables load bounded shards - this tool flags monoliths that should
  be sharded.

Schema
------
Output schema ID: auditooor.derived_artifact_size_budget.v1

Artifact verdict values:
  within_budget         - size < soft budget threshold
  over_soft_budget      - soft_budget_bytes <= size < hard_budget_bytes
  over_hard_budget      - size >= hard_budget_bytes (closeout blocker)
  missing               - path expected but not found

Remediation recommendations:
  shard_by_language     - shard the JSONL by language field (for cross-language)
  shard_by_source       - shard by source/subtree (for detector_relationship etc)
  compact_index         - build a compact index file instead of full JSONL monolith
  already_sharded       - artifact is a shard directory with manifest; within budget
  no_action_needed      - artifact is within all budgets

Usage
-----
  python3 tools/derived-artifact-size-budget.py [--root DIR] [--json]
      [--per-artifact-budget-mb SOFT] [--hard-artifact-budget-mb HARD]
      [--total-budget-mb TOTAL] [--strict]

Defaults:
  soft per-artifact: 25 MB  (flag for remediation)
  hard per-artifact: 50 MB  (GitHub push-warning threshold; closeout blocker)
  total budget:      500 MB (total derived dir)

Exit codes:
  0 - all artifacts within hard budget (or --strict not set)
  1 - at least one artifact over HARD budget (only when --strict)
  2 - usage / I/O error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema identifiers
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "auditooor.derived_artifact_size_budget.v1"

# Default budget thresholds (bytes)
DEFAULT_SOFT_BYTES = 25 * 1024 * 1024   # 25 MB - start recommending sharding
DEFAULT_HARD_BYTES = 50 * 1024 * 1024   # 50 MB - GitHub push-warning boundary
DEFAULT_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB total derived dir

# Shard directory suffix patterns used by existing sharding tools (B8).
# A directory named <stem>.d next to a manifest <stem>.manifest.json is a
# sharded artifact - measure it as a unit.
SHARD_DIR_SUFFIX = ".d"
MANIFEST_SUFFIX = ".manifest.json"

# Known artifact names to remediation hints (best-effort; falls back to generic)
_ARTIFACT_REMEDIATIONS: dict[str, str] = {
    "exploit_predicates.jsonl": "already_sharded",      # has .d/ shards
    "cross_language_analogues.jsonl": "shard_by_language",
    "detector_relationship_records.jsonl": "shard_by_source",
    "chain_candidates.jsonl": "shard_by_source",
    "proof_hardening.jsonl": "shard_by_source",
    "record_quality.jsonl": "compact_index",
}


# ---------------------------------------------------------------------------
# Size helpers
# ---------------------------------------------------------------------------

def _dir_size(path: Path) -> int:
    """Recursively sum sizes of all files under path."""
    total = 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total


def _artifact_size(path: Path) -> int:
    """Return the byte size of a path (file or directory)."""
    if path.is_dir():
        return _dir_size(path)
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _max_shard_size(path: Path) -> tuple[int, int]:
    """For a sharded .d/ directory, return (max_shard_bytes, shard_count).

    The J3e size budget applies PER SHARD, not to the directory total -
    bounded per-file load is the whole point of sharding. A sharded
    directory whose every shard is within budget is compliant regardless
    of the aggregate directory size.
    """
    max_bytes = 0
    count = 0
    if path.is_dir():
        for entry in path.iterdir():
            if entry.is_file() and entry.name.endswith(".jsonl"):
                try:
                    sz = entry.stat().st_size
                except OSError:
                    continue
                count += 1
                if sz > max_bytes:
                    max_bytes = sz
    return max_bytes, count


# ---------------------------------------------------------------------------
# Remediation logic
# ---------------------------------------------------------------------------

def _remediation_for(name: str, size_bytes: int, is_sharded: bool) -> str:
    """Return a remediation recommendation string for an over-budget artifact."""
    if is_sharded:
        return "already_sharded"
    if size_bytes < DEFAULT_SOFT_BYTES:
        return "no_action_needed"
    # Check known artifact table first
    hint = _ARTIFACT_REMEDIATIONS.get(name)
    if hint:
        return hint
    # Generic heuristics
    name_lower = name.lower()
    if "language" in name_lower or "analogue" in name_lower:
        return "shard_by_language"
    if any(k in name_lower for k in ("record", "relationship", "candidate",
                                      "predicate", "hardening")):
        return "shard_by_source"
    return "compact_index"


# ---------------------------------------------------------------------------
# Artifact discovery
# ---------------------------------------------------------------------------

def _discover_artifacts(root: Path) -> list[Path]:
    """Discover top-level derived artifacts (files + shard dirs) under root.

    Rules:
    - Each immediate child that is a regular file is a candidate artifact.
    - A <stem>.d directory paired with a <stem>.manifest.json is treated as
      ONE sharded artifact unit represented by the .d directory; the .jsonl
      monolith stub (if any) and the .manifest.json are excluded from
      individual measurement because they belong to the sharded unit.
    - The .d directory itself IS measured (total shard size).
    - Empty or missing root: returns [].
    """
    if not root.exists() or not root.is_dir():
        return []

    children = sorted(root.iterdir())

    # Build a set of names that belong to sharded units so we can skip them
    shard_dirs = {c for c in children if c.is_dir() and c.name.endswith(SHARD_DIR_SUFFIX)}
    sharded_stems = {sd.name[: -len(SHARD_DIR_SUFFIX)] for sd in shard_dirs}

    artifacts: list[Path] = []
    for child in children:
        if child.is_dir():
            if child.name.endswith(SHARD_DIR_SUFFIX):
                # Include the shard dir as the unit artifact
                artifacts.append(child)
        elif child.is_file():
            stem = child.stem
            suffix = child.suffix
            # Skip manifest files that belong to a sharded unit
            if child.name.endswith(MANIFEST_SUFFIX):
                base = child.name[: -len(MANIFEST_SUFFIX)]
                if base in sharded_stems:
                    continue
            # Skip the monolith stub when a shard dir exists for the same stem
            if stem in sharded_stems:
                continue
            artifacts.append(child)

    return artifacts


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

def check_artifacts(
    root: Path,
    soft_bytes: int = DEFAULT_SOFT_BYTES,
    hard_bytes: int = DEFAULT_HARD_BYTES,
    total_bytes: int = DEFAULT_TOTAL_BYTES,
) -> dict[str, Any]:
    """Scan root and return a report dict matching schema SCHEMA_VERSION.

    Never raises; errors are surfaced in the report's ``error`` field.
    """
    report: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "root": str(root),
        "budgets": {
            "per_artifact_soft_bytes": soft_bytes,
            "per_artifact_hard_bytes": hard_bytes,
            "total_bytes": total_bytes,
        },
        "artifacts": [],
        "summary": {
            "total_artifacts": 0,
            "within_budget": 0,
            "over_soft_budget": 0,
            "over_hard_budget": 0,
            "total_size_bytes": 0,
            "total_verdict": "within_budget",
        },
        "closeout_blockers": [],
        "error": None,
    }

    if not root.exists():
        report["error"] = f"derived root does not exist: {root}"
        report["summary"]["total_verdict"] = "missing"
        return report

    if not root.is_dir():
        report["error"] = f"derived root is not a directory: {root}"
        report["summary"]["total_verdict"] = "missing"
        return report

    artifacts = _discover_artifacts(root)
    if not artifacts:
        # Empty directory is valid - zero artifacts, all within budget
        report["summary"]["total_verdict"] = "within_budget"
        return report

    total_size = 0
    artifact_rows = []
    for path in artifacts:
        size = _artifact_size(path)
        total_size += size
        is_dir = path.is_dir()
        is_sharded = is_dir and path.name.endswith(SHARD_DIR_SUFFIX)

        # For a sharded .d/ directory the J3e budget applies PER SHARD, not to
        # the directory total - bounded per-file load is the whole point of
        # sharding. Base the verdict on the largest shard, not the aggregate.
        max_shard_bytes, shard_count = (_max_shard_size(path) if is_sharded else (0, 0))
        budget_basis = max_shard_bytes if is_sharded else size

        if budget_basis >= hard_bytes:
            verdict = "over_hard_budget"
        elif budget_basis >= soft_bytes:
            verdict = "over_soft_budget"
        else:
            verdict = "within_budget"

        remediation = _remediation_for(path.name, size, is_sharded)
        if verdict == "within_budget" and not is_sharded:
            remediation = "no_action_needed"

        row: dict[str, Any] = {
            "name": path.name,
            "path": str(path),
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "is_sharded_dir": is_sharded,
            "verdict": verdict,
            "remediation": remediation,
        }
        if is_sharded:
            row["max_shard_bytes"] = max_shard_bytes
            row["max_shard_mb"] = round(max_shard_bytes / (1024 * 1024), 2)
            row["shard_count"] = shard_count
        artifact_rows.append(row)

    # Total-budget verdict
    total_verdict = "within_budget"
    if total_size >= total_bytes:
        total_verdict = "over_hard_budget"

    # Aggregate counts
    within = sum(1 for r in artifact_rows if r["verdict"] == "within_budget")
    over_soft = sum(1 for r in artifact_rows if r["verdict"] == "over_soft_budget")
    over_hard = sum(1 for r in artifact_rows if r["verdict"] == "over_hard_budget")

    closeout_blockers = [r["name"] for r in artifact_rows if r["verdict"] == "over_hard_budget"]
    if total_verdict == "over_hard_budget":
        closeout_blockers.append("__total__")

    report["artifacts"] = artifact_rows
    report["summary"] = {
        "total_artifacts": len(artifact_rows),
        "within_budget": within,
        "over_soft_budget": over_soft,
        "over_hard_budget": over_hard,
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "total_verdict": total_verdict,
    }
    report["closeout_blockers"] = closeout_blockers

    return report


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _human_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Derived-artifact size budget check ({report['root']})")
    lines.append("=" * 70)

    if report.get("error"):
        lines.append(f"ERROR: {report['error']}")
        return "\n".join(lines)

    budgets = report["budgets"]
    soft_mb = budgets["per_artifact_soft_bytes"] / (1024 * 1024)
    hard_mb = budgets["per_artifact_hard_bytes"] / (1024 * 1024)
    total_mb = budgets["total_bytes"] / (1024 * 1024)
    lines.append(
        f"Budgets: soft={soft_mb:.0f} MB / hard={hard_mb:.0f} MB per artifact, "
        f"total={total_mb:.0f} MB"
    )
    lines.append("")

    artifacts = report.get("artifacts", [])
    if not artifacts:
        lines.append("No artifacts found (directory empty or does not exist).")
    else:
        col_w = max((len(a["name"]) for a in artifacts), default=30) + 2
        lines.append(f"{'Artifact':<{col_w}} {'Size MB':>10}  {'Verdict':<20}  Remediation")
        lines.append("-" * (col_w + 55))
        for a in artifacts:
            flag = ""
            if a["verdict"] == "over_hard_budget":
                flag = " [BLOCKER]"
            elif a["verdict"] == "over_soft_budget":
                flag = " [WARN]"
            lines.append(
                f"{a['name']:<{col_w}} {a['size_mb']:>10.2f}  "
                f"{a['verdict'] + flag:<28}  {a['remediation']}"
            )

    lines.append("")
    s = report["summary"]
    lines.append(
        f"Total: {s['total_size_mb']:.2f} MB across {s['total_artifacts']} artifacts  "
        f"(within={s['within_budget']}, soft={s['over_soft_budget']}, "
        f"hard={s['over_hard_budget']})"
    )
    lines.append(f"Total-budget verdict: {s['total_verdict']}")

    blockers = report.get("closeout_blockers", [])
    if blockers:
        lines.append("")
        lines.append(
            "CLOSEOUT BLOCKERS (over hard budget - GitHub push warnings):"
        )
        for b in blockers:
            if b == "__total__":
                lines.append(f"  - [total derived directory exceeds {total_mb:.0f} MB budget]")
            else:
                lines.append(f"  - {b}")
        lines.append("Fix: shard or compact the listed artifacts before closing the engagement.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="J3e: Derived-artifact size discipline gate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root",
        default="audit/corpus_tags/derived",
        help="Root directory to scan (default: audit/corpus_tags/derived)",
    )
    parser.add_argument(
        "--per-artifact-budget-mb",
        type=float,
        default=DEFAULT_SOFT_BYTES / (1024 * 1024),
        dest="soft_mb",
        help=f"Soft per-artifact budget in MB (default: {DEFAULT_SOFT_BYTES // (1024*1024)})",
    )
    parser.add_argument(
        "--hard-artifact-budget-mb",
        type=float,
        default=DEFAULT_HARD_BYTES / (1024 * 1024),
        dest="hard_mb",
        help=f"Hard per-artifact budget in MB (closeout blocker, default: {DEFAULT_HARD_BYTES // (1024*1024)})",
    )
    parser.add_argument(
        "--total-budget-mb",
        type=float,
        default=DEFAULT_TOTAL_BYTES / (1024 * 1024),
        dest="total_mb",
        help=f"Total derived-dir budget in MB (default: {DEFAULT_TOTAL_BYTES // (1024*1024)})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON report to stdout instead of human-readable output",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any artifact is over the hard budget (closeout-blocker mode)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    root = Path(args.root)
    soft_bytes = int(args.soft_mb * 1024 * 1024)
    hard_bytes = int(args.hard_mb * 1024 * 1024)
    total_bytes = int(args.total_mb * 1024 * 1024)

    report = check_artifacts(
        root=root,
        soft_bytes=soft_bytes,
        hard_bytes=hard_bytes,
        total_bytes=total_bytes,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_human_report(report))

    if args.strict:
        blockers = report.get("closeout_blockers", [])
        if blockers:
            if not args.json:
                print(
                    "\nStrict mode: exiting non-zero due to closeout blockers.",
                    file=sys.stderr,
                )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
