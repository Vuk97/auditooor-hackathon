#!/usr/bin/env python3
"""outcome_reweight.py — PR 112 outcome-driven reweighting helper.

Reads `reference/outcomes.jsonl` (written by `tools/outcome-telemetry.py`)
and computes per-angle score deltas + human-readable rationales so
`tools/mining-prioritizer.py` can penalize duplicate-heavy bug classes
and promote classes with accepted/paid outcomes.

Design:
- Pure helper module. Importable from mining-prioritizer.py.
- Ships a `__main__` block for ad-hoc inspection.
- Gracefully returns (0.0, []) whenever `outcomes.jsonl` is missing or
  the class has insufficient history (<3 total). Never raises on missing
  data — the caller logs baseline-mode.
- Every rationale line includes `outcome_history_version=<sha256[:16]>`
  on the first line so operators can diff deltas across snapshots.

PR 112 rules (final tuning shipped here):
  accepted >= 1 AND accepted/total >= 0.30  -> +2.0  (promote)
  duplicate/total >= 0.50 AND total >= 3    -> -3.0  (penalize dupe-heavy)
  rejected_reasons['out-of-scope']/total>=.5-> -2.0  (OOS warning)
  workspace already surfaced this class     -> -1.0  (dupe-self-risk)
  otherwise (insufficient data)             -> 0.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from outcome_semantics import derive_outcome_semantics

# Mapping of CCIA angle ID -> canonical bug-class slug. Keep aligned with
# tools/mining-prioritizer.py's severity/bonus table.
_ANGLE_ID_TO_SLUG: Dict[str, str] = {
    "A-REENT": "reentrancy",
    "A-AUTH": "access-control",
    "A-ORACLE": "oracle",
    "A-DELEGATE": "delegatecall",
    "A-ERC4626": "erc4626",
    "A-FLASH": "flash-loan",
    "A-TIMESTAMP": "timestamp",
    "A-RACE": "race",
    "A-UPGRADE": "upgrade",
    "A-VAULT": "vault",
}

# Keyword -> slug fallback for when angle.id doesn't match.
_KEYWORD_TO_SLUG: List[Tuple[str, str]] = [
    ("reentran", "reentrancy"),
    ("access control", "access-control"),
    ("unauthenticat", "access-control"),
    ("auth", "access-control"),
    ("role", "access-control"),
    ("oracle", "oracle"),
    ("delegatecall", "delegatecall"),
    ("erc4626", "erc4626"),
    ("vault", "vault"),
    ("flash", "flash-loan"),
    ("timestamp", "timestamp"),
    ("race", "race"),
    ("duplicate", "balance-delta"),
    ("balance", "balance-delta"),
    ("refund", "balance-delta"),
    ("upgrade", "upgrade"),
]


def classify_angle(angle: Dict[str, Any]) -> Optional[str]:
    """Infer a bug-class slug from an angle dict. Returns None if unknown."""
    angle_id = str(angle.get("id") or "").strip().upper()
    if angle_id in _ANGLE_ID_TO_SLUG:
        return _ANGLE_ID_TO_SLUG[angle_id]

    tags = angle.get("tags") or []
    if isinstance(tags, list):
        for tag in tags:
            tag_l = str(tag).strip().lower()
            if tag_l in _ANGLE_ID_TO_SLUG.values():
                return tag_l

    text = " ".join(
        str(angle.get(k) or "")
        for k in ("title", "description", "bug_class", "class", "category")
    ).lower()
    for keyword, slug in _KEYWORD_TO_SLUG:
        if keyword in text:
            return slug
    return None


def classify_title(title: str) -> Optional[str]:
    """Classify a historical submission title to the same slug namespace."""
    text = title.lower()
    for keyword, slug in _KEYWORD_TO_SLUG:
        if keyword in text:
            return slug
    return None


def _guess_rejected_reason(status: str) -> Optional[str]:
    s = status.lower()
    if "out of scope" in s or "out-of-scope" in s or "oos" in s:
        return "out-of-scope"
    if "invalid" in s:
        return "invalid"
    if "informational" in s or "info" in s:
        return "informational"
    if "rejected" in s:
        return "rejected-other"
    return None


def load_outcome_history(outcomes_path: Path) -> Dict[str, Dict[str, Any]]:
    """Read reference/outcomes.jsonl into a class -> stats dict.

    Returns a dict of the shape:
        { bug_class_slug: {
              "total": int,
              "accepted": int,
              "duplicate": int,
              "rejected_reasons": {reason: count, ...},
              "workspaces_seen": set[str],
          }, ... }

    Missing file -> empty dict. Malformed lines are skipped silently.
    The dict also carries a reserved "__version__" key with a sha256
    hex of the raw file bytes (first 16 chars) so callers can surface
    an outcome_history_version tag on each rationale line.
    """
    history: Dict[str, Dict[str, Any]] = {}
    if not outcomes_path.exists():
        return history

    raw = outcomes_path.read_bytes()
    version = hashlib.sha256(raw).hexdigest()[:16] if raw else "empty"
    history["__version__"] = {"sha256_16": version, "path": str(outcomes_path)}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        semantics = derive_outcome_semantics(rec)
        if not semantics.eligible_for_learning:
            continue
        title = str(rec.get("title") or "")
        outcome = semantics.outcome
        status = str(rec.get("status") or "")
        workspace = str(rec.get("workspace") or "")
        slug = classify_title(title)
        if not slug:
            continue
        bucket = history.setdefault(
            slug,
            {
                "total": 0,
                "accepted": 0,
                "duplicate": 0,
                "rejected_reasons": {},
                "workspaces_seen": set(),
            },
        )
        bucket["total"] += 1
        if workspace:
            bucket["workspaces_seen"].add(workspace)
        # Codex PR-102 non-blocker 1: `paid` is a stronger positive signal
        # than `accepted` (it means the bounty was actually disbursed) but
        # the previous rule only counted `accepted`, so paid rows dropped
        # off the accept_rate numerator and could block a class from being
        # promoted. Fold `paid` into the accepted bucket.
        if outcome in {"accepted", "paid"}:
            bucket["accepted"] += 1
        elif outcome == "duplicate":
            bucket["duplicate"] += 1
        elif outcome == "rejected":
            reason = _guess_rejected_reason(status) or "rejected-other"
            bucket["rejected_reasons"][reason] = (
                bucket["rejected_reasons"].get(reason, 0) + 1
            )
    return history


def history_version(history: Dict[str, Dict[str, Any]]) -> str:
    meta = history.get("__version__") if history else None
    if isinstance(meta, dict):
        return str(meta.get("sha256_16") or "absent")
    return "absent"


def compute_reweight(
    angle: Dict[str, Any],
    history: Dict[str, Dict[str, Any]],
    workspace_name: str,
) -> Tuple[float, List[str]]:
    """Return (delta_score, rationale_lines) for a CCIA angle.

    delta_score > 0 promotes, < 0 penalizes. Rationale is empty when
    there's insufficient signal, so callers don't pollute output.
    """
    # Empty / missing history -> baseline mode.
    if not history or all(k == "__version__" for k in history):
        return 0.0, []

    slug = classify_angle(angle)
    if not slug:
        return 0.0, []

    stats = history.get(slug)
    if not stats:
        # No history at all for this slug.
        return 0.0, []

    total = int(stats["total"])
    accepted = int(stats["accepted"])
    duplicate = int(stats["duplicate"])
    rejected_reasons = stats.get("rejected_reasons", {}) or {}
    workspaces_seen = stats.get("workspaces_seen", set()) or set()
    version = history_version(history)

    delta = 0.0
    lines: List[str] = []

    # Codex PR-102 non-blocker 2: the self-workspace dedup signal is
    # deterministic (the class either was or was not already submitted in
    # this workspace) — gating it behind total>=3 meant the first couple
    # of submissions in a fresh workspace escaped the penalty. Always
    # apply this signal regardless of total count.
    if workspace_name and workspace_name in workspaces_seen:
        delta -= 1.0
        lines.append(
            f"class '{slug}' already surfaced in THIS workspace "
            f"'{workspace_name}' (see SUBMISSIONS.md) (-1.0)"
        )

    if total < 3:
        # Statistical signals need at least 3 samples to be meaningful.
        # Self-workspace penalty above is deterministic and already applied.
        if lines:
            lines[0] = f"[outcome_history_version={version}] " + lines[0]
        return delta, lines

    # Promote paid classes.
    accept_rate = accepted / total if total else 0.0
    if accepted >= 1 and accept_rate >= 0.30:
        delta += 2.0
        lines.append(
            f"class '{slug}' paid in {len(workspaces_seen)} workspace(s) "
            f"(accept rate {accept_rate * 100:.0f}%, {accepted}/{total}) (+2.0)"
        )

    # Penalize dupe-heavy classes.
    dupe_rate = duplicate / total if total else 0.0
    if dupe_rate >= 0.50 and total >= 3:
        delta -= 3.0
        lines.append(
            f"class '{slug}' has {dupe_rate * 100:.0f}% dupe rate across "
            f"{total} submission(s); pursue only with distinct victim/path (-3.0)"
        )

    # Warn OOS-heavy classes.
    oos_count = int(rejected_reasons.get("out-of-scope", 0))
    if total and oos_count / total >= 0.50:
        delta -= 2.0
        lines.append(
            f"class '{slug}' commonly rejected as OOS "
            f"({oos_count}/{total}); verify scope before investing (-2.0)"
        )

    if lines:
        # Prefix the first rationale line with the history version tag so
        # operators can always tell which snapshot drove the reweight.
        lines[0] = f"[outcome_history_version={version}] " + lines[0]

    return delta, lines


def _print_ad_hoc(history: Dict[str, Dict[str, Any]]) -> None:
    version = history_version(history)
    print(f"outcome_history_version = {version}")
    for slug, stats in history.items():
        if slug == "__version__":
            continue
        print(
            f"  {slug:<18} total={stats['total']:<3} "
            f"accepted={stats['accepted']:<3} duplicate={stats['duplicate']:<3} "
            f"rej_reasons={dict(stats['rejected_reasons'])} "
            f"workspaces={sorted(stats['workspaces_seen'])}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ad-hoc outcome-reweight inspector. "
        "Reads reference/outcomes.jsonl and prints per-slug stats."
    )
    parser.add_argument(
        "--outcomes",
        default="reference/outcomes.jsonl",
        help="Path to outcomes.jsonl (default: reference/outcomes.jsonl)",
    )
    args = parser.parse_args()
    path = Path(args.outcomes).expanduser().resolve()
    if not path.exists():
        print(f"[outcome-reweight] no outcomes history at {path}", file=sys.stderr)
        return 0
    history = load_outcome_history(path)
    _print_ad_hoc(history)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
