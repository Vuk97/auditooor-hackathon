#!/usr/bin/env python3
"""ranker-apply-weights — operator-approved ranker weight application.

Usage:
    python3 tools/ranker-apply-weights.py --sha <sha8> [--force]

Pre-conditions:
1. audit/ranker_weights.<sha8>.yaml must exist (= a snapshot was generated
   by tools/ranker-learn.py).
2. audit/ranker_weight_diff.md must exist (= operator has the rendered diff
   available; without it we refuse, because we want to discourage applying
   arbitrary snapshot files).
3. Without --force: interactive y/N confirmation.

On apply:
- Replace audit/ranker_weights.yaml with the snapshot content.
- Append a row to audit/ranker_weight_apply_log.jsonl with prev_sha8 + ts.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
RANKER_WEIGHTS = REPO_ROOT / "audit" / "ranker_weights.yaml"
DIFF_PATH = REPO_ROOT / "audit" / "ranker_weight_diff.md"
APPLY_LOG = REPO_ROOT / "audit" / "ranker_weight_apply_log.jsonl"


def _sha8(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:8]
    except Exception:
        return "00000000"


def apply_snapshot(
    sha: str,
    force: bool = False,
    weights_path: Path = RANKER_WEIGHTS,
    diff_path: Path = DIFF_PATH,
    apply_log: Path = APPLY_LOG,
    confirm_input: Optional[str] = None,
) -> int:
    snapshot = weights_path.parent / f"ranker_weights.{sha}.yaml"
    if not snapshot.exists():
        print(f"error: snapshot not found: {snapshot}", file=sys.stderr)
        return 3
    if not diff_path.exists():
        print(
            f"error: diff file missing: {diff_path}\n"
            "Run `python3 tools/ranker-learn.py --filing-id ... --outcome ...` first.",
            file=sys.stderr,
        )
        return 4
    prev_sha8 = _sha8(weights_path)
    if not force:
        if confirm_input is None:
            ans = input(
                f"Apply weights snapshot {sha}? "
                f"Diff at audit/ranker_weight_diff.md. y/N: "
            )
        else:
            ans = confirm_input
        if not ans.strip().lower().startswith("y"):
            print("aborted (no changes)")
            return 5
    # Atomic replace
    body = snapshot.read_text(encoding="utf-8")
    weights_path.write_text(body, encoding="utf-8")
    # Apply log
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    def _rel(p: Path) -> str:
        try:
            return str(p.relative_to(REPO_ROOT))
        except ValueError:
            return str(p)

    row = {
        "ts": ts,
        "sha8": sha,
        "prev_sha8": prev_sha8,
        "applied_by_user": os.environ.get("USER", "unknown"),
        "snapshot_path": _rel(snapshot),
    }
    apply_log.parent.mkdir(parents=True, exist_ok=True)
    with apply_log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"applied: sha8={sha} (prev={prev_sha8}). Logged to {_rel(apply_log)}.")
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Apply approved ranker weight snapshot.")
    p.add_argument("--sha", required=True, help="sha8 of the snapshot file")
    p.add_argument("--force", action="store_true",
                   help="Skip interactive y/N confirmation")
    args = p.parse_args(argv)
    return apply_snapshot(sha=args.sha, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
