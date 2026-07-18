#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""hunt-orchestrate-ensure-clone.py - step 1: unshallow the source tree.

Tier-6 bidirectional commit-mining needs the FULL git history. A
``--depth 1`` shallow clone makes backward mining impossible. This step
locates the in-scope source repo under the workspace and, if it is a
shallow clone, runs ``git fetch --unshallow`` to deepen it.

Deterministic, offline-safe (a fetch failure is reported but does not
raise), stdlib-only. Exits 0 when the tree is already full OR was
successfully unshallowed; exits 0 with a WARN line when no repo is found
(a release-tarball target is a legitimate no-op); exits non-zero only on
a true unshallow failure when STRICT=1.

CLI
---
    python3 tools/hunt-orchestrate-ensure-clone.py <workspace> [--json] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.l36_ensure_full_clone.v1"
GATE = "L36-ENSURE-FULL-CLONE"


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _find_source_repo(ws: Path) -> Path | None:
    if _exists(ws / ".git"):
        return ws
    for sub in ("external", "src", "repo", "target", "source"):
        base = ws / sub
        if not _exists(base) or not base.is_dir():
            continue
        if _exists(base / ".git"):
            return base
        try:
            for c in sorted(base.iterdir()):
                if c.is_dir() and _exists(c / ".git"):
                    return c
        except OSError:
            continue
    try:
        for c in sorted(ws.iterdir()):
            if c.is_dir() and _exists(c / ".git"):
                return c
    except OSError:
        pass
    return None


def _is_shallow(repo: Path) -> bool | None:
    git_dir = repo / ".git"
    try:
        if git_dir.is_dir() and (git_dir / "shallow").exists():
            return True
    except OSError:
        pass
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() == "true"


def _unshallow(repo: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "fetch", "--unshallow"],
            capture_output=True, text=True, timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"fetch error: {exc}"
    if proc.returncode != 0:
        return False, f"git fetch --unshallow rc={proc.returncode}: {proc.stderr.strip()[:200]}"
    return True, "unshallowed"


def run(ws: Path) -> tuple[dict, int]:
    repo = _find_source_repo(ws)
    if repo is None:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "pass-no-source-repo",
            "reason": "no in-scope source git clone found; nothing to unshallow (release-tarball target?)",
        }, 0
    shallow = _is_shallow(repo)
    if shallow is not True:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "pass-already-full", "repo": str(repo),
            "reason": "source clone already full (not shallow)",
        }, 0
    ok, msg = _unshallow(repo)
    if ok:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "pass-unshallowed", "repo": str(repo), "reason": msg,
        }, 0
    return {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": "warn-unshallow-failed", "repo": str(repo), "reason": msg,
    }, 0  # best-effort: WARN-grade, not a hard fail unless --strict


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hunt-orchestrate-ensure-clone.py", description=__doc__)
    p.add_argument("workspace")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="Exit non-zero on unshallow failure.")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {"schema": SCHEMA, "gate": GATE, "workspace": str(ws),
                   "verdict": "error", "reason": "workspace not found"}
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error")
        return 2

    result, rc = run(ws)
    if args.strict and result["verdict"] == "warn-unshallow-failed":
        rc = 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{GATE}] verdict={result['verdict']} - {result['reason']}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
