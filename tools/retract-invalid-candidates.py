#!/usr/bin/env python3
"""retract-invalid-candidates.py - move INVALID paste-ready findings out of
submissions/paste_ready/ into the canonical dead-finding status dir submissions/_killed/
so they stop polluting the workspace-wide pre-submit scans (poc-freshness #138,
dupe/quarantine checks) and can never be filed by mistake.

Uses the EXISTING canonical status-dir vocabulary defined by
tools/submission-folder-structure-check.py (R41/L27: staging, ready, filed, packaged,
_killed, _oos_rejected, paste_ready, held, superseded) - `_killed` is the recognized
bucket for a finding that is no longer valid (here: its target source was removed at the
current pin). Does NOT invent a new folder.

Default pipeline behavior (Strata 2026-07-07): a finding authored against an older
pin whose PoC imports a source file the re-pin REMOVED (e.g. srt-haircut importing
`AccountingLib.sol`, deleted at 2be97f9) is INVALID at the live HEAD - it cannot
compile, so it is not fileable. Left in paste_ready/ it fails the workspace-wide
poc-freshness gate and blocks EVERY co-located valid finding from a clean pre-submit.

Invalidity signals (mechanical, never a judgement call):
  - stale-poc: a Solidity PoC (loose *.t.sol/*.sol or an inline ```solidity md block)
    imports a .sol basename that no longer exists in the current source tree. Reuses
    poc-freshness-recheck's drift detector (single source of truth).

Non-destructive: MOVES a finding dir (+ its sibling <name>.md.hash) into
submissions/_killed/<dir>/ and drops a _RETRACTION.json (reason + original path +
drift detail). Never deletes; fully reversible with a git mv back. Idempotent: a
finding already under _killed/ is never re-scanned. Dry-run by DEFAULT; --apply moves.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_pocfresh():
    spec = importlib.util.spec_from_file_location(
        "poc_freshness_recheck", _HERE / "poc-freshness-recheck.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def find_invalid(ws: Path) -> list[dict]:
    """Return one record per INVALID paste-ready finding dir (stale-poc)."""
    pf = _load_pocfresh()
    basenames = pf._workspace_sol_basenames(ws)
    pr = ws / "submissions" / "paste_ready"
    if not pr.is_dir():
        return []
    invalid: dict[str, dict] = {}
    for cand in sorted(pr.iterdir()):
        if not cand.is_dir() or cand.name == "filed":
            continue
        drift: list[str] = []
        for sf in cand.rglob("*.sol"):
            try:
                drift += pf._sol_import_drift(
                    sf.read_text(encoding="utf-8", errors="replace"), sf, basenames)
            except OSError:
                continue
        for md in cand.rglob("*.md"):
            try:
                text = md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for block in pf._MD_SOL_BLOCK_RE.findall(text):
                if "import" in block:
                    drift += pf._sol_import_drift(block, None, basenames)
        if drift:
            invalid[cand.name] = {
                "dir": str(cand), "name": cand.name,
                "reason": "stale-poc-removed-source-import",
                "drift": sorted(set(drift)),
            }
    return list(invalid.values())


def retract(ws: Path, apply: bool) -> dict:
    invalid = find_invalid(ws)
    # Canonical dead-finding bucket (submission-folder-structure-check.py STATUS_DIRS).
    dest_root = ws / "submissions" / "_killed"
    moved = []
    for rec in invalid:
        src = Path(rec["dir"])
        dest = dest_root / src.name
        rec["dest"] = str(dest)
        if apply:
            dest_root.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                rec["skipped"] = "dest-exists"
                continue
            shutil.move(str(src), str(dest))
            # sibling <name>.md.hash next to the finding dir
            for h in src.parent.glob(f"{src.name}*.md.hash"):
                try:
                    shutil.move(str(h), str(dest_root / h.name))
                except OSError:
                    pass
            (dest / "_RETRACTION.json").write_text(json.dumps(
                {"reason": rec["reason"], "original_path": rec["dir"],
                 "drift": rec["drift"]}, indent=2))
            moved.append(rec)
    return {
        "workspace": str(ws), "invalid_count": len(invalid),
        "invalid": invalid, "applied": apply, "moved_count": len(moved),
        "verdict": ("retracted" if (apply and moved) else
                    "would-retract" if invalid else "none-invalid"),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--apply", action="store_true",
                    help="actually move invalid candidates (default: dry-run report)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = retract(a.workspace, a.apply)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"retract-invalid-candidates: {r['verdict']} "
              f"({r['invalid_count']} invalid, {r['moved_count']} moved)")
        for rec in r["invalid"]:
            act = "MOVED" if rec.get("dest") and a.apply and "skipped" not in rec else "would-move"
            print(f"  [{act}] {rec['name']}: {rec['reason']}")
            for d in rec["drift"][:2]:
                print(f"          {d}")
    # rc 0 always on dry-run (it is a report); rc 0 on apply too (moves are the action).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
