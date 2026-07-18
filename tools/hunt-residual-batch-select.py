#!/usr/bin/env python3
"""Select the hunt-plan batches that actually intersect the coverage-gate residual.

PROBLEM (SEI 2026-07-05, 8 wasted waves): ``make hunt-scoped`` emits agent_batch_NNNN.md
in BUILDER order - which front-loads Solidity ``contracts/src/*.sol`` example/test
contracts and scatters the in-scope crown-jewel Go units (precompiles / x/evm / evmrpc)
into the high-numbered batches. Dispatching batches by index (0000, 0001, ...) or by a
path-grep therefore hunts OOS mirrors and credits ~0 to ``queued_not_scanned``. The
residual can never drain that way.

FIX: rank batches by how many of the gate's live ``queued_not_scanned`` units each batch's
``function_anchor`` entries actually target, and dispatch the top-K. A batch's anchors are
matched to residual units on (basename, fn) - the same key the residual worker queue uses -
so the selection is exactly the units the gate still wants scanned.

This is READ-ONLY and side-effect-free: it prints a ranked batch list (and optionally the
per-batch residual-unit count) so the orchestrator dispatches the residual-hitting batches
first. It never mutates the plan or any gate artifact.

Usage:
  python3 tools/hunt-residual-batch-select.py --workspace <ws> [--top 8] [--json]
      [--plan-dir <dir>]   # default: newest audit/corpus_tags/derived/haiku_harness_*_/_haiku_plan
      [--domains precompiles,x/evm,evmrpc]  # restrict residual to these path substrings
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_ANCHOR_RX = re.compile(r'"function_anchor"\s*:\s*\{[^}]*"file"\s*:\s*"([^"]+)"[^}]*"fn"\s*:\s*"([^"]+)"')
# Also match the rendered form: **function_anchor**: {"file": "...", "fn": "..."}
_ANCHOR_RX2 = re.compile(r'function_anchor\*\*:\s*\{"file":\s*"([^"]+)",\s*"fn":\s*"([^"]+)"')


def _gate_residual(ws: Path, repo_root: Path) -> list[str]:
    """Return the gate's live queued_not_scanned units (via --json), [] on any failure."""
    gate = repo_root / "tools" / "hunt-coverage-gate.py"
    try:
        out = subprocess.run(
            [sys.executable, str(gate), "--workspace", str(ws), "--json"],
            capture_output=True, text=True, timeout=300,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return []
    # The gate prints a human line then the JSON; grab the last JSON object.
    for chunk in (out, out[out.find("{"):] if "{" in out else ""):
        try:
            d = json.loads(chunk)
            if isinstance(d, dict) and "queued_not_scanned" in d:
                return list(d["queued_not_scanned"])
        except (ValueError, TypeError):
            continue
    return []


def _relpath_suffix(fp: str) -> str:
    """Normalize a unit/anchor path to its ``src/...`` suffix so a residual unit id
    (already ``src/...``) and a batch anchor (an absolute ``/ws/src/...`` path) share the
    SAME key. Falls back to the basename only if no ``src/`` segment is present.

    KEYING ON THE FULL RELPATH (not the basename) is load-bearing: a Cosmos-EVM L1 has
    ~10 legacy version copies of each precompile (legacy/v620/gov.go vs legacy/v640/gov.go
    vs gov.go), all sharing basename ``gov.go``. A basename key collides across them, so
    the selector would re-pick an already-hunted batch while a DIFFERENT version's unit is
    what still sits in the residual (SEI 2026-07-05)."""
    fp = fp.replace("\\", "/")
    i = fp.find("/src/")
    if i >= 0:
        return fp[i + 1 :]
    if fp.startswith("src/"):
        return fp
    return os.path.basename(fp)


def _residual_keys(
    units: list[str], domains: list[str], prefer_canonical: bool = False
) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for u in units:
        if "::" not in u:
            continue
        fp, fn = u.split("::", 1)
        fn = fn.split("(", 1)[0].strip()
        if not fn:
            continue
        if domains and not any(d in fp for d in domains):
            continue
        if prefer_canonical and "/legacy/v" in fp:
            # Skip legacy version copies: hunting the canonical unlocks Lane H
            # (byte-identical legacy credit) for all its siblings at once.
            continue
        keys.add((_relpath_suffix(fp), fn))
    return keys


def _batch_anchor_keys(text: str) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for rx in (_ANCHOR_RX, _ANCHOR_RX2):
        for fpath, fn in rx.findall(text):
            keys.add((_relpath_suffix(fpath), fn.split("(", 1)[0].strip()))
    return keys


def _newest_plan_dir(ws: Path, repo_root: Path) -> Path | None:
    pats = [
        str(repo_root / "audit/corpus_tags/derived/haiku_harness_*_/_haiku_plan"),
        str(repo_root / "audit/corpus_tags/derived/haiku_harness_*/_haiku_plan"),
    ]
    cands: list[str] = []
    for p in pats:
        cands.extend(glob.glob(p))
    if not cands:
        return None
    cands.sort(key=lambda d: os.path.getmtime(d), reverse=True)
    return Path(cands[0])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--plan-dir", default=None)
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--domains", default="",
                    help="comma-separated path substrings to restrict residual (e.g. precompiles,x/evm,evmrpc)")
    ap.add_argument("--prefer-canonical", action="store_true",
                    help="skip legacy/vNNN version copies; hunt the canonical, then the "
                         "gate's byte-identical-legacy credit (Lane H) covers its siblings")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ws = Path(args.workspace).resolve()
    repo_root = Path(__file__).resolve().parents[1]
    plan_dir = Path(args.plan_dir) if args.plan_dir else _newest_plan_dir(ws, repo_root)
    if not plan_dir or not plan_dir.is_dir():
        print(json.dumps({"error": "no plan dir found"}) if args.json
              else "ERROR: no _haiku_plan dir found", file=sys.stderr)
        return 2

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    residual = _gate_residual(ws, repo_root)
    res_keys = _residual_keys(residual, domains, prefer_canonical=args.prefer_canonical)
    if not res_keys:
        # Empty residual is the terminal-green state, NOT an error - report it honestly.
        print(json.dumps({"plan_dir": str(plan_dir), "residual_keys": 0, "batches": []})
              if args.json else "residual-empty: no queued_not_scanned units to target")
        return 0

    scored: list[tuple[int, str, str]] = []
    for b in sorted(glob.glob(str(plan_dir / "agent_batch_*.md"))):
        try:
            txt = Path(b).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = _batch_anchor_keys(txt) & res_keys
        if hits:
            num = os.path.basename(b).replace("agent_batch_", "").replace(".md", "")
            scored.append((len(hits), num, os.path.basename(b)))
    scored.sort(reverse=True)

    top = scored[: args.top]
    if args.json:
        print(json.dumps({
            "plan_dir": str(plan_dir),
            "residual_keys": len(res_keys),
            "batches_hitting_residual": len(scored),
            "top": [{"batch": n, "residual_hits": h, "file": f} for h, n, f in top],
        }, indent=2))
    else:
        print(f"plan_dir: {plan_dir}")
        print(f"residual_keys={len(res_keys)}  batches_hitting_residual={len(scored)}")
        print(f"top {len(top)} residual-hitting batches (batch  hits):")
        for h, n, _f in top:
            print(f"  {n}  {h}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
