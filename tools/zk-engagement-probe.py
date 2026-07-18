#!/usr/bin/env python3
"""zk-engagement-probe.py — structural grep for ZK tokens in a workspace.

Wave-5 Track K-zkBugs Step 9 (stub). Walks a workspace tree and counts
hits for canonical ZK framework tokens. If zero hits → emits a
`NEGATIVE_zk_engagement_probe.md` that records the absence. This saves
half a loop of wasted ZK-lane dispatch on workspaces that have no
relevant surface.

Usage:
    python3 tools/zk-engagement-probe.py <workspace>

Exit codes:
    0  hits >= 1 (workspace has ZK surface; ZK lanes are warranted)
    1  hits == 0 (workspace is ZK-empty; NEGATIVE artifact written)
    2  argument error
"""
from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path
from typing import Iterable


TOKENS = [
    r"\bcircom\b",
    r"\bhalo2\b",
    r"\bgroth16\b",
    r"\bplonk\b",
    r"\bfiat[._-]?shamir\b",
    r"\bnullifier\b",
    r"\brange[._-]?check\b",
    r"\bemulated[._-]?field\b",
    r"\bsnark\b",
    r"\bstark\b",
    r"\bplonky\d?\b",
    r"\bcairo\b",
    r"\bbellperson\b",
    r"\barkworks\b",
]

# Verifier-side tokens (Solidity BaseHonkVerifier / Shplemini surface)
VERIFIER_TOKENS = [
    r"function\s+verify\b",
    r"\bpairing\s*\(",
    r"\bstaticcall\s*\(\s*gas\(\)\s*,\s*7\b",
    r"\.invert\s*\(",
    r"\bTranscript\b",
    r"\bsplitChallenge\b",
    r"\brejectPointAtInfinity\b",
    r"\bBaseHonkVerifier\b",
    r"\bBaseZKHonkVerifier\b",
    r"\bShplemini\b",
    r"\bSumcheck\b",
    r"\bpublicInputDelta\b",
    r"\bverifySumcheck\b",
    r"\bverifyShplemini\b",
    r"\bbatchMul\b",
]

PATTERN = re.compile("|".join(TOKENS), re.IGNORECASE)
VERIFIER_PATTERN = re.compile("|".join(VERIFIER_TOKENS), re.IGNORECASE)

EXTENSIONS = {".rs", ".circom", ".sol", ".cairo", ".go", ".py", ".ts", ".js", ".md", ".toml", ".yaml", ".yml", ".json"}
SKIP_DIRS = {
    ".auditooor",
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "dist",
    "node_modules",
    "out",
    "poc-tests",
    "target",
    "test",
    "tests",
}


def _iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in EXTENSIONS:
            continue
        try:
            if p.stat().st_size > 5 * 1024 * 1024:  # 5 MB cap
                continue
        except OSError:
            continue
        yield p


def probe(workspace: Path) -> tuple[int, list[tuple[Path, int]]]:
    """Return (total_hits, per_file_counts). per_file_counts is a list
    of (path, hit_count) entries with hit_count >= 1."""
    per_file: list[tuple[Path, int]] = []
    total = 0
    for p in _iter_files(workspace):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        count = len(PATTERN.findall(text))
        if count > 0:
            per_file.append((p, count))
            total += count
    per_file.sort(key=lambda kv: -kv[1])
    return total, per_file


def _probe_verifier(workspace: Path) -> list[dict]:
    """Return list of verifier-file dicts (path, hit_count) for zk_surface.json."""
    import json as _json
    results = []
    for p in workspace.rglob("*.sol"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > 2 * 1024 * 1024:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = len(VERIFIER_PATTERN.findall(text))
        if hits > 0:
            results.append({"path": str(p), "hits": hits})
    results.sort(key=lambda x: -x["hits"])
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ZK engagement probe")
    ap.add_argument("workspace", help="Path to workspace root to scan")
    ap.add_argument("--emit-surface", action="store_true",
                    help="Also write <ws>/.auditooor/zk_surface.json with verifier-file list")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        sys.stderr.write(f"error: not a directory: {ws}\n")
        return 2

    total, per_file = probe(ws)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

    # Verifier-side surface (always probed; written only with --emit-surface)
    verifier_files = _probe_verifier(ws)

    if args.emit_surface:
        import json as _json
        surface_dir = ws / ".auditooor"
        surface_dir.mkdir(parents=True, exist_ok=True)
        surface_path = surface_dir / "zk_surface.json"
        surface_data = {
            "schema": "auditooor.zk_surface.v1",
            "workspace": str(ws),
            "generated_at": ts,
            "circuit_hits": total,
            "verifier_files": verifier_files,
        }
        surface_path.write_text(_json.dumps(surface_data, indent=2) + "\n", encoding="utf-8")
        print(f"[zep] wrote surface -> {surface_path} ({len(verifier_files)} verifier files)")

    if total == 0 and not verifier_files:
        out_path = ws / "NEGATIVE_zk_engagement_probe.md"
        out_path.write_text(
            f"# NEGATIVE — workspace has no ZK surface\n\n"
            f"- Probed: `{ws}`\n"
            f"- Generated: `{ts}`\n"
            f"- Token pattern: `{PATTERN.pattern}`\n"
            f"- Scanned extensions: `{sorted(EXTENSIONS)}`\n\n"
            "Skip ZK lanes (Circom / Halo2 / Cairo / Plonky3 / Solidity-Honk) for this "
            "workspace — none of the canonical tokens were observed.\n",
            encoding="utf-8",
        )
        print(f"[zep] NEGATIVE — 0 hits in {ws}")
        print(f"[zep] wrote {out_path}")
        return 1

    print(f"[zep] POSITIVE — {total} circuit hits + {len(verifier_files)} verifier files in {ws}")
    for p, c in per_file[:10]:
        print(f"  {c:5d}  {p.relative_to(ws)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
