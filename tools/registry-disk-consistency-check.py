#!/usr/bin/env python3
"""registry-disk-consistency-check.py — T-01.

CI-blocking gate. For every Tier-A / Tier-B / Tier-S row in
`detectors/_tier_registry.yaml`, verify:

  1. The detector .py file exists.
  2. The vulnerable + clean fixtures exist (test_fixtures/ snake or
     patterns/fixtures/ kebab convention).
  3. The row carries `verified: true` (set by inventory-bulk-promote
     after smoke pass).
  4. Optional --strict-smoke: re-run smoke test live; row must still pass.

Exit codes:
  0 — clean: every Tier-A/B/S row has verified=true + on-disk artifacts.
  1 — drift: at least one row claims Tier-A/B/S but lacks artifacts or
      verification metadata.
  2 — invalid args / cannot read registry.

Output: prints summary; on drift, lists offending rows with reason.

Usage:
  python3 tools/registry-disk-consistency-check.py
  python3 tools/registry-disk-consistency-check.py --strict-smoke
  python3 tools/registry-disk-consistency-check.py --json-out report.json

Wire into Makefile:
  make registry-disk-consistency-check:
      python3 tools/registry-disk-consistency-check.py
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"
HIGH_TIERS = {"S", "A", "B"}


def find_py_for_argument(arg: str) -> Path | None:
    """Search wave* dirs for a .py whose ARGUMENT matches."""
    snake = arg.replace("-", "_")
    # Fast path: file name matches snake form
    for wave_dir in (REPO / "detectors").glob("wave*"):
        if not wave_dir.is_dir():
            continue
        candidate = wave_dir / f"{snake}.py"
        if candidate.exists():
            return candidate
    # Slow path: read every .py looking for ARGUMENT = "..."
    pattern = re.compile(rf'^\s*ARGUMENT\s*=\s*[\'"]{re.escape(arg)}[\'"]', re.MULTILINE)
    for p in (REPO / "detectors").glob("wave*/*.py"):
        if p.name.startswith("_"):
            continue
        try:
            if pattern.search(p.read_text(encoding="utf-8", errors="replace")):
                return p
        except Exception:
            continue
    return None


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _owned_detector_local_fixture_dir(arg: str, row: dict | None) -> Path | None:
    """Return an explicit detectors/_fixtures/<arg> dir owned by a focused test."""
    if not row:
        return None
    fixture_pair = row.get("fixture_pair")
    if not isinstance(fixture_pair, str) or not fixture_pair:
        return None

    rel = Path(fixture_pair)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    if len(rel.parts) != 3 or rel.parts[:2] != ("detectors", "_fixtures"):
        return None

    snake = arg.replace("-", "_")
    if rel.name != snake:
        return None

    fixture_dir = (REPO / rel).resolve()
    fixture_root = (REPO / "detectors" / "_fixtures").resolve()
    if not _is_relative_to(fixture_dir, fixture_root) or not fixture_dir.is_dir():
        return None

    owner_test = REPO / "tools" / "tests" / f"test_{snake}.py"
    if not owner_test.is_file():
        return None
    try:
        owner_source = owner_test.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    if rel.name not in owner_source or "_fixtures" not in owner_source:
        return None
    return fixture_dir


def _matching_clean_for(vuln: Path) -> Path | None:
    replacements = [
        ("_vulnerable", "_clean"),
        ("_vuln", "_clean"),
        ("_positive", "_negative"),
    ]
    for old, new in replacements:
        if vuln.stem.endswith(old):
            clean = vuln.with_name(f"{vuln.stem[:-len(old)]}{new}{vuln.suffix}")
            if clean.exists():
                return clean
    return None


def _smoke_command_vuln_fixture(row: dict | None, fixture_dir: Path) -> Path | None:
    if not row:
        return None
    command = row.get("smoke_test_command")
    if not isinstance(command, str) or not command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        candidate = (REPO / token).resolve()
        if (
            candidate.is_file()
            and _is_relative_to(candidate, fixture_dir.resolve())
            and re.search(r"_(vulnerable|vuln|positive)\.[^.]+$", candidate.name)
        ):
            return candidate
    return None


def _find_owned_detector_local_fixtures(
    arg: str,
    row: dict | None,
) -> tuple[Path | None, Path | None]:
    fixture_dir = _owned_detector_local_fixture_dir(arg, row)
    if fixture_dir is None:
        return None, None

    preferred = _smoke_command_vuln_fixture(row, fixture_dir)
    vuln_candidates = []
    if preferred is not None:
        vuln_candidates.append(preferred)
    for pattern in ("*_vulnerable.*", "*_vuln.*", "*_positive.*"):
        vuln_candidates.extend(sorted(fixture_dir.glob(pattern)))

    seen: set[Path] = set()
    for vuln in vuln_candidates:
        if vuln in seen:
            continue
        seen.add(vuln)
        clean = _matching_clean_for(vuln)
        if clean is not None:
            return vuln, clean
    return None, None


def find_fixtures(arg: str, row: dict | None = None) -> tuple[Path | None, Path | None]:
    snake = arg.replace("-", "_")
    candidates_v = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "test_fixtures" / f"{snake}_vuln.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_vulnerable.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_vulnerable.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_vuln.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_vulnerable.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_vuln.sol",
        # alt-language: positive/negative naming under <lang>_wave1/test_fixtures
        REPO / "detectors" / "rust_wave1"   / "test_fixtures" / f"{snake}_positive.rs",
        REPO / "detectors" / "circom_wave1" / "test_fixtures" / f"{snake}_positive.circom",
        REPO / "detectors" / "go_wave1"     / "test_fixtures" / f"{snake}_positive.go",
        REPO / "detectors" / "python_wave1" / "test_fixtures" / f"{snake}_positive.py",
    ]
    candidates_c = [
        REPO / "detectors" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "test_fixtures" / f"{arg}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{arg}_clean.sol",
        REPO / "patterns" / "fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "wave_graveyard" / "test_fixtures" / f"{snake}_clean.sol",
        REPO / "detectors" / "rust_wave1"   / "test_fixtures" / f"{snake}_negative.rs",
        REPO / "detectors" / "circom_wave1" / "test_fixtures" / f"{snake}_negative.circom",
        REPO / "detectors" / "go_wave1"     / "test_fixtures" / f"{snake}_negative.go",
        REPO / "detectors" / "python_wave1" / "test_fixtures" / f"{snake}_negative.py",
    ]
    vuln = next((p for p in candidates_v if p.exists()), None)
    clean = next((p for p in candidates_c if p.exists()), None)
    if vuln is None or clean is None:
        local_vuln, local_clean = _find_owned_detector_local_fixtures(arg, row)
        if local_vuln is not None and local_clean is not None:
            return local_vuln, local_clean
    return vuln, clean


_DONE_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")


def run_smoke(arg: str, fixture: Path) -> int:
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=REPO)
    except subprocess.TimeoutExpired:
        return -1
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _DONE_HITS_RE.search(out)
    return int(m.group(1)) if m else -1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict-smoke", action="store_true",
                    help="Live re-run smoke test for each row (slow; ~1s/detector).")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--ignore-paper", action="store_true",
                    help="Treat tier=PAPER as a separate (non-failing) bucket.")
    args = ap.parse_args()

    if not TIER_REGISTRY.exists():
        print(f"registry not found: {TIER_REGISTRY}", file=sys.stderr)
        return 2

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.get("tiers", {}) or {}

    drift_rows: list[dict] = []
    ok_rows: list[dict] = []
    for arg, row in tiers.items():
        tier = row.get("tier", "")
        if tier not in HIGH_TIERS:
            continue
        py_path = find_py_for_argument(arg)
        vuln, clean = find_fixtures(arg, row)
        verified = bool(row.get("verified"))
        problems = []
        if py_path is None:
            problems.append("no .py file")
        if vuln is None:
            problems.append("no vulnerable fixture")
        if clean is None:
            problems.append("no clean fixture")
        if not verified:
            problems.append("missing verified=true")
        smoke_vh = None
        smoke_ch = None
        if args.strict_smoke and not problems:
            smoke_vh = run_smoke(arg, vuln)
            smoke_ch = run_smoke(arg, clean)
            if smoke_vh < 1 or smoke_ch != 0:
                problems.append(f"strict_smoke: clean_hits={smoke_ch} vuln_hits={smoke_vh}")
        if problems:
            drift_rows.append({
                "argument": arg, "tier": tier, "problems": problems,
                "py_path": str(py_path.relative_to(REPO)) if py_path else None,
                "vuln_fixture": str(vuln.relative_to(REPO)) if vuln else None,
                "clean_fixture": str(clean.relative_to(REPO)) if clean else None,
                "row_keys": sorted(row.keys()),
                "reason": row.get("reason", ""),
            })
        else:
            ok_rows.append({
                "argument": arg, "tier": tier,
                "py_path": str(py_path.relative_to(REPO)) if py_path else None,
                "vuln_fixture": str(vuln.relative_to(REPO)) if vuln else None,
                "clean_fixture": str(clean.relative_to(REPO)) if clean else None,
                "smoke_vuln_hits": smoke_vh,
                "smoke_clean_hits": smoke_ch,
                "reason": row.get("reason", ""),
            })

    summary = {
        "schema": "auditooor.registry_disk_consistency.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "registry": str(TIER_REGISTRY.relative_to(REPO)),
        "strict_smoke": args.strict_smoke,
        "total_high_tier_rows": len(drift_rows) + len(ok_rows),
        "ok_count": len(ok_rows),
        "drift_count": len(drift_rows),
        "drift_rows": drift_rows,
        "ok_rows": ok_rows,
    }
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(summary, indent=2))

    print(f"[registry-disk-consistency] high-tier rows: {summary['total_high_tier_rows']}")
    print(f"  ok:    {len(ok_rows)}")
    print(f"  drift: {len(drift_rows)}")
    if drift_rows:
        print()
        print("=== drift detail (first 20) ===")
        for d in drift_rows[:20]:
            print(f"  [{d['tier']}] {d['argument']:55} problems={d['problems']}")
        if len(drift_rows) > 20:
            print(f"  ... and {len(drift_rows)-20} more (see --json-out)")
        print()
        print("Remediation:")
        print("  - 'no .py file': stale registry row; remove or re-compile YAML")
        print("  - 'no vulnerable/clean fixture': add fixture or downgrade tier")
        print("  - 'missing verified=true': run inventory-bulk-promote after smoke pass")
        print("  - 'strict_smoke: ...': detector or fixture broke; investigate runtime")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
