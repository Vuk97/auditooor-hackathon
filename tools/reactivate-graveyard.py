#!/usr/bin/env python3
"""
reactivate-graveyard.py — apply R54 graveyard-audit verdicts.

Reads JSON verdicts embedded in /tmp/r54_graveyard/audit_*.md reports,
parses REACTIVATE + tier_s_candidate entries, copies those .py files
from detectors/wave_graveyard/waveN/ into detectors/wave17_graveyard_reactivated/,
and appends entries to detectors/_tier_registry.yaml.

Idempotent: skips any file already present in the destination.

Usage:
    python3 tools/reactivate-graveyard.py [--dry-run] [--include-rework]

Exit codes:
    0 — all verdicts applied cleanly
    1 — usage/parse error
    2 — some files failed import-check after reactivation (see report)

This is the R54 Issue #161 action: the M3 near-miss exposed that the
graveyard contained mis-classified high-signal patterns. The audit found
~75 clear reactivations + ~40 rework candidates across 195 detectors.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

AUDITOOOR = Path(__file__).resolve().parent.parent
GRAVEYARD = AUDITOOOR / "detectors" / "wave_graveyard"
REACTIVATED_DIR = AUDITOOOR / "detectors" / "wave17_graveyard_reactivated"
TIER_REGISTRY = AUDITOOOR / "detectors" / "_tier_registry.yaml"
AUDIT_REPORTS = Path("/tmp/r54_graveyard")


def _extract_json_block(md_text: str) -> list[dict[str, Any]]:
    """Pull every ```json ... ``` block from a markdown report.

    Supports both:
      - Single array: ```json [ {...}, {...} ] ```
      - Multiple per-detector objects: ```json {...} ``` repeated.
    """
    results = []
    for m in re.finditer(r"```json\s*(\{.*?\}|\[.*?\])\s*```", md_text, re.DOTALL):
        raw = m.group(1)
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                results.extend(parsed)
            elif isinstance(parsed, dict):
                results.append(parsed)
        except json.JSONDecodeError as e:
            print(f"[warn] JSON parse error in block: {e}", file=sys.stderr)
    return results


def _normalize(v: dict[str, Any]) -> dict[str, Any]:
    """Accept any of the agent-emitted schemas and produce a canonical shape.

    Canonical fields we rely on:
      detector        — slug without .py extension
      wave            — e.g. 'wave8'
      verdict         — 'REACTIVATE' | 'NEEDS-REWORK' | 'KEEP-GRAVEYARD' | 'DUPE-OF-ACTIVE'
      tier_s_candidate — bool
    """
    out = dict(v)
    # detector: prefer 'detector' / 'name' / fall back to 'file' (strip path + .py)
    slug = v.get("detector") or v.get("name")
    if not slug:
        file_ref = v.get("file", "")
        if "/" in file_ref:
            slug = file_ref.rsplit("/", 1)[1]
        else:
            slug = file_ref
    if slug and slug.endswith(".py"):
        slug = slug[:-3]
    out["detector"] = slug

    # wave: prefer 'wave' / derive from 'file' path
    if not out.get("wave"):
        file_ref = v.get("file", "")
        if "/" in file_ref:
            out["wave"] = file_ref.split("/", 1)[0]

    # verdict: some agents emit 'verdict_refined' to override an initial verdict
    if v.get("verdict_refined"):
        out["verdict"] = v["verdict_refined"]

    # tier_s_candidate: bool OR 'tier_candidate' = 'S' string
    if "tier_s_candidate" not in out:
        tc = v.get("tier_candidate", "")
        out["tier_s_candidate"] = str(tc).upper() == "S"

    return out


def _load_all_verdicts() -> list[dict[str, Any]]:
    """Read every audit_*.md report, concatenate JSON verdicts."""
    all_verdicts = []
    if not AUDIT_REPORTS.exists():
        print(f"[err] {AUDIT_REPORTS} missing", file=sys.stderr)
        sys.exit(1)
    for report in sorted(AUDIT_REPORTS.glob("audit_*.md")):
        text = report.read_text()
        raw_verdicts = _extract_json_block(text)
        for v in raw_verdicts:
            v["_source_report"] = report.name
            all_verdicts.append(_normalize(v))
    return all_verdicts


def _source_path(wave: str, detector: str) -> Path | None:
    cand = GRAVEYARD / wave / f"{detector}.py"
    return cand if cand.exists() else None


def _dest_path(detector: str) -> Path:
    return REACTIVATED_DIR / f"{detector}.py"


def _import_check(py_file: Path) -> tuple[bool, str]:
    """Load the detector module the same way run_custom.py does (importlib.util)."""
    script = (
        "import sys, importlib.util\n"
        f"sys.path.insert(0, {str(AUDITOOOR / 'detectors')!r})\n"
        f"spec = importlib.util.spec_from_file_location('r54_check', {str(py_file)!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "print('ok')\n"
    )
    cmd = ["python3", "-c", script]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, "ok"


def _update_tier_registry(verdicts: list[dict[str, Any]], dry_run: bool) -> int:
    """Append R54-reactivated entries to _tier_registry.yaml (idempotent)."""
    try:
        import yaml
    except ImportError:
        print("[err] PyYAML required", file=sys.stderr)
        sys.exit(1)

    if not TIER_REGISTRY.exists():
        print(f"[err] tier registry missing: {TIER_REGISTRY}", file=sys.stderr)
        sys.exit(1)

    data = yaml.safe_load(TIER_REGISTRY.read_text()) or {}
    tiers = data.get("tiers", {})
    added = 0
    for v in verdicts:
        raw = v.get("detector") or v.get("name")
        if not raw:
            continue
        slug = raw[:-3] if raw.endswith(".py") else raw
        # underscore → hyphen for the pattern naming convention
        key = slug.replace("_", "-")
        if key in tiers:
            continue
        tier = "S" if v.get("tier_s_candidate") else "E"
        reason = (
            f"R54 graveyard reactivation from {v.get('wave')} "
            f"(verdict: {v.get('verdict')}; {v.get('reasoning', '')[:100]})"
        )
        tiers[key] = {
            "tier": tier,
            "reason": reason,
            "waves": ["wave17_graveyard_reactivated"],
            "fixture_pair": None,  # will be re-associated if fixture is copied
            "first_added": "2026-04-17",
            "reactivated_from": v.get("wave"),
            "reactivated_at": "2026-04-17",
        }
        added += 1

    if dry_run:
        print(f"[dry-run] would add {added} entries to tier registry")
        return added

    data["tiers"] = tiers
    TIER_REGISTRY.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))
    print(f"[ok] added {added} entries to {TIER_REGISTRY}")
    return added


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="no file writes")
    ap.add_argument(
        "--include-rework",
        action="store_true",
        help="also reactivate NEEDS-REWORK (Tier-E, operator must review before trust)",
    )
    args = ap.parse_args()

    verdicts = _load_all_verdicts()
    print(f"[info] loaded {len(verdicts)} verdicts from {AUDIT_REPORTS}")

    wanted = {"REACTIVATE"}
    if args.include_rework:
        wanted.add("NEEDS-REWORK")
    targets = [v for v in verdicts if v.get("verdict") in wanted]
    print(
        f"[info] targets: {len(targets)} "
        f"({sum(1 for v in targets if v.get('tier_s_candidate'))} tier-S candidates)"
    )

    if not args.dry_run:
        REACTIVATED_DIR.mkdir(parents=True, exist_ok=True)
        init_py = REACTIVATED_DIR / "__init__.py"
        if not init_py.exists():
            init_py.write_text("")

    moved = 0
    skipped = 0
    missing = 0
    import_fail = 0

    for v in targets:
        raw = v.get("detector") or v.get("name")
        if not raw:
            print(f"[skip] entry missing 'detector' field: {v}")
            missing += 1
            continue
        # Strip trailing .py (some agents emitted "name.py" vs "name")
        slug = raw[:-3] if raw.endswith(".py") else raw
        wave = v.get("wave")
        src = _source_path(wave, slug) if wave else None
        if src is None:
            print(f"[skip] source not found: {wave}/{slug}.py")
            missing += 1
            continue
        dst = _dest_path(slug)
        if dst.exists():
            skipped += 1
            continue
        if args.dry_run:
            print(f"[dry-run] would copy {src} -> {dst}")
            moved += 1
            continue
        shutil.copy2(src, dst)
        ok, msg = _import_check(dst)
        if not ok:
            print(f"[import-FAIL] {slug}: {msg}")
            dst.unlink()  # roll back
            import_fail += 1
            continue
        moved += 1

    print(
        f"[summary] moved={moved} skipped={skipped} missing={missing} "
        f"import_fail={import_fail}"
    )

    # Only register detectors that actually landed on disk.
    landed = [v for v in targets if _dest_path((v.get("detector") or v.get("name") or "").removesuffix(".py")).exists()]
    registry_added = _update_tier_registry(landed, args.dry_run)
    print(f"[summary] tier-registry added={registry_added} (from {len(landed)} landed files)")

    if import_fail > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
