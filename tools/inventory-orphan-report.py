#!/usr/bin/env python3
"""inventory-orphan-report.py — T-12.

Reads inventory_smoke_summary.json + walks repository to identify three
classes of orphan:

1. **detector-orphans** — wave detectors with no fixture pair on disk
   (`skipped_no_fix` in T-11 output). For each: report whether a YAML
   exists, whether the YAML declares fixtures elsewhere, and whether
   any source corpus reference still exists.

2. **YAML-orphans** — YAMLs in reference/patterns.dsl/ with no compiled
   .py detector under detectors/wave*/.

3. **fixture-orphans** — fixtures in detectors/test_fixtures/ or
   patterns/fixtures/ with no associated detector.

Output:
  inventory_orphan_report.json  — per-orphan rows with category + remediation hint
  inventory_orphan_summary.txt  — human-readable summary

Usage:
  python3 tools/inventory-orphan-report.py \\
    --smoke-summary /private/tmp/auditooor-inventory/inventory_smoke_summary.json \\
    --output-dir /private/tmp/auditooor-inventory
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
TEST_FIXTURES_DIR = REPO / "detectors" / "test_fixtures"
PATTERNS_FIXTURES_DIR = REPO / "patterns" / "fixtures"


def read_yaml_status(yaml_path: Path) -> dict:
    """Lightweight YAML field read — no yaml dep needed for our 4 fields."""
    out = {"status": None, "fixtures_vuln": None, "fixtures_clean": None, "source": None}
    try:
        text = yaml_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return out
    m = re.search(r"^\s*status\s*:\s*(\S+)", text, re.MULTILINE)
    if m:
        out["status"] = m.group(1).strip().rstrip(",")
    m = re.search(r"^\s*source\s*:\s*(\S.*?)$", text, re.MULTILINE)
    if m:
        out["source"] = m.group(1).strip()
    m = re.search(r"^\s*vuln\s*:\s*(\S.*?)$", text, re.MULTILINE)
    if m:
        out["fixtures_vuln"] = m.group(1).strip()
    m = re.search(r"^\s*clean\s*:\s*(\S.*?)$", text, re.MULTILINE)
    if m:
        out["fixtures_clean"] = m.group(1).strip()
    return out


def build_yaml_index() -> set[str]:
    return {p.stem for p in DSL_DIR.glob("*.yaml")}


def build_fixture_index() -> tuple[set[str], set[str]]:
    """Return (set_of_arg_kebab_with_fixture, set_of_arg_kebab_with_clean_only)."""
    have_vuln = set()
    have_clean = set()
    for p in TEST_FIXTURES_DIR.glob("*_vulnerable.sol"):
        have_vuln.add(p.stem.removesuffix("_vulnerable").replace("_", "-"))
    for p in TEST_FIXTURES_DIR.glob("*_clean.sol"):
        have_clean.add(p.stem.removesuffix("_clean").replace("_", "-"))
    for p in PATTERNS_FIXTURES_DIR.glob("*_vuln.sol"):
        have_vuln.add(p.stem.removesuffix("_vuln"))
    for p in PATTERNS_FIXTURES_DIR.glob("*_vulnerable.sol"):
        have_vuln.add(p.stem.removesuffix("_vulnerable"))
    for p in PATTERNS_FIXTURES_DIR.glob("*_clean.sol"):
        have_clean.add(p.stem.removesuffix("_clean"))
    return have_vuln, have_clean


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke-summary", required=True)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    smoke = json.loads(Path(args.smoke_summary).read_text(encoding="utf-8"))
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    yaml_index = build_yaml_index()  # set of YAML stems
    have_vuln, have_clean = build_fixture_index()

    # 1. detector-orphans — from smoke_summary, status=skipped_no_fix
    detector_orphans = []
    for r in smoke["results"]:
        if r.get("status") != "skipped_no_fix":
            continue
        arg = r.get("argument")
        if not arg:
            continue
        yaml_stem = arg  # YAMLs use kebab-case stems matching ARGUMENT
        yaml_meta = {}
        if yaml_stem in yaml_index:
            yaml_meta = read_yaml_status(DSL_DIR / f"{yaml_stem}.yaml")
        detector_orphans.append({
            "argument": arg,
            "py_path": r.get("py_path"),
            "wave": r.get("wave"),
            "has_yaml": yaml_stem in yaml_index,
            "yaml_path": str((DSL_DIR / f"{yaml_stem}.yaml").relative_to(REPO)) if yaml_stem in yaml_index else None,
            "yaml_status": yaml_meta.get("status"),
            "yaml_source": yaml_meta.get("source"),
            "yaml_decl_fixtures_vuln": yaml_meta.get("fixtures_vuln"),
            "yaml_decl_fixtures_clean": yaml_meta.get("fixtures_clean"),
            "remediation_hint": (
                "yaml_status=documentation_only → not detector orphan, descriptor only" if yaml_meta.get("status") == "documentation_only"
                else "has YAML + source — synthesize fixture pair via LLM (Phase B target)" if yaml_meta.get("source")
                else "no YAML — needs fresh extraction from corpus or manual fixture authoring"
            ),
        })

    # 2. YAML-orphans — YAMLs without compiled .py
    py_args = set()
    for p in (REPO / "detectors").glob("wave*/*.py"):
        if p.name.startswith("_"):
            continue
        # Read ARGUMENT from the file
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            m = re.search(r'^\s*ARGUMENT\s*=\s*[\'"]([\w\-]+)[\'"]', text, re.MULTILINE)
            if m:
                py_args.add(m.group(1))
        except Exception:
            continue
    yaml_orphans = []
    for stem in sorted(yaml_index):
        if stem not in py_args:
            yaml_meta = read_yaml_status(DSL_DIR / f"{stem}.yaml")
            yaml_orphans.append({
                "argument": stem,
                "yaml_path": str((DSL_DIR / f"{stem}.yaml").relative_to(REPO)),
                "yaml_status": yaml_meta.get("status"),
                "yaml_source": yaml_meta.get("source"),
                "remediation_hint": (
                    "yaml_status=documentation_only → not orphan, descriptor only" if yaml_meta.get("status") == "documentation_only"
                    else "run: python3 tools/pattern-compile.py " + stem + ".yaml"
                ),
            })

    # 3. fixture-orphans — fixtures with no detector ARGUMENT match
    all_fixture_args = have_vuln | have_clean
    fixture_orphans = []
    for arg in sorted(all_fixture_args):
        if arg not in py_args and arg.replace("-", "_") not in {a.replace("-", "_") for a in py_args}:
            # Check both naming conventions
            fixture_orphans.append({
                "argument_or_stem": arg,
                "has_vuln_fixture": arg in have_vuln,
                "has_clean_fixture": arg in have_clean,
                "remediation_hint": (
                    "fixture exists but no detector loads ARGUMENT — check if YAML exists, then compile"
                ),
            })

    summary = {
        "schema": "auditooor.inventory_orphan.v1",
        "ran_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "detector_orphan_count": len(detector_orphans),
        "yaml_orphan_count": len(yaml_orphans),
        "fixture_orphan_count": len(fixture_orphans),
        "detector_orphans": detector_orphans,
        "yaml_orphans": yaml_orphans,
        "fixture_orphans": fixture_orphans,
    }
    (out_dir / "inventory_orphan_report.json").write_text(json.dumps(summary, indent=2))

    # Bucket detector orphans by remediation
    by_remed: dict[str, int] = {}
    docs_only_count = 0
    has_source_count = 0
    no_source_count = 0
    for r in detector_orphans:
        h = r["remediation_hint"]
        by_remed[h[:60]] = by_remed.get(h[:60], 0) + 1
        if r.get("yaml_status") == "documentation_only":
            docs_only_count += 1
        elif r.get("yaml_source"):
            has_source_count += 1
        else:
            no_source_count += 1

    txt = []
    txt.append(f"INVENTORY ORPHAN REPORT — {summary['ran_at']}")
    txt.append("=" * 70)
    txt.append("")
    txt.append(f"detector-orphans (.py with no fixture pair on disk): {len(detector_orphans)}")
    txt.append(f"  yaml_status=documentation_only:               {docs_only_count}  (NOT orphans)")
    txt.append(f"  yaml has source ref (Phase B target):         {has_source_count}")
    txt.append(f"  no YAML / unknown:                            {no_source_count}")
    txt.append("")
    txt.append(f"YAML-orphans (no compiled .py):                       {len(yaml_orphans)}")
    txt.append(f"  → run pattern-compile.py to fix")
    txt.append("")
    txt.append(f"fixture-orphans (.sol with no detector):              {len(fixture_orphans)}")
    txt.append("")
    txt.append("Top remediation buckets:")
    for h, n in sorted(by_remed.items(), key=lambda kv: -kv[1])[:5]:
        txt.append(f"  {n:5d}  {h}")
    (out_dir / "inventory_orphan_summary.txt").write_text("\n".join(txt) + "\n")

    print("\n".join(txt))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
