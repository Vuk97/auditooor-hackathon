#!/usr/bin/env python3
"""r94-rust-bulk-wire.py — Wire r94 phase7 Rust DSL specs into runnable detectors.

For each phase7_rust_fixture_*.json in the input directory:
  1. Parses the JSON (strips markdown fences if present).
  2. Generates detectors/rust_wave1/<spec_id>.py (regex-based run() from regex_indicators).
  3. Writes test_fixtures/<spec_id>_positive.rs and <spec_id>_negative.rs
     from fixture_pair_vulnerable_rs / fixture_pair_clean_rs.
  4. Skips any spec_id that already exists as a detector.

After wiring, optionally runs inventory-smoke-rust.py --limit for smoke-testing.

Usage:
  python3 tools/r94-rust-bulk-wire.py \\
    --phase7-dir /private/tmp/auditooor-overnight/phase7_outputs \\
    [--output-dir /tmp/auditooor-r94-smoke] \\
    [--dry-run] \\
    [--smoke]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DETECTORS_DIR = REPO / "detectors" / "rust_wave1"
FIXTURES_DIR = DETECTORS_DIR / "test_fixtures"

# Template for the generated detector .py
DETECTOR_TEMPLATE = '''\
"""
{spec_id}

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: {pattern_id}
Platform: {platform}
Source: phase7_rust_fixture_{spec_id}.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = {indicator_patterns!r}

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = {min_match}


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    match_count = sum(1 for c in _COMPILED if c.search(text))
    if match_count < _MIN_MATCH:
        return hits

    # Find a representative line for the first matching pattern
    first_line = 1
    first_snippet = ""
    for compiled, raw in zip(_COMPILED, _INDICATOR_PATTERNS):
        m = compiled.search(text)
        if m:
            first_line = text[: m.start()].count("\\n") + 1
            first_snippet = text[m.start() : m.start() + 120].replace("\\n", " ").strip()
            break

    hits.append({{
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{{filepath}}: pattern \'{spec_id}\' detected "
            f"({{match_count}}/{{len(_COMPILED)}} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    }})
    return hits
'''


def load_spec(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    # Strip markdown fences if present
    if text.lstrip().startswith("```"):
        lines = text.splitlines()
        # drop first and last fence lines
        start = next(i for i, l in enumerate(lines) if l.strip().startswith("```")) + 1
        end = len(lines) - 1
        while end > start and not lines[end].strip().startswith("```"):
            end -= 1
        text = "\n".join(lines[start:end])
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[error] JSON parse failed for {path.name}: {e}", file=sys.stderr)
        return None


def safe_id(s: str) -> str:
    """Convert spec_id (may have hyphens) to Python-safe module name (underscores)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)


def wire_spec(spec: dict, dry_run: bool) -> dict:
    """Wire one spec. Returns result dict."""
    spec_id_raw = spec.get("spec_id", "")
    spec_id = safe_id(spec_id_raw)
    platform = spec.get("platform", "unknown")
    detector_spec = spec.get("detector_spec", {})
    pattern_id = detector_spec.get("pattern_id", spec_id_raw)
    regex_indicators = detector_spec.get("regex_indicators", [])

    positive_rs = spec.get("fixture_pair_vulnerable_rs", "")  # vulnerable = positive hit
    negative_rs = spec.get("fixture_pair_clean_rs", "")       # clean = negative (no hit)

    det_path = DETECTORS_DIR / f"{spec_id}.py"
    pos_path = FIXTURES_DIR / f"{spec_id}_positive.rs"
    neg_path = FIXTURES_DIR / f"{spec_id}_negative.rs"

    result = {
        "spec_id": spec_id,
        "spec_id_raw": spec_id_raw,
        "platform": platform,
        "num_indicators": len(regex_indicators),
        "det_written": False,
        "pos_written": False,
        "neg_written": False,
        "skipped_existing": False,
        "error": None,
    }

    if det_path.exists():
        result["skipped_existing"] = True
        return result

    if not regex_indicators:
        result["error"] = "no regex_indicators in spec"
        return result

    # Choose min_match: require at least 1, but if many indicators use 2
    min_match = 1 if len(regex_indicators) <= 2 else 2

    py_code = DETECTOR_TEMPLATE.format(
        spec_id=spec_id,
        pattern_id=pattern_id,
        platform=platform,
        indicator_patterns=regex_indicators,
        min_match=min_match,
    )

    if not dry_run:
        det_path.write_text(py_code, encoding="utf-8")
        result["det_written"] = True

        if positive_rs and not pos_path.exists():
            pos_path.write_text(positive_rs, encoding="utf-8")
            result["pos_written"] = True

        if negative_rs and not neg_path.exists():
            neg_path.write_text(negative_rs, encoding="utf-8")
            result["neg_written"] = True
    else:
        result["det_written"] = True  # would be written
        result["pos_written"] = bool(positive_rs)
        result["neg_written"] = bool(negative_rs)

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase7-dir",
                    default="/private/tmp/auditooor-overnight/phase7_outputs")
    ap.add_argument("--output-dir", default="/tmp/auditooor-r94-smoke")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--smoke", action="store_true",
                    help="Run inventory-smoke-rust.py after wiring")
    args = ap.parse_args()

    phase7_dir = Path(args.phase7_dir)
    out_dir = Path(args.output_dir)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(phase7_dir.glob("phase7_rust_fixture_*.json"))
    print(f"[info] found {len(files)} phase7 JSON files in {phase7_dir}")

    results = []
    written = 0
    skipped = 0
    errored = 0

    for f in files:
        spec = load_spec(f)
        if spec is None:
            errored += 1
            results.append({"spec_id": f.stem, "error": "parse_failed"})
            continue
        res = wire_spec(spec, dry_run=args.dry_run)
        results.append(res)
        if res.get("skipped_existing"):
            skipped += 1
        elif res.get("error"):
            errored += 1
        else:
            written += 1

    print(f"[info] wired={written} skipped_existing={skipped} errored={errored}")

    summary_path = out_dir / "r94_wire_summary.json" if not args.dry_run else Path("/tmp/r94_wire_summary.json")
    if not args.dry_run:
        summary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[info] summary → {summary_path}")

    if args.smoke and not args.dry_run:
        print("[info] running inventory-smoke-rust.py ...")
        smoke_script = Path(__file__).parent / "inventory-smoke-rust.py"
        ret = subprocess.run(
            [sys.executable, str(smoke_script),
             "--output-dir", str(out_dir),
             "--workers", "8"],
            cwd=str(REPO),
        )
        return ret.returncode

    return 0


if __name__ == "__main__":
    sys.exit(main())
