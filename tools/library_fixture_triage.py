#!/usr/bin/env python3
"""Library fixture triage (one-shot survey, NO edits to patterns).

Bucketise the YAML patterns under ``reference/patterns.dsl/`` that have no
paired ``<name>_vulnerable.sol`` / ``<name>_clean.sol`` fixture under
``detectors/test_fixtures/``. Bucketing is by the ``source:`` field of the
YAML, falling back to filename prefix when the field is missing.

Outputs JSON on stdout.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PATTERNS_DIR = REPO / "reference" / "patterns.dsl"
FIXTURES_DIR = REPO / "detectors" / "test_fixtures"

# ---------- helpers --------------------------------------------------------


def _pattern_to_under(name: str) -> str:
    return name.replace("-", "_")


def _read_source(path: Path) -> str:
    """Return the literal ``source:`` value (best-effort) of a YAML pattern.

    We do NOT load YAML — these files use unquoted multi-line freeform fields
    in ``wiki_*`` keys that PyYAML handles fine, but we want zero deps and a
    stable line-prefix scan that's robust to malformed stragglers.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        m = re.match(r'^\s*source\s*:\s*(.+?)\s*$', line)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return ""


def _bucket_for_source(source: str, pattern_name: str) -> str:
    """Map a source-citation string to a high-level bucket label."""
    s = (source or "").lower()
    n = (pattern_name or "").lower()

    # Filename-prefix overrides — these family prefixes are the fastest
    # signal even when source: is empty.
    if n.startswith("glider-") or n.startswith("glider_"):
        return "glider-family"
    if n.startswith("certora-") or n.startswith("certora_"):
        return "certora-family"
    if n.startswith("fx-") or n.startswith("fx_"):
        return "fx-family"
    if n.startswith("ec-") or n.startswith("ec_"):
        return "ec-family"
    if n.startswith("lisa-") or "lisa" in n.split("-")[0:1]:
        return "lisa-bench"

    if not s:
        return "synthetic-no-source"

    # Source-string prefixes
    if "glider" in s:
        return "glider-family"
    if "certora" in s:
        return "certora-family"
    if s.startswith("fx-") or "forta" in s:
        return "fx-family"
    if s.startswith("ec-") or "etherscan-catalog" in s or "etherscan_catalog" in s:
        return "ec-family"
    if "lisa" in s:
        return "lisa-bench"

    # Workspace-cited heuristic: source mentions auditooor-RNN or contains
    # a known workspace name.
    workspace_words = (
        "centrifuge", "monetrix", "morpho", "polymarket", "snowbridge",
        "thegraph", "kiln", "k2", "base-azul", "auditooor",
        "aave", "compound", "uniswap", "balancer", "lido",
    )
    if re.search(r'\bauditooor[-_]r\d+', s, re.IGNORECASE):
        return "workspace-cited"
    for w in workspace_words:
        if w in s:
            return "workspace-cited"

    if "fixdiff" in s or "exploit" in s or "post-mortem" in s or "rekt" in s:
        return "workspace-cited"

    return "synthetic-no-source"


# ---------- main -----------------------------------------------------------


def main() -> int:
    if not PATTERNS_DIR.is_dir():
        print(json.dumps({"error": "patterns dir missing"}))
        return 2
    if not FIXTURES_DIR.is_dir():
        print(json.dumps({"error": "fixtures dir missing"}))
        return 2

    yamls: list[Path] = sorted(
        p for p in PATTERNS_DIR.iterdir()
        if p.is_file() and p.suffix == ".yaml"
    )
    fx_vuln: set[str] = set()
    fx_clean: set[str] = set()
    for p in FIXTURES_DIR.iterdir():
        if not p.is_file() or p.suffix != ".sol":
            continue
        stem = p.stem
        if stem.endswith("_vulnerable"):
            fx_vuln.add(stem[: -len("_vulnerable")])
        elif stem.endswith("_clean"):
            fx_clean.add(stem[: -len("_clean")])

    buckets: dict[str, list[dict[str, str]]] = defaultdict(list)
    no_fixture_total = 0
    has_fixture_total = 0

    documentation_only = 0

    for y in yamls:
        name = y.stem
        under = _pattern_to_under(name)
        # Skip documentation-only YAMLs (status: documentation-only) — these
        # should not be in the fixture-less bucket because the consistency
        # check explicitly excludes them.
        text = y.read_text(encoding="utf-8", errors="replace")
        if re.search(r'^\s*status\s*:\s*documentation-only\b',
                     text, re.MULTILINE):
            documentation_only += 1
            continue

        has_vuln = under in fx_vuln
        has_clean = under in fx_clean
        if has_vuln or has_clean:
            has_fixture_total += 1
            continue

        no_fixture_total += 1
        source = _read_source(y)
        bucket = _bucket_for_source(source, name)
        buckets[bucket].append({
            "pattern": name,
            "source": source,
        })

    summary = {
        "total_yaml": len(yamls),
        "documentation_only_excluded": documentation_only,
        "has_fixture_total": has_fixture_total,
        "no_fixture_total": no_fixture_total,
        "fx_vuln_count": len(fx_vuln),
        "fx_clean_count": len(fx_clean),
        "buckets": {
            b: {
                "count": len(rows),
                "examples": [r["pattern"] for r in rows[:5]],
            }
            for b, rows in sorted(buckets.items())
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
