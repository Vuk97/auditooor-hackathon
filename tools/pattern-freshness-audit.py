#!/usr/bin/env python3
"""
pattern-freshness-audit.py — score DSL pattern specs on staleness heuristics.

Scans reference/patterns.dsl/*.yaml and scores each pattern on heuristics that
correlate with false-positive risk or under-specification:

  H1  no `function.not_source_matches_regex` negation   (no FP guard)
  H2  no `contract.source_matches_regex` preamble       (no contract anchor)
  H3  severity: HIGH + confidence: LOW                   (suspicious combo)
  H4  name regex uses `\\w+` or `.*`                     (too broad)
  H5  fewer than 3 match predicates                      (under-specified)
  H6  git-last-modified > 60 days ago                    (bit-rotten)

Each heuristic contributes +1 to the staleness score. Patterns are ranked by
score (descending) and the top 30 are written to docs/PATTERN_FRESHNESS_AUDIT.md
alongside per-heuristic counts and top-10 remediation hints.

Exits 0 regardless — this is an advisory tool.

Usage:
    python3 tools/pattern-freshness-audit.py
    make freshness
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
OUT_DOC = ROOT / "docs" / "PATTERN_FRESHNESS_AUDIT.md"

STALE_DAYS = 60
STALE_SECONDS = STALE_DAYS * 86400
TOP_N = 30
TOP_REMEDIATE = 10


HEURISTICS = [
    ("H1", "no function.not_source_matches_regex negation (no FP guard)"),
    ("H2", "no contract.source_matches_regex preamble (no contract anchor)"),
    ("H3", "severity HIGH + confidence LOW (suspicious combo)"),
    ("H4", "name regex uses \\w+ or .* (too broad)"),
    ("H5", "fewer than 3 match predicates (under-specified)"),
    ("H6", "git last-modified > 60 days ago (bit-rotten)"),
]


REMEDIATION = {
    "H1": "Add `function.not_source_matches_regex: <safe-sugar-or-guarded-shape>` to cut FPs from safe variants.",
    "H2": "Add `preconditions: - contract.source_matches_regex: <anchor-symbol>` to limit scan to relevant contracts.",
    "H3": "Lower severity to MEDIUM or raise confidence — HIGH/LOW is a ranking-system smell.",
    "H4": "Tighten name regex — replace `\\w+` / `.*` with an explicit alternation of real function names.",
    "H5": "Add more match predicates (body_contains / body_not_contains / negations) — 3+ specifics cut FPs sharply.",
    "H6": "Re-review against recent Solodit findings; refresh `source:` and regen fixtures if shape drifted.",
}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _simple_yaml_value(text: str, key: str) -> str | None:
    """Cheap top-level scalar extractor — avoids requiring PyYAML."""
    m = re.search(rf"^{re.escape(key)}\s*:\s*([A-Za-z0-9_\-]+)\s*$", text, re.MULTILINE)
    return m.group(1) if m else None


def _count_match_predicates(text: str) -> int:
    """Count `- function.xxx:` / `- contract.xxx:` bullets inside the match: block."""
    lines = text.splitlines()
    in_match = False
    count = 0
    for line in lines:
        stripped = line.strip()
        if re.match(r"^match\s*:\s*$", stripped):
            in_match = True
            continue
        if in_match:
            # End of match block: any top-level key (no leading whitespace, ends with ':')
            if line and not line[0].isspace() and re.match(r"^[A-Za-z_][\w\-]*\s*:", line):
                in_match = False
                continue
            if stripped.startswith("- function.") or stripped.startswith("- contract."):
                count += 1
    return count


def _git_mtime(path: Path) -> float | None:
    """Unix timestamp of the last git commit touching `path`. None if not tracked."""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%ct", "--", str(path)],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return float(out.stdout.strip())
    except Exception:
        pass
    return None


def score_pattern(path: Path, now: float) -> dict[str, Any]:
    text = _read(path)
    hits: list[str] = []

    # H1: no function.not_source_matches_regex negation
    if "function.not_source_matches_regex" not in text:
        hits.append("H1")

    # H2: no contract.source_matches_regex preamble
    if "contract.source_matches_regex" not in text:
        hits.append("H2")

    # H3: severity HIGH + confidence LOW
    sev = (_simple_yaml_value(text, "severity") or "").upper()
    conf = (_simple_yaml_value(text, "confidence") or "").upper()
    if sev == "HIGH" and conf == "LOW":
        hits.append("H3")

    # H4: name regex uses \w+ or .*
    name_match = re.search(
        r"function\.name_matches\s*:\s*['\"]?([^'\"\n]+)['\"]?", text
    )
    if name_match:
        pattern_text = name_match.group(1)
        if r"\w+" in pattern_text or ".*" in pattern_text:
            hits.append("H4")

    # H5: fewer than 3 match predicates
    pred_count = _count_match_predicates(text)
    if pred_count < 3:
        hits.append("H5")

    # H6: git-mtime > 60 days
    mtime = _git_mtime(path)
    if mtime is not None and (now - mtime) > STALE_SECONDS:
        hits.append("H6")

    return {
        "name": path.stem,
        "path": path,
        "score": len(hits),
        "hits": hits,
        "severity": sev,
        "confidence": conf,
        "predicates": pred_count,
    }


def main() -> int:
    if not PATTERNS_DIR.is_dir():
        print(f"[freshness] missing {PATTERNS_DIR}", file=sys.stderr)
        return 0

    now = time.time()
    yaml_files = sorted(PATTERNS_DIR.glob("*.yaml"))
    results = [score_pattern(p, now) for p in yaml_files]

    per_heuristic: dict[str, int] = {h: 0 for h, _ in HEURISTICS}
    for r in results:
        for h in r["hits"]:
            per_heuristic[h] += 1

    results.sort(key=lambda r: (-r["score"], r["name"]))

    OUT_DOC.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Pattern Freshness Audit")
    lines.append("")
    lines.append(f"Generated by `tools/pattern-freshness-audit.py` — advisory only.")
    lines.append("")
    lines.append(f"- Patterns scanned: **{len(results)}**")
    lines.append(f"- Heuristics: **{len(HEURISTICS)}** (each worth +1 staleness)")
    lines.append("")
    lines.append("## Per-heuristic counts")
    lines.append("")
    lines.append("| ID | Heuristic | Count |")
    lines.append("|----|-----------|-------|")
    for h, desc in HEURISTICS:
        lines.append(f"| {h} | {desc} | {per_heuristic[h]} |")
    lines.append("")

    lines.append(f"## Top {TOP_N} stalest patterns")
    lines.append("")
    lines.append("| Rank | Score | Pattern | Trips |")
    lines.append("|-----:|------:|---------|-------|")
    for i, r in enumerate(results[:TOP_N], 1):
        trips = ",".join(r["hits"]) or "—"
        lines.append(f"| {i} | {r['score']} | `{r['name']}` | {trips} |")
    lines.append("")

    lines.append(f"## Recommended remediation (top {TOP_REMEDIATE})")
    lines.append("")
    for i, r in enumerate(results[:TOP_REMEDIATE], 1):
        # Pick the most impactful heuristic hit (first in H1..H6 order)
        ordered = [h for h, _ in HEURISTICS if h in r["hits"]]
        primary = ordered[0] if ordered else None
        fix = REMEDIATION.get(primary, "Review manually.") if primary else "Clean — no action."
        lines.append(f"{i}. `{r['name']}` (score {r['score']}) — {fix}")
    lines.append("")

    OUT_DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Stdout summary
    print(f"[freshness] scanned {len(results)} patterns → {OUT_DOC.relative_to(ROOT)}")
    print(f"[freshness] per-heuristic counts: " + ", ".join(
        f"{h}={per_heuristic[h]}" for h, _ in HEURISTICS
    ))
    print(f"[freshness] top 3:")
    for r in results[:3]:
        print(f"  score={r['score']}  {r['name']}  [{','.join(r['hits'])}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
