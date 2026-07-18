#!/usr/bin/env python3
"""fixture-shape-audit.py - report which vuln/clean fixture pairs differ
ONLY in cosmetic / template-shape ways (e.g. add or remove a single
require()), so they cannot exercise the real bug class.

Why this exists (PR #607 root cause):
  fp_repair_v2 produced 91/91 fakes because the underlying fixture pairs
  were wave-14 phase-B-prime synthesis output: every pair differs by a
  single `require(newVal <= 10000, "cap");` line. Asked to distinguish
  such a pair, an LLM correctly emits a fixture-shape predicate that
  encodes nothing about the real bug class.

  This tool walks `detectors/test_fixtures/<arg>_vulnerable.sol` /
  `<arg>_clean.sol` pairs and classifies the diff:

    - identical:        vuln == clean (broken pair).
    - cosmetic_require: only diff is +/- exactly one `require(...);` line
                        (after stripping wave-14 contract-name template
                         suffix `Vulnerable`/`Clean`).
    - cosmetic_minor:   total non-whitespace, non-comment diff <= 80 chars.
    - structural:       diff is larger / multi-line / non-trivial. Likely OK.
    - parse_error:      unable to read one of the files.

  Operators use the report to decide which pairs to regenerate before
  re-running fp_repair with the new prompt.

Usage:
  python3 tools/fixture-shape-audit.py \\
    [--fixtures-dir detectors/test_fixtures] \\
    [--out-json reports/fixture_shape_audit.json] \\
    [--out-md docs/FIXTURE_SHAPE_AUDIT_2026-05-04.md] \\
    [--limit-args N]   # debug: only audit the first N pairs

Exit codes:
  0 - completed (report always written if paths are given)
  2 - bad input
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = REPO / "detectors" / "test_fixtures"

# Heuristic: a pair classified as "cosmetic_require" iff the diff is
# exactly one added or removed line that LOOKS like a require/revert/assert
# guard. We tolerate variations on whitespace and the message argument.
RE_REQUIRE_LIKE = re.compile(
    r"^\s*(?:require|assert|revert)\b.*$"
)

COMMENT_LINE = re.compile(r"^\s*(?://.*)?$")

# Wave-14 phase-B-prime fixtures swap a `Vulnerable` / `Clean` suffix on the
# contract name in the otherwise-identical pair. That diff is template-shape
# noise and should not count toward the "is this a real structural diff"
# decision.
RE_CONTRACT_NAME_VULN = re.compile(r"^\s*contract\s+\w+Vulnerable\b.*$")
RE_CONTRACT_NAME_CLEAN = re.compile(r"^\s*contract\s+\w+Clean\b.*$")


def _is_template_contract_name_pair(removed: str, added: str) -> bool:
    return bool(
        RE_CONTRACT_NAME_VULN.match(removed)
        and RE_CONTRACT_NAME_CLEAN.match(added)
    )


def _strip_comments_and_blank(text: str) -> list[str]:
    """Return the lines that materially affect Solidity behavior."""
    out: list[str] = []
    in_block = False
    for raw in text.splitlines():
        ln = raw.rstrip()
        if in_block:
            if "*/" in ln:
                in_block = False
                ln = ln.split("*/", 1)[1]
            else:
                continue
        # strip /* ... */ on a single line
        while "/*" in ln and "*/" in ln:
            i = ln.find("/*"); j = ln.find("*/", i + 2)
            ln = ln[:i] + ln[j + 2:]
        if "/*" in ln:
            in_block = True
            ln = ln.split("/*", 1)[0]
        if COMMENT_LINE.match(ln):
            continue
        # strip trailing // comments
        if "//" in ln:
            ln = ln.split("//", 1)[0].rstrip()
            if not ln.strip():
                continue
        out.append(ln)
    return out


def _classify_pair(vuln_path: Path, clean_path: Path) -> dict:
    try:
        vuln_raw = vuln_path.read_text(encoding="utf-8", errors="replace")
        clean_raw = clean_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {"shape_class": "parse_error", "error": str(exc)}

    if vuln_raw == clean_raw:
        return {"shape_class": "identical"}

    vuln_lines = _strip_comments_and_blank(vuln_raw)
    clean_lines = _strip_comments_and_blank(clean_raw)

    # Build the unified-diff line list (added / removed).
    diff = list(difflib.unified_diff(vuln_lines, clean_lines, lineterm=""))
    added = [d[1:].strip() for d in diff if d.startswith("+") and not d.startswith("+++")]
    removed = [d[1:].strip() for d in diff if d.startswith("-") and not d.startswith("---")]

    added_nonempty = [a for a in added if a]
    removed_nonempty = [r for r in removed if r]

    # Wave-14 template noise: drop matching `contract X Vulnerable` /
    # `contract X Clean` line pairs from the diff before classifying.
    drop_added: set[int] = set()
    drop_removed: set[int] = set()
    for ri, r in enumerate(removed_nonempty):
        if not RE_CONTRACT_NAME_VULN.match(r):
            continue
        for ai, a in enumerate(added_nonempty):
            if ai in drop_added:
                continue
            if _is_template_contract_name_pair(r, a):
                drop_added.add(ai)
                drop_removed.add(ri)
                break
    added_nonempty = [a for i, a in enumerate(added_nonempty) if i not in drop_added]
    removed_nonempty = [r for i, r in enumerate(removed_nonempty) if i not in drop_removed]

    # cosmetic_require: net change is one require/revert/assert line
    # added or removed, with no other material diff.
    if (len(added_nonempty) + len(removed_nonempty)) == 1:
        only = added_nonempty[0] if added_nonempty else removed_nonempty[0]
        if RE_REQUIRE_LIKE.match(only):
            return {
                "shape_class": "cosmetic_require",
                "only_diff_line": only,
                "side_added": bool(added_nonempty),
            }
        # single line but not a guard - still cosmetic_minor
        return {
            "shape_class": "cosmetic_minor",
            "only_diff_line": only,
            "side_added": bool(added_nonempty),
        }

    # Sum the absolute char-delta as a rough proxy for "is the diff trivial".
    char_delta = sum(len(s) for s in added_nonempty + removed_nonempty)
    if char_delta == 0:
        # Diff was 100% template noise (contract-name suffix only).
        return {"shape_class": "cosmetic_minor", "char_delta": 0,
                "note": "only contract-name template-suffix differs"}
    if char_delta <= 80:
        return {
            "shape_class": "cosmetic_minor",
            "added_lines_count": len(added_nonempty),
            "removed_lines_count": len(removed_nonempty),
            "char_delta": char_delta,
        }

    return {
        "shape_class": "structural",
        "added_lines_count": len(added_nonempty),
        "removed_lines_count": len(removed_nonempty),
        "char_delta": char_delta,
    }


def _walk_pairs(fixtures_dir: Path) -> list[tuple[str, Path, Path]]:
    """Yield (arg, vuln_path, clean_path) for every paired fixture."""
    pairs: list[tuple[str, Path, Path]] = []
    seen: set[str] = set()
    for path in fixtures_dir.glob("*_vulnerable.sol"):
        snake = path.name[: -len("_vulnerable.sol")]
        if snake in seen:
            continue
        seen.add(snake)
        clean = fixtures_dir / f"{snake}_clean.sol"
        if not clean.exists():
            continue
        arg = snake.replace("_", "-")
        pairs.append((arg, path, clean))
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES))
    ap.add_argument("--out-json", default=str(REPO / "reports" / "fixture_shape_audit.json"))
    ap.add_argument("--out-md", default=str(REPO / "docs" / "FIXTURE_SHAPE_AUDIT_2026-05-04.md"))
    ap.add_argument("--limit-args", type=int, default=0)
    args = ap.parse_args()

    fixtures_dir = Path(args.fixtures_dir)
    if not fixtures_dir.is_dir():
        print(f"[fixture-shape-audit] no such directory: {fixtures_dir}")
        return 2

    pairs = _walk_pairs(fixtures_dir)
    if args.limit_args:
        pairs = pairs[: args.limit_args]

    rows: list[dict] = []
    counter: Counter = Counter()
    require_diff_counter: Counter = Counter()

    for arg, vuln_path, clean_path in pairs:
        cls = _classify_pair(vuln_path, clean_path)
        counter[cls["shape_class"]] += 1
        if cls["shape_class"] == "cosmetic_require":
            require_diff_counter[cls.get("only_diff_line", "")] += 1
        rows.append({
            "argument": arg,
            "vuln_fixture": str(vuln_path.relative_to(REPO)),
            "clean_fixture": str(clean_path.relative_to(REPO)),
            **cls,
        })

    # Sort: cosmetic_require first, then identical, then cosmetic_minor, then structural.
    sort_order = {
        "identical": 0,
        "cosmetic_require": 1,
        "cosmetic_minor": 2,
        "structural": 3,
        "parse_error": 9,
    }
    rows.sort(key=lambda r: (sort_order.get(r["shape_class"], 99), r["argument"]))

    report = {
        "schema": "auditooor.fixture_shape_audit.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "fixtures_dir": str(fixtures_dir.relative_to(REPO)),
        "total_pairs": len(rows),
        "shape_class_counts": dict(counter),
        "top_cosmetic_require_diff_lines": require_diff_counter.most_common(10),
        "rows": rows,
    }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_lines: list[str] = []
    md_lines.append("# Fixture Shape Audit - 2026-05-04")
    md_lines.append("")
    md_lines.append("Generated by `tools/fixture-shape-audit.py` (PR ACT5).")
    md_lines.append("")
    md_lines.append(
        "Background: PR #607 quarantined 91 fake fp_repair_v2 outputs that "
        "collapsed to a single regex predicate. Root cause was upstream: "
        "wave-14 phase-B-prime fixture synthesis produced vuln/clean pairs "
        "that differ only in one cosmetic `require(...);` line, so the LLM "
        "encoded that diff instead of the bug class. This audit catalogs "
        "every fixture pair by shape so operators can decide which pairs "
        "to regenerate before re-running fp_repair with the new prompt."
    )
    md_lines.append("")
    md_lines.append(f"- Total fixture pairs: **{len(rows)}**")
    for k in ("identical", "cosmetic_require", "cosmetic_minor", "structural", "parse_error"):
        md_lines.append(f"- shape_class={k}: **{counter.get(k, 0)}**")
    md_lines.append("")
    md_lines.append("## Top recurring `cosmetic_require` diff lines")
    md_lines.append("")
    md_lines.append("| count | diff line |")
    md_lines.append("|---:|---|")
    for ln, n in require_diff_counter.most_common(10):
        md_lines.append(f"| {n} | `{ln}` |")
    md_lines.append("")
    md_lines.append("## Sample arguments per shape_class (first 10 each)")
    md_lines.append("")
    by_class: dict[str, list[dict]] = {}
    for r in rows:
        by_class.setdefault(r["shape_class"], []).append(r)
    for cls in ("identical", "cosmetic_require", "cosmetic_minor", "structural", "parse_error"):
        members = by_class.get(cls, [])
        if not members:
            continue
        md_lines.append(f"### {cls} ({len(members)} pairs)")
        md_lines.append("")
        for r in members[:10]:
            md_lines.append(f"- `{r['argument']}`")
        if len(members) > 10:
            md_lines.append(f"- ... ({len(members) - 10} more)")
        md_lines.append("")
    md_lines.append("## Operator action items")
    md_lines.append("")
    md_lines.append(
        "1. Pairs in `identical` and `cosmetic_require` cannot meaningfully "
        "exercise their bug class. Regenerate via "
        "`tools/exploit-anchor-fixtures/` or hand-write before re-running "
        "fp_repair on those arguments."
    )
    md_lines.append(
        "2. Pairs in `cosmetic_minor` are suspect; spot-check before "
        "running fp_repair on them."
    )
    md_lines.append(
        "3. Pairs in `structural` are likely usable as-is."
    )
    md_lines.append(
        "4. Even with structural pairs, the rewritten fp_repair prompt "
        "(PR ACT5) ignores fixture diffs and encodes from audit text, so "
        "operators can re-run without first regenerating fixtures - but "
        "expect cosmetic-pair tasks to smoke-fail more often, since the "
        "bug-class predicate may not match the cosmetic stand-in. Smoke "
        "fail is preferred to fake pass."
    )
    md_lines.append("")
    md_lines.append("Full machine-readable report: "
                    f"`{out_json.relative_to(REPO)}`.")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"[fixture-shape-audit] {len(rows)} pairs classified")
    for k in ("identical", "cosmetic_require", "cosmetic_minor", "structural", "parse_error"):
        print(f"  {k}: {counter.get(k, 0)}")
    print(f"  json -> {out_json}")
    print(f"  md   -> {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
