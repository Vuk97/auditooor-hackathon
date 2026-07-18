#!/usr/bin/env python3
"""no-yaml-synthesis.py — build LLM queue to reverse-engineer YAML DSL specs from orphan detectors.

For every detector that has no matching YAML in reference/patterns.dsl/, build one
prompt record that asks an LLM to read the .py source and emit the equivalent YAML.

Output queue: one JSONL line per detector, written to --queue-out.
Feed to the LLM via llm-dispatch.py + no-yaml-synthesis-wirer.py.

Usage:
    python3 tools/no-yaml-synthesis.py \\
        --inventory /private/tmp/auditooor-inventory/inventory_orphan_report.json \\
        --queue-out /tmp/no-yaml-synthesis-queue.jsonl \\
        [--limit N]          # process at most N entries (default: all)
        [--dry-run]          # print queue size + first entry, no file written
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
PATTERN_DSL_MD = REPO / "reference" / "PATTERN_DSL.md"

# One-shot example YAML: a well-formed, mid-complexity Solidity pattern that uses
# several predicate classes (preconditions + match + regex + skip-list).
EXAMPLE_YAML_PATH = DSL_DIR / "aave-auto-collateral-enable-isolated-or-ltv-zero.yaml"

# Fixture search roots — checked in order; first match wins.
_FIXTURE_ROOTS = [
    REPO / "patterns" / "fixtures",
    REPO / "detectors" / "test_fixtures",
]

_DELIM_FORMAT = """\
===BEGIN_YAML===
<full YAML matching the detector's logic>
===END_YAML===
===BEGIN_RATIONALE===
<one paragraph explaining the mapping from Python logic to DSL predicates>
===END_RATIONALE===
===BEGIN_METADATA===
argument: <kebab>
source_py: detectors/.../<id>.py
===END_METADATA==="""


def _load_inventory(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    orphans = data.get("detector_orphans", [])
    return [x for x in orphans if not x.get("has_yaml", True)]


def _read_py(rel_path: str) -> str | None:
    p = REPO / rel_path
    if p.exists():
        return p.read_text(errors="replace")
    return None


def _find_fixtures(argument: str) -> dict:
    """Return {vuln: Path|None, clean: Path|None} for fixture .sol files."""
    slug = argument.replace("-", "_")
    candidates = {
        "vuln": [f"{slug}_vuln.sol", f"{slug}_vulnerable.sol", f"{slug}_bad.sol"],
        "clean": [f"{slug}_clean.sol", f"{slug}_safe.sol"],
    }
    result: dict[str, Path | None] = {"vuln": None, "clean": None}
    for label, names in candidates.items():
        for root in _FIXTURE_ROOTS:
            for name in names:
                p = root / name
                if p.exists():
                    result[label] = p
                    break
            if result[label]:
                break
    return result


def _pick_example_yaml() -> str:
    if EXAMPLE_YAML_PATH.exists():
        return EXAMPLE_YAML_PATH.read_text()
    # Fallback: grab the first YAML we find
    for p in sorted(DSL_DIR.glob("*.yaml")):
        return p.read_text()
    return "# (no example YAML found)"


def _read_dsl_md() -> str:
    if PATTERN_DSL_MD.exists():
        return PATTERN_DSL_MD.read_text()
    return "# (PATTERN_DSL.md not found)"


def _build_prompt(entry: dict, py_source: str, dsl_md: str, example_yaml: str,
                  fixtures: dict) -> str:
    argument = entry["argument"]
    py_path = entry.get("py_path", "unknown")
    wave = entry.get("wave", "unknown")

    fixture_block = ""
    for label, p in fixtures.items():
        if p:
            snippet = p.read_text(errors="replace")[:2000]
            fixture_block += f"\n--- EXISTING FIXTURE ({label}) ---\n{snippet}\n"

    prompt = f"""You are a smart contract security auditor and DSL compiler author.

Your task: reverse-engineer the YAML DSL spec for an existing Slither detector.

## Context

The auditooor project uses a Pattern DSL (patterns.dsl/) to describe vulnerability
detectors declaratively. A compiler (tools/pattern-compile.py) turns each YAML into
a runnable Slither detector. Some older hand-written detectors predate the DSL and
have no YAML equivalent. You must produce one.

## Detector metadata

- argument: {argument}
- source file: {py_path}
- wave: {wave}

## Detector source (.py)

```python
{py_source[:6000]}
```

## Supported DSL predicates (reference/PATTERN_DSL.md excerpt)

{dsl_md[:4000]}

## Example YAML (reference one-shot)

```yaml
{example_yaml[:2000]}
```
{fixture_block}
## Your output

Emit EXACTLY the four sections below, in order, with no extra text before or after.
Inside each section write content VERBATIM with REAL newlines — no \\n escapes,
no markdown fences, no JSON encoding.

{_DELIM_FORMAT}

Rules:
- `pattern:` field MUST be the kebab-case argument: `{argument}`
- Only use predicate keys listed in PATTERN_DSL.md. If the Python logic has no
  clean DSL equivalent, use `function.body_contains_regex` or
  `contract.source_matches_regex` as escape hatches.
- If the detector uses a non-Solidity backend (Rust, Anchor, Cosmos, etc.),
  set `backend:` accordingly.
- The YAML must be self-contained and compilable by tools/pattern-compile.py.
- severity/confidence must match the IMPACT/CONFIDENCE set in the Python class.
- Do NOT invent fixture paths that do not exist on disk.
"""
    return prompt


def build_queue(inventory_path: Path, limit: int = 0) -> list[dict]:
    no_yaml = _load_inventory(inventory_path)
    if limit > 0:
        no_yaml = no_yaml[:limit]

    dsl_md = _read_dsl_md()
    example_yaml = _pick_example_yaml()
    queue: list[dict] = []

    for entry in no_yaml:
        argument = entry.get("argument", "")
        py_path = entry.get("py_path", "")
        if not argument or not py_path:
            continue

        py_source = _read_py(py_path)
        if not py_source:
            # Skip if .py doesn't exist on disk
            continue

        fixtures = _find_fixtures(argument)
        prompt = _build_prompt(entry, py_source, dsl_md, example_yaml, fixtures)

        record = {
            "schema": "auditooor.no-yaml-synthesis.v1",
            "argument": argument,
            "source_py": py_path,
            "wave": entry.get("wave", ""),
            "fixture_vuln": str(fixtures["vuln"]) if fixtures["vuln"] else None,
            "fixture_clean": str(fixtures["clean"]) if fixtures["clean"] else None,
            "prompt": prompt,
        }
        queue.append(record)

    return queue


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--inventory",
        default="/private/tmp/auditooor-inventory/inventory_orphan_report.json",
        help="Path to inventory_orphan_report.json",
    )
    ap.add_argument(
        "--queue-out",
        default="/tmp/no-yaml-synthesis-queue.jsonl",
        help="Output JSONL path",
    )
    ap.add_argument("--limit", type=int, default=0,
                    help="Max entries to enqueue (0 = all)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print queue size and first entry; do not write file")
    args = ap.parse_args()

    inventory_path = Path(args.inventory)
    if not inventory_path.exists():
        print(f"[error] inventory not found: {inventory_path}", file=sys.stderr)
        sys.exit(1)

    queue = build_queue(inventory_path, limit=args.limit)
    print(f"[no-yaml-synthesis] queue size: {len(queue)}", file=sys.stderr)

    if args.dry_run:
        if queue:
            first = dict(queue[0])
            first["prompt"] = first["prompt"][:500] + "... (truncated)"
            print(json.dumps(first, indent=2))
        return

    out_path = Path(args.queue_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for record in queue:
            fh.write(json.dumps(record) + "\n")

    print(f"[no-yaml-synthesis] wrote {len(queue)} records → {out_path}")


if __name__ == "__main__":
    main()
