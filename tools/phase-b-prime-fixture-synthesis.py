#!/usr/bin/env python3
"""phase-b-prime-fixture-synthesis.py — fixture synthesis for YAML-with-source orphans.

Reads inventory_orphan_report.json. For each detector-orphan that:
  - has a YAML at reference/patterns.dsl/<arg>.yaml
  - the YAML has a `source:` ref (some Solodit/audit URL/citation)
  - the YAML is not `documentation_only`
  - no fixture exists at either detectors/test_fixtures/ or patterns/fixtures/

Build an LLM task asking for clean+vulnerable Solidity fixtures matching
the YAML's predicates. Output uses the delimiter format spec
(docs/llm-codegen-format-spec.md) so we don't repeat yesterday's
JSON-escape disaster.

After dispatch + smoke test, run inventory-bulk-promote to register passes.

Usage:
  python3 tools/phase-b-prime-fixture-synthesis.py \\
    --orphan-report /private/tmp/auditooor-inventory/inventory_orphan_report.json \\
    --queue-out /private/tmp/auditooor-inventory/phase_b_prime_queue.jsonl \\
    --prompts-dir /private/tmp/auditooor-inventory/phase_b_prime_prompts \\
    --outputs-dir /private/tmp/auditooor-inventory/phase_b_prime_outputs \\
    [--limit 50]   # process at most N orphans (debug)

The queue file is consumed by tools/overnight-llm-loop.sh in the usual way.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
TEST_FIXTURES_DIR = REPO / "detectors" / "test_fixtures"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orphan-report", required=True)
    ap.add_argument("--queue-out", required=True)
    ap.add_argument("--prompts-dir", required=True)
    ap.add_argument("--outputs-dir", required=True)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    report = json.loads(Path(args.orphan_report).read_text())
    detector_orphans = report["detector_orphans"]

    prompts_dir = Path(args.prompts_dir); prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir = Path(args.outputs_dir); outputs_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(args.queue_out); queue_path.parent.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    skipped_no_source = 0
    skipped_docs_only = 0
    skipped_no_yaml = 0

    for r in detector_orphans:
        arg = r["argument"]
        if not r.get("has_yaml"):
            skipped_no_yaml += 1
            continue
        if r.get("yaml_status") == "documentation_only":
            skipped_docs_only += 1
            continue
        if not r.get("yaml_source"):
            skipped_no_source += 1
            continue
        yaml_path = REPO / r["yaml_path"]
        try:
            yaml_text = yaml_path.read_text(encoding="utf-8")
        except Exception:
            continue

        # Build prompt
        snake = arg.replace("-", "_")
        prompt = textwrap.dedent(f"""\
            You are synthesizing a clean+vulnerable Solidity fixture pair to back
            a Slither detector specified by the YAML below. The detector already
            exists and has been compiled; we need test fixtures that exercise
            the YAML's predicates correctly.

            === DETECTOR ARGUMENT ===
            {arg}

            === DETECTOR YAML (reference/patterns.dsl/{arg}.yaml) ===
            {yaml_text}
            === END YAML ===

            === REQUIREMENTS ===

            Produce TWO Solidity 0.8.x source files:
              1. **vulnerable.sol** — a self-contained contract (or contracts)
                 that EXHIBITS the bug pattern described by the YAML's
                 `match:` predicates. The detector MUST fire ≥1 time on this
                 fixture.
              2. **clean.sol** — a self-contained contract (or contracts)
                 that DO NOT exhibit the bug. Minimal differences from the
                 vulnerable variant; e.g. the missing check IS present, or
                 the missing modifier IS applied. The detector MUST NOT fire.

            Both files:
              - SPDX-License-Identifier: MIT
              - pragma solidity ^0.8.20;
              - 50–150 LOC each
              - Self-contained: no external imports beyond standard things
                like IERC20 declared inline
              - Compile cleanly with solc 0.8.20+
              - DO NOT use the literal class names from the YAML's source —
                pick fresh, descriptive names

            Read the YAML's `match:` predicates carefully. The vulnerable
            fixture must satisfy EVERY predicate in `match`. The clean fixture
            must violate at least ONE (typically by adding the missing check
            or removing the trigger pattern).

            === OUTPUT FORMAT (STRICT) ===

            Output ONLY three sections, in this exact order, separated by the
            shown delimiter lines. Inside each section, write Solidity
            VERBATIM with REAL newlines — no \\n, no escapes, no markdown
            fences.

            ===BEGIN_VULNERABLE_SOL===
            <the vulnerable Solidity fixture verbatim>
            ===END_VULNERABLE_SOL===
            ===BEGIN_CLEAN_SOL===
            <the clean Solidity fixture verbatim>
            ===END_CLEAN_SOL===
            ===BEGIN_METADATA===
            argument: {arg}
            snake: {snake}
            ===END_METADATA===

            Be precise. The wirer will write your fixtures to
            detectors/test_fixtures/{snake}_{{vulnerable,clean}}.sol and run
            slither smoke; if vulnerable_hits == 0 OR clean_hits > 0, the
            fixture pair is rejected.
        """)

        prompt_path = prompts_dir / f"phase_b_prime_{snake}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        out_path = outputs_dir / f"phase_b_prime_{snake}.json"
        tasks.append({
            "task_id": f"phase-b-prime-{arg}",
            "provider": "minimax",
            "task_type": "fixture-synthesis",
            "prompt_path": str(prompt_path),
            "output_path": str(out_path),
            "max_tokens": 8000,
        })

    if args.limit:
        tasks = tasks[: args.limit]

    with queue_path.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")

    print(f"phase-b-prime queue: {queue_path}")
    print(f"  total tasks: {len(tasks)}")
    print(f"  skipped (no YAML): {skipped_no_yaml}")
    print(f"  skipped (docs_only): {skipped_docs_only}")
    print(f"  skipped (no source): {skipped_no_source}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
