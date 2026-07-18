#!/usr/bin/env python3
"""architectural-mismatch-fixture-redesign.py — build LLM redesign queue for the
77 Tier-D detectors flagged as architectural-mismatch by silent-detector-diagnostic.

CONTEXT
-------
silent-detector-diagnostic.py classifies silent Tier-D detectors into four
buckets. The "architectural-mismatch" bucket means the YAML predicates compile
and look right, but the fixture lacks the *structural anchor* the detector
expects — wrong function name, missing cross-contract reach, vuln logic stuck
in a leaf helper that the detector explicitly excludes, etc.

For each such detector this builder emits ONE LLM task asking the model to:
  1. Read the current vulnerable fixture
  2. Read the YAML's `match` block predicates (and preconditions)
  3. Identify which structural property the fixture is missing
  4. Generate a NEW vulnerable fixture that satisfies every predicate
  5. Generate a NEW clean variant that violates exactly one predicate

OUTPUT FORMAT (per docs/llm-codegen-format-spec.md, delimiter-based — no JSON)
  ===BEGIN_REDESIGNED_VUNERABLE_SOL=== ... ===END_REDESIGNED_VUNERABLE_SOL===
  ===BEGIN_REDESIGNED_CLEAN_SOL===     ... ===END_REDESIGNED_CLEAN_SOL===
  ===BEGIN_RATIONALE===                 ... ===END_RATIONALE===
  ===BEGIN_METADATA===                  ... ===END_METADATA===

Inputs:
  --diagnostic   silent_detector_diagnostic.json (classifications)
  --revival      tier_d_revival_summary.json (fixture paths join key)
  --queue-out    JSONL where each line is one LLM task
  --prompts-dir  directory to drop one .txt prompt per detector
  --outputs-dir  directory the runner will populate with one .txt per detector

This script does NOT call any LLM. It just builds the queue + prompts on disk.
The downstream runner is overnight-llm-loop.sh which fans out the queue to
LLM workers and writes outputs to outputs-dir.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DIAGNOSTIC_DEFAULT = Path("/private/tmp/auditooor-inventory/silent_detector_diagnostic.json")
REVIVAL_DEFAULT = Path("/private/tmp/auditooor-inventory/tier_d_revival_summary.json")
TARGET_BUCKET = "architectural-mismatch"


def _safe_read(p: Path, max_bytes: int = 12_000) -> str:
    """Read a file, truncating to avoid blowing the LLM context."""
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return f"<<could not read {p}: {exc}>>"
    if len(text) > max_bytes:
        head = text[: max_bytes - 200]
        return head + f"\n\n<<... truncated ({len(text) - max_bytes + 200} bytes) ...>>\n"
    return text


def _to_snake(arg: str) -> str:
    return arg.replace("-", "_")


def _build_prompt(arg: str, snake: str, yaml_text: str, vuln_text: str,
                  reasons: list[str]) -> str:
    reason_block = "\n".join(f"  - {r}" for r in (reasons or ["(diagnostic gave no reason)"]))
    return textwrap.dedent(f"""\
        You are repairing a Slither pattern fixture. The detector's YAML
        predicates are correct, but the existing vulnerable fixture does not
        contain the STRUCTURAL ANCHOR the detector expects. Common shapes:

          - YAML wants `function callback(...)` (specific name) but fixture
            has `targetFn(...)` — wrong name.
          - YAML wants cross-contract reach `ContractX.fnY` but fixture is
            single-contract — no second contract for the call to land in.
          - YAML excludes leaf-helpers (functions called by no-one inside the
            contract) but the fixture's vuln logic IS in a leaf helper.
          - YAML requires a contract precondition (ERC4626 / inherits Pausable
            / has state var of given shape) that the fixture does not model.

        Detector argument:    {arg}
        Detector snake_id:    {snake}

        Diagnostic-engine reasons the fixture currently fails to fire:
        {reason_block}

        ───── YAML predicate file (the source of truth) ─────────────────────
        {yaml_text}

        ───── Current vulnerable fixture (the file to redesign) ─────────────
        {vuln_text}

        ───── Your task ──────────────────────────────────────────────────────
        1. Read the YAML `match:` block. Enumerate every predicate.
        2. Read the YAML `preconditions:` block (if any) — those gate
           contract-level structure (interface tags, inheritance, state vars).
        3. Compare against the existing fixture. Identify the ONE structural
           property the fixture is missing — name it explicitly in the
           rationale.
        4. Emit a NEW vulnerable fixture that satisfies EVERY predicate
           (positive matches hit, negatives don't fire, preconditions hold).
        5. Emit a NEW clean variant that violates EXACTLY ONE predicate from
           the match block — no more, no less. The clean must compile and be
           realistic Solidity, not a stub.

        Hard constraints:
          - Solidity ^0.8.0 unless the YAML explicitly anchors a different
            pragma. Always use `pragma solidity ^0.8.0;`.
          - Both files must compile under solc 0.8.x without external imports.
          - Inline minimal interfaces / mock contracts when the YAML demands
            cross-contract reach — keep the file self-contained.
          - Do NOT add comments that name the predicate ("// matches X regex"),
            since some detectors use comment-line negative anchors. Keep
            comments natural.

        Output FOUR sections in this exact order, separated by the literal
        delimiter lines below. Inside each section, write VERBATIM source —
        real newlines, real quotes, no escape sequences, no markdown fences.

        ===BEGIN_REDESIGNED_VUNERABLE_SOL===
        <full Solidity source for the new vulnerable fixture>
        ===END_REDESIGNED_VUNERABLE_SOL===
        ===BEGIN_REDESIGNED_CLEAN_SOL===
        <full Solidity source for the new clean fixture>
        ===END_REDESIGNED_CLEAN_SOL===
        ===BEGIN_RATIONALE===
        <one paragraph: which predicate the original fixture was missing,
        what new structure was added, which predicate the clean variant now
        violates>
        ===END_RATIONALE===
        ===BEGIN_METADATA===
        argument: {arg}
        snake: {snake}
        redesign_reason: architectural-mismatch
        ===END_METADATA===
        """)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--diagnostic", default=str(DIAGNOSTIC_DEFAULT))
    ap.add_argument("--revival", default=str(REVIVAL_DEFAULT))
    ap.add_argument("--queue-out", required=True)
    ap.add_argument("--prompts-dir", required=True)
    ap.add_argument("--outputs-dir", required=True)
    ap.add_argument("--max-tasks", type=int, default=0,
                    help="If >0, only emit this many tasks (debug).")
    args = ap.parse_args()

    diag = json.loads(Path(args.diagnostic).read_text())
    rev = json.loads(Path(args.revival).read_text())

    # Build join index from revival summary: argument -> {vuln_fixture, clean_fixture}.
    rev_index = {row["argument"]: row for row in rev["classifications"]["viable_for_smoke"]}

    arch_rows = [c for c in diag["classifications"] if c["bucket"] == TARGET_BUCKET]
    if args.max_tasks > 0:
        arch_rows = arch_rows[: args.max_tasks]

    prompts_dir = Path(args.prompts_dir); prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir = Path(args.outputs_dir); outputs_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(args.queue_out); queue_path.parent.mkdir(parents=True, exist_ok=True)

    skipped = []
    tasks = []
    for row in arch_rows:
        arg = row["argument"]
        snake = _to_snake(arg)
        rev_row = rev_index.get(arg)
        if rev_row is None:
            skipped.append({"argument": arg, "reason": "no-revival-row (cannot locate fixtures)"})
            continue
        yaml_path = REPO / row["yaml_path"]
        vuln_path = REPO / rev_row["vuln_fixture"]
        clean_path = REPO / rev_row["clean_fixture"]
        if not yaml_path.is_file() or not vuln_path.is_file():
            skipped.append({"argument": arg,
                            "reason": f"missing-on-disk yaml={yaml_path.is_file()} vuln={vuln_path.is_file()}"})
            continue

        yaml_text = _safe_read(yaml_path)
        vuln_text = _safe_read(vuln_path)
        prompt = _build_prompt(arg, snake, yaml_text, vuln_text, row.get("reasons", []))

        prompt_path = prompts_dir / f"redesign_{snake}.txt"
        output_path = outputs_dir / f"redesign_{snake}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "argument": arg,
            "snake": snake,
            "yaml_path": str(yaml_path.relative_to(REPO)),
            "vuln_fixture": str(vuln_path.relative_to(REPO)),
            "clean_fixture": str(clean_path.relative_to(REPO)),
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "reasons": row.get("reasons", []),
            "redesign_reason": "architectural-mismatch",
        })

    with queue_path.open("w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")

    print(f"[queue] arch-mismatch input rows: {len(arch_rows)}")
    print(f"[queue] tasks emitted:            {len(tasks)}")
    print(f"[queue] skipped:                  {len(skipped)}")
    for s in skipped[:10]:
        print(f"   - {s['argument']}: {s['reason']}")
    print(f"[queue] queue file:               {queue_path}")
    print(f"[queue] prompts dir:              {prompts_dir}")
    print(f"[queue] outputs dir (to-be-fed):  {outputs_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
