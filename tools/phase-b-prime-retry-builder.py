#!/usr/bin/env python3
"""phase-b-prime-retry-builder.py — build retry queue for Phase B-prime smoke failures.

Reads a Phase B-prime wirer summary JSON. For each non-pass result (silent,
false_positive, parse_failed) that hasn't exceeded the retry cap (2 rounds),
builds a follow-up LLM task with targeted feedback and emits a JSONL queue
consumable by tools/phase-b-prime-wirer.py.

Usage:
  python3 tools/phase-b-prime-retry-builder.py \\
    --summary /private/tmp/auditooor-inventory/phase_b_prime_loop1_summary.json \\
    --queue-out /private/tmp/auditooor-inventory/phase_b_prime_retry_queue.jsonl \\
    --prompts-dir /private/tmp/auditooor-inventory/phase_b_prime_retry_prompts \\
    --outputs-dir /private/tmp/auditooor-inventory/phase_b_prime_retry_outputs \\
    [--max-round 2]  # default 2
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"

_DELIM_RE = re.compile(
    r"===BEGIN_VULNERABLE_SOL===\s*(.*?)\s*===END_VULNERABLE_SOL==="
    r".*?===BEGIN_CLEAN_SOL===\s*(.*?)\s*===END_CLEAN_SOL==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)

MAX_ROUND_DEFAULT = 2

# ── feedback templates ────────────────────────────────────────────────────────

_FEEDBACK_SILENT = textwrap.dedent("""\
    === RETRY FEEDBACK (round {round}) ===
    FAILURE MODE: silent (vuln_hits=0, clean_hits=0)

    Your previous vulnerable fixture did NOT trigger the detector at all.
    Read the YAML's `match:` predicates very carefully and produce a
    vulnerable fixture that EXPLICITLY contains EVERY required pattern:
      - Each `function.body_contains_regex` must appear verbatim in the
        function body. Do not paraphrase or abstract it away.
      - The function name must match `function.name_matches`.
      - The function visibility must match `function.kind`.
    Do not rely on semantic equivalence — the detector is regex-based.

""")

_FEEDBACK_FALSE_POSITIVE = textwrap.dedent("""\
    === RETRY FEEDBACK (round {round}) ===
    FAILURE MODE: false_positive (vuln_hits={vh}, clean_hits={ch})

    Your clean fixture ALSO fired the detector. The clean contract must NOT
    contain the vulnerable pattern. Specifically:
      - Look at each `function.body_contains_regex` predicate in the YAML.
      - Identify which regex matched in your clean fixture.
      - Remove or rewrite that pattern in the clean contract so it no longer
        appears. The clean contract should demonstrate the CORRECT/SAFE
        implementation that avoids the bug.
      - Your vulnerable fixture may remain the same if it already passes
        (vuln_hits >= 1). Re-emit it unchanged if so.

""")

_FEEDBACK_PARSE_FAILED = textwrap.dedent("""\
    === RETRY FEEDBACK (round {round}) ===
    FAILURE MODE: parse_failed

    Your previous output did not follow the required delimiter format,
    or was truncated. Re-emit your answer using EXACTLY this structure
    with NO deviations — no markdown, no extra text between sections:

    ===BEGIN_VULNERABLE_SOL===
    <your vulnerable Solidity here>
    ===END_VULNERABLE_SOL===
    ===BEGIN_CLEAN_SOL===
    <your clean Solidity here>
    ===END_CLEAN_SOL===
    ===BEGIN_METADATA===
    argument: <kebab-argument>
    snake: <snake_argument>
    retry_round: {round}
    ===END_METADATA===

    Do NOT wrap sections in markdown code fences. Do NOT truncate.

""")


def feedback_for(status: str, vuln_hits: int | None, clean_hits: int | None,
                 retry_round: int) -> str:
    vh = vuln_hits or 0
    ch = clean_hits or 0
    if status == "silent":
        return _FEEDBACK_SILENT.format(round=retry_round)
    if status in ("false_positive",):
        return _FEEDBACK_FALSE_POSITIVE.format(round=retry_round, vh=vh, ch=ch)
    # parse_failed, parse_error, missing_metadata, no_py_for_arg, timeout — all
    # treated as format failures
    return _FEEDBACK_PARSE_FAILED.format(round=retry_round)


def load_yaml(arg: str) -> str | None:
    yaml_path = DSL_DIR / f"{arg}.yaml"
    if yaml_path.exists():
        return yaml_path.read_text(encoding="utf-8")
    return None


def load_original_output(input_path: str) -> str:
    try:
        return Path(input_path).read_text(encoding="utf-8")
    except Exception:
        return "(original output not available)"


def extract_retry_round(raw_output: str) -> int:
    """Parse retry_round from an existing LLM output (0 if first attempt)."""
    m = _DELIM_RE.search(raw_output)
    if not m:
        return 0
    meta_block = m.group(3)
    for line in meta_block.splitlines():
        if "retry_round" in line and ":" in line:
            _, _, v = line.partition(":")
            try:
                return int(v.strip())
            except ValueError:
                pass
    return 0


def build_prompt(arg: str, snake: str, status: str,
                 vuln_hits: int | None, clean_hits: int | None,
                 original_output: str, yaml_text: str | None,
                 retry_round: int) -> str:
    yaml_block = yaml_text if yaml_text else "(YAML not found — use the argument name to infer predicates)"
    fb = feedback_for(status, vuln_hits, clean_hits, retry_round)

    return textwrap.dedent(f"""\
        You are refining a clean+vulnerable Solidity fixture pair to back
        a Slither detector specified by the YAML below. A previous synthesis
        attempt failed smoke testing; targeted feedback is provided below.

        === DETECTOR ARGUMENT ===
        {arg}

        === DETECTOR YAML (reference/patterns.dsl/{arg}.yaml) ===
        {yaml_block}
        === END YAML ===

        === PREVIOUS LLM OUTPUT (failed) ===
        {original_output}
        === END PREVIOUS OUTPUT ===

        === SMOKE RESULT ===
        vuln_hits={vuln_hits if vuln_hits is not None else "N/A"} clean_hits={clean_hits if clean_hits is not None else "N/A"}

        {fb}
        === REQUIREMENTS ===

        Produce TWO Solidity 0.8.x source files:
          1. **vulnerable.sol** — a self-contained contract that EXHIBITS the bug
             pattern. The detector MUST fire >= 1 time on this file.
          2. **clean.sol** — a self-contained contract that does NOT exhibit the
             bug. The detector MUST fire 0 times on this file.

        Both files must be compilable standalone (no missing imports).
        Do NOT include mock/test/fixture in any contract name.

        Output format — EXACTLY this structure, no markdown fences, no extras:

        ===BEGIN_VULNERABLE_SOL===
        <vulnerable Solidity>
        ===END_VULNERABLE_SOL===
        ===BEGIN_CLEAN_SOL===
        <clean Solidity>
        ===END_CLEAN_SOL===
        ===BEGIN_METADATA===
        argument: {arg}
        snake: {snake}
        retry_round: {retry_round}
        ===END_METADATA===
    """)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--summary", required=True,
                    help="Path to Phase B-prime wirer summary JSON")
    ap.add_argument("--queue-out", required=True,
                    help="Output JSONL queue path")
    ap.add_argument("--prompts-dir", required=True,
                    help="Directory to write retry prompt .txt files")
    ap.add_argument("--outputs-dir", required=True,
                    help="Directory where LLM outputs will be written")
    ap.add_argument("--max-round", type=int, default=MAX_ROUND_DEFAULT,
                    help=f"Maximum retry rounds per detector (default {MAX_ROUND_DEFAULT})")
    args = ap.parse_args()

    summary_path = Path(args.summary)
    if not summary_path.exists():
        print(f"ERROR: summary not found: {summary_path}", file=sys.stderr)
        return 1

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    results = summary.get("results", [])

    prompts_dir = Path(args.prompts_dir)
    outputs_dir = Path(args.outputs_dir)
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    queue_path = Path(args.queue_out)
    queue_path.parent.mkdir(parents=True, exist_ok=True)

    # Non-pass statuses we handle
    retryable = {"silent", "false_positive", "parse_failed", "parse_error",
                 "missing_metadata", "no_py_for_arg"}

    counts: dict[str, int] = {}
    skipped_max_round = 0
    skipped_pass = 0
    skipped_no_arg = 0
    tasks: list[dict] = []

    for r in results:
        status = r.get("status", "")
        if status == "smoke_pass":
            skipped_pass += 1
            continue
        if status not in retryable:
            # unknown / no_py_for_arg etc — still attempt if arg is known
            if status not in retryable:
                counts[status] = counts.get(status, 0) + 1

        # Determine argument
        arg = r.get("argument")
        input_path = r.get("input", "")

        # For parse_failed, arg may be None — try to recover from filename
        if not arg and input_path:
            fname = Path(input_path).stem  # e.g. phase_b_prime_aave_foo_bar
            # Strip common prefix
            for prefix in ("phase_b_prime_", "phase-b-prime-"):
                if fname.startswith(prefix):
                    fname = fname[len(prefix):]
                    break
            arg = fname.replace("_", "-")

        if not arg:
            skipped_no_arg += 1
            continue

        snake = arg.replace("-", "_")

        # Determine current retry_round from existing output
        original_output = load_original_output(input_path) if input_path else ""
        current_round = extract_retry_round(original_output)
        next_round = current_round + 1

        if next_round > args.max_round:
            skipped_max_round += 1
            continue

        counts[status] = counts.get(status, 0) + 1

        yaml_text = load_yaml(arg)
        prompt = build_prompt(
            arg=arg,
            snake=snake,
            status=status,
            vuln_hits=r.get("vuln_hits"),
            clean_hits=r.get("clean_hits"),
            original_output=original_output,
            yaml_text=yaml_text,
            retry_round=next_round,
        )

        # Write prompt file
        prompt_fname = f"phase_b_prime_retry_r{next_round}_{snake}.txt"
        prompt_path = prompts_dir / prompt_fname
        prompt_path.write_text(prompt, encoding="utf-8")

        # Output path for the LLM response
        output_fname = f"phase_b_prime_retry_r{next_round}_{snake}.json"
        output_path = outputs_dir / output_fname

        task = {
            "task_id": f"phase-b-prime-retry-r{next_round}-{arg}",
            "provider": "minimax",
            "task_type": "fixture-synthesis-retry",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 8000,
            # metadata for downstream / debugging
            "original_status": status,
            "original_input": input_path,
            "retry_round": next_round,
            "argument": arg,
        }
        tasks.append(task)

    # Write queue
    with queue_path.open("w", encoding="utf-8") as fq:
        for t in tasks:
            fq.write(json.dumps(t) + "\n")

    # Report
    total_non_pass = len(results) - skipped_pass
    print(f"Summary: {summary_path.name}")
    print(f"  total results       : {len(results)}")
    print(f"  smoke_pass (skipped): {skipped_pass}")
    print(f"  non-pass total      : {total_non_pass}")
    print(f"  max_round capped    : {skipped_max_round}")
    print(f"  no arg (skipped)    : {skipped_no_arg}")
    print()
    print("Retry queue breakdown by original status:")
    for s, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {s:20} {n:3d}")
    print(f"\nRetry queue: {len(tasks)} tasks -> {queue_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
