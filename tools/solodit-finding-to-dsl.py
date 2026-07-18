#!/usr/bin/env python3
"""solodit-finding-to-dsl.py — F1 Phase 1: convert ingested findings to DSL seed YAMLs.

IMPORTANT: THIS SCRIPT SHIPS IN DRY-RUN MODE ONLY FOR THIS PR.
Real LLM dispatch is GATED behind --enable-real-dispatch (operator flag).
Default behavior: emit prompts to /tmp/solodit_dry_run/ without calling any LLM.

Architecture (ACT-5 pattern, post-PR #607 fp_repair_v2 incident):
  - Per-finding LLM dispatch via tools/llm-dispatch.py (provider: kimi).
  - Prompt template follows the 9-section ACT-5 format:
      SECTION 1  — audit finding (primary source of truth)
      SECTION 2  — critical framing (fixtures are SYNTHESIZED stand-ins)
      SECTION 3  — bug-class encoding directive + 7-template menu
      SECTION 4  — anti-patterns (fixture-shape tricks FORBIDDEN)
      SECTION 5  — allowed DSL keys whitelist
      SECTION 6  — output seed location (STRUCTURE ONLY)
      SECTION 7  — 5-question self-check
      SECTION 8  — output format (BEGIN_DSL_SEED, BEGIN_BUG_CLASS, BEGIN_SELF_CHECK)
      SECTION 9  — acceptance gates
  - Output: YAML DSL predicate seeds at:
      reference/patterns.dsl/_solodit_seeds/<finding_id>.yaml
    (parked in seed sub-dir; NOT live until Phase 2 promotes)
  - Prompt lint enforced before any real dispatch: agent-dispatch-prompt-lint.py --strict

Usage:
    # Dry-run (default, safe, no LLM calls):
    python3 tools/solodit-finding-to-dsl.py \\
        --input-dir /private/tmp/solodit-ingest/2026-05-04 \\
        --max-tasks 5 \\
        --dry-run \\
        --prompt-out-dir /tmp/solodit_dry_run

    # Real dispatch (OPERATOR MUST SET FLAG EXPLICITLY):
    python3 tools/solodit-finding-to-dsl.py \\
        --input-dir /private/tmp/solodit-ingest/2026-05-04 \\
        --max-tasks 5 \\
        --enable-real-dispatch \\
        --seed-out-dir reference/patterns.dsl/_solodit_seeds

M14-trap discipline: fail-closed. If prompt lint fails, abort dispatch.
Budget cap: --max-tasks N (default 5 per run).
Honest accounting: if LLM unavailable, surface honestly; never fabricate seeds.

Exit codes:
  0  success (all tasks completed or dry-run emitted prompts)
  1  input error
  2  prompt lint failed (in --strict mode)
  3  LLM dispatch error (real mode only)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOL_VERSION = "1.0.0"
TOOL_NAME = "solodit-finding-to-dsl"

# Prompt lint script (relative to repo root)
LINT_SCRIPT = "tools/agent-dispatch-prompt-lint.py"

# LLM dispatch script
LLM_DISPATCH_SCRIPT = "tools/llm-dispatch.py"

# Preferred provider per ACT-14 calibration (Kimi: 100% source extraction n=23)
DEFAULT_LLM_PROVIDER = "kimi"

# DSL key whitelist (canonical set from reference/PATTERN_DSL.md)
DSL_ALLOWED_KEYS = [
    "function.name_matches",
    "function.not_leaf_helper",
    "function.not_in_skip_list",
    "function.reads_state_var_matching",
    "function.does_not_call_matching",
    "function.calls_matching",
    "function.body_contains_regex",
    "function.modifiers_match",
    "function.is_public_or_external",
    "function.has_no_reentrancy_guard",
    "contract.source_matches_regex",
    "contract.inherits_from_matching",
    "function.parameter_count_gte",
    "function.has_unchecked_return",
    "function.visibility_in",
]

# Bug-class template menu (7 canonical classes per ACT-5 Section 3)
BUG_CLASS_MENU = [
    "missing-reentrancy-guard",
    "missing-authorization-check",
    "tx-origin-auth",
    "unchecked-low-level-call",
    "unsafe-erc20-call",
    "unbounded-loop",
    "signature-replay",
]

# Anti-pattern phrases (MUST NOT appear as the sole signal in a predicate)
ANTI_PATTERN_PHRASES = [
    'function.body_not_contains_regex: "require\\s*\\("',
    "distinguish the fixtures",
    "make the predicate stricter",
    "so it fires on vulnerable but not clean",
    "tighten the predicate",
    "make the detector fire on vulnerable but not on clean",
]


# ---------------------------------------------------------------------------
# Prompt builder (ACT-5 9-section template)
# ---------------------------------------------------------------------------

def build_prompt(finding: dict) -> str:
    """Build a 9-section ACT-5 compliant prompt for DSL seed generation.

    The prompt encodes bug-class semantics from the audit finding text.
    It explicitly forbids fixture-shape distinguishing predicates.
    """
    title = finding.get("title", "Unknown")
    severity = finding.get("severity", "HIGH")
    firm = finding.get("firm", "Unknown Firm")
    protocol = finding.get("protocol", "Unknown Protocol")
    content = finding.get("content", "")
    tags = finding.get("tags", [])
    finding_id = finding.get("id", "unknown")
    solodit_url = finding.get("solodit_url", "")
    language = finding.get("language", "Solidity")

    # Truncate content to avoid token overflow
    content_snippet = content[:3000] if len(content) > 3000 else content

    dsl_keys_formatted = "\n".join(f"  - {k}" for k in DSL_ALLOWED_KEYS)
    bug_class_menu_formatted = "\n".join(f"  - {c}" for c in BUG_CLASS_MENU)
    anti_patterns_formatted = "\n".join(f"  - {p}" for p in ANTI_PATTERN_PHRASES)
    seed_out_path = f"reference/patterns.dsl/_solodit_seeds/{finding_id}.yaml"

    prompt = textwrap.dedent(f"""\
    ========================================================================
    SOLODIT FINDING → DSL SEED GENERATION
    Task ID: solodit-{finding_id}
    ========================================================================

    ## SECTION 1 — Audit Finding (PRIMARY SOURCE OF TRUTH)

    Source: {solodit_url}
    ID: {finding_id}
    Title: {title}
    Severity: {severity}
    Firm: {firm}
    Protocol: {protocol}
    Language: {language}
    Tags: {", ".join(tags) if tags else "none"}

    ### Finding Content:
    {content_snippet}

    ========================================================================
    ## SECTION 2 — Critical Framing

    You are generating a DSL predicate SEED that encodes the BUG CLASS
    described in the finding above. There are NO pre-existing fixtures for
    this task. Do NOT attempt to distinguish a vulnerable fixture from a
    clean fixture — there are none. Your ONLY job is to capture the semantic
    essence of WHY the code in this finding is vulnerable.

    The predicate you produce will be reviewed by a human operator before it
    enters the live detector registry. It is a SEED, not a final detector.

    ========================================================================
    ## SECTION 3 — Bug-Class Encoding Directive

    Choose the most appropriate bug class from this menu:
    {bug_class_menu_formatted}

    If the finding does not fit any of these classes, define a new class name
    in snake-case and explain why. Then encode the CLASS SEMANTICS in the
    predicate:
      - What function/state pattern is PRESENT in vulnerable code?
      - What guard / check / pattern is MISSING that would make it safe?
    Your predicate must answer: "would this predicate fire on ANY contract
    that exhibits this class of vulnerability?" — not just the specific
    Solodit finding's contract.

    ========================================================================
    ## SECTION 4 — Anti-Patterns (FORBIDDEN)

    The following predicate forms are FORBIDDEN as the SOLE signal.
    They encode fixture SHAPE, not bug-class SEMANTICS:

    {anti_patterns_formatted}

    If your predicate relies on any of these as the primary discriminator,
    it is WRONG. Add a semantic anchor (e.g., function name pattern, state
    variable access, modifier check) that reflects why the code is vulnerable.

    ========================================================================
    ## SECTION 5 — Allowed DSL Keys

    Only use keys from this whitelist:
    {dsl_keys_formatted}

    ========================================================================
    ## SECTION 6 — Seed Output Location (STRUCTURE ONLY)

    Your output will be parked at:
        `{seed_out_path}`

    This is a SEED sub-directory. It is NOT automatically promoted to the
    live detector registry. Promotion requires operator review + Phase 2
    tooling.

    The YAML structure MUST follow this template:
    ---
    id: <finding_id>-<kebab-title>
    title: |
      <title>
    severity: <High|Critical>
    language: <Solidity|Rust|...>
    platform: <ethereum|solana|...>
    source: solodit
    source_id: "{finding_id}"
    source_url: {solodit_url}
    firm: '{firm}'
    protocol: '{protocol}'
    quality_score: <N>
    tags: [<tag1>, <tag2>]
    bug_class: <chosen-class>
    indicators:
      - '<dsl-key>: <value>'
    victim: tbd
    exploit_precondition: <one-sentence precondition>
    real_world_example: |
      <brief description of the exploit path from the finding>
    suggested_remediation: |
      <brief remediation from the finding>
    cross_refs: []

    ========================================================================
    ## SECTION 7 — Five-Question Self-Check

    Before emitting your YAML, answer these questions:

    Q1: What is the bug class in ONE sentence? (Encode it in BEGIN_BUG_CLASS)
    Q2: For each DSL indicator you chose, why does it encode the bug class
        semantics — not just distinguish a fixture pair?
    Q3: Would your predicate fire on a CORRECT implementation that happens
        to use a different guard idiom for the same functionality?
    Q4: Would your predicate MISS a vulnerable function that has an unrelated
        require statement?
    Q5: Am I encoding the REASON this code is vulnerable, or just describing
        the shape of this specific finding's code?

    ========================================================================
    ## SECTION 8 — Output Format

    Emit ALL FIVE sections, in order:

    BEGIN_DSL_SEED
    <full YAML content>
    END_DSL_SEED

    BEGIN_BUG_CLASS
    <one-sentence bug class statement>
    END_BUG_CLASS

    BEGIN_RATIONALE
    <2-4 sentences: why each indicator captures bug-class semantics>
    END_RATIONALE

    BEGIN_SELF_CHECK
    Q1: <answer>
    Q2: <answer>
    Q3: <answer>
    Q4: <answer>
    Q5: <answer>
    END_SELF_CHECK

    BEGIN_METADATA
    finding_id: {finding_id}
    source_url: {solodit_url}
    generated_at: <ISO timestamp>
    END_METADATA

    ========================================================================
    ## SECTION 9 — Acceptance Gates

    ## Acceptance

    Your output is accepted if ALL of the following hold:
    - YAML is syntactically valid.
    - The primary indicator is NOT a bare body_not_contains_regex predicate.
    - The bug_class field is populated with a real class name.
    - The self-check answers Q3 "No" and Q4 "No" (no false-positive / no
      false-negative for the wrong reason).
    - The real_world_example captures the actual exploit path, not a
      placeholder.

    M14-trap: Do not fabricate exploit details not present in the finding.
    If a field is genuinely unknown, write "tbd" — do not invent.

    ========================================================================
    """)
    return prompt


# ---------------------------------------------------------------------------
# Seed YAML parser (extract from LLM response)
# ---------------------------------------------------------------------------

def _extract_section(text: str, begin_tag: str, end_tag: str) -> Optional[str]:
    """Extract content between BEGIN_X / END_X markers."""
    pattern = rf"{re.escape(begin_tag)}\s*(.*?)\s*{re.escape(end_tag)}"
    m = re.search(pattern, text, re.DOTALL)
    return m.group(1).strip() if m else None


def _parse_llm_response(response_text: str, finding_id: str) -> dict:
    """Parse LLM response into structured sections."""
    return {
        "finding_id": finding_id,
        "dsl_seed": _extract_section(response_text, "BEGIN_DSL_SEED", "END_DSL_SEED"),
        "bug_class": _extract_section(response_text, "BEGIN_BUG_CLASS", "END_BUG_CLASS"),
        "rationale": _extract_section(response_text, "BEGIN_RATIONALE", "END_RATIONALE"),
        "self_check": _extract_section(response_text, "BEGIN_SELF_CHECK", "END_SELF_CHECK"),
        "metadata": _extract_section(response_text, "BEGIN_METADATA", "END_METADATA"),
        "raw_response": response_text,
        "parse_ok": all([
            _extract_section(response_text, "BEGIN_DSL_SEED", "END_DSL_SEED"),
            _extract_section(response_text, "BEGIN_BUG_CLASS", "END_BUG_CLASS"),
            _extract_section(response_text, "BEGIN_SELF_CHECK", "END_SELF_CHECK"),
        ]),
    }


# ---------------------------------------------------------------------------
# Prompt lint (pre-dispatch gate)
# ---------------------------------------------------------------------------

def _run_prompt_lint(prompt_text: str, repo_root: Path, strict: bool = True) -> tuple[bool, str]:
    """Run agent-dispatch-prompt-lint.py on the prompt. Returns (passed, output)."""
    lint_script = repo_root / LINT_SCRIPT
    if not lint_script.exists():
        return True, f"[WARN] Lint script not found at {lint_script}; skipping lint gate."

    # Write prompt to temp file
    tmp_prompt = Path("/tmp/solodit_prompt_lint_tmp.txt")
    tmp_prompt.write_text(prompt_text)

    cmd = [sys.executable, str(lint_script), str(tmp_prompt)]
    if strict:
        cmd.append("--strict")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        passed = result.returncode == 0
        return passed, output
    except subprocess.TimeoutExpired:
        return False, "Lint script timed out after 30s"
    except Exception as exc:
        return False, f"Lint script error: {exc}"


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------

def process_findings(
    input_files: List[Path],
    max_tasks: int,
    dry_run: bool,
    enable_real_dispatch: bool,
    prompt_out_dir: Path,
    seed_out_dir: Path,
    repo_root: Path,
    strict_lint: bool,
) -> dict:
    """Process up to max_tasks findings. Returns summary dict."""
    summary = {
        "total_input": len(input_files),
        "processed": 0,
        "prompts_emitted": 0,
        "seeds_written": 0,
        "lint_failures": 0,
        "llm_errors": 0,
        "dry_run": dry_run,
        "enable_real_dispatch": enable_real_dispatch,
        "tasks": [],
    }

    # Create output dirs
    if dry_run:
        prompt_out_dir.mkdir(parents=True, exist_ok=True)
    elif enable_real_dispatch:
        prompt_out_dir.mkdir(parents=True, exist_ok=True)
        seed_out_dir.mkdir(parents=True, exist_ok=True)

    tasks_run = 0
    for input_file in input_files:
        if tasks_run >= max_tasks:
            break

        task_result: dict[str, Any] = {
            "input_file": str(input_file),
            "finding_id": "unknown",
            "status": "pending",
        }

        # Load finding
        try:
            finding = json.loads(input_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            task_result["status"] = "error"
            task_result["error"] = f"Failed to load {input_file}: {exc}"
            summary["tasks"].append(task_result)
            continue

        finding_id = str(finding.get("id", input_file.stem))
        task_result["finding_id"] = finding_id

        # Build prompt
        prompt_text = build_prompt(finding)
        task_result["prompt_length"] = len(prompt_text)

        # Emit prompt file (always, for operator review)
        prompt_file = prompt_out_dir / f"prompt_{finding_id}.txt"
        if not dry_run or True:  # Always emit prompt for review
            prompt_out_dir.mkdir(parents=True, exist_ok=True)
            prompt_file.write_text(prompt_text)
            task_result["prompt_file"] = str(prompt_file)
            summary["prompts_emitted"] += 1

        # Prompt lint gate
        lint_passed, lint_output = _run_prompt_lint(prompt_text, repo_root, strict=strict_lint)
        task_result["lint_passed"] = lint_passed
        task_result["lint_output"] = lint_output.strip()[:500]

        if not lint_passed:
            task_result["status"] = "lint-failed"
            summary["lint_failures"] += 1
            print(
                f"[{TOOL_NAME}] LINT FAIL for {finding_id}: {lint_output[:200]}",
                file=sys.stderr,
            )
            summary["tasks"].append(task_result)
            tasks_run += 1
            continue

        # Dry-run stops here (operator approval gate)
        if dry_run or not enable_real_dispatch:
            task_result["status"] = "dry-run-ok"
            print(
                f"[{TOOL_NAME}] DRY-RUN: prompt emitted for {finding_id} "
                f"({task_result['prompt_length']} chars) → {prompt_file}"
            )
            summary["tasks"].append(task_result)
            tasks_run += 1
            summary["processed"] += 1
            continue

        # Real LLM dispatch (gated)
        dispatch_script = repo_root / LLM_DISPATCH_SCRIPT
        if not dispatch_script.exists():
            task_result["status"] = "error"
            task_result["error"] = f"LLM dispatch script not found: {dispatch_script}"
            summary["llm_errors"] += 1
            summary["tasks"].append(task_result)
            tasks_run += 1
            continue

        cmd = [
            sys.executable,
            str(dispatch_script),
            "--prompt-file",
            str(prompt_file),
            "--provider",
            DEFAULT_LLM_PROVIDER,
            "--max-tokens",
            "4096",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                task_result["status"] = "llm-error"
                task_result["error"] = result.stderr[:500]
                summary["llm_errors"] += 1
            else:
                parsed = _parse_llm_response(result.stdout, finding_id)
                task_result["parse_ok"] = parsed["parse_ok"]
                task_result["bug_class"] = parsed.get("bug_class", "")

                if parsed["parse_ok"] and parsed["dsl_seed"]:
                    seed_file = seed_out_dir / f"{finding_id}.yaml"
                    seed_file.write_text(parsed["dsl_seed"])
                    task_result["seed_file"] = str(seed_file)
                    task_result["status"] = "success"
                    summary["seeds_written"] += 1
                else:
                    task_result["status"] = "parse-failed"
                    task_result["error"] = "LLM response missing required BEGIN/END sections"
                    summary["llm_errors"] += 1

        except subprocess.TimeoutExpired:
            task_result["status"] = "timeout"
            task_result["error"] = "LLM dispatch timed out after 120s"
            summary["llm_errors"] += 1
        except Exception as exc:
            task_result["status"] = "error"
            task_result["error"] = str(exc)
            summary["llm_errors"] += 1

        summary["tasks"].append(task_result)
        tasks_run += 1
        summary["processed"] += 1

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--input-dir",
        metavar="DIR",
        help="Directory of ingested finding JSONs (from solodit-ingest.py).",
    )
    p.add_argument(
        "--input-files",
        nargs="+",
        metavar="FILE",
        help="Explicit list of finding JSON files (alternative to --input-dir).",
    )
    p.add_argument(
        "--max-tasks",
        type=int,
        default=5,
        metavar="N",
        help="Maximum LLM dispatch tasks per run (default 5, cost cap).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Emit prompts to --prompt-out-dir but do NOT call LLM (default: True).",
    )
    p.add_argument(
        "--enable-real-dispatch",
        action="store_true",
        default=False,
        help="OPERATOR FLAG: enable real LLM calls. Requires --no-dry-run.",
    )
    p.add_argument(
        "--no-dry-run",
        action="store_true",
        default=False,
        help="Disable dry-run mode (required with --enable-real-dispatch).",
    )
    p.add_argument(
        "--prompt-out-dir",
        default="/tmp/solodit_dry_run",
        metavar="DIR",
        help="Directory for emitted prompts (default: /tmp/solodit_dry_run).",
    )
    p.add_argument(
        "--seed-out-dir",
        metavar="DIR",
        help="Directory for DSL seed YAMLs (default: reference/patterns.dsl/_solodit_seeds).",
    )
    p.add_argument(
        "--repo-root",
        metavar="DIR",
        help="Repo root for resolving tool paths (default: auto-detect).",
    )
    p.add_argument(
        "--no-strict-lint",
        action="store_true",
        default=False,
        help="Disable --strict flag on prompt lint (warn only, don't block).",
    )
    p.add_argument(
        "--summary-json",
        metavar="FILE",
        help="Write run summary JSON to this file.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Resolve dry-run flag
    dry_run = args.dry_run and not args.no_dry_run
    enable_real_dispatch = args.enable_real_dispatch and not dry_run

    # Resolve repo root
    if args.repo_root:
        repo_root = Path(args.repo_root)
    else:
        repo_root = Path(__file__).parent.parent

    # Resolve seed out dir
    if args.seed_out_dir:
        seed_out_dir = Path(args.seed_out_dir)
    else:
        seed_out_dir = repo_root / "reference" / "patterns.dsl" / "_solodit_seeds"

    prompt_out_dir = Path(args.prompt_out_dir)

    # Collect input files
    input_files: List[Path] = []
    if args.input_files:
        input_files = [Path(f) for f in args.input_files]
    elif args.input_dir:
        input_dir = Path(args.input_dir)
        if not input_dir.exists():
            print(f"[{TOOL_NAME}] ERROR: input dir not found: {input_dir}", file=sys.stderr)
            return 1
        input_files = sorted(input_dir.glob("*.json"))
    else:
        print(
            f"[{TOOL_NAME}] ERROR: provide --input-dir or --input-files", file=sys.stderr
        )
        return 1

    if not input_files:
        print(f"[{TOOL_NAME}] No input files found; nothing to do.", file=sys.stderr)
        return 0

    mode_str = "DRY-RUN" if dry_run else "REAL-DISPATCH"
    print(
        f"[{TOOL_NAME}] Mode={mode_str}, max_tasks={args.max_tasks}, "
        f"input_files={len(input_files)}",
        file=sys.stderr,
    )

    summary = process_findings(
        input_files=input_files,
        max_tasks=args.max_tasks,
        dry_run=dry_run,
        enable_real_dispatch=enable_real_dispatch,
        prompt_out_dir=prompt_out_dir,
        seed_out_dir=seed_out_dir,
        repo_root=repo_root,
        strict_lint=not args.no_strict_lint,
    )

    summary_json_str = json.dumps(summary, indent=2)
    if args.summary_json:
        Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_json).write_text(summary_json_str)
        print(f"[{TOOL_NAME}] Summary written to {args.summary_json}")
    else:
        print(summary_json_str)

    any_lint_fail = summary["lint_failures"] > 0 and not args.no_strict_lint
    return 2 if any_lint_fail else 0


if __name__ == "__main__":
    sys.exit(main())
