#!/usr/bin/env python3
"""provider-output-normalizer.py -- Normalize raw Kimi/MiniMax provider output into typed work-queue items.

HACKERMAN_V2 Slice 1 deliverable.

Every raw provider result is classified into exactly one of 8 normalized types:

  verified_source_fact_pending_local_check  -- provider cited a source fact; local grep needed
  candidate_detector_generalization         -- provider derived a broader detector pattern
  candidate_fixture                         -- provider proposed a new fixture/test vector
  candidate_chain_edge                      -- provider found a chained attack edge
  candidate_poc_task                        -- provider outlined a PoC to build/run
  kill_reason_pending_local_check           -- provider said KILL but local confirm needed
  duplicate_or_oos_risk                     -- provider flagged duplicate or OOS risk
  provider_failure                          -- provider call failed or output is unusable

Every normalized item carries the required fields from the plan (lines ~198-208):
  provider, model, task_type, prompt_path, output_path, token_estimate,
  local_verification_command, disposition (KEEP/KILL/DEFER/SOURCE_NEEDED),
  local_verification_run (bool).

Usage
-----
  # From a raw text output file:
  python3 tools/provider-output-normalizer.py \\
      --provider minimax --model MiniMax-M2.7 \\
      --task-type adversarial-kill \\
      --prompt-path agent_outputs/my_prompt.md \\
      --output-path agent_outputs/my_output.txt \\
      --token-estimate 3200 \\
      [--raw-file agent_outputs/my_output.txt] \\
      [--raw-stdin] \\
      [--json] \\
      [--append-queue reports/provider_normalized_work_queue.jsonl]

Stdin mode: pass --raw-stdin to read raw output from stdin.
File mode:  pass --raw-file <path> to read from file.

If neither --raw-file nor --raw-stdin is provided, the tool infers raw content
from --output-path if that file exists; otherwise it emits a provider_failure item.

Append mode: --append-queue writes the normalized item as a JSONL line and is
idempotent (deduplicates by output_path + normalized_type before appending).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NORMALIZED_TYPES = (
    "verified_source_fact_pending_local_check",
    "candidate_detector_generalization",
    "candidate_fixture",
    "candidate_chain_edge",
    "candidate_poc_task",
    "kill_reason_pending_local_check",
    "duplicate_or_oos_risk",
    "provider_failure",
)

DISPOSITIONS = ("KEEP", "KILL", "DEFER", "SOURCE_NEEDED")

SCHEMA_VERSION = "auditooor.provider_normalized_work_queue.v1"


# ---------------------------------------------------------------------------
# Classification heuristics
# ---------------------------------------------------------------------------

# Each heuristic is (normalized_type, disposition, keywords).
# The FIRST match wins (order matters - more specific first).
_HEURISTICS: List[Tuple[str, str, List[str]]] = [
    # Provider failure indicators
    ("provider_failure", "KILL", [
        "http-4", "http-5", "cannot-run:", "no-api-key",
        "transport-error", "dispatch-failed", "thinking-only-after-retry",
        "malformed-response", "no-consent",
    ]),
    # Duplicate or OOS risk
    ("duplicate_or_oos_risk", "DEFER", [
        "duplicate", "oos", "out-of-scope", "out of scope",
        "already filed", "already known", "in scope exclusion",
        "not in scope", "known limitation", "previously reported",
    ]),
    # Kill reason (adversarial verdict)
    ("kill_reason_pending_local_check", "KILL", [
        "kill:", "verdict: kill", "verdict:kill", "drop:", "verdict: drop",
        "fp:", "false positive", "insufficient evidence", "no direct path",
        "cannot be exploited", "not exploitable", "not a finding",
        "verdict: reject", "verdict:reject",
    ]),
    # PoC task
    ("candidate_poc_task", "KEEP", [
        "poc task:", "build a poc", "write a poc", "poc needed",
        "harness:", "test to write", "reproduce with", "harness plan",
    ]),
    # Chain edge
    ("candidate_chain_edge", "KEEP", [
        "chain edge", "chained with", "attack chain", "combo with",
        "combined with", "requires first", "prerequisite:", "pre-condition:",
    ]),
    # Fixture candidate
    ("candidate_fixture", "KEEP", [
        "fixture:", "new fixture", "test vector", "test case:",
        "candidate fixture", "example input", "invariant:",
    ]),
    # Detector generalization
    ("candidate_detector_generalization", "KEEP", [
        "detector:", "detector pattern", "generalize", "generalised",
        "new detector", "pattern class", "pattern generalization",
        "extend detector", "rule:", "dsl pattern",
    ]),
    # Source fact (default KEEP-class if none of the above fires)
    ("verified_source_fact_pending_local_check", "SOURCE_NEEDED", [
        "source:", "file:", "line:", "function:", "at line",
        "grep:", "path:", "loc:", "source fact", "file path",
        "contract:", "module:", "package:", "at commit",
    ]),
]


def _classify(raw_text: str, explicit_type: Optional[str] = None) -> Tuple[str, str]:
    """Return (normalized_type, disposition).

    If explicit_type is provided and valid, it is used directly.
    Otherwise heuristic matching is applied.
    Fallback: verified_source_fact_pending_local_check / SOURCE_NEEDED.
    """
    if explicit_type and explicit_type in NORMALIZED_TYPES:
        # Derive a sensible default disposition from the explicit type
        default_disp = {
            "verified_source_fact_pending_local_check": "SOURCE_NEEDED",
            "candidate_detector_generalization": "KEEP",
            "candidate_fixture": "KEEP",
            "candidate_chain_edge": "KEEP",
            "candidate_poc_task": "KEEP",
            "kill_reason_pending_local_check": "KILL",
            "duplicate_or_oos_risk": "DEFER",
            "provider_failure": "KILL",
        }.get(explicit_type, "DEFER")
        return explicit_type, default_disp

    if not raw_text or not raw_text.strip():
        return "provider_failure", "KILL"

    lowered = raw_text.lower()
    for ntype, disp, keywords in _HEURISTICS:
        for kw in keywords:
            if kw.lower() in lowered:
                return ntype, disp

    # Default: treat as a source fact needing local verification
    return "verified_source_fact_pending_local_check", "SOURCE_NEEDED"


def _default_local_verify_command(ntype: str, output_path: str) -> str:
    """Return a sensible default local verification command for the type."""
    if ntype == "provider_failure":
        return "# No local verification - provider call failed"
    if ntype in ("kill_reason_pending_local_check", "duplicate_or_oos_risk"):
        return f"# Review output manually: cat {output_path}"
    if ntype == "candidate_poc_task":
        return f"# Build and run PoC described in: {output_path}"
    if ntype == "candidate_fixture":
        return f"# Extract fixture and run: python3 -m pytest -- {output_path}"
    if ntype == "candidate_detector_generalization":
        return f"# Validate pattern against corpus: python3 tools/detector-smoke-test.py --output {output_path}"
    if ntype == "candidate_chain_edge":
        return f"# Verify chain edge reachability: review {output_path} + grep target repo"
    # verified_source_fact_pending_local_check
    return f"# grep target repo to confirm: cat {output_path} | grep -E 'file:|line:|function:'"


def _token_estimate_from_text(raw_text: str) -> int:
    """Rough token estimate: 1 token ~= 4 chars."""
    if not raw_text:
        return 0
    return max(1, len(raw_text) // 4)


def _utc_now_iso() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _dedup_key(item: Dict[str, Any]) -> str:
    """Stable dedup key for idempotent append."""
    return hashlib.sha256(
        f"{item.get('output_path','')}\x00{item.get('normalized_type','')}".encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Core normalization
# ---------------------------------------------------------------------------

def normalize(
    *,
    raw_text: str,
    provider: str,
    model: str,
    task_type: str,
    prompt_path: str,
    output_path: str,
    token_estimate: Optional[int] = None,
    local_verification_command: Optional[str] = None,
    local_verification_run: bool = False,
    explicit_type: Optional[str] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Produce a single normalized work-queue item.

    Required fields per plan lines ~198-208:
      provider, model, task_type, prompt_path, output_path,
      token_estimate, local_verification_command, disposition,
      local_verification_run.
    Plus: normalized_type, schema, ts, dedup_key, raw_length.
    """
    ntype, disp = _classify(raw_text, explicit_type)

    tok_est = token_estimate
    if tok_est is None:
        tok_est = _token_estimate_from_text(raw_text)

    lcv = local_verification_command
    if not lcv:
        lcv = _default_local_verify_command(ntype, output_path)

    item: Dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "ts": _utc_now_iso(),
        "normalized_type": ntype,
        "disposition": disp,
        # Plan-required fields
        "provider": provider,
        "model": model,
        "task_type": task_type,
        "prompt_path": str(prompt_path),
        "output_path": str(output_path),
        "token_estimate": tok_est,
        "local_verification_command": lcv,
        "local_verification_run": bool(local_verification_run),
        # Diagnostics
        "raw_length": len(raw_text) if raw_text else 0,
    }
    if extra_fields:
        for k, v in extra_fields.items():
            if k not in item:  # never overwrite required fields
                item[k] = v

    item["dedup_key"] = _dedup_key(item)
    return item


# ---------------------------------------------------------------------------
# Append-queue (idempotent JSONL append)
# ---------------------------------------------------------------------------

def append_to_queue(queue_path: pathlib.Path, item: Dict[str, Any]) -> bool:
    """Append item to queue_path as a JSONL line. Idempotent by dedup_key.

    Returns True if appended, False if already present (skipped as duplicate).
    """
    queue_path.parent.mkdir(parents=True, exist_ok=True)

    new_key = item.get("dedup_key", "")
    existing_keys: set = set()

    if queue_path.exists():
        with queue_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    k = row.get("dedup_key", "")
                    if k:
                        existing_keys.add(k)
                except (ValueError, KeyError):
                    pass

    if new_key and new_key in existing_keys:
        return False

    line_out = json.dumps(item, sort_keys=True, separators=(",", ":"))
    with queue_path.open("a", encoding="utf-8") as fh:
        fh.write(line_out + "\n")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="provider-output-normalizer.py",
        description=(
            "Normalize a raw Kimi/MiniMax provider result into a typed "
            "work-queue item (HACKERMAN_V2 Slice 1)."
        ),
    )
    parser.add_argument("--provider", required=True, help="Provider name (kimi/minimax/anthropic).")
    parser.add_argument("--model", required=True, help="Model/version string.")
    parser.add_argument("--task-type", required=True, dest="task_type",
                        help="Task type (adversarial-kill, source-extract, etc.).")
    parser.add_argument("--prompt-path", required=True, dest="prompt_path",
                        help="Path to the prompt file that was dispatched.")
    parser.add_argument("--output-path", required=True, dest="output_path",
                        help="Path to the provider output file.")
    parser.add_argument("--token-estimate", type=int, default=None, dest="token_estimate",
                        help="Token estimate (input+output). Auto-derived from text if omitted.")
    parser.add_argument("--local-verify-cmd", default=None, dest="local_verify_cmd",
                        help="Local verification command. Auto-derived if omitted.")
    parser.add_argument("--local-verification-run", action="store_true", dest="local_verification_run",
                        help="Set if local verification has already run on this output.")
    parser.add_argument("--raw-file", default=None, dest="raw_file",
                        help="Read raw provider output from this file.")
    parser.add_argument("--raw-stdin", action="store_true", dest="raw_stdin",
                        help="Read raw provider output from stdin.")
    parser.add_argument("--explicit-type", default=None, dest="explicit_type",
                        choices=list(NORMALIZED_TYPES),
                        help="Force a specific normalized_type instead of auto-classifying.")
    parser.add_argument("--append-queue", default=None, dest="append_queue",
                        help="Append normalized item to this JSONL file (idempotent).")
    parser.add_argument("--json", action="store_true",
                        help="Print normalized item as JSON to stdout.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    # Resolve raw text
    raw_text = ""
    if args.raw_stdin:
        raw_text = sys.stdin.read()
    elif args.raw_file:
        rp = pathlib.Path(args.raw_file)
        if rp.exists():
            raw_text = rp.read_text(encoding="utf-8", errors="replace")
        else:
            sys.stderr.write(f"provider-output-normalizer: --raw-file not found: {rp}\n")
    else:
        # Try to infer from --output-path
        op = pathlib.Path(args.output_path)
        if op.exists():
            raw_text = op.read_text(encoding="utf-8", errors="replace")
        else:
            sys.stderr.write(
                f"provider-output-normalizer: --output-path not found and no --raw-file/--raw-stdin; "
                f"emitting provider_failure.\n"
            )

    item = normalize(
        raw_text=raw_text,
        provider=args.provider,
        model=args.model,
        task_type=args.task_type,
        prompt_path=args.prompt_path,
        output_path=args.output_path,
        token_estimate=args.token_estimate,
        local_verification_command=args.local_verify_cmd,
        local_verification_run=args.local_verification_run,
        explicit_type=args.explicit_type,
    )

    if args.append_queue:
        qpath = pathlib.Path(args.append_queue)
        appended = append_to_queue(qpath, item)
        sys.stderr.write(
            f"provider-output-normalizer: {'appended' if appended else 'skipped (dup)'} "
            f"-> {qpath}\n"
        )

    if args.json or not args.append_queue:
        sys.stdout.write(json.dumps(item, indent=2, sort_keys=True) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
