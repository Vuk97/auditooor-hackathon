#!/usr/bin/env python3
# R36 pathspec discipline: this lane is registered as
# lane-DEEPSEEK-BATCH-GEN in .auditooor/agent_pathspec.json via
# tools/agent-pathspec-register.py (TTL 2h, registered 2026-05-26).
# <!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json TTL 2h with this file in declared pathspec -->

"""deepseek-batch-gen-tok-a.py - TOK-A rationale-mining batch generator.

Reads corpus-mined finding slices (reference/corpus_mined/*.md) and emits
a JSONL batch compatible with tools/llm-fanout-dispatcher.py. Each
emitted task asks DeepSeek to mine the explicit attack-class rationale
behind one finding (root cause + invariant violated + canonical detector
sketch). Batches default-target tier-3-synthetic-taxonomy-anchored per R37.

CLI
---
python3 tools/deepseek-batch-gen-tok-a.py \\
    --source <path-or-glob> \\
    --output-dir <dir> \\
    --max-batch-size <N> \\
    [--dry-run] [--json] \\
    [--task-id-prefix tok_a_rationale_mine] \\
    [--verification-tier tier-3-synthetic-taxonomy-anchored]

Output JSONL shape (one task per line):
    {
      "task_id": "tok_a_rationale_mine_0001",
      "task_type": "tok_a_rationale_mine",
      "prompt": "<prompt text>",
      "max_input_tokens": 6000,
      "max_output_tokens": 1500,
      "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
      "meta": {
        "source_path": "<file>",
        "finding_line": "<excerpt>",
        "generator": "deepseek-batch-gen-tok-a",
        "generator_version": "v1"
      }
    }

Discipline
----------
- Per L34 v2: default --output-dir is
  <workspace>/audit/corpus_tags/derived/deepseek_fanout/tok-a/ when
  --workspace is given. Refuses to write to submissions/<status>/<slug>/
  draft-file paths.
- Per R37: every emitted task carries verification_tier_target.
- Per R36: stdlib-only; no third-party deps.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


SCHEMA_ID = "auditooor.deepseek_batch_gen_tok_a.v1"
TASK_TYPE = "tok_a_rationale_mine"
GENERATOR_NAME = "deepseek-batch-gen-tok-a"
GENERATOR_VERSION = "v1"

DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
DEFAULT_MAX_INPUT_TOKENS = 6000
DEFAULT_MAX_OUTPUT_TOKENS = 1500
DEFAULT_MAX_BATCH_SIZE = 50

# Per-task prompt template for TOK-A.
PROMPT_TEMPLATE = """You are an expert smart-contract security auditor mining canonical attack-class rationales from disclosed findings.

Input finding (one-line excerpt from public audit corpus):

  {finding_line}

Source artifact: {source_path}

Task: produce a STRUCTURED attack-class rationale with the following fields, in JSON:

  {{
    "finding_handle": "<short slug for this finding>",
    "attack_class": "<canonical class, e.g. missing-slippage, reentrancy-cross-function, oracle-staleness, etc.>",
    "root_cause_one_sentence": "<root cause in <=160 chars>",
    "invariant_violated": "<the protocol/safety invariant the bug breaks>",
    "canonical_detector_sketch": "<file-shape predicate or Slither/Glider query sketch>",
    "minimal_repro_steps": ["<step1>", "<step2>"],
    "confidence_self_assessment": "<low|medium|high>",
    "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored"
  }}

Rules:
- Output ONLY the JSON object. No prose preamble.
- Do not invent file:line citations. If the input does not name a file, omit it.
- Be honest: if the input is ambiguous, set confidence_self_assessment to "low".
"""

# L34 v2 draft-file bucket regex - canonical shape.
_L34_DRAFT_FILE_RE = re.compile(
    r"submissions/(staging|paste_ready|ready|filed|packaged|held|superseded|"
    r"_killed|_oos_rejected)/[^/]+/[^/]+\.(md|md\.hash|hardening\.md|"
    r"hackenproof-plain\.txt|hackenproof-plain\.json|hackenproof-plain\.txt\.hash|"
    r"poc-transcript\.txt|poc\.zip)$"
)

EXIT_OK = 0
EXIT_CANNOT_RUN = 2
EXIT_ERROR = 3


def _ts_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stderr(msg: str) -> None:
    sys.stderr.write(f"[{GENERATOR_NAME} {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _l34_refuses_path(path: pathlib.Path) -> bool:
    return bool(_L34_DRAFT_FILE_RE.search(str(path)))


def _resolve_sources(source: str) -> List[pathlib.Path]:
    """Expand --source into a list of files. Accepts file, dir, or glob."""
    p = pathlib.Path(source)
    if p.is_file():
        return [p]
    if p.is_dir():
        files = sorted(p.glob("*.md"))
        return [f for f in files if f.is_file()]
    # Try glob.
    matches = sorted(pathlib.Path(m) for m in glob.glob(source))
    return [m for m in matches if m.is_file()]


def _existing_task_ids(
    skip_existing_in_dir: Optional[str],
    task_id_prefix: str,
) -> Tuple[Set[str], int]:
    """Return completed task ids and the maximum numeric suffix seen."""
    if not skip_existing_in_dir:
        return set(), 0
    base = pathlib.Path(skip_existing_in_dir)
    if not base.exists():
        return set(), 0
    done: Set[str] = set()
    max_idx = 0
    name_re = re.compile(rf"^{re.escape(task_id_prefix)}_(?P<idx>\d+)\.json$")
    for path in base.glob(f"{task_id_prefix}_*.json"):
        m = name_re.match(path.name)
        if not m:
            continue
        idx = int(m.group("idx"))
        done.add(f"{task_id_prefix}_{idx:04d}")
        if idx > max_idx:
            max_idx = idx
    return done, max_idx


# Match bullet finding entries: lines starting with `- **handle** (Severity)` followed by description.
# Accept short-form (H/M/L) AND long-form (HIGH/MEDIUM/LOW/CRITICAL) severity tokens.
# <!-- r36-rebuttal: lane-tok-a-regex-extend-2026-05-27 registered, single-file scope -->
FINDING_LINE_RE = re.compile(
    r"^- \*\*(?P<handle>[^*]+)\*\*\s*\((?P<severity>CRITICAL|HIGH|MEDIUM|LOW|critical|high|medium|low|[HMLChmlc])\)\s*[—\-]\s*(?P<desc>.+?)\s*$"
)


def extract_findings(text: str, source_path: str) -> List[Dict[str, Any]]:
    """Parse corpus_mined slice text into per-finding records."""
    out: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        m = FINDING_LINE_RE.match(raw.rstrip())
        if not m:
            continue
        handle = m.group("handle").strip()
        # <!-- r36-rebuttal: lane-tok-a-regex-extend-2026-05-27 registered, single-file scope -->
        # Normalise long-form severity tokens to single letters for downstream consumers.
        raw_sev = m.group("severity").upper()
        severity = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L"}.get(raw_sev, raw_sev)
        desc = m.group("desc").strip()
        # Cap finding_line at 600 chars to bound prompt length.
        finding_line = f"{handle} ({severity}) - {desc}"[:600]
        out.append({
            "finding_handle": handle,
            "severity": severity,
            "desc": desc,
            "finding_line": finding_line,
            "source_path": source_path,
        })
    return out


def build_task_record(
    idx: int,
    finding: Dict[str, Any],
    task_id_prefix: str,
    verification_tier: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task_id = f"{task_id_prefix}_{idx:04d}"
    prompt = PROMPT_TEMPLATE.format(
        finding_line=finding["finding_line"],
        source_path=finding["source_path"],
    )
    return {
        "task_id": task_id,
        "task_type": TASK_TYPE,
        "prompt": prompt,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "verification_tier_target": verification_tier,
        "meta": {
            "source_path": finding["source_path"],
            "finding_handle": finding["finding_handle"],
            "severity": finding.get("severity"),
            "finding_line": finding["finding_line"],
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "schema_id": SCHEMA_ID,
        },
    }


def generate_batch(
    source: str,
    task_id_prefix: str,
    verification_tier: str,
    max_batch_size: int,
    max_input_tokens: int,
    max_output_tokens: int,
    skip_existing_in_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    files = _resolve_sources(source)
    if not files:
        return []
    done_task_ids, max_existing_idx = _existing_task_ids(
        skip_existing_in_dir, task_id_prefix
    )
    resume_start_idx = max_existing_idx + 1 if done_task_ids else 1
    records: List[Dict[str, Any]] = []
    idx = 1
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            _stderr(f"failed to read {f}: {exc}")
            continue
        findings = extract_findings(text, str(f))
        for fnd in findings:
            if len(records) >= max_batch_size:
                return records
            task_id = f"{task_id_prefix}_{idx:04d}"
            if idx < resume_start_idx or task_id in done_task_ids:
                idx += 1
                continue
            records.append(build_task_record(
                idx, fnd, task_id_prefix, verification_tier,
                max_input_tokens, max_output_tokens,
            ))
            idx += 1
    return records


def write_batch(
    records: List[Dict[str, Any]],
    output_dir: pathlib.Path,
    task_type: str = TASK_TYPE,
) -> pathlib.Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = output_dir / f"{task_type}-batch-{ts}.jsonl"
    if _l34_refuses_path(out_path):
        raise SystemExit(f"[{GENERATOR_NAME}] L34 v2 refusal: {out_path} is a draft-file bucket")
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return out_path


def resolve_output_dir(args: argparse.Namespace) -> pathlib.Path:
    if args.output_dir:
        return pathlib.Path(args.output_dir)
    ws = pathlib.Path(args.workspace) if args.workspace else pathlib.Path.cwd()
    return ws / "audit" / "corpus_tags" / "derived" / "deepseek_fanout" / "tok-a"


def estimate_cost_usd(records: List[Dict[str, Any]]) -> float:
    """Estimate batch cost at deepseek-flash pricing.

    flash: $0.00014/1K input, $0.00028/1K output (matches dispatcher's
    _DEFAULT_PRICING table). Approximates input_tokens = len(prompt)/4 and
    output_tokens = max_output_tokens.
    """
    total = 0.0
    for r in records:
        prompt_len = len(r.get("prompt", ""))
        in_toks = max(1, prompt_len // 4)
        out_toks = r.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
        total += (in_toks / 1000.0) * 0.00014
        total += (out_toks / 1000.0) * 0.00028
    return round(total, 6)


def main() -> int:
    p = argparse.ArgumentParser(
        prog=GENERATOR_NAME,
        description="Generate a DeepSeek fanout batch for TOK-A rationale mining.",
    )
    p.add_argument("--source", required=True,
                   help="Source file, directory, or glob (corpus_mined slices).")
    p.add_argument("--output-dir", default=None,
                   help=("Where to write the JSONL batch. Defaults to "
                         "<workspace>/audit/corpus_tags/derived/deepseek_fanout/tok-a/."))
    p.add_argument("--workspace", default=None,
                   help="Workspace path; used when --output-dir is not given.")
    p.add_argument("--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE,
                   help=f"Cap on emitted tasks (default {DEFAULT_MAX_BATCH_SIZE}).")
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--task-id-prefix", default="tok_a_rationale_mine")
    p.add_argument("--skip-existing-in-dir", default=None,
                   help=("Directory containing completed <task-id>.json sidecars. "
                         "When set, resumes after the max existing numeric task id."))
    p.add_argument("--verification-tier", default=DEFAULT_VERIFICATION_TIER)
    p.add_argument("--dry-run", action="store_true",
                   help="Print summary; do not write the batch file.")
    p.add_argument("--json", action="store_true",
                   help="Emit a JSON summary to stdout.")
    args = p.parse_args()

    try:
        records = generate_batch(
            source=args.source,
            task_id_prefix=args.task_id_prefix,
            verification_tier=args.verification_tier,
            max_batch_size=args.max_batch_size,
            max_input_tokens=args.max_input_tokens,
            max_output_tokens=args.max_output_tokens,
            skip_existing_in_dir=args.skip_existing_in_dir,
        )
    except Exception as exc:
        _stderr(f"generate_batch failed: {exc}")
        return EXIT_ERROR

    done_task_ids, max_existing_idx = _existing_task_ids(
        args.skip_existing_in_dir, args.task_id_prefix
    )

    if not records:
        if done_task_ids:
            _stderr(
                f"no new findings extracted from --source={args.source}; "
                f"skip-existing max={max_existing_idx}"
            )
            status = "no-new-records"
        else:
            _stderr(f"no findings extracted from --source={args.source}")
            status = "no-records"
        summary = {
            "schema_id": SCHEMA_ID,
            "task_type": TASK_TYPE,
            "records_emitted": 0,
            "output_path": None,
            "dry_run": args.dry_run,
            "estimated_cost_usd_flash": 0.0,
            "status": status,
            "skip_existing_in_dir": args.skip_existing_in_dir,
            "existing_task_count": len(done_task_ids),
            "max_existing_task_index": max_existing_idx,
        }
        if args.json:
            print(json.dumps(summary, sort_keys=True))
        return EXIT_OK

    cost = estimate_cost_usd(records)

    if args.dry_run:
        summary = {
            "schema_id": SCHEMA_ID,
            "task_type": TASK_TYPE,
            "records_emitted": len(records),
            "output_path": None,
            "dry_run": True,
            "estimated_cost_usd_flash": cost,
            "status": "dry-run",
            "sample_task_ids": [r["task_id"] for r in records[:3]],
            "skip_existing_in_dir": args.skip_existing_in_dir,
            "existing_task_count": len(done_task_ids),
            "max_existing_task_index": max_existing_idx,
        }
        if args.json:
            print(json.dumps(summary, sort_keys=True))
        else:
            _stderr(f"DRY RUN: {len(records)} tasks would be emitted; est cost ${cost}")
        return EXIT_OK

    out_dir = resolve_output_dir(args)
    out_path = write_batch(records, out_dir, task_type=TASK_TYPE)

    summary = {
        "schema_id": SCHEMA_ID,
        "task_type": TASK_TYPE,
        "records_emitted": len(records),
        "output_path": str(out_path),
        "dry_run": False,
        "estimated_cost_usd_flash": cost,
        "status": "ok",
        "sample_task_ids": [r["task_id"] for r in records[:3]],
        "skip_existing_in_dir": args.skip_existing_in_dir,
        "existing_task_count": len(done_task_ids),
        "max_existing_task_index": max_existing_idx,
    }
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        _stderr(f"wrote {len(records)} tasks to {out_path}; est cost ${cost}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
