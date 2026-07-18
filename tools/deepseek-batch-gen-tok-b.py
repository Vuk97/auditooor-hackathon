#!/usr/bin/env python3
# R36 pathspec discipline: lane-DEEPSEEK-BATCH-GEN
# <!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json TTL 2h with this file in declared pathspec -->
"""deepseek-batch-gen-tok-b.py - TOK-B invariant-lift batch generator.

Reads existing invariant records (invariants_pilot.jsonl,
invariants_extracted.jsonl, or invariant_library_index.json) and emits a
JSONL batch asking DeepSeek to LIFT each invariant into:
  - a cross-language equivalent
  - a worklist-predicate sketch (file-shape grep / Slither query)
  - a known-violation example (with a vague hand-wave; not file:line)

CLI
---
python3 tools/deepseek-batch-gen-tok-b.py \\
    --source <jsonl-path-or-glob> \\
    --output-dir <dir> \\
    --max-batch-size <N> \\
    [--target-lang solidity|rust|go|move|any] \\
    [--dry-run] [--json]

Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional


SCHEMA_ID = "auditooor.deepseek_batch_gen_tok_b.v1"
TASK_TYPE = "tok_b_invariant_lift"
GENERATOR_NAME = "deepseek-batch-gen-tok-b"
GENERATOR_VERSION = "v1"

DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
DEFAULT_MAX_INPUT_TOKENS = 6000
DEFAULT_MAX_OUTPUT_TOKENS = 1500
DEFAULT_MAX_BATCH_SIZE = 50

PROMPT_TEMPLATE = """You are a smart-contract security researcher lifting a known invariant into a cross-language detector seed.

Invariant under analysis:

  invariant_id: {invariant_id}
  category: {category}
  statement: {statement}
  source_lang: {source_lang}
  abstraction_level: {abstraction_level}
  commit_point_pattern: {commit_point_pattern}
  defense_layer: {defense_layer}

Target language to lift into: {target_lang}

Task: produce a STRUCTURED lift record with the following fields, in JSON:

  {{
    "invariant_id": "{invariant_id}",
    "lifted_statement_{target_lang}": "<restatement in target language idiom; <=400 chars>",
    "worklist_predicate_sketch": "<regex / Slither query / Glider query sketch>",
    "canonical_violation_pattern": "<one-line shape of a typical violation>",
    "negative_control_pattern": "<shape that satisfies the invariant>",
    "applicability_caveats": ["<caveat1>", "<caveat2>"],
    "confidence_self_assessment": "<low|medium|high>",
    "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored"
  }}

Rules:
- Output ONLY the JSON object. No prose preamble.
- Do not invent file:line citations.
- Be honest: if the lift is forced or unnatural for the target language, set
  confidence_self_assessment to "low".
"""

_L34_DRAFT_FILE_RE = re.compile(
    r"submissions/(staging|paste_ready|ready|filed|packaged|held|superseded|"
    r"_killed|_oos_rejected)/[^/]+/[^/]+\.(md|md\.hash|hardening\.md|"
    r"hackenproof-plain\.txt|hackenproof-plain\.json|hackenproof-plain\.txt\.hash|"
    r"poc-transcript\.txt|poc\.zip)$"
)

EXIT_OK = 0
EXIT_ERROR = 3


def _ts_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stderr(msg: str) -> None:
    sys.stderr.write(f"[{GENERATOR_NAME} {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _l34_refuses_path(path: pathlib.Path) -> bool:
    return bool(_L34_DRAFT_FILE_RE.search(str(path)))


def _resolve_sources(source: str) -> List[pathlib.Path]:
    p = pathlib.Path(source)
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(p.glob("*.jsonl"))
    matches = sorted(pathlib.Path(m) for m in glob.glob(source))
    return [m for m in matches if m.is_file()]


def load_invariants(path: pathlib.Path) -> List[Dict[str, Any]]:
    """Load invariant records from JSONL. Tolerant of malformed lines."""
    out: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                if "invariant_id" in rec or "statement" in rec:
                    out.append(rec)
    except Exception as exc:
        _stderr(f"failed to read {path}: {exc}")
    return out


def build_task_record(
    idx: int,
    invariant: Dict[str, Any],
    task_id_prefix: str,
    target_lang: str,
    verification_tier: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task_id = f"{task_id_prefix}_{idx:04d}"
    inv_id = invariant.get("invariant_id", f"unknown-{idx:04d}")
    prompt = PROMPT_TEMPLATE.format(
        invariant_id=inv_id,
        category=invariant.get("category", "unknown"),
        statement=invariant.get("statement", "")[:600],
        source_lang=invariant.get("target_lang", "any"),
        abstraction_level=invariant.get("abstraction_level", "unknown"),
        commit_point_pattern=invariant.get("commit_point_pattern", "n/a"),
        defense_layer=invariant.get("defense_layer", "n/a"),
        target_lang=target_lang,
    )
    return {
        "task_id": task_id,
        "task_type": TASK_TYPE,
        "prompt": prompt,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "verification_tier_target": verification_tier,
        "meta": {
            "invariant_id": inv_id,
            "source_category": invariant.get("category"),
            "target_lang": target_lang,
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "schema_id": SCHEMA_ID,
        },
    }


def generate_batch(
    source: str,
    task_id_prefix: str,
    target_lang: str,
    verification_tier: str,
    max_batch_size: int,
    max_input_tokens: int,
    max_output_tokens: int,
) -> List[Dict[str, Any]]:
    files = _resolve_sources(source)
    if not files:
        return []
    records: List[Dict[str, Any]] = []
    idx = 1
    for f in files:
        invariants = load_invariants(f)
        for inv in invariants:
            if len(records) >= max_batch_size:
                return records
            records.append(build_task_record(
                idx, inv, task_id_prefix, target_lang, verification_tier,
                max_input_tokens, max_output_tokens,
            ))
            idx += 1
    return records


def write_batch(records: List[Dict[str, Any]], output_dir: pathlib.Path) -> pathlib.Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = output_dir / f"{TASK_TYPE}-batch-{ts}.jsonl"
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
    return ws / "audit" / "corpus_tags" / "derived" / "deepseek_fanout" / "tok-b"


def estimate_cost_usd(records: List[Dict[str, Any]]) -> float:
    total = 0.0
    for r in records:
        in_toks = max(1, len(r.get("prompt", "")) // 4)
        out_toks = r.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
        total += (in_toks / 1000.0) * 0.00014
        total += (out_toks / 1000.0) * 0.00028
    return round(total, 6)


def main() -> int:
    p = argparse.ArgumentParser(
        prog=GENERATOR_NAME,
        description="Generate a DeepSeek fanout batch for TOK-B invariant-lift.",
    )
    p.add_argument("--source", required=True,
                   help="Source JSONL file, directory, or glob.")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--workspace", default=None)
    p.add_argument("--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE)
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--task-id-prefix", default="tok_b_invariant_lift")
    p.add_argument("--target-lang", default="rust",
                   choices=["solidity", "go", "rust", "vyper", "move", "cairo",
                            "huff", "assembly", "typescript-onchain", "python-onchain",
                            "circom", "sway", "noir", "leo", "cairo-zk", "any"])
    p.add_argument("--verification-tier", default=DEFAULT_VERIFICATION_TIER)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    try:
        records = generate_batch(
            source=args.source,
            task_id_prefix=args.task_id_prefix,
            target_lang=args.target_lang,
            verification_tier=args.verification_tier,
            max_batch_size=args.max_batch_size,
            max_input_tokens=args.max_input_tokens,
            max_output_tokens=args.max_output_tokens,
        )
    except Exception as exc:
        _stderr(f"generate_batch failed: {exc}")
        return EXIT_ERROR

    if not records:
        _stderr(f"no invariants extracted from --source={args.source}")
        summary = {
            "schema_id": SCHEMA_ID,
            "task_type": TASK_TYPE,
            "records_emitted": 0,
            "output_path": None,
            "dry_run": args.dry_run,
            "estimated_cost_usd_flash": 0.0,
            "status": "no-records",
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
        }
        if args.json:
            print(json.dumps(summary, sort_keys=True))
        else:
            _stderr(f"DRY RUN: {len(records)} tasks; est cost ${cost}")
        return EXIT_OK

    out_dir = resolve_output_dir(args)
    out_path = write_batch(records, out_dir)
    summary = {
        "schema_id": SCHEMA_ID,
        "task_type": TASK_TYPE,
        "records_emitted": len(records),
        "output_path": str(out_path),
        "dry_run": False,
        "estimated_cost_usd_flash": cost,
        "status": "ok",
        "sample_task_ids": [r["task_id"] for r in records[:3]],
    }
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        _stderr(f"wrote {len(records)} tasks to {out_path}; est cost ${cost}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
