#!/usr/bin/env python3
# R36 pathspec discipline: lane-DEEPSEEK-BATCH-GEN
# <!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json TTL 2h with this file in declared pathspec -->
"""deepseek-batch-gen-tok-c.py - TOK-C hypothesis-gen batch generator.

Reads the workspace attack-class taxonomy (audit/corpus_tags/derived/
attack_class_taxonomy.json) and emits a JSONL batch asking DeepSeek to
GENERATE a target-shape hypothesis for each attack class: given the class
name + record-count signal, generate the canonical exploit path skeleton,
worklist predicates an auditor would walk, and the "if I see X in the
codebase, this class is live" trigger phrase.

CLI
---
python3 tools/deepseek-batch-gen-tok-c.py \\
    --source <attack_class_taxonomy.json> \\
    --output-dir <dir> \\
    --max-batch-size <N> \\
    [--min-records <N>] [--dry-run] [--json]

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
from typing import Any, Dict, List


SCHEMA_ID = "auditooor.deepseek_batch_gen_tok_c.v1"
TASK_TYPE = "tok_c_hypothesis_gen"
GENERATOR_NAME = "deepseek-batch-gen-tok-c"
GENERATOR_VERSION = "v1"

DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
DEFAULT_MAX_INPUT_TOKENS = 4000
DEFAULT_MAX_OUTPUT_TOKENS = 2000
DEFAULT_MAX_BATCH_SIZE = 50
DEFAULT_MIN_RECORDS = 20  # Per R39 orphan threshold.

PROMPT_TEMPLATE = """You are a smart-contract security researcher generating exploit-shape hypotheses for a known attack class.

Attack class under analysis:

  attack_class: {attack_class}
  total_records_in_corpus: {total_records}
  subtrees_covered: {subtrees}
  tier1_count: {tier1_count}
  tier2_count: {tier2_count}

Task: produce a STRUCTURED hypothesis with the following fields, in JSON:

  {{
    "attack_class": "{attack_class}",
    "exploit_path_skeleton": ["<step1>", "<step2>", "<step3>", "<...>"],
    "worklist_predicates": ["<predicate1>", "<predicate2>"],
    "trigger_phrase_if_codebase_shows_X": "<one-line trigger that would tell an auditor this class is live>",
    "canonical_function_shape": "<typical function name / signature / modifier pattern that exposes this class>",
    "canonical_state_field_shape": "<typical storage var / mapping pattern>",
    "false_positive_traps": ["<trap1>", "<trap2>"],
    "confidence_self_assessment": "<low|medium|high>",
    "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored"
  }}

Rules:
- Output ONLY the JSON object. No prose preamble.
- Do not invent file:line citations.
- If you don't recognize the attack_class as a meaningful class
  (e.g. it's a corpus-platform tag like "contest-platform-finding-code4rena"),
  output a record with confidence_self_assessment "low" and skeleton noting
  that the class is a meta/source tag, not a finding class.
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
        return sorted(p.glob("*.json"))
    matches = sorted(pathlib.Path(m) for m in glob.glob(source))
    return [m for m in matches if m.is_file()]


def load_taxonomy(path: pathlib.Path) -> List[Dict[str, Any]]:
    """Load attack class records from taxonomy JSON. Tolerant of shape."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        _stderr(f"failed to read {path}: {exc}")
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        classes = data.get("classes") or data.get("attack_classes") or []
        return [r for r in classes if isinstance(r, dict)]
    return []


def build_task_record(
    idx: int,
    cls: Dict[str, Any],
    task_id_prefix: str,
    verification_tier: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task_id = f"{task_id_prefix}_{idx:04d}"
    attack_class = cls.get("attack_class", f"unknown-{idx:04d}")
    subtrees = cls.get("subtrees", [])
    if isinstance(subtrees, list):
        subtrees_str = ", ".join(map(str, subtrees))[:200]
    else:
        subtrees_str = str(subtrees)[:200]
    prompt = PROMPT_TEMPLATE.format(
        attack_class=attack_class,
        total_records=cls.get("total_records", 0),
        subtrees=subtrees_str or "(none)",
        tier1_count=cls.get("tier1_count", 0),
        tier2_count=cls.get("tier2_count", 0),
    )
    return {
        "task_id": task_id,
        "task_type": TASK_TYPE,
        "prompt": prompt,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "verification_tier_target": verification_tier,
        "meta": {
            "attack_class": attack_class,
            "total_records": cls.get("total_records", 0),
            "subtrees": subtrees if isinstance(subtrees, list) else [],
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
    min_records: int,
    max_input_tokens: int,
    max_output_tokens: int,
) -> List[Dict[str, Any]]:
    files = _resolve_sources(source)
    if not files:
        return []
    records: List[Dict[str, Any]] = []
    idx = 1
    for f in files:
        classes = load_taxonomy(f)
        # Sort by total_records desc to prioritize well-supported classes.
        classes.sort(key=lambda c: c.get("total_records", 0), reverse=True)
        for cls in classes:
            tot = cls.get("total_records", 0)
            if tot < min_records:
                continue
            if len(records) >= max_batch_size:
                return records
            records.append(build_task_record(
                idx, cls, task_id_prefix, verification_tier,
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
    return ws / "audit" / "corpus_tags" / "derived" / "deepseek_fanout" / "tok-c"


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
        description="Generate a DeepSeek fanout batch for TOK-C hypothesis-gen.",
    )
    p.add_argument("--source", required=True,
                   help="Path to attack_class_taxonomy.json (or glob).")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--workspace", default=None)
    p.add_argument("--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE)
    p.add_argument("--min-records", type=int, default=DEFAULT_MIN_RECORDS,
                   help=f"Skip attack classes with fewer than this many corpus records (default {DEFAULT_MIN_RECORDS} per R39).")
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--task-id-prefix", default="tok_c_hypothesis_gen")
    p.add_argument("--verification-tier", default=DEFAULT_VERIFICATION_TIER)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    try:
        records = generate_batch(
            source=args.source,
            task_id_prefix=args.task_id_prefix,
            verification_tier=args.verification_tier,
            max_batch_size=args.max_batch_size,
            min_records=args.min_records,
            max_input_tokens=args.max_input_tokens,
            max_output_tokens=args.max_output_tokens,
        )
    except Exception as exc:
        _stderr(f"generate_batch failed: {exc}")
        return EXIT_ERROR

    if not records:
        _stderr(f"no eligible attack classes from --source={args.source}")
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
