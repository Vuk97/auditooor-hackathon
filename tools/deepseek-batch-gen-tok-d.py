#!/usr/bin/env python3
# R36 pathspec discipline: lane-DEEPSEEK-BATCH-GEN
# <!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json TTL 2h with this file in declared pathspec -->
"""deepseek-batch-gen-tok-d.py - TOK-D adversarial-persona batch generator.

Reads attacker mental-frame YAMLs (reference/attacker_frames/*.yaml) and
emits a JSONL batch asking DeepSeek to ROLE-PLAY each frame as an
adversarial researcher: given the frame's attacker_question and mental
steps, produce 3 concrete worked exploit-search examples targeting
canonical protocol shapes (bridge, lending, perp, dex, statechain).

CLI
---
python3 tools/deepseek-batch-gen-tok-d.py \\
    --source <reference/attacker_frames or glob> \\
    --output-dir <dir> \\
    --max-batch-size <N> \\
    [--dry-run] [--json]

Stdlib only. Does NOT depend on PyYAML; the YAML parser here is a minimal
key:value scanner sufficient for the controlled frame schema. Records
that fail to parse are skipped (no fabrication).
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


SCHEMA_ID = "auditooor.deepseek_batch_gen_tok_d.v1"
TASK_TYPE = "tok_d_adversarial_persona"
GENERATOR_NAME = "deepseek-batch-gen-tok-d"
GENERATOR_VERSION = "v1"

DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
DEFAULT_MAX_INPUT_TOKENS = 6000
DEFAULT_MAX_OUTPUT_TOKENS = 2000
DEFAULT_MAX_BATCH_SIZE = 50

PROMPT_TEMPLATE = """You are role-playing an adversarial smart-contract security researcher using a documented mental frame.

Mental frame under analysis:

  frame_id: {frame_id}
  title: {title}
  bug_class: {bug_class}
  protocol_class: {protocol_class}
  attacker_question: |
{attacker_question}

  preconditions_summary: {preconditions_summary}

Task: produce a STRUCTURED adversarial-persona record with the following fields, in JSON:

  {{
    "frame_id": "{frame_id}",
    "worked_examples": [
      {{
        "target_shape": "<bridge|lending|perp|dex|statechain|other>",
        "scenario_narrative": "<2-3 sentence adversarial walk-through>",
        "concrete_grep_or_query_strings": ["<query1>", "<query2>"],
        "expected_smell_when_class_present": "<one-line smell>",
        "expected_smell_when_class_absent": "<one-line negative-control smell>"
      }},
      {{...}},
      {{...}}
    ],
    "frame_strength_assessment": "<low|medium|high>",
    "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored"
  }}

Rules:
- Output ONLY the JSON object. No prose preamble.
- 3 worked examples, each from a DIFFERENT protocol shape.
- No fabricated file:line citations.
- If the frame is too abstract to ground, set frame_strength_assessment "low".
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
        return sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml")))
    matches = sorted(pathlib.Path(m) for m in glob.glob(source))
    return [m for m in matches if m.is_file()]


def _minimal_yaml_extract(text: str) -> Dict[str, Any]:
    """Minimal YAML extractor for the attacker-frame schema.

    Returns dict with keys: frame_id, title, bug_class, protocol_class (list),
    attacker_question (multi-line str), preconditions (list). Tolerant of
    unknown keys (ignored). Returns {} on total parse failure.
    """
    out: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    current_list_key: Optional[str] = None
    current_block_key: Optional[str] = None
    block_buf: List[str] = []
    block_indent: Optional[int] = None
    while i < n:
        raw = lines[i]
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            if current_block_key:
                # blank line inside block scalar - keep
                block_buf.append("")
            i += 1
            continue
        # Block scalar accumulation.
        if current_block_key is not None:
            leading = len(raw) - len(raw.lstrip(" "))
            if block_indent is None and raw.strip():
                block_indent = leading
            if raw.strip() and (block_indent is None or leading >= block_indent):
                block_buf.append(raw[block_indent or 0:])
                i += 1
                continue
            else:
                # End of block scalar.
                out[current_block_key] = "\n".join(block_buf).rstrip()
                current_block_key = None
                block_buf = []
                block_indent = None
                # Fall through to re-process this line.
        # List item.
        if line.startswith("  - ") or line.startswith("- "):
            if current_list_key:
                item = line.split("- ", 1)[1].strip().strip('"').strip("'")
                out.setdefault(current_list_key, []).append(item)
                i += 1
                continue
        # Top-level key: value or key: |.
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            current_list_key = None
            if val == "|" or val == ">" or val == "|-" or val == ">-":
                current_block_key = key
                block_buf = []
                block_indent = None
            elif val == "":
                # Empty value -> probably a list start; mark current_list_key.
                current_list_key = key
            else:
                # Strip quotes.
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                out[key] = val
            i += 1
            continue
        i += 1
    # Flush trailing block.
    if current_block_key is not None:
        out[current_block_key] = "\n".join(block_buf).rstrip()
    return out


def load_attacker_frames(path: pathlib.Path) -> List[Dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _stderr(f"failed to read {path}: {exc}")
        return []
    parsed = _minimal_yaml_extract(text)
    if not parsed:
        return []
    if "frame_id" not in parsed and "title" not in parsed:
        return []
    parsed["_source_path"] = str(path)
    return [parsed]


def build_task_record(
    idx: int,
    frame: Dict[str, Any],
    task_id_prefix: str,
    verification_tier: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task_id = f"{task_id_prefix}_{idx:04d}"
    frame_id = frame.get("frame_id", f"unknown-{idx:04d}")
    title = frame.get("title", "(no title)")
    bug_class = frame.get("bug_class", "unknown")
    protocol_class = frame.get("protocol_class", [])
    if isinstance(protocol_class, list):
        protocol_class_str = ", ".join(protocol_class)
    else:
        protocol_class_str = str(protocol_class)
    attacker_question = frame.get("attacker_question", "")[:800]
    # Indent question for readability in prompt.
    aq_indented = "\n".join(f"    {ln}" for ln in attacker_question.splitlines()) or "    (none)"
    preconditions = frame.get("preconditions", [])
    if isinstance(preconditions, list):
        preconditions_summary = "; ".join(preconditions)[:400] or "(none)"
    else:
        preconditions_summary = str(preconditions)[:400]
    prompt = PROMPT_TEMPLATE.format(
        frame_id=frame_id,
        title=title,
        bug_class=bug_class,
        protocol_class=protocol_class_str or "(none)",
        attacker_question=aq_indented,
        preconditions_summary=preconditions_summary,
    )
    return {
        "task_id": task_id,
        "task_type": TASK_TYPE,
        "prompt": prompt,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "verification_tier_target": verification_tier,
        "meta": {
            "frame_id": frame_id,
            "title": title,
            "bug_class": bug_class,
            "protocol_class": protocol_class if isinstance(protocol_class, list) else [],
            "source_path": frame.get("_source_path"),
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
) -> List[Dict[str, Any]]:
    files = _resolve_sources(source)
    if not files:
        return []
    records: List[Dict[str, Any]] = []
    idx = 1
    for f in files:
        frames = load_attacker_frames(f)
        for frame in frames:
            if len(records) >= max_batch_size:
                return records
            records.append(build_task_record(
                idx, frame, task_id_prefix, verification_tier,
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
    return ws / "audit" / "corpus_tags" / "derived" / "deepseek_fanout" / "tok-d"


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
        description="Generate a DeepSeek fanout batch for TOK-D adversarial-persona.",
    )
    p.add_argument("--source", required=True,
                   help="Attacker frame YAML file, directory, or glob.")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--workspace", default=None)
    p.add_argument("--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE)
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--task-id-prefix", default="tok_d_adversarial_persona")
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
            max_input_tokens=args.max_input_tokens,
            max_output_tokens=args.max_output_tokens,
        )
    except Exception as exc:
        _stderr(f"generate_batch failed: {exc}")
        return EXIT_ERROR

    if not records:
        _stderr(f"no attacker frames extracted from --source={args.source}")
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
