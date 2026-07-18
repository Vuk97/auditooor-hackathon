#!/usr/bin/env python3
# R36 pathspec discipline: lane-DEEPSEEK-BATCH-GEN
# <!-- r36-rebuttal: lane-DEEPSEEK-BATCH-GEN registered in .auditooor/agent_pathspec.json TTL 2h with this file in declared pathspec -->
"""deepseek-batch-gen-tok-g.py - TOK-G anti-pattern-corpus-expansion batch generator.

Reads anti-pattern docs (reference/anti_patterns.md or similar markdown
catalogs) and emits a JSONL batch asking DeepSeek to EXPAND each
anti-pattern into:
  - 2 additional concrete worked examples
  - a detection-heuristic the orchestrator can use to catch the
    anti-pattern mid-loop (proactive, not just retrospective)
  - a corrective phrasing the operator can paste into a worker brief

CLI
---
python3 tools/deepseek-batch-gen-tok-g.py \\
    --source <anti_patterns.md or glob> \\
    --output-dir <dir> \\
    --max-batch-size <N> \\
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


SCHEMA_ID = "auditooor.deepseek_batch_gen_tok_g.v1"
TASK_TYPE = "tok_g_antipattern_expand"
GENERATOR_NAME = "deepseek-batch-gen-tok-g"
GENERATOR_VERSION = "v1"

DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
DEFAULT_MAX_INPUT_TOKENS = 6000
DEFAULT_MAX_OUTPUT_TOKENS = 2000
DEFAULT_MAX_BATCH_SIZE = 50

PROMPT_TEMPLATE = """You are expanding a known audit-process anti-pattern into a richer detection-ready record.

Anti-pattern under analysis:

  anti_pattern_title: {title}
  anti_pattern_body: |
{body}

Task: produce a STRUCTURED expansion record with the following fields, in JSON:

  {{
    "anti_pattern_title": "{title}",
    "two_additional_worked_examples": [
      {{
        "scenario": "<2-3 sentence narrative of a NEW concrete case>",
        "telltale_signal": "<one-line signal an orchestrator could detect mid-loop>"
      }},
      {{
        "scenario": "<...>",
        "telltale_signal": "<...>"
      }}
    ],
    "mid_loop_detection_heuristic": "<one-paragraph heuristic the orchestrator can apply BEFORE the mistake is finalized>",
    "worker_brief_corrective_phrasing": "<verbatim sentence the operator can paste into a worker prompt to prevent recurrence>",
    "confidence_self_assessment": "<low|medium|high>",
    "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored"
  }}

Rules:
- Output ONLY the JSON object. No prose preamble.
- New worked examples MUST differ from the input body's existing example.
- The detection heuristic must be actionable mid-loop (not retrospective).
- The corrective phrasing must be paste-ready (no placeholders).
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
        return sorted(p.glob("*.md"))
    matches = sorted(pathlib.Path(m) for m in glob.glob(source))
    return [m for m in matches if m.is_file()]


# Parse anti-pattern entries: H3 headers "### N. Title" followed by body until next H3 or H2.
ENTRY_HEADER_RE = re.compile(r"^###\s+(?P<num>\d+)\.\s+(?P<title>.+?)\s*$")
SECTION_BOUNDARY_RE = re.compile(r"^(#{1,3})\s+")


def extract_anti_patterns(text: str, source_path: str) -> List[Dict[str, Any]]:
    """Parse markdown anti-pattern catalog into per-entry records."""
    out: List[Dict[str, Any]] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = ENTRY_HEADER_RE.match(lines[i].rstrip())
        if not m:
            i += 1
            continue
        title = m.group("title").strip()
        body_lines: List[str] = []
        i += 1
        while i < n:
            ln = lines[i].rstrip()
            if ENTRY_HEADER_RE.match(ln):
                break
            # Top-level section boundary (# or ##) ends this entry.
            sm = SECTION_BOUNDARY_RE.match(ln)
            if sm and len(sm.group(1)) < 3:
                break
            body_lines.append(ln)
            i += 1
        body = "\n".join(body_lines).strip()
        # Cap body at 1500 chars.
        body = body[:1500]
        if not body:
            continue
        out.append({
            "title": title,
            "body": body,
            "source_path": source_path,
        })
    return out


def build_task_record(
    idx: int,
    entry: Dict[str, Any],
    task_id_prefix: str,
    verification_tier: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task_id = f"{task_id_prefix}_{idx:04d}"
    body_indented = "\n".join(f"    {ln}" for ln in entry["body"].splitlines()) or "    (empty)"
    prompt = PROMPT_TEMPLATE.format(
        title=entry["title"],
        body=body_indented,
    )
    return {
        "task_id": task_id,
        "task_type": TASK_TYPE,
        "prompt": prompt,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "verification_tier_target": verification_tier,
        "meta": {
            "anti_pattern_title": entry["title"],
            "source_path": entry["source_path"],
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
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            _stderr(f"failed to read {f}: {exc}")
            continue
        entries = extract_anti_patterns(text, str(f))
        for entry in entries:
            if len(records) >= max_batch_size:
                return records
            records.append(build_task_record(
                idx, entry, task_id_prefix, verification_tier,
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
    return ws / "audit" / "corpus_tags" / "derived" / "deepseek_fanout" / "tok-g"


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
        description="Generate a DeepSeek fanout batch for TOK-G anti-pattern expansion.",
    )
    p.add_argument("--source", required=True,
                   help="Anti-pattern markdown file, directory, or glob.")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--workspace", default=None)
    p.add_argument("--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE)
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--task-id-prefix", default="tok_g_antipattern_expand")
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
        _stderr(f"no anti-patterns extracted from --source={args.source}")
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
