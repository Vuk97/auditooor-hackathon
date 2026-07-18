#!/usr/bin/env python3
"""Wave-2 hackerman ETL runner: drives ``hackerman-etl-from-contest-platforms.py``
across the contests that wave-1 parked under ``contests_skipped_by_sampling``.

Background (PR #726 wave-1, ``b92a733376``):

* Wave-1 shipped at ``sample_size=15`` per platform, yielding 1,328
  records across 24 contests (Code4rena + Sherlock).
* Wave-1 explicitly parked ~361 older Code4rena contests + ~214 older
  Sherlock contests under the ``contests_skipped_by_sampling`` block.

Wave-2 runs the underlying miner with ``--all --skip-already-mined``
against the same out-dir so that:

* Every matched repo (`code-423n4/*-findings`, `sherlock-audit/*-judging`)
  is enumerated via ``gh api`` once.
* Contests already covered by wave-1 (detected by scanning the
  ``<platform>__<contest>__<finding>`` subdirs under ``--out-dir``) are
  excluded from the fetch loop, so no gh-api budget is wasted re-mining
  wave-1's sample and no record-id collisions occur (the underlying
  miner also dedups by ``record_id``, but skipping at fetch saves
  hundreds of API calls).
* ``--per-contest-cap`` defaults to 75 to keep per-contest yields
  balanced (smaller / older contests vary widely in finding counts; 75
  is well below the wave-1 cap of 200 but still above the median count
  observed in spot-checks of the wave-1 sample).

This runner is intentionally thin: all real ETL logic lives in
``hackerman-etl-from-contest-platforms.py``. The wave-2 runner only
exists to (a) document the intent ("expand wave-1 coverage") and
(b) lock in the default flag set.

CLI:

    # Default wave-2 run (mines every older Code4rena + Sherlock contest):
    python3 tools/hackerman-etl-from-contest-platforms-wave2.py \\
        --out-dir audit/corpus_tags/tags/contest_platform_findings

    # Restrict to one platform:
    python3 tools/hackerman-etl-from-contest-platforms-wave2.py \\
        --out-dir audit/corpus_tags/tags/contest_platform_findings \\
        --filter-platform sherlock

    # Offline replay of a wave-1 cache (no live gh-api calls):
    python3 tools/hackerman-etl-from-contest-platforms-wave2.py \\
        --out-dir /tmp/wave2-replay \\
        --cache-file /tmp/wave2-cache.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import List, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-contest-platforms.py"

DEFAULT_PER_CONTEST_CAP_WAVE2 = 75


def _load_underlying_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_etl_from_contest_platforms_wave2_inner",
        str(TOOL_PATH),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules["_hackerman_etl_from_contest_platforms_wave2_inner"] = mod
    spec.loader.exec_module(mod)
    return mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--per-contest-cap",
        type=int,
        default=DEFAULT_PER_CONTEST_CAP_WAVE2,
        help=(
            "Wave-2 default {0}. Smaller than wave-1's 200 to keep yields "
            "balanced across the long tail of older contests."
        ).format(DEFAULT_PER_CONTEST_CAP_WAVE2),
    )
    parser.add_argument(
        "--filter-platform",
        choices=("code4rena", "sherlock"),
        help="Restrict to a single platform.",
    )
    parser.add_argument(
        "--cache-file",
        help="Read fetched payload from a JSON cache instead of calling gh api.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched gh-api payload to this path for later offline replay.",
    )
    parser.add_argument(
        "--no-skip-already-mined",
        action="store_true",
        help=(
            "Disable the wave-1 skip-set (debug only). Default behaviour "
            "is to scan --out-dir and skip already-mined contests."
        ),
    )
    parser.add_argument(
        "--skip-already-mined-dir",
        help=(
            "Optional explicit dir to scan for already-mined contests. "
            "Defaults to --out-dir."
        ),
    )
    parser.add_argument(
        "--max-contests",
        type=int,
        default=None,
        help=(
            "Cap NEW contests fetched per platform (already-mined skips "
            "don't count). Use to bound runtime when mining long-tail."
        ),
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    if args.per_contest_cap < 0:
        print("--per-contest-cap must be non-negative", file=sys.stderr)
        return 2

    tool = _load_underlying_tool()
    out_dir = Path(args.out_dir).expanduser().resolve()
    summary = tool.convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        sample_size=tool.DEFAULT_SAMPLE_SIZE,  # ignored when sample_all=True
        per_contest_cap=args.per_contest_cap,
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=(
            Path(args.write_cache_file).expanduser().resolve()
            if args.write_cache_file
            else None
        ),
        filter_platform=args.filter_platform,
        sample_all=True,
        skip_already_mined=not args.no_skip_already_mined,
        skip_already_mined_dir=(
            Path(args.skip_already_mined_dir).expanduser().resolve()
            if args.skip_already_mined_dir
            else None
        ),
        max_contests=args.max_contests,
    )
    summary["wave"] = "wave-2"
    summary["wave2_runner_path"] = str(Path(__file__).resolve())
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        already = summary.get("contests_skipped_already_mined") or {}
        already_counts = {k: len(v or []) for k, v in already.items()}
        print(
            "hackerman wave-2 contest-platform ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"verification_tier={summary['verification_tier']} "
            f"per_contest_cap={summary['per_contest_cap']} "
            f"by_platform={summary['by_platform']} "
            f"by_severity={summary['by_severity']} "
            f"already_mined_skipped={already_counts} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
