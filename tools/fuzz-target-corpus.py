#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.lib.fuzz_target_corpus import (
    discover_latest_fuzz_results,
    emit_fuzz_targets,
    emit_inscope_worklist,
    extract_fuzz_target_rows_from_file,
    fuzz_target_output_path,
    workspace_slug,
    worklist_output_path,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Emit auditooor.fuzz_target.v1 rows into "
            "audit/corpus_tags/<ws>/fuzz_targets.jsonl from a fuzz_results.json input, "
            "OR (--from-inscope) emit the <ws>/.auditooor/fuzz_targets.jsonl WORKLIST "
            "(one obligation row per value-moving in-scope asset+fn cluster that still "
            "needs a fuzz campaign)."
        )
    )
    p.add_argument("--workspace", required=True, help="Workspace path or slug.")
    p.add_argument("--input", type=Path, help="Explicit fuzz_results.json input.")
    p.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    p.add_argument("--out", type=Path, help="Override output JSONL path.")
    p.add_argument("--limit", type=int, default=0, help="Emit at most N target rows.")
    p.add_argument("--json", action="store_true", help="Emit machine-readable summary.")
    p.add_argument(
        "--from-inscope",
        action="store_true",
        help=(
            "Generate the WORKLIST (<ws>/.auditooor/fuzz_targets.jsonl) from "
            "inscope_units.jsonl joined against value_moving_functions.json instead of "
            "extracting run-result rows from a fuzz_results.json."
        ),
    )
    p.add_argument(
        "--vmf-json",
        type=Path,
        help="Override the value_moving_functions.json input (--from-inscope mode).",
    )
    return p


def _run_from_inscope(args: argparse.Namespace) -> int:
    workspace_arg = args.workspace
    ws = workspace_slug(workspace_arg)
    ws_path = Path(workspace_arg).expanduser()
    if not ws_path.is_dir():
        # slug-only: resolve against repo-root/<slug> if that exists, else bail.
        candidate = args.repo_root / ws
        ws_path = candidate if candidate.is_dir() else ws_path
    if not ws_path.is_dir():
        payload = {
            "schema": "auditooor.fuzz_target_worklist_emit.v1",
            "verdict": "fail-no-workspace-dir",
            "workspace": ws,
            "reason": f"workspace directory not found: {workspace_arg}",
        }
        print(json.dumps(payload, sort_keys=True) if args.json
              else f"[fuzz-target-corpus] workspace dir not found: {workspace_arg}",
              file=sys.stdout)
        return 1
    out_path = args.out or worklist_output_path(ws_path)
    summary = emit_inscope_worklist(
        ws_path, ws, vmf_path=args.vmf_json, out_path=out_path
    )
    payload = {
        "schema": "auditooor.fuzz_target_worklist_emit.v1",
        "verdict": "pass" if summary.get("written") else "pass-empty-worklist",
        "workspace": ws,
        **summary,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"[fuzz-target-corpus] workspace={ws} worklist={summary['path']} "
            f"rows_written={summary['rows_written']} clusters={summary.get('clusters', 0)} "
            f"dropped_oos={summary.get('dropped_out_of_scope', 0)}"
            + (f" reason={summary['reason']}" if summary.get("reason") else "")
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.from_inscope:
        return _run_from_inscope(args)
    workspace_arg = args.workspace
    ws = workspace_slug(workspace_arg)
    input_path = args.input
    if input_path is None:
        input_path = discover_latest_fuzz_results(args.repo_root, workspace_arg)
    if input_path is None or not input_path.is_file():
        print(
            json.dumps(
                {
                    "schema": "auditooor.fuzz_target_emit.v1",
                    "verdict": "fail-no-input",
                    "workspace": ws,
                    "reason": "no fuzz_results.json found for workspace",
                },
                sort_keys=True,
            )
            if args.json
            else f"[fuzz-target-corpus] no fuzz_results.json found for workspace={ws}",
            file=sys.stdout,
        )
        return 1
    rows = extract_fuzz_target_rows_from_file(
        input_path,
        ws=ws,
        limit=args.limit if args.limit > 0 else None,
    )
    summary = emit_fuzz_targets(
        args.out or fuzz_target_output_path(args.repo_root, ws),
        rows,
    )
    payload = {
        "schema": "auditooor.fuzz_target_emit.v1",
        "verdict": "pass",
        "workspace": ws,
        "input": str(input_path),
        **summary,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"[fuzz-target-corpus] workspace={ws} input={input_path} "
            f"rows_appended={summary['rows_appended']} targets_found={summary['targets_found']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
