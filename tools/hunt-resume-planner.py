#!/usr/bin/env python3
# R36 pathspec discipline: lane hunt-resume-planner-2026-05-30 registered in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.
"""hunt-resume-planner.py - resumable + failover-capable re-hunt planner.

ROOT-CAUSE THIS TOOL ADDRESSES
------------------------------
Per-function MIMO hunts (dydx, morpho) FAILED with
status=failed / error="retry-max-exhausted: rate-limited", producing near-zero
real anchors (e.g. dydx mega_perfn_dydx_KEY6: 82 ok / 111
retry-max-exhausted). The dispatcher (tools/llm-fanout-dispatcher.py)
DOES have retries (they exhausted), so "add retries" is NOT the gap. The two
real gaps are:

  (1) NO CHECKPOINT/RESUME: a rate-limited task STILL writes a result file
      (a `status=failed` record). The dispatcher's skip-existing logic then
      treats that file as "done" and PERMANENTLY skips the task on any re-run.
      The rate-limited work is lost, not just deferred.
  (2) NO PROVIDER-FAILOVER: `provider` is fixed for the whole batch. A 429
      from the single configured provider only triggers same-provider backoff;
      after retry-max it just fails. One rate-limited provider takes the whole
      hunt down instead of failing over to an alternate.

WHAT THIS TOOL DOES (standalone; does NOT edit the live dispatcher)
------------------------------------------------------------------
Given a finished hunt RECORD DIR (mega*<ws>*/, mimo_harness_<ws>*/, ...):

  - RESUME PLAN: classify every record (reusing the EXACT classifier from
    tools/hunt-run-health-check.py) and select the set of tasks that produced
    NO real anchor and SHOULD be re-hunted: status=failed / rate_limited /
    empty (ran-but-anchored-nothing). The already-successful tasks are NEVER
    selected. Plus, when --original-batch is supplied, UNATTEMPTED tasks
    (present in the batch, no result file at all) are added to the plan.

  - FAILOVER ROUTING: for each rate_limited task, pick an ALTERNATE provider
    (different from the one that rate-limited it) read from the provider
    registry (tools/calibration/llm_budget.json -> providers). No hardcoded
    provider list. The chosen provider is annotated onto each resume-batch
    task so the re-dispatch routes around the saturated provider.

  - RESUME BATCH (only with --original-batch): rehydrate the full task objects
    (prompt + metadata) for the selected task_ids from the original batch
    JSONL, set each task's `provider` to its failover target, and write a
    resume-batch JSONL. Re-dispatch it with the EXISTING dispatcher using
    `--overwrite-existing` so the stale failed result files are replaced:

        python3 tools/llm-fanout-dispatcher.py \
            --task-batch <resume_batch.jsonl> \
            --output-dir <same record dir> \
            --overwrite-existing \
            --provider <fallback default>     # per-task provider honored only
                                              # if dispatcher patch applied;
                                              # see INTEGRATION SPEC below.

    NOTE: result records carry no `prompt` field, so a re-dispatchable batch
    requires --original-batch. Without it the planner still emits the resume
    PLAN (the task_id set + per-task failover provider) - honest partial
    output, not a re-dispatchable batch.

IDEMPOTENCE
-----------
Re-running the planner on a record dir that is now fully successful yields an
EMPTY plan (0 tasks to re-hunt). This makes resume safe to loop.

OFFLINE
-------
Pure record/batch/config reads. No network. No live LLM calls. The failover
provider list comes from llm_budget.json; --providers-json overrides for tests.

Stdlib only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_ID = "auditooor.hunt_resume_planner.v1"

_THIS = Path(__file__).resolve()
_TOOLS = _THIS.parent
_ROOT = _TOOLS.parent

# Default provider registry (no hardcoded provider list; this is the PATH).
_DEFAULT_BUDGET_CONFIG = _TOOLS / "calibration" / "llm_budget.json"

# Klasses (from hunt-run-health-check) that mean "no real anchor -> re-hunt".
# success is NEVER re-hunted. empty == ran-but-anchored-nothing; included
# because a re-hunt (possibly via a stronger/alternate provider) may anchor it.
_REHUNT_KLASSES = {"failed", "rate_limited", "empty"}
# klasses where provider failover is the right remedy (rate-limit specifically)
_FAILOVER_KLASSES = {"rate_limited"}


def _import_health_check():
    """Import the classifier + dir-finder from hunt-run-health-check.py.

    Reuses the EXACT classification logic rather than re-deriving it, so the
    resume plan's notion of "failed/rate-limited/empty/success" is identical to
    the HUNT-RUN-HEALTH detector's.
    """
    path = _TOOLS / "hunt-run-health-check.py"
    spec = importlib.util.spec_from_file_location("_hrh", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load classifier from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_providers(budget_config: Path,
                   providers_json: Optional[Path] = None) -> List[str]:
    """Return the ordered list of known providers.

    Source priority: --providers-json (test override) > llm_budget.json
    `providers` keys. Never hardcoded.
    """
    if providers_json is not None:
        try:
            data = json.loads(providers_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if isinstance(data, list):
            return [str(p) for p in data]
        if isinstance(data, dict):
            provs = data.get("providers", data)
            if isinstance(provs, dict):
                return list(provs.keys())
            if isinstance(provs, list):
                return [str(p) for p in provs]
        return []
    try:
        data = json.loads(budget_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    provs = data.get("providers") if isinstance(data, dict) else None
    return list(provs.keys()) if isinstance(provs, dict) else []


def pick_failover_provider(saturated_provider: str,
                           providers: List[str]) -> Optional[str]:
    """Pick an alternate provider distinct from the saturated one.

    Deterministic: first provider in the registry that is not the saturated
    one. Returns None if no alternate exists (single-provider deployment ->
    failover is impossible, honest None).
    """
    sat = (saturated_provider or "").strip().lower()
    for p in providers:
        if str(p).strip().lower() != sat:
            return str(p)
    return None


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _read_record(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def scan_record_dir(record_dir: Path, classify_record) -> Dict[str, Any]:
    """Classify every result record file in record_dir.

    Returns {task_id: {"klass": ..., "provider": ..., "error": ..., "path": ...}}
    plus aggregate counts. The result filename stem is the task_id join key.
    """
    by_task: Dict[str, Dict[str, Any]] = {}
    counts = {"success": 0, "failed": 0, "rate_limited": 0, "empty": 0}
    for jf in sorted(record_dir.glob("*.json")):
        rec = _read_record(jf)
        if rec is None:
            continue
        task_id = str(rec.get("task_id") or jf.stem)
        klass, file_ref = classify_record(rec)
        if klass in counts:
            counts[klass] += 1
        by_task[task_id] = {
            "klass": klass,
            "file_ref": file_ref,
            "provider": rec.get("provider"),
            "error": rec.get("error"),
            "source_question_id": rec.get("source_question_id"),
            "path": str(jf),
        }
    return {"by_task": by_task, "counts": counts}


def build_resume_plan(
    record_dir: Path,
    classify_record,
    providers: List[str],
    original_batch: Optional[List[Dict[str, Any]]] = None,
    rehunt_empty: bool = True,
) -> Dict[str, Any]:
    """Compute the resume plan + per-task failover routing.

    Selection rule:
      - success records -> NEVER selected.
      - failed / rate_limited records -> selected (re-hunt).
      - empty records -> selected iff rehunt_empty (default True).
      - unattempted batch tasks (in original_batch, no result file) ->
        selected (only knowable when original_batch is supplied).

    Failover:
      - rate_limited tasks get a failover provider distinct from the one that
        rate-limited them.
      - other selected tasks keep their original/default provider (or the
        batch's provider when rehydrated).
    """
    scan = scan_record_dir(record_dir, classify_record)
    by_task = scan["by_task"]
    rehunt_set = set(_REHUNT_KLASSES)
    if not rehunt_empty:
        rehunt_set.discard("empty")

    selected: List[Dict[str, Any]] = []
    for task_id, info in by_task.items():
        if info["klass"] not in rehunt_set:
            continue
        entry: Dict[str, Any] = {
            "task_id": task_id,
            "reason": info["klass"],
            "prior_provider": info["provider"],
            "prior_error": info["error"],
        }
        if info["klass"] in _FAILOVER_KLASSES:
            fp = pick_failover_provider(str(info["provider"] or ""), providers)
            entry["failover_provider"] = fp
            entry["failover_available"] = fp is not None
        else:
            entry["failover_provider"] = None
            entry["failover_available"] = False
        selected.append(entry)

    # UNATTEMPTED tasks: in original batch but with no result file at all.
    unattempted = 0
    batch_by_id: Dict[str, Dict[str, Any]] = {}
    if original_batch is not None:
        for t in original_batch:
            tid = str(t.get("task_id") or "")
            if not tid:
                continue
            batch_by_id[tid] = t
            if tid not in by_task:
                unattempted += 1
                selected.append({
                    "task_id": tid,
                    "reason": "unattempted",
                    "prior_provider": None,
                    "prior_error": None,
                    "failover_provider": None,
                    "failover_available": False,
                })

    selected.sort(key=lambda e: e["task_id"])

    plan = {
        "schema": SCHEMA_ID,
        "record_dir": str(record_dir),
        "providers_known": providers,
        "counts": scan["counts"],
        "total_records": sum(scan["counts"].values()),
        "unattempted_in_batch": unattempted,
        "resume_task_count": len(selected),
        "rehunt_empty": rehunt_empty,
        "resume_tasks": selected,
        "idempotent_empty": len(selected) == 0,
    }
    return plan, batch_by_id


def write_resume_batch(
    plan: Dict[str, Any],
    batch_by_id: Dict[str, Dict[str, Any]],
    out_path: Path,
) -> Tuple[int, int]:
    """Rehydrate full task objects for selected task_ids and write a re-hunt
    batch JSONL with per-task failover provider set.

    Returns (written, missing_prompt) where missing_prompt counts selected
    task_ids that could not be rehydrated (absent from original batch -> no
    prompt, cannot re-dispatch).
    """
    written = 0
    missing = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for entry in plan["resume_tasks"]:
            tid = entry["task_id"]
            base = batch_by_id.get(tid)
            if base is None:
                missing += 1
                continue
            task = dict(base)
            fp = entry.get("failover_provider")
            if fp:
                task["provider"] = fp
                task["_resume_failover_from"] = entry.get("prior_provider")
            task["_resume_reason"] = entry["reason"]
            fh.write(json.dumps(task, sort_keys=True) + "\n")
            written += 1
    return written, missing


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hunt-resume-planner",
        description="Resumable + failover-capable re-hunt planner.",
    )
    ap.add_argument("--record-dir", required=True,
                    help="finished hunt record dir (mega*<ws>*/, mimo_harness_<ws>*/)")
    ap.add_argument("--original-batch",
                    help="original task-batch JSONL (carries prompt; required to "
                         "emit a re-dispatchable resume batch and to detect "
                         "unattempted tasks)")
    ap.add_argument("--resume-batch-out",
                    help="write rehydrated resume batch JSONL here "
                         "(requires --original-batch)")
    ap.add_argument("--budget-config", default=str(_DEFAULT_BUDGET_CONFIG),
                    help="provider registry (llm_budget.json)")
    ap.add_argument("--providers-json",
                    help="override provider list (test hook): JSON list or "
                         "{'providers': {...}}")
    ap.add_argument("--no-rehunt-empty", action="store_true",
                    help="exclude ran-but-anchored-nothing (empty) records "
                         "from the plan; only re-hunt failed/rate-limited")
    ap.add_argument("--json", action="store_true",
                    help="emit the full plan as JSON on stdout")
    args = ap.parse_args(argv)

    record_dir = Path(args.record_dir).resolve()
    if not record_dir.is_dir():
        sys.stderr.write(f"ERROR: record-dir not a directory: {record_dir}\n")
        return 2

    hrh = _import_health_check()
    classify_record = hrh.classify_record

    providers = load_providers(
        Path(args.budget_config),
        Path(args.providers_json) if args.providers_json else None,
    )

    original_batch = None
    if args.original_batch:
        original_batch = _read_jsonl(Path(args.original_batch).resolve())

    plan, batch_by_id = build_resume_plan(
        record_dir,
        classify_record,
        providers,
        original_batch=original_batch,
        rehunt_empty=not args.no_rehunt_empty,
    )

    resume_batch_written = None
    resume_batch_missing = None
    if args.resume_batch_out:
        if original_batch is None:
            sys.stderr.write(
                "ERROR: --resume-batch-out requires --original-batch "
                "(result records carry no prompt to rehydrate).\n"
            )
            return 2
        written, missing = write_resume_batch(
            plan, batch_by_id, Path(args.resume_batch_out).resolve()
        )
        resume_batch_written = written
        resume_batch_missing = missing
        plan["resume_batch_out"] = str(Path(args.resume_batch_out).resolve())
        plan["resume_batch_written"] = written
        plan["resume_batch_missing_prompt"] = missing

    if args.json:
        sys.stdout.write(json.dumps(plan, sort_keys=True, indent=2) + "\n")
    else:
        c = plan["counts"]
        sys.stdout.write(f"record_dir: {plan['record_dir']}\n")
        sys.stdout.write(
            f"records: success={c['success']} failed={c['failed']} "
            f"rate_limited={c['rate_limited']} empty={c['empty']}\n"
        )
        sys.stdout.write(f"unattempted_in_batch: {plan['unattempted_in_batch']}\n")
        sys.stdout.write(f"resume_task_count: {plan['resume_task_count']}\n")
        sys.stdout.write(f"providers_known: {plan['providers_known']}\n")
        sys.stdout.write(f"idempotent_empty: {plan['idempotent_empty']}\n")
        if resume_batch_written is not None:
            sys.stdout.write(
                f"resume_batch_written: {resume_batch_written} "
                f"(missing_prompt: {resume_batch_missing})\n"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
