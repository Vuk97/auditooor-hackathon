#!/usr/bin/env python3
# R36 pathspec discipline: this lane is registered as
# lane-DEEPSEEK-FANOUT-HARNESS in .auditooor/agent_pathspec.json via
# tools/agent-pathspec-register.py (TTL 2h, registered 2026-05-26).
"""llm-fanout-dispatcher.py - mass-fanout dispatcher for LLM calls (MIMO/DeepSeek).

# RENAMED 2026-06-13: was deepseek-fanout-dispatcher.py. Old name kept only in
# comments/docs. Use tools/llm-fanout-dispatcher.py for all new invocations.

Lane DEEPSEEK-FANOUT-HARNESS (2026-05-26). Builds on top of the
DEEPSEEK-INTEGRATION-CORE lane's per-call dispatch (tools/llm-dispatch.py
or AUDITOOOR_LLM_PROVIDER=deepseek path). This wrapper runs 100-500
concurrent DeepSeek requests against a JSONL batch of tasks, enforces a
budget cap, retries 429/503/network errors with exponential backoff, and
emits a per-task result file plus a state-change monitor JSONL stream.

CLI
---
python3 tools/llm-fanout-dispatcher.py \
    --task-batch <batch.jsonl> \
    [--provider deepseek-flash|deepseek-pro] \
    [--concurrency 50] [--aggressive] \
    --output-dir <dir> \
    --monitor-jsonl <path> \
    [--budget-cap-usd 10] \
    [--retry-max 3] \
    [--backoff-base-s 1.0] \
    [--per-task-timeout-s 120] \
    [--workspace <path>] \
    [--mock] [--json] [--dry-run] \
    [--verification-tier tier-3-synthetic-taxonomy-anchored]

Task batch JSONL shape (one line per task):
    {
      "task_id": "tok_a_corpus_mine_0001",
      "task_type": "tok_a_corpus_mine",
      "prompt": "<prompt text>",
      "max_input_tokens": 8000,
      "max_output_tokens": 1500,
      "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
      "meta": {...}
    }

Per-task result file (output-dir/<task_id>.json):
    {
      "task_id": ..., "status": "ok|failed|timeout|halted",
      "provider": "deepseek-flash", "model_id": ...,
      "input_tokens": N, "output_tokens": N, "cost_usd": F,
      "verification_tier": "tier-3-...",
      "duration_s": F, "result": "<text>" or None,
      "error": "<error msg>" or None,
      "retries": N, "started_at_utc": ..., "ended_at_utc": ...
    }

Monitor JSONL (one event per task-state-change):
    {"ts_utc": "...", "event": "task_started|task_ok|task_failed|task_retry|batch_halt",
     "task_id": ..., "in_flight": N, "done": N, "failed": N,
     "cost_usd_cumulative": F, "details": {...}}

Rate-limit + retry policy
-------------------------
- HTTP 429: exponential backoff (base * 2**attempt), respect Retry-After
  header if present, up to --retry-max retries.
- HTTP 503: same as 429.
- HTTP 401: immediate halt of the entire batch + operator alert + exit 2.
  Auth errors do not retry.
- "Insufficient Balance" / "balance" in error message: halt batch +
  emit INSUFFICIENT_BALANCE_HALT event + exit 2.
- Network timeout / connection error: 3x retry (independent of retry-max
  for transport errors; this matches the deliverable spec).
- Per-task max duration: --per-task-timeout-s (default 120).

Output discipline (R37 verification_tier + L34 v2 path)
-------------------------------------------------------
- Default output-dir base: <workspace>/audit/corpus_tags/derived/deepseek_fanout/<task_type>/
  if --workspace and no --output-dir override. Operators can override with
  --output-dir but the dispatcher emits a stderr warn if the path is
  outside the workspace's audit/corpus_tags/ tree.
- Every emitted result carries verification_tier (default
  "tier-3-synthetic-taxonomy-anchored" unless overridden per-task by
  meta.verification_tier_target).
- L34 v2: dispatcher refuses to write to any path matching
  submissions/<status>/<slug>/<slug>.md (draft-file bucket). The
  classifier ships with tools/l34-path-classifier.py; if missing, a local
  regex fallback recognizes the canonical draft-file shape.

Security
--------
- DEEPSEEK_API_KEY value is NEVER echoed to stderr, stdout, or any audit
  trail. Only "present"/"absent" is logged.
- All non-mock paths route through tools/llm-dispatch.py when invoked
  via subprocess. The dispatcher does NOT bypass the universal
  llm-dispatch wrapper.

Mock mode
---------
--mock disables network. Each task returns a synthetic result deterministic
on task_id (sha256-derived). Cost is computed via mock pricing constants.
All other paths (semaphore, retry, monitor JSONL, output files) execute.

Stdlib only: argparse, asyncio, datetime, hashlib, json, os, pathlib, re,
sys, time, urllib (via subprocess to llm-dispatch.py). No requests, no
aiohttp, no third-party deps.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_ID = "auditooor.deepseek_fanout_dispatcher.v1"
PROVIDER_RECEIPT_SCHEMA = "auditooor.provider_fanout_receipt.v1"

# Pricing (USD per 1K tokens). Mock-mode + real-mode share this table.
# Values approximate DeepSeek public pricing 2026 Q2; the dispatcher
# does NOT call the live API to discover pricing. Operators can override
# via --pricing-json.
_DEFAULT_PRICING = {
    # local-cli (Sonnet via the local Claude CLI subscription) is metered by the
    # subscription, not per-token here -> 0 so cost reporting does not mis-attribute
    # deepseek rates to a free local dispatch.
    "local-cli": {"input_per_1k": 0.0, "output_per_1k": 0.0},
    "deepseek-flash": {"input_per_1k": 0.00014, "output_per_1k": 0.00028},
    "deepseek-pro": {"input_per_1k": 0.00060, "output_per_1k": 0.00120},
    # <!-- r36-rebuttal: lane claude-mimo-mining-2026-05-27 registered -->
    # Xiaomi MiMo Token Plan overseas pricing per operator docs 2026-05-27.
    # mimo-v2.5: $0.14 in cache-miss / $0.28 out per 1M tokens.
    # mimo-v2.5-pro: $0.435 in cache-miss / $0.87 out per 1M tokens.
    # Default to mimo-v2.5 (cheaper) for bulk mining work.
    "mimo": {"input_per_1k": 0.00014, "output_per_1k": 0.00028},
}

# Concurrency caps. Operators MUST pass --aggressive to exceed 50.
_CONCURRENCY_DEFAULT = 50
_CONCURRENCY_AGGRESSIVE_MAX = 500

# Retry policy
_TRANSPORT_RETRY_MAX = 3  # independent of --retry-max for transport errors
_BACKOFF_CAP_S = 60.0

# Default verification tier - R37 emit-time tier declaration.
_DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

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
    """Return a UTC ISO-8601 timestamp with seconds precision."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stderr_warn(msg: str) -> None:
    sys.stderr.write(f"[deepseek-fanout WARN {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _stderr_info(msg: str) -> None:
    sys.stderr.write(f"[deepseek-fanout {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _emit_jsonl(path: pathlib.Path, record: Dict[str, Any]) -> None:
    """Append one record to a JSONL file. Best-effort; never raises."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except Exception as exc:
        _stderr_warn(f"failed to write monitor record: {exc}")


def _l34_refuses_path(path: pathlib.Path, workspace: Optional[pathlib.Path]) -> bool:
    """Return True if writing to `path` violates L34 v2 draft-file bucket.

    First tries tools/l34-path-classifier.py for canonical classification;
    falls back to the local _L34_DRAFT_FILE_RE if the classifier is absent.
    """
    classifier = pathlib.Path(__file__).resolve().parent / "l34-path-classifier.py"
    if classifier.exists():
        try:
            cmd = ["python3", str(classifier), str(path), "--json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                if data.get("bucket") == "draft-file":
                    return True
        except Exception:
            pass  # fall through to regex
    # Fallback regex check.
    path_str = str(path)
    return bool(_L34_DRAFT_FILE_RE.search(path_str))


def _compute_cost_usd(
    provider: str, input_tokens: int, output_tokens: int,
    pricing: Optional[Dict[str, Any]] = None,
) -> float:
    """Compute cost in USD for a single call."""
    table = pricing or _DEFAULT_PRICING
    rates = table.get(provider, _DEFAULT_PRICING["deepseek-flash"])
    return (input_tokens / 1000.0) * rates["input_per_1k"] + \
           (output_tokens / 1000.0) * rates["output_per_1k"]


def _mock_response(task: Dict[str, Any], provider: str) -> Tuple[str, int, int]:
    """Generate a deterministic mock response from task_id.

    Returns (result_text, input_tokens, output_tokens).
    """
    task_id = task.get("task_id", "unknown")
    seed = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    result = (
        f'{{"mock": true, "task_id": "{task_id}", "task_type": '
        f'"{task.get("task_type", "")}", "digest": "{seed[:16]}", '
        f'"note": "synthetic deterministic response from --mock mode"}}'
    )
    prompt_len = len(task.get("prompt", ""))
    input_tokens = max(1, prompt_len // 4)
    output_tokens = max(1, len(result) // 4)
    return result, input_tokens, output_tokens


def _result_path(output_dir: pathlib.Path, task_id: str) -> pathlib.Path:
    """Return the canonical result path for a task id."""
    safe_id = re.sub(r"[^A-Za-z0-9_.\-]", "_", task_id)
    return output_dir / f"{safe_id}.json"


def _write_provider_receipt(workspace: pathlib.Path, receipt: Dict[str, Any]) -> pathlib.Path:
    """Atomically publish the workspace-local provider dispatch receipt."""
    target = workspace / ".auditooor" / "provider_dispatch_receipt.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as fh:
        json.dump(receipt, fh, sort_keys=True, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temporary, target)
    return target


async def _dispatch_via_subprocess(
    task: Dict[str, Any],
    provider: str,
    per_task_timeout_s: float,
) -> Tuple[bool, str, int, int, Optional[str]]:
    """Dispatch a single task via tools/llm-dispatch.py subprocess.

    Returns (ok, result_text_or_error, input_tokens, output_tokens, http_status).
    http_status is "401" / "429" / "503" / "balance" / "timeout" / None
    depending on the failure mode, so caller can apply retry policy.
    """
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="deepseek_fanout_", suffix=".prompt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(task.get("prompt", ""))
        dispatch = pathlib.Path(__file__).resolve().parent / "llm-dispatch.py"
        cmd = [
            sys.executable, str(dispatch),
            "--prompt-file", tmp_path,
            "--provider", provider,
            "--max-tokens", str(task.get("max_output_tokens", 1500)),
            "--timeout", str(int(per_task_timeout_s)),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=per_task_timeout_s
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return (False, "per-task timeout", 0, 0, "timeout")
        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        if proc.returncode != 0:
            err_lower = stderr.lower()
            if "401" in stderr or "unauthorized" in err_lower or "auth" in err_lower:
                return (False, "auth-failed", 0, 0, "401")
            if "429" in stderr or "rate limit" in err_lower:
                return (False, "rate-limited", 0, 0, "429")
            if "503" in stderr or "service unavailable" in err_lower:
                return (False, "service-unavailable", 0, 0, "503")
            if "insufficient balance" in err_lower or "balance" in err_lower:
                return (False, "insufficient-balance", 0, 0, "balance")
            if "timeout" in err_lower or "timed out" in err_lower:
                return (False, "transport-timeout", 0, 0, "timeout")
            return (False, f"dispatch-exit-{proc.returncode}: {stderr[:200]}",
                    0, 0, None)
        prompt_len = len(task.get("prompt", ""))
        input_tokens = max(1, prompt_len // 4)
        output_tokens = max(1, len(stdout) // 4)
        return (True, stdout, input_tokens, output_tokens, None)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


class FanoutState:
    """Mutable state shared across coroutines for monitor reporting."""

    def __init__(self, total_tasks: int, monitor_path: Optional[pathlib.Path],
                 budget_cap_usd: float) -> None:
        self.total = total_tasks
        self.in_flight = 0
        self.done = 0
        self.failed = 0
        self.cost_usd = 0.0
        self.monitor_path = monitor_path
        self.budget_cap_usd = budget_cap_usd
        self.halted = False
        self.halt_reason: Optional[str] = None
        self._lock = asyncio.Lock()

    async def emit(self, event: str, task_id: str,
                   details: Optional[Dict[str, Any]] = None) -> None:
        async with self._lock:
            record = {
                "ts_utc": _ts_utc(),
                "event": event,
                "task_id": task_id,
                "in_flight": self.in_flight,
                "done": self.done,
                "failed": self.failed,
                "cost_usd_cumulative": round(self.cost_usd, 6),
                "details": details or {},
            }
        if self.monitor_path is not None:
            _emit_jsonl(self.monitor_path, record)


async def _run_one_task(
    task: Dict[str, Any],
    semaphore: asyncio.Semaphore,
    state: FanoutState,
    args: argparse.Namespace,
    output_dir: pathlib.Path,
    pricing: Dict[str, Any],
) -> Dict[str, Any]:
    """Run a single task with the full retry/backoff state machine."""
    task_id = task.get("task_id", "unknown")
    provider = args.provider
    started = _ts_utc()
    started_mono = time.monotonic()

    if state.halted:
        result_record = {
            "task_id": task_id,
            "status": "halted",
            "provider": provider,
            "model_id": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "verification_tier": task.get(
                "verification_tier_target", args.verification_tier
            ),
            "duration_s": 0.0,
            "result": None,
            "error": f"batch-halted: {state.halt_reason}",
            "retries": 0,
            "started_at_utc": started,
            "ended_at_utc": _ts_utc(),
        }
        _write_result(
            output_dir, task_id, result_record,
            overwrite_existing=args.overwrite_existing,
        )
        return result_record

    async with semaphore:
        state.in_flight += 1
        await state.emit("task_started", task_id, {"task_type": task.get("task_type")})

        retries = 0
        last_error: Optional[str] = None
        result_text: Optional[str] = None
        input_tokens = 0
        output_tokens = 0
        retry_max = args.retry_max
        backoff_base = args.backoff_base_s
        per_task_timeout = args.per_task_timeout_s

        if args.mock:
            result_text, input_tokens, output_tokens = _mock_response(task, provider)
            await asyncio.sleep(0.005)
            ok = True
        else:
            ok = False
            transport_retries = 0
            text_or_err = ""
            while True:
                try:
                    ok, text_or_err, in_tok, out_tok, http_status = \
                        await _dispatch_via_subprocess(
                            task, provider, per_task_timeout
                        )
                except Exception as exc:
                    ok = False
                    text_or_err = f"exception: {exc}"
                    in_tok = 0
                    out_tok = 0
                    http_status = "exception"
                if ok:
                    result_text = text_or_err
                    input_tokens = in_tok
                    output_tokens = out_tok
                    break
                if http_status == "401":
                    state.halted = True
                    state.halt_reason = "AUTH_FAILED_HALT"
                    last_error = text_or_err
                    await state.emit(
                        "batch_halt", task_id,
                        {"reason": "AUTH_FAILED_HALT", "exit": 2},
                    )
                    _stderr_warn(
                        f"AUTH FAILURE on {task_id}: halting batch (exit 2). "
                        f"Check DEEPSEEK_API_KEY presence (not echoed)."
                    )
                    break
                if http_status == "balance":
                    state.halted = True
                    state.halt_reason = "INSUFFICIENT_BALANCE_HALT"
                    last_error = text_or_err
                    await state.emit(
                        "batch_halt", task_id,
                        {"reason": "INSUFFICIENT_BALANCE_HALT", "exit": 2},
                    )
                    _stderr_warn(
                        f"INSUFFICIENT BALANCE on {task_id}: halting batch (exit 2)."
                    )
                    break
                if http_status in ("429", "503"):
                    if retries >= retry_max:
                        last_error = f"retry-max-exhausted: {text_or_err}"
                        break
                    retries += 1
                    sleep_s = min(backoff_base * (2 ** (retries - 1)), _BACKOFF_CAP_S)
                    await state.emit(
                        "task_retry", task_id,
                        {"http_status": http_status, "retry": retries,
                         "sleep_s": sleep_s},
                    )
                    await asyncio.sleep(sleep_s)
                    continue
                if http_status in ("timeout", "exception"):
                    if transport_retries >= _TRANSPORT_RETRY_MAX:
                        last_error = f"transport-retry-exhausted: {text_or_err}"
                        break
                    transport_retries += 1
                    sleep_s = min(backoff_base * (2 ** (transport_retries - 1)),
                                  _BACKOFF_CAP_S)
                    await state.emit(
                        "task_retry", task_id,
                        {"http_status": http_status, "transport_retry": transport_retries,
                         "sleep_s": sleep_s},
                    )
                    await asyncio.sleep(sleep_s)
                    continue
                last_error = text_or_err
                break

        duration = time.monotonic() - started_mono
        ended = _ts_utc()

        cost = _compute_cost_usd(provider, input_tokens, output_tokens, pricing)
        state.cost_usd += cost
        if state.cost_usd > state.budget_cap_usd and not state.halted:
            state.halted = True
            state.halt_reason = "BUDGET_CAP_EXCEEDED"
            await state.emit(
                "batch_halt", task_id,
                {"reason": "BUDGET_CAP_EXCEEDED",
                 "cost_usd": state.cost_usd, "cap_usd": state.budget_cap_usd},
            )
            _stderr_warn(
                f"BUDGET CAP EXCEEDED: cost {state.cost_usd:.4f} USD > "
                f"cap {state.budget_cap_usd:.4f} USD. Halting batch."
            )

        if ok and result_text is not None:
            state.done += 1
            await state.emit("task_ok", task_id, {"cost_usd": cost,
                                                  "duration_s": duration})
            status = "ok"
            error = None
        else:
            state.failed += 1
            await state.emit("task_failed", task_id, {"error": last_error,
                                                      "retries": retries})
            if last_error and "timeout" in (last_error or ""):
                status = "timeout"
            elif state.halted:
                status = "halted"
            else:
                status = "failed"
            error = last_error

        state.in_flight -= 1

        # r36-rebuttal: lane mimo-corpus-mining-wave-2026-05-28
        # Preserve input task metadata in result so downstream miners
        # (mimo-corpus-miner.py, hacker-q-reweighter.py) can join verdicts
        # back to source_question_id / workspace / function_anchor.
        result_record = {
            "task_id": task_id,
            "status": status,
            "provider": provider,
            "model_id": None,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(cost, 6),
            "verification_tier": task.get(
                "verification_tier_target", args.verification_tier
            ),
            "duration_s": round(duration, 4),
            "result": result_text,
            "error": error,
            "retries": retries,
            "started_at_utc": started,
            "ended_at_utc": ended,
            # Propagated input metadata for downstream join
            "source_question_id": task.get("source_question_id"),
            "workspace": task.get("workspace"),
            "workspace_path": task.get("workspace_path"),
            "task_type": task.get("task_type"),
            "attack_class": task.get("attack_class"),
            "hacker_q_reweight": task.get("hacker_q_reweight") or {},
            "mimo_context_feed": task.get("mimo_context_feed") or {},
            "file_anchor": task.get("file_anchor") or {},
            "function_anchor": task.get("function_anchor"),
            "rank": task.get("rank"),
            "score": task.get("score"),
        }
        _write_result(
            output_dir, task_id, result_record,
            overwrite_existing=args.overwrite_existing,
        )
        return result_record


def _write_result(output_dir: pathlib.Path, task_id: str,
                  record: Dict[str, Any],
                  overwrite_existing: bool = False) -> bool:
    """Write a single per-task result file, skipping existing files by default."""
    target = _result_path(output_dir, task_id)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if overwrite_existing else "x"
        with target.open(mode, encoding="utf-8") as fh:
            json.dump(record, fh, sort_keys=True, indent=2)
            fh.write("\n")
        return True
    except FileExistsError:
        _stderr_info(f"skip-existing output for {task_id}: {target}")
        return False
    except Exception as exc:
        _stderr_warn(f"failed to write result for {task_id}: {exc}")
        return False


def _read_task_batch(path: pathlib.Path) -> List[Dict[str, Any]]:
    """Read a JSONL task batch. Malformed lines are skipped with warn."""
    tasks: List[Dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(f"task batch not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                task = json.loads(line)
            except json.JSONDecodeError as exc:
                _stderr_warn(f"line {lineno} JSON decode failed: {exc}")
                continue
            if "task_id" not in task:
                _stderr_warn(f"line {lineno} missing task_id; skipping")
                continue
            tasks.append(task)
    return tasks


async def _progress_reporter(state: FanoutState, total: int,
                             interval_s: float = 5.0) -> None:
    """Stderr progress every interval_s. Cancelled when batch completes."""
    try:
        while True:
            await asyncio.sleep(interval_s)
            _stderr_info(
                f"[fanout] in-flight={state.in_flight} "
                f"done={state.done}/{total} failed={state.failed} "
                f"cost=${state.cost_usd:.4f}"
            )
            if state.done + state.failed >= total:
                return
    except asyncio.CancelledError:
        return


async def _run_batch(args: argparse.Namespace) -> Dict[str, Any]:
    """Top-level async runner."""
    batch_path = pathlib.Path(args.task_batch).resolve()
    run_started = _ts_utc()
    tasks = _read_task_batch(batch_path)
    input_total = len(tasks)
    if input_total == 0:
        _stderr_warn("task batch is empty; nothing to do")
        return {
            "schema": SCHEMA_ID,
            "total_tasks": 0,
            "total_input_tasks": 0,
            "skipped_existing": 0,
            "summary": "empty-batch",
        }

    workspace = pathlib.Path(args.workspace).resolve() if args.workspace else None
    if args.output_dir:
        output_dir = pathlib.Path(args.output_dir).resolve()
    elif workspace is not None:
        output_dir = workspace / "audit" / "corpus_tags" / "derived" / \
                     "deepseek_fanout" / tasks[0].get("task_type", "default")
    else:
        output_dir = pathlib.Path("./deepseek_fanout_out").resolve()

    if _l34_refuses_path(output_dir, workspace):
        _stderr_warn(
            f"L34 v2 refusal: output-dir {output_dir} resolves to draft-file "
            f"bucket. Fanout dispatcher will not write to submissions/<status>/<slug>/."
        )
        return {"schema": SCHEMA_ID, "total_tasks": input_total,
                "total_input_tasks": input_total,
                "skipped_existing": 0,
                "summary": "l34-refused", "output_dir": str(output_dir)}

    output_dir.mkdir(parents=True, exist_ok=True)

    skipped_existing_ids: List[str] = []
    if not args.overwrite_existing:
        pending_tasks: List[Dict[str, Any]] = []
        for task in tasks:
            task_id = task.get("task_id", "unknown")
            if _result_path(output_dir, task_id).exists():
                skipped_existing_ids.append(task_id)
                continue
            pending_tasks.append(task)
        tasks = pending_tasks
        if skipped_existing_ids:
            _stderr_info(
                f"skip-existing: skipped {len(skipped_existing_ids)} "
                f"pre-existing output files in {output_dir}"
            )

    total = len(tasks)

    _stderr_info(
        f"R37 emit-time tier: every result will carry verification_tier="
        f"'{args.verification_tier}' unless overridden per-task."
    )

    cap = args.concurrency
    if args.aggressive and cap > _CONCURRENCY_AGGRESSIVE_MAX:
        _stderr_warn(
            f"--concurrency {cap} exceeds aggressive max "
            f"{_CONCURRENCY_AGGRESSIVE_MAX}; clamping."
        )
        cap = _CONCURRENCY_AGGRESSIVE_MAX
    elif not args.aggressive and cap > _CONCURRENCY_DEFAULT:
        _stderr_warn(
            f"--concurrency {cap} exceeds default cap "
            f"{_CONCURRENCY_DEFAULT} (no --aggressive); clamping."
        )
        cap = _CONCURRENCY_DEFAULT
    semaphore = asyncio.Semaphore(cap)

    monitor_path = pathlib.Path(args.monitor_jsonl).resolve() if args.monitor_jsonl else None
    if monitor_path is not None:
        monitor_path.parent.mkdir(parents=True, exist_ok=True)
        if monitor_path.exists():
            monitor_path.unlink()

    pricing = _DEFAULT_PRICING
    if args.pricing_json:
        try:
            pricing = json.loads(pathlib.Path(args.pricing_json).read_text())
        except Exception as exc:
            _stderr_warn(f"failed to load pricing-json: {exc}; using defaults")

    if args.dry_run:
        summary: Dict[str, Any] = {
            "schema": SCHEMA_ID,
            "dry_run": True,
            "total_tasks": total,
            "task_type_counts": {},
            "concurrency_cap": cap,
            "provider": args.provider,
            "output_dir": str(output_dir),
            "monitor_jsonl": str(monitor_path) if monitor_path else None,
            "budget_cap_usd": args.budget_cap_usd,
            "verification_tier_default": args.verification_tier,
            "estimated_cost_usd_low": 0.0,
            "estimated_cost_usd_high": 0.0,
        }
        for t in tasks:
            tt = t.get("task_type", "unknown")
            summary["task_type_counts"][tt] = \
                summary["task_type_counts"].get(tt, 0) + 1
        est_low = 0.0
        est_high = 0.0
        for t in tasks:
            est_low += _compute_cost_usd(
                args.provider,
                int(t.get("max_input_tokens", 4000) * 0.5),
                int(t.get("max_output_tokens", 1000) * 0.3),
                pricing,
            )
            est_high += _compute_cost_usd(
                args.provider,
                int(t.get("max_input_tokens", 4000)),
                int(t.get("max_output_tokens", 1000)),
                pricing,
            )
        summary["estimated_cost_usd_low"] = round(est_low, 6)
        summary["estimated_cost_usd_high"] = round(est_high, 6)
        summary["total_input_tasks"] = input_total
        summary["skipped_existing"] = len(skipped_existing_ids)
        summary["overwrite_existing"] = args.overwrite_existing
        return summary

    if total == 0:
        summary = {
            "schema": SCHEMA_ID,
            "total_tasks": 0,
            "total_input_tasks": input_total,
            "skipped_existing": len(skipped_existing_ids),
            "summary": "all-tasks-skipped-existing",
            "ok": 0,
            "failed": 0,
            "exceptions": 0,
            "cost_usd_total": 0.0,
            "budget_cap_usd": args.budget_cap_usd,
            "concurrency_cap": cap,
            "provider": args.provider,
            "output_dir": str(output_dir),
            "monitor_jsonl": str(monitor_path) if monitor_path else None,
            "halted": False,
            "halt_reason": None,
            "verification_tier_default": args.verification_tier,
            "overwrite_existing": args.overwrite_existing,
        }
        if workspace is not None:
            summary["provider_receipt"] = str(_write_provider_receipt(workspace, {
                "schema": PROVIDER_RECEIPT_SCHEMA, "workspace": str(workspace),
                "output_dir": str(output_dir), "plan_token": args.plan_token or output_dir.name,
                "provider": args.provider, "task_count": input_total,
                "terminal_counts": {"ok": 0, "failed": 0, "skipped": len(skipped_existing_ids)},
                "started_at_utc": run_started, "ended_at_utc": _ts_utc(),
            }))
        return summary

    state = FanoutState(total, monitor_path, args.budget_cap_usd)
    reporter = asyncio.create_task(_progress_reporter(state, total))
    try:
        coros = [
            _run_one_task(task, semaphore, state, args, output_dir, pricing)
            for task in tasks
        ]
        results = await asyncio.gather(*coros, return_exceptions=True)
    finally:
        reporter.cancel()
        try:
            await reporter
        except (asyncio.CancelledError, Exception):
            pass

    ok_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "ok")
    failed_count = sum(1 for r in results if isinstance(r, dict)
                       and r.get("status") not in ("ok",))
    exception_count = sum(1 for r in results if isinstance(r, Exception))

    summary = {
        "schema": SCHEMA_ID,
        "total_tasks": total,
        "total_input_tasks": input_total,
        "skipped_existing": len(skipped_existing_ids),
        "ok": ok_count,
        "failed": failed_count,
        "exceptions": exception_count,
        "cost_usd_total": round(state.cost_usd, 6),
        "budget_cap_usd": args.budget_cap_usd,
        "concurrency_cap": cap,
        "provider": args.provider,
        "output_dir": str(output_dir),
        "monitor_jsonl": str(monitor_path) if monitor_path else None,
        "halted": state.halted,
        "halt_reason": state.halt_reason,
        "verification_tier_default": args.verification_tier,
        "overwrite_existing": args.overwrite_existing,
    }
    if workspace is not None:
        summary["provider_receipt"] = str(_write_provider_receipt(workspace, {
            "schema": PROVIDER_RECEIPT_SCHEMA, "workspace": str(workspace),
            "output_dir": str(output_dir), "plan_token": args.plan_token or output_dir.name,
            "provider": args.provider, "task_count": input_total,
            "terminal_counts": {"ok": ok_count, "failed": failed_count,
                                 "exceptions": exception_count, "skipped": len(skipped_existing_ids)},
            "started_at_utc": run_started, "ended_at_utc": _ts_utc(),
        }))
    return summary


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-fanout-dispatcher",
        description=(
            "Mass-fanout DeepSeek dispatcher with semaphore + retry + monitor."
        ),
    )
    p.add_argument("--task-batch", required=True,
                   help="path to JSONL task batch")
    # <!-- r36-rebuttal: lane claude-mimo-mining-2026-05-27 registered -->
    # mimo added to choices per operator instruction 2026-05-27 (Xiaomi MiMo
    # Token Plan, 20B-token unmetered envelope). llm-dispatch.py handles
    # actual base_url/auth routing per provider name.
    p.add_argument("--provider", default="local-cli",
                   choices=["local-cli", "deepseek-flash", "deepseek-pro", "mimo"],
                   help="Provider id. DEFAULT local-cli = SONNET via the local Claude CLI "
                        "subscription (no API key - operator-chosen 2026-06-30; deepseek/mimo "
                        "need an HTTP key this env does not have and AUTH-fail). deepseek/mimo "
                        "remain available where a key is present.")
    p.add_argument("--concurrency", type=int, default=_CONCURRENCY_DEFAULT,
                   help=f"concurrent task cap (default {_CONCURRENCY_DEFAULT}, "
                        f"max {_CONCURRENCY_AGGRESSIVE_MAX} with --aggressive)")
    p.add_argument("--aggressive", action="store_true",
                   help="allow concurrency cap up to "
                        f"{_CONCURRENCY_AGGRESSIVE_MAX}")
    p.add_argument("--output-dir",
                   help="output directory for per-task result files. "
                        "If omitted and --workspace set, defaults to "
                        "<workspace>/audit/corpus_tags/derived/deepseek_fanout/")
    p.add_argument("--monitor-jsonl",
                   help="path to write monitor JSONL (one event per state-change)")
    p.add_argument("--budget-cap-usd", type=float, default=10.0,
                   help="abort the batch when cumulative cost exceeds this (USD)")
    p.add_argument("--retry-max", type=int, default=3,
                   help="max 429/503 retries per task")
    p.add_argument("--backoff-base-s", type=float, default=1.0,
                   help="exponential backoff base (seconds)")
    p.add_argument("--per-task-timeout-s", type=float, default=120.0,
                   help="max wall time for a single task")
    p.add_argument("--workspace",
                   help="workspace path (resolves default output-dir + R37 path)")
    p.add_argument("--plan-token", help="stable token identifying the dispatched plan")
    p.add_argument("--verification-tier", default=_DEFAULT_VERIFICATION_TIER,
                   help="R37 emit-time verification tier (default "
                        f"{_DEFAULT_VERIFICATION_TIER})")
    p.add_argument("--pricing-json",
                   help="optional override for the per-1K-token pricing table")
    p.add_argument("--mock", action="store_true",
                   help="disable network; deterministic synthetic responses")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON summary on stdout")
    p.add_argument("--dry-run", action="store_true",
                   help="print summary + cost estimate; do not dispatch")
    p.add_argument("--overwrite-existing", action="store_true",
                   help="replace existing per-task result files. Default is skip.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)

    if not args.mock and not args.dry_run:
        present = bool(os.environ.get("DEEPSEEK_API_KEY"))
        if not present:
            _stderr_warn(
                "DEEPSEEK_API_KEY not present in environment. "
                "Non-mock dispatch will fail at the first call. "
                "Hint: --mock for offline runs, or check L33 shell-rc export."
            )
        else:
            _stderr_info("DEEPSEEK_API_KEY present (value NOT echoed).")

    try:
        summary = asyncio.run(_run_batch(args))
    except FileNotFoundError as exc:
        _stderr_warn(str(exc))
        return EXIT_CANNOT_RUN
    except KeyboardInterrupt:
        _stderr_warn("interrupted by operator")
        return EXIT_ERROR

    if args.json:
        sys.stdout.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    else:
        sys.stdout.write(f"Total: {summary.get('total_tasks', 0)}\n")
        sys.stdout.write(f"OK: {summary.get('ok', 0)}\n")
        sys.stdout.write(f"Failed: {summary.get('failed', 0)}\n")
        sys.stdout.write(f"Cost USD: {summary.get('cost_usd_total', 0.0)}\n")
        sys.stdout.write(f"Halted: {summary.get('halted', False)}\n")
        sys.stdout.write(f"Output: {summary.get('output_dir', '')}\n")

    if summary.get("summary") == "l34-refused":
        return EXIT_CANNOT_RUN
    if summary.get("halt_reason") in ("AUTH_FAILED_HALT", "INSUFFICIENT_BALANCE_HALT"):
        return EXIT_CANNOT_RUN
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
