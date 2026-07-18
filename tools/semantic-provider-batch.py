#!/usr/bin/env python3
"""Resumable advisory Kimi -> Minimax loop for semantic worklist rows."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
DISPATCH_PREFLIGHT = ROOT / "tools" / "dispatch-preflight.py"
SEMANTIC_WORKLIST = ROOT / "tools" / "semantic-detector-worklist.py"
DEFAULT_KIMI_PACKETS_PER_LOOP = 22
DEFAULT_MINIMAX_PACKETS_PER_LOOP = 30
DEFAULT_LARGE_BATCH_SIZE = 50
DEFAULT_DISPATCH_CONCURRENCY = 1


class ReadinessError(RuntimeError):
    """Fail-fast readiness error with an operator-safe next command."""

    def __init__(self, message: str, *, next_command: str, artifact: Path | None = None) -> None:
        super().__init__(message)
        self.next_command = next_command
        self.artifact = artifact


class ConsentError(RuntimeError):
    """Fail-fast live-dispatch error with offline recovery commands."""

    def __init__(self, message: str, *, artifact: Path, safe_next_command: str) -> None:
        super().__init__(message)
        self.artifact = artifact
        self.safe_next_command = safe_next_command


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "row"


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_sha256_or_missing(path: Path) -> str:
    return _sha256(path) if path.is_file() else "missing"


def _load_previous_state(out_dir: Path, worklist_sha256: str) -> dict[str, Any]:
    path = out_dir / "semantic_provider_batch_state.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("worklist_sha256") != worklist_sha256:
        return {}
    return payload


def _semantic_graph_command(workspace: Path) -> str:
    return f"make semantic-graph WS={workspace}"


def _worklist_command(workspace: Path, path: Path) -> str:
    return (
        f"python3 tools/semantic-detector-worklist.py --workspace {workspace} "
        f"--out-json {path}"
    )


def _base_batch_command(workspace: Path, worklist: Path, out_dir: Path) -> str:
    return (
        f"python3 tools/semantic-provider-batch.py --workspace {workspace} "
        f"--worklist {worklist} --out-dir {out_dir}"
    )


def _next_commands(workspace: Path, worklist: Path, out_dir: Path, *, limit: int, start_index: int) -> dict[str, str]:
    base = _base_batch_command(workspace, worklist, out_dir)
    bounded = f"{base} --start-index {start_index} --limit {limit}"
    return {
        "build_semantic_graph": _semantic_graph_command(workspace),
        "generate_worklist": _worklist_command(workspace, worklist),
        "dry_run": f"{bounded} --dry-run",
        "mock": f"{bounded} --mock",
        "large_batch_dry_run": f"{base} --large-batch --dry-run",
        "large_batch_mock": f"{base} --large-batch --mock",
        "live_requires_consent": f"AUDITOOOR_LLM_NETWORK_CONSENT=1 {bounded}",
    }


def _write_readiness_failure(
    *,
    out_dir: Path,
    workspace: Path,
    worklist: Path,
    reason: str,
    detail: str,
    next_command: str,
    rerun_command: str,
) -> dict[str, Any]:
    payload = {
        "schema": "auditooor.semantic_provider_batch_readiness.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "blocked",
        "reason": reason,
        "detail": detail,
        "workspace": str(workspace),
        "semantic_graph": str(workspace / ".auditooor" / "semantic_graph.json"),
        "worklist": str(worklist),
        "next_command": next_command,
        "rerun_command": rerun_command,
        "next_commands": {
            "build_semantic_graph": _semantic_graph_command(workspace),
            "generate_worklist": _worklist_command(workspace, worklist),
            "dry_run_after_ready": rerun_command,
            "mock_after_ready": rerun_command.replace(" --dry-run", " --mock"),
        },
        "live_dispatch_blocked_without_consent": os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1",
        "advisory_only": True,
        "promotion_authority": False,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "semantic_provider_batch_readiness.json"
    md_path = out_dir / "semantic_provider_batch_readiness.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_readiness_markdown(payload), encoding="utf-8")
    return payload


def render_readiness_markdown(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Semantic Provider Batch Readiness",
            "",
            "Provider-assist dispatch is blocked before any live provider call.",
            "",
            f"- status: `{payload['status']}`",
            f"- reason: `{payload['reason']}`",
            f"- detail: {payload['detail']}",
            f"- workspace: `{payload['workspace']}`",
            f"- semantic graph: `{payload['semantic_graph']}`",
            f"- worklist: `{payload['worklist']}`",
            f"- live dispatch blocked without consent: `{str(payload['live_dispatch_blocked_without_consent']).lower()}`",
            "",
            "## Next Command",
            "",
            f"```bash\n{payload['next_command']}\n```",
            "",
            "## Then Rerun",
            "",
            f"```bash\n{payload['rerun_command']}\n```",
            "",
            "Rows remain advisory-only after readiness is fixed; live providers still require explicit consent.",
        ]
    ) + "\n"


def _ensure_worklist(workspace: Path, path: Path, generate: bool, out_dir: Path) -> None:
    graph = workspace / ".auditooor" / "semantic_graph.json"
    rerun = (
        f"python3 tools/semantic-provider-batch.py --workspace {workspace} "
        f"--worklist {path} --out-dir {out_dir} --dry-run"
    )
    if not graph.is_file() and not generate:
        payload = _write_readiness_failure(
            out_dir=out_dir,
            workspace=workspace,
            worklist=path,
            reason="missing_semantic_graph",
            detail=f"semantic graph is required before provider-assist worklist generation: {graph}",
            next_command=_semantic_graph_command(workspace),
            rerun_command=rerun,
        )
        raise ReadinessError(
            "[semantic-provider-batch] readiness blocked: missing semantic graph",
            next_command=str(payload["next_command"]),
            artifact=out_dir / "semantic_provider_batch_readiness.json",
        )
    if path.is_file():
        return
    cmd = [sys.executable, str(SEMANTIC_WORKLIST), "--workspace", str(workspace), "--out-json", str(path)]
    if generate:
        cmd.append("--generate-graph")
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"worklist generation failed rc={proc.returncode}"
        next_command = _semantic_graph_command(workspace) if not graph.is_file() else _worklist_command(workspace, path)
        payload = _write_readiness_failure(
            out_dir=out_dir,
            workspace=workspace,
            worklist=path,
            reason="worklist_generation_failed",
            detail=detail,
            next_command=next_command,
            rerun_command=rerun,
        )
        raise ReadinessError(
            "[semantic-provider-batch] readiness blocked: worklist generation failed",
            next_command=str(payload["next_command"]),
            artifact=out_dir / "semantic_provider_batch_readiness.json",
        )


def _write_consent_failure(
    *,
    out_dir: Path,
    workspace: Path,
    worklist: Path,
    selected_count: int,
    next_commands: dict[str, str],
) -> dict[str, Any]:
    payload = {
        "schema": "auditooor.semantic_provider_batch_consent.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "blocked",
        "reason": "missing_live_provider_consent",
        "detail": "Live provider dispatch is refused unless AUDITOOOR_LLM_NETWORK_CONSENT=1 is set by the operator.",
        "workspace": str(workspace),
        "worklist": str(worklist),
        "selected_task_count": selected_count,
        "safe_next_command": next_commands["dry_run"],
        "operator_live_command": next_commands["live_requires_consent"],
        "next_commands": next_commands,
        "advisory_only": True,
        "promotion_authority": False,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "semantic_provider_batch_consent.json"
    md_path = out_dir / "semantic_provider_batch_consent.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_consent_markdown(payload), encoding="utf-8")
    return payload


def render_consent_markdown(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Semantic Provider Batch Consent Block",
            "",
            "Live provider dispatch was refused before any provider calls.",
            "",
            f"- status: `{payload['status']}`",
            f"- reason: `{payload['reason']}`",
            f"- selected tasks: `{payload['selected_task_count']}`",
            "",
            "## Safe Offline Next Command",
            "",
            f"```bash\n{payload['safe_next_command']}\n```",
            "",
            "## Operator-Approved Live Command",
            "",
            f"```bash\n{payload['operator_live_command']}\n```",
            "",
            "Do not run the live command unless the operator explicitly grants provider network consent.",
        ]
    ) + "\n"


def _write_queue_artifacts(out_dir: Path, manifest: dict[str, Any]) -> None:
    queue = manifest.get("provider_packet_queue", [])
    (out_dir / "provider_packet_queue.json").write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Provider Packet Queue",
        "",
        "Advisory-only queue rows. Prompt validation or mock output is not provider evidence.",
        "",
        "| Slot | Provider | Task | Template | Status | Class |",
        "|---:|---|---|---|---|---|",
    ]
    if not queue:
        lines.append("| 0 | _none_ | _none_ | _none_ | _none_ | _none_ |")
    for idx, row in enumerate(queue, 1):
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                idx,
                row.get("provider", ""),
                row.get("task_id", ""),
                row.get("template", ""),
                row.get("status", ""),
                row.get("slot_class", ""),
            )
        )
    (out_dir / "provider_packet_queue.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _positive_int(value: int | None, fallback: int) -> int:
    try:
        parsed = int(value if value is not None else fallback)
    except (TypeError, ValueError):
        parsed = fallback
    return max(0, parsed)


def _default_dispatch_concurrency() -> int:
    try:
        return max(1, int(os.environ.get("AUDITOOOR_PROVIDER_DISPATCH_CONCURRENCY", DEFAULT_DISPATCH_CONCURRENCY)))
    except (TypeError, ValueError):
        return DEFAULT_DISPATCH_CONCURRENCY


def state_open_or_failed(rows: list[dict[str, Any]]) -> list[str]:
    return [str(row.get("task_id")) for row in rows if row.get("status") not in {"ok", "skipped-existing"}]


def _source_excerpt(workspace: Path, row: dict[str, Any], radius: int = 24) -> str:
    rel = str(row.get("file") or "")
    try:
        line_no = int(row.get("line") or 0)
    except (TypeError, ValueError):
        line_no = 0
    if not rel or line_no <= 0:
        return "[no source excerpt available]"
    path = workspace / rel
    if not path.is_file():
        return f"[source file missing: {rel}]"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join([f"=== {rel}:{start}-{end} ==="] + [f"{i}: {lines[i - 1]}" for i in range(start, end + 1)])


def _memory_context_block(workspace: Path) -> str:
    receipt_path = workspace / ".auditooor" / "memory_context_receipt.json"
    if not receipt_path.is_file():
        return (
            "memory_context: |\n"
            "  missing: run `python3 tools/memory-context-load.py --workspace "
            f"{workspace} --from-requirements --write-receipt` before live provider dispatch"
        )
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "memory_context: |\n  invalid_or_unreadable_receipt"

    lines = ["memory_context: |"]
    for ctx in receipt.get("loaded_contexts", [])[:8]:
        if not isinstance(ctx, dict):
            continue
        context_id = str(ctx.get("context_pack_id") or "").strip()
        context_hash = str(ctx.get("context_pack_hash") or "").strip()
        requirement = str(ctx.get("requirement_id") or "").strip()
        if not context_id:
            continue
        lines.append(f"  - requirement_id: {requirement or 'unknown'}")
        lines.append(f"    context_pack_id: {context_id}")
        if context_hash:
            lines.append(f"    context_pack_hash: {context_hash}")
        refs = [str(ref) for ref in ctx.get("source_refs", []) if str(ref).strip()][:5]
        if refs:
            lines.append("    source_refs:")
            for ref in refs:
                lines.append(f"      - {ref}")
    if len(lines) == 1:
        lines.append("  loaded_contexts: none")
    return "\n".join(lines)


def build_kimi_prompt(workspace: Path, row: dict[str, Any]) -> str:
    task_id = str(row.get("task_id") or "semantic-row")
    file_ref = str(row.get("file") or row.get("source_id") or task_id)
    line = row.get("line") or ""
    target = f"{file_ref}:{line}" if line else file_ref
    return "\n".join([
        f"workspace_path: {workspace}",
        _memory_context_block(workspace),
        "target_files:",
        f"  - {target}",
        "hypotheses:",
        f"  - Advisory detector worklist row {task_id}: extract source-grounded detector facts only.",
        f"  - Candidate detector family: {row.get('candidate_detector_family', 'unknown')}",
        "prior_failed_attempts: none",
        "expected_output_shape: |",
        "  JSON object per line with task_id, extracted_source_facts, candidate_detector_shape,",
        "  local_checks_required, duplicate_or_prior_art_risk, advisory_only=true.",
        "",
        "Rules: no severity, no selected impact, no novelty claim, no report text, no submission-ready posture.",
        "Every output remains advisory until local grep, fixtures, exact impact contract, and tests.",
        "",
        "=== SEMANTIC WORKLIST ROW ===",
        json.dumps(row, indent=2, sort_keys=True),
        "",
        "=== SOURCE EXCERPT ===",
        _source_excerpt(workspace, row),
    ]) + "\n"


def build_minimax_prompt(workspace: Path, row: dict[str, Any], kimi_output: str) -> str:
    return "\n".join([
        f"workspace_path: {workspace}",
        _memory_context_block(workspace),
        "candidate_list:",
        f"  - {row.get('task_id', 'semantic-row')}",
        "oos_text: |",
        "  none",
        "truncation_flag: complete",
        "expected_output_shape: |",
        "  JSON object per line with task_id, classification, reason, contradiction_citation,",
        "  minimum_followup_check, local_verification_required=true.",
        "",
        "Rules: reject weak assumptions. KEEP_FOR_LOCAL_VERIFICATION is not approval. No severity or report text.",
        "",
        "=== SEMANTIC WORKLIST ROW ===",
        json.dumps(row, indent=2, sort_keys=True),
        "",
        "=== KIMI ADVISORY OUTPUT ===",
        kimi_output,
    ]) + "\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _dispatch(args: argparse.Namespace, workspace: Path, out_dir: Path, provider: str, template: str, prompt: Path, output: Path) -> dict[str, Any]:
    if args.mock:
        _write(output, json.dumps({"provider": provider, "template": template, "advisory_only": True, "local_verification_required": True, "mock": True}) + "\n")
        return {"status": "mock", "returncode": 0, "output": str(output)}
    cmd = [
        sys.executable, str(DISPATCH_PREFLIGHT),
        "--template", template,
        "--prompt-file", str(prompt),
        "--workspace", str(workspace),
        "--audit-log", str(out_dir / "dispatch_audit.jsonl"),
        "--provider", provider,
        "--output-file", str(output),
        "--timeout", str(args.timeout),
        "--forward", f"--audit-dir {out_dir / 'audit'} --max-tokens {args.kimi_max_tokens if provider == 'kimi' else args.minimax_max_tokens} --timeout {args.timeout}",
    ]
    if args.dry_run:
        cmd.append("--dry-run")
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {"status": "dry-run" if args.dry_run and proc.returncode == 0 else ("ok" if proc.returncode == 0 else "failed"), "returncode": proc.returncode, "output": str(output), "stderr_tail": proc.stderr.strip()[-600:], "command": cmd}


def run(args: argparse.Namespace) -> dict[str, Any]:
    workspace = args.workspace.expanduser().resolve()
    out_dir = args.out_dir.expanduser().resolve()
    worklist = (args.worklist or workspace / ".auditooor" / "semantic_detector_worklist.json").expanduser().resolve()
    _ensure_worklist(workspace, worklist, args.generate_worklist, out_dir)
    worklist_payload = _load_json(worklist)
    semantic_graph = workspace / ".auditooor" / "semantic_graph.json"
    all_tasks = [row for row in worklist_payload.get("tasks", []) if isinstance(row, dict)]
    kimi_limit = _positive_int(args.kimi_limit, _positive_int(args.kimi_packets_per_loop, DEFAULT_KIMI_PACKETS_PER_LOOP))
    minimax_limit = _positive_int(args.minimax_limit, _positive_int(args.minimax_packets_per_loop, DEFAULT_MINIMAX_PACKETS_PER_LOOP))
    task_window = max(kimi_limit, minimax_limit)
    tasks = list(all_tasks)
    if args.start_index > 1:
        tasks = tasks[args.start_index - 1:]
    selection_limit = args.limit if args.limit > 0 else task_window
    if task_window > 0:
        # Do not select rows that no provider will actually queue this loop.
        # Otherwise the cursor can advance past "not-queued" rows and silently
        # skip work during long overnight runs.
        selection_limit = min(selection_limit, task_window)
    if selection_limit > 0:
        tasks = tasks[:selection_limit]
    selected_count = len(tasks)
    command_hints = _next_commands(
        workspace,
        worklist,
        out_dir,
        limit=args.limit if args.limit > 0 else task_window,
        start_index=args.start_index,
    )
    if not args.dry_run and not args.mock and os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1":
        payload = _write_consent_failure(
            out_dir=out_dir,
            workspace=workspace,
            worklist=worklist,
            selected_count=selected_count,
            next_commands=command_hints,
        )
        raise ConsentError(
            "[semantic-provider-batch] live dispatch blocked: missing AUDITOOOR_LLM_NETWORK_CONSENT=1",
            artifact=out_dir / "semantic_provider_batch_consent.json",
            safe_next_command=str(payload["safe_next_command"]),
        )
    loop_capacity = {
        "kimi_source_extract": max(0, int(args.kimi_packets_per_loop)),
        "minimax_adversarial_kill": max(0, int(args.minimax_packets_per_loop)),
        "kimi_task_window": kimi_limit,
        "minimax_task_window": minimax_limit,
        "live_requires_consent_env": "AUDITOOOR_LLM_NETWORK_CONSENT=1",
        "recommended_live_shape": (
            f"{max(0, int(args.kimi_packets_per_loop))} Kimi source-extract packets + "
            f"{max(0, int(args.minimax_packets_per_loop))} Minimax adversarial-kill packets per loop"
        ),
    }
    def _process_one(idx: int, row: dict[str, Any]) -> dict[str, Any]:
        task_id = str(row.get("task_id") or f"row-{idx}")
        slug = _slug(task_id)
        final = out_dir / "final" / f"{slug}.provider-assist.json"
        packet_queue: list[dict[str, Any]] = []
        local_prompt_count = 0
        local_output_count = 0
        local_final_count = 0
        if args.skip_existing and final.is_file():
            return {
                "row": {"task_id": task_id, "status": "skipped-existing", "final": str(final)},
                "provider_packet_queue": packet_queue,
                "prompt_count": local_prompt_count,
                "output_count": local_output_count,
                "final_count": 1,
            }
        kp = out_dir / "prompts" / f"{slug}.kimi.md"
        ko = out_dir / "kimi" / f"{slug}.kimi.out.jsonl"
        mp = out_dir / "prompts" / f"{slug}.minimax.md"
        mo = out_dir / "minimax" / f"{slug}.minimax.out.jsonl"
        kimi_queued = idx <= kimi_limit
        minimax_queued = idx <= minimax_limit
        if kimi_queued:
            _write(kp, build_kimi_prompt(workspace, row))
            local_prompt_count += 1
            kimi = _dispatch(args, workspace, out_dir, "kimi", "source-extract", kp, ko)
            if ko.is_file():
                kimi_text = ko.read_text(encoding="utf-8")
                local_output_count += 1
            else:
                kimi_text = json.dumps(
                    {
                        "task_id": task_id,
                        "status": "pending_kimi_output",
                        "advisory_only": True,
                        "local_verification_required": True,
                        "note": "Dry-run prompt validation produced no provider text; live or mock Kimi output must replace this before Minimax adjudication.",
                    },
                    sort_keys=True,
                )
            packet_queue.append(
                {
                    "provider": "kimi",
                    "template": "source-extract",
                    "task_id": task_id,
                    "prompt": str(kp),
                    "output": str(ko),
                    "status": kimi.get("status"),
                    "advisory_only": True,
                    "promotion_authority": False,
                    "loop_slot": idx,
                    "slot_class": "current_loop_source_extract",
                }
            )
        else:
            kimi = {
                "status": "not-queued-this-loop",
                "returncode": None,
                "output": str(ko),
                "note": "Reserved for Minimax backlog capacity; expects prior or future Kimi advisory output before live adjudication.",
            }
            kimi_text = json.dumps(
                {
                    "task_id": task_id,
                    "status": "prior_or_future_kimi_output_required",
                    "advisory_only": True,
                    "local_verification_required": True,
                    "note": "Dry-run capacity validation placeholder for Minimax backlog slot. Do not treat as provider evidence.",
                },
                sort_keys=True,
            )
        if not minimax_queued:
            return {
                "row": {"task_id": task_id, "status": "kimi-queued-only" if kimi_queued else "not-queued", "kimi": kimi},
                "provider_packet_queue": packet_queue,
                "prompt_count": local_prompt_count,
                "output_count": local_output_count,
                "final_count": local_final_count,
            }
        _write(mp, build_minimax_prompt(workspace, row, kimi_text))
        local_prompt_count += 1
        if kimi_queued and kimi["status"] not in {"ok", "dry-run", "mock"}:
            return {
                "row": {"task_id": task_id, "status": "kimi-failed", "kimi": kimi},
                "provider_packet_queue": packet_queue,
                "prompt_count": local_prompt_count,
                "output_count": local_output_count,
                "final_count": local_final_count,
            }
        minimax = _dispatch(args, workspace, out_dir, "minimax", "adversarial-kill", mp, mo)
        if mo.is_file():
            local_output_count += 1
        packet_queue.append(
            {
                "provider": "minimax",
                "template": "adversarial-kill",
                "task_id": task_id,
                "prompt": str(mp),
                "output": str(mo),
                "status": minimax.get("status"),
                "depends_on": str(ko) if kimi_queued else "prior-or-future-kimi-output-required",
                "advisory_only": True,
                "promotion_authority": False,
                "loop_slot": idx,
                "slot_class": "paired_current_loop" if kimi_queued else "minimax_backlog_or_placeholder",
            }
        )
        final_payload = {
            "schema": "auditooor.semantic_provider_assist_result.v1",
            "task_id": task_id,
            "advisory_only": True,
            "promotion_authority": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "severity": "none",
            "selected_impact": "",
            "local_verification_required": True,
            "kimi_output": str(ko),
            "minimax_output": str(mo),
            "kimi": kimi,
            "minimax": minimax,
        }
        final.parent.mkdir(parents=True, exist_ok=True)
        final.write_text(json.dumps(final_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        local_final_count += 1
        return {
            "row": {"task_id": task_id, "status": "ok" if minimax["status"] in {"ok", "dry-run", "mock"} else "minimax-failed", "final": str(final)},
            "provider_packet_queue": packet_queue,
            "prompt_count": local_prompt_count,
            "output_count": local_output_count,
            "final_count": local_final_count,
        }

    rows: list[dict[str, Any]] = []
    provider_packet_queue: list[dict[str, Any]] = []
    prompt_count = 0
    output_count = 0
    final_count = 0
    work_items = list(enumerate(tasks, 1))
    dispatch_concurrency = max(1, int(args.dispatch_concurrency or DEFAULT_DISPATCH_CONCURRENCY))
    if dispatch_concurrency > 1 and len(work_items) > 1:
        ordered_results: list[dict[str, Any] | None] = [None] * len(work_items)
        with ThreadPoolExecutor(max_workers=min(dispatch_concurrency, len(work_items))) as pool:
            future_to_pos = {
                pool.submit(_process_one, idx, row): pos
                for pos, (idx, row) in enumerate(work_items)
            }
            for future in as_completed(future_to_pos):
                ordered_results[future_to_pos[future]] = future.result()
        results = [res for res in ordered_results if res is not None]
    else:
        results = [_process_one(idx, row) for idx, row in work_items]

    for result in results:
        rows.append(result["row"])
        provider_packet_queue.extend(result["provider_packet_queue"])
        prompt_count += int(result["prompt_count"])
        output_count += int(result["output_count"])
        final_count += int(result["final_count"])
    summary: dict[str, int] = {}
    for row in rows:
        summary[str(row.get("status") or "unknown")] = summary.get(str(row.get("status") or "unknown"), 0) + 1
    successful_or_skipped = sum(1 for row in rows if row.get("status") in {"ok", "skipped-existing"})
    kimi_packets_queued = sum(1 for row in provider_packet_queue if row["provider"] == "kimi")
    minimax_packets_queued = sum(1 for row in provider_packet_queue if row["provider"] == "minimax")
    paired_packets_queued = sum(1 for row in provider_packet_queue if row.get("slot_class") == "paired_current_loop")
    minimax_backlog_or_placeholder = sum(1 for row in provider_packet_queue if row.get("slot_class") == "minimax_backlog_or_placeholder")
    next_start_index = args.start_index + selected_count
    remaining_after_batch = max(0, len(all_tasks) - (next_start_index - 1))
    provider_accounting = {
        "worklist_task_count": len(all_tasks),
        "selected_task_count": selected_count,
        "successful_or_skipped_task_count": successful_or_skipped,
        "loop_capacity": loop_capacity,
        "paired_rows_this_run": paired_packets_queued,
        "current_loop_paired_rows": paired_packets_queued,
        "minimax_backlog_or_placeholder_rows": minimax_backlog_or_placeholder,
        "kimi_packets_queued": kimi_packets_queued,
        "minimax_packets_queued": minimax_packets_queued,
        "kimi_capacity_remaining": max(0, loop_capacity["kimi_source_extract"] - kimi_packets_queued),
        "minimax_capacity_remaining": max(0, loop_capacity["minimax_adversarial_kill"] - minimax_packets_queued),
        "minimax_backlog_capacity_remaining": max(0, loop_capacity["minimax_adversarial_kill"] - minimax_packets_queued),
        "prompts_written": prompt_count,
        "provider_outputs_observed": output_count,
        "final_results_written": final_count,
        "dispatch_concurrency": dispatch_concurrency,
        "dry_run_or_mock": bool(args.dry_run or args.mock),
        "large_batch": bool(args.large_batch),
        "large_batch_size": int(args.large_batch_size),
        "live_dispatch_blocked_without_consent": not args.dry_run and not args.mock and os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1",
        "live_dispatch_allowed": not args.dry_run and not args.mock and os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1",
    }
    cursor = {
        "start_index": args.start_index,
        "requested_limit": args.limit,
        "selected_count": selected_count,
        "next_start_index": next_start_index,
        "remaining_after_batch": remaining_after_batch,
        "resume_command_hint": (
            f"python3 tools/semantic-provider-batch.py --workspace {workspace} "
            f"--worklist {worklist} --out-dir {out_dir} --start-index {next_start_index} "
            f"--limit {args.limit if args.limit > 0 else task_window} "
            f"--kimi-limit {kimi_limit} --minimax-limit {minimax_limit} --dry-run"
        ),
    }
    readiness = {
        "status": "ready",
        "semantic_graph": str(semantic_graph),
        "semantic_graph_sha256": _file_sha256_or_missing(semantic_graph),
        "worklist": str(worklist),
        "worklist_sha256": _sha256(worklist),
        "worklist_task_count": len(all_tasks),
        "selected_task_count": selected_count,
        "live_requires_consent_env": "AUDITOOOR_LLM_NETWORK_CONSENT=1",
        "advisory_only": True,
        "promotion_authority": False,
    }
    command_hints = dict(command_hints)
    command_hints["resume"] = cursor["resume_command_hint"]
    manifest = {
        "schema": "auditooor.semantic_provider_batch.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "worklist": str(worklist),
        "out_dir": str(out_dir),
        "dry_run": bool(args.dry_run),
        "mock": bool(args.mock),
        "advisory_only": True,
        "promotion_authority": False,
        "readiness": readiness,
        "next_commands": command_hints,
        "worklist_schema": worklist_payload.get("schema"),
        "worklist_sha256": _sha256(worklist),
        "provider_accounting": provider_accounting,
        "cursor": cursor,
        "provider_packet_queue": provider_packet_queue,
        "summary": dict(sorted(summary.items())),
        "rows": rows,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "semantic_provider_batch.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    previous_state = _load_previous_state(out_dir, str(manifest["worklist_sha256"]))
    previous_completed = [
        str(task_id)
        for task_id in previous_state.get("completed_task_ids", [])
        if task_id
    ]
    batch_completed = [str(row.get("task_id")) for row in rows if row.get("status") in {"ok", "skipped-existing"}]
    cumulative_completed = list(dict.fromkeys(previous_completed + batch_completed))
    state = {
        "schema": "auditooor.semantic_provider_batch_state.v1",
        "updated_at_utc": manifest["generated_at_utc"],
        "workspace": str(workspace),
        "worklist": str(worklist),
        "worklist_sha256": manifest["worklist_sha256"],
        "cursor": cursor,
        "provider_accounting": provider_accounting,
        "completed_task_ids": cumulative_completed,
        "batch_completed_task_ids": batch_completed,
        "previous_completed_task_count": len(previous_completed),
        "cumulative_completed_task_count": len(cumulative_completed),
        "open_or_failed_task_ids": state_open_or_failed(rows),
        "advisory_only": True,
        "promotion_authority": False,
        "readiness": readiness,
        "next_commands": command_hints,
        "last_run_status": "ok" if not state_open_or_failed(rows) else "completed_with_open_or_failed_rows",
    }
    (out_dir / "semantic_provider_batch_state.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "semantic_provider_batch.md").write_text(render_markdown(manifest), encoding="utf-8")
    _write_queue_artifacts(out_dir, manifest)
    return manifest


def render_markdown(manifest: dict[str, Any]) -> str:
    accounting = manifest["provider_accounting"]
    cursor = manifest["cursor"]
    readiness = manifest.get("readiness", {})
    next_commands = manifest.get("next_commands", {})
    lines = [
        "# Semantic Provider Batch",
        "",
        "Advisory-only Kimi source-extract + Minimax adversarial-kill queue.",
        "",
        "No row is a finding, severity approval, selected-impact proof, PoC, or paste-ready report.",
        "",
        f"- workspace: `{manifest['workspace']}`",
        f"- worklist: `{manifest['worklist']}`",
        f"- semantic graph: `{readiness.get('semantic_graph', '')}`",
        f"- semantic graph sha256: `{readiness.get('semantic_graph_sha256', '')}`",
        f"- worklist sha256: `{manifest['worklist_sha256']}`",
        f"- dry run: `{str(manifest['dry_run']).lower()}`",
        f"- mock: `{str(manifest['mock']).lower()}`",
        f"- large batch: `{str(accounting.get('large_batch', False)).lower()}`",
        f"- summary: `{json.dumps(manifest['summary'], sort_keys=True)}`",
        f"- recommended live shape: `{accounting['loop_capacity']['recommended_live_shape']}`",
        f"- selected tasks: `{accounting['selected_task_count']}` / `{accounting['worklist_task_count']}`",
        f"- queued packets: Kimi `{accounting['kimi_packets_queued']}`, Minimax `{accounting['minimax_packets_queued']}`",
        f"- dispatch concurrency: `{accounting.get('dispatch_concurrency', 1)}`",
        f"- current-loop paired rows: `{accounting['current_loop_paired_rows']}`",
        f"- Minimax backlog/placeholder rows: `{accounting['minimax_backlog_or_placeholder_rows']}`",
        f"- remaining capacity: Kimi `{accounting['kimi_capacity_remaining']}`, Minimax `{accounting['minimax_capacity_remaining']}`",
        f"- next start index: `{cursor['next_start_index']}`",
        f"- remaining after batch: `{cursor['remaining_after_batch']}`",
        "",
        "## Resume",
        "",
        f"```bash\n{cursor['resume_command_hint']}\n```",
        "",
        "## Safe Next Commands",
        "",
        f"```bash\n{next_commands.get('dry_run', '')}\n```",
        "",
        f"```bash\n{next_commands.get('large_batch_mock', '')}\n```",
        "",
        "Live dispatch remains blocked unless the operator explicitly sets `AUDITOOOR_LLM_NETWORK_CONSENT=1`.",
        "",
        "## Provider Queue",
        "",
        "| Provider | Task | Template | Status | Prompt |",
        "|---|---|---|---|---|",
    ]
    for row in manifest.get("provider_packet_queue", [])[:200]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row.get("provider", ""),
                row.get("task_id", ""),
                row.get("template", ""),
                row.get("status", ""),
                row.get("prompt", ""),
            )
        )
    if not manifest.get("provider_packet_queue"):
        lines.append("| _none_ | _none_ | _none_ | _none_ | _none_ |")
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--worklist", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--limit", type=int, default=0, help="Maximum worklist rows to inspect; default uses max(Kimi, Minimax) loop window")
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--kimi-packets-per-loop", type=int, default=DEFAULT_KIMI_PACKETS_PER_LOOP)
    parser.add_argument("--minimax-packets-per-loop", type=int, default=DEFAULT_MINIMAX_PACKETS_PER_LOOP)
    parser.add_argument("--kimi-limit", type=int, help="Kimi source-extract rows to queue in this loop; defaults to Kimi loop capacity")
    parser.add_argument("--minimax-limit", type=int, help="Minimax adversarial-kill rows to queue in this loop; defaults to Minimax loop capacity")
    parser.add_argument("--large-batch", action="store_true", help="Offline-friendly 50-row queue rehearsal unless explicit limits override it")
    parser.add_argument("--large-batch-size", type=int, default=DEFAULT_LARGE_BATCH_SIZE)
    parser.add_argument("--generate-worklist", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--kimi-max-tokens", type=int, default=4000)
    parser.add_argument("--minimax-max-tokens", type=int, default=3000)
    parser.add_argument(
        "--dispatch-concurrency",
        type=int,
        default=_default_dispatch_concurrency(),
        help=(
            "Maximum provider row pairs to process concurrently. "
            "Rows still run Kimi before Minimax locally; separate rows may fan out in parallel."
        ),
    )
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    parser.set_defaults(skip_existing=True)
    args = parser.parse_args(argv)
    if args.out_dir is None:
        args.out_dir = args.workspace / ".auditooor" / "provider_assist" / "semantic_batch"
    if args.large_batch:
        size = max(1, int(args.large_batch_size or DEFAULT_LARGE_BATCH_SIZE))
        if args.limit <= 0:
            args.limit = size
        if args.kimi_limit is None:
            args.kimi_limit = size
        if args.minimax_limit is None:
            args.minimax_limit = size
        if args.kimi_packets_per_loop == DEFAULT_KIMI_PACKETS_PER_LOOP:
            args.kimi_packets_per_loop = size
        if args.minimax_packets_per_loop == DEFAULT_MINIMAX_PACKETS_PER_LOOP:
            args.minimax_packets_per_loop = size
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = run(args)
    except ReadinessError as exc:
        print(str(exc), file=sys.stderr)
        print(f"next_command: {exc.next_command}", file=sys.stderr)
        if exc.artifact is not None:
            print(f"readiness_artifact: {exc.artifact}", file=sys.stderr)
        return 2
    except ConsentError as exc:
        print(str(exc), file=sys.stderr)
        print(f"safe_next_command: {exc.safe_next_command}", file=sys.stderr)
        print(f"consent_artifact: {exc.artifact}", file=sys.stderr)
        return 2
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
