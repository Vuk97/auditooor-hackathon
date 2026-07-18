#!/usr/bin/env python3
# LEGACY 2026-06-13: HACKERMAN_V3 campaign artifact (8-Kimi+8-MiniMax).
# Kimi provider is dead. Referenced by Makefile target v3-provider-fanout-run -
# kept to avoid breaking that target. Do NOT use for new work; use
# tools/llm-fanout-dispatcher.py instead.
"""Run a Hackerman V3 Kimi/MiniMax fanout queue through dispatch preflight.

This runner consumes the queue written by ``v3-provider-fanout-queue.py`` and
executes each row via ``tools/dispatch-preflight.py``. It preserves the two
hard boundaries needed for cheap provider work to stay useful:

* provider output is advisory-only and persisted to disk;
* live dispatch requires operator network consent plus MCP receipt evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
DEFAULT_DISPATCH_PREFLIGHT = ROOT / "tools" / "dispatch-preflight.py"
DEFAULT_MCP_REFRESH = Path.home() / ".auditooor" / "bin" / "auditooor-session-start.sh"


@dataclass
class RunningTask:
    row: dict[str, Any]
    proc: subprocess.Popen[str]
    stdout_path: Path
    stderr_path: Path
    started_at: float
    env_summary: dict[str, str] = field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"queue manifest must be a JSON object: {path}")
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError(f"queue manifest missing rows[]: {path}")
    return payload


def _sha256_short(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _receipt_snapshot(workspace: Path) -> dict[str, Any]:
    receipt = workspace / ".auditooor" / "last_mcp_recall.json"
    if not receipt.is_file():
        return {"present": False, "path": str(receipt)}
    payload: dict[str, Any] = {}
    try:
        payload = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    out: dict[str, Any] = {
        "present": True,
        "path": str(receipt),
        "sha256_16": _sha256_short(receipt),
    }
    for key in ("recall_ts", "context_pack_id", "context_pack_hash"):
        if key in payload:
            out[key] = payload[key]
    return out


def _default_queue(workspace: Path, campaign_id: str) -> Path:
    return (
        workspace
        / ".auditooor"
        / "provider_fanout"
        / campaign_id
        / "v3_provider_fanout_queue.json"
    )


def _selected_rows(
    rows: Sequence[dict[str, Any]],
    *,
    provider: str | None,
    start_index: int,
    limit: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if int(row.get("index", 0)) < start_index:
            continue
        if provider and str(row.get("provider")) != provider:
            continue
        selected.append(row)
    if limit > 0:
        selected = selected[:limit]
    return selected


def _build_command(
    row: dict[str, Any],
    *,
    workspace: Path,
    dispatch_preflight: Path,
    dry_run: bool,
    mock_dispatcher: Path | None,
    timeout_override: int | None,
    llm_audit_dir: Path,
    output_path: Path,
) -> list[str]:
    timeout = int(timeout_override or row.get("timeout_seconds") or 900)
    http_timeout = int(row.get("http_timeout_seconds") or min(timeout, 300))
    max_tokens = int(row.get("max_tokens") or 8000)
    forward = (
        f"--max-tokens {max_tokens} --timeout {http_timeout} "
        f"--audit-dir {llm_audit_dir} --operator-live-network-consent "
        f"--require-mcp-receipt --strategic-llm-allowed"
    )
    cmd = [
        sys.executable,
        str(dispatch_preflight),
        "--template",
        str(row["template"]),
        "--task-type",
        str(row.get("task_type") or row["template"]),
        "--prompt-file",
        str(row["prompt_path"]),
        "--workspace",
        str(workspace),
        "--provider",
        str(row["provider"]),
        "--output-file",
        str(output_path),
        "--require-mcp-context",
        "--timeout",
        str(timeout),
        "--forward",
        forward,
    ]
    if dry_run:
        cmd.append("--dry-run")
    if mock_dispatcher is not None:
        cmd.extend(["--mock-dispatcher", str(mock_dispatcher)])
    return cmd


def _make_child_env(
    *,
    base_env: dict[str, str],
    manifest: dict[str, Any],
    row: dict[str, Any],
    live_consent: bool,
) -> tuple[dict[str, str], dict[str, str]]:
    env = base_env.copy()
    provider = str(row["provider"])
    campaign_id = str(manifest.get("campaign_id") or DEFAULT_CAMPAIGN_ID)
    env["AUDITOOOR_LLM_PROVIDER"] = provider
    env["AUDITOOOR_CAMPAIGN_ID"] = campaign_id
    env["AUDITOOOR_CAMPAIGN_LANE"] = str(row["task_id"])
    env["AUDITOOOR_CAMPAIGN_ROLE"] = provider
    env["AUDITOOOR_CAMPAIGN_WORKSPACE"] = str(manifest.get("workspace", ""))
    if live_consent:
        env["AUDITOOOR_LLM_NETWORK_CONSENT"] = "1"
    # Gate High/Critical rows at dispatch-preflight by forwarding severity and the
    # local candidate-judgment bundle path as env-var fallbacks. dispatch-preflight.py
    # reads AUDITOOOR_DISPATCH_SEVERITY / AUDITOOOR_LOCAL_JUDGMENT_BUNDLE when the
    # corresponding CLI flags are absent, so the judgment-bundle gate fires for
    # provider-fanout dispatch the same as for direct CLI invocation.
    row_severity = str(row.get("claimed_severity") or row.get("likely_severity") or "")
    if row_severity:
        env["AUDITOOOR_DISPATCH_SEVERITY"] = row_severity
    bundle_path = str(manifest.get("local_judgment_bundle_path") or "")
    if bundle_path:
        env["AUDITOOOR_LOCAL_JUDGMENT_BUNDLE"] = bundle_path
    summary = {
        "AUDITOOOR_LLM_PROVIDER": provider,
        "AUDITOOOR_CAMPAIGN_ID": campaign_id,
        "AUDITOOOR_CAMPAIGN_LANE": str(row["task_id"]),
        "AUDITOOOR_CAMPAIGN_ROLE": provider,
        "AUDITOOOR_CAMPAIGN_WORKSPACE": str(manifest.get("workspace", "")),
        "AUDITOOOR_LLM_NETWORK_CONSENT": "1" if live_consent else env.get("AUDITOOOR_LLM_NETWORK_CONSENT", ""),
        "AUDITOOOR_DISPATCH_SEVERITY": env.get("AUDITOOOR_DISPATCH_SEVERITY", ""),
        "AUDITOOOR_LOCAL_JUDGMENT_BUNDLE": env.get("AUDITOOOR_LOCAL_JUDGMENT_BUNDLE", ""),
    }
    if "AUDITOOOR_MCP_SESSION_TOKEN" in env:
        summary["AUDITOOOR_MCP_SESSION_TOKEN"] = "present"
    return env, summary


def _read_bounded(path: Path, limit: int = 8000) -> str:
    if not path.is_file():
        return "<missing>"
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...[truncated by fanout runner]"


def _successful_kimi_outputs(completed: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in completed:
        if row.get("provider") != "kimi" or row.get("returncode") != 0:
            continue
        output_path = Path(str(row.get("provider_output_path", "")))
        if output_path.is_file() and output_path.stat().st_size > 0:
            rows.append(row)
    return rows


def _materialize_minimax_prompt(
    *,
    row: dict[str, Any],
    run_dir: Path,
    completed: Sequence[dict[str, Any]],
    dry_run: bool,
    standalone_advisory: bool = False,
) -> Path:
    source = Path(str(row["prompt_path"]))
    prompt_dir = run_dir / "minimax_prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    out = prompt_dir / f"{row['task_id']}.md"
    parts = [
        source.read_text(encoding="utf-8"),
        "",
    ]
    if standalone_advisory:
        parts.extend(
            [
                "## MiniMax Standalone Advisory Mode",
                "",
                "- kimi_unavailable: true",
                "- local_verification_required: true",
                "- advisory_only: true",
                "",
                "Kimi output was unavailable for this MiniMax-only run. Produce an",
                "independent advisory review only, do not claim Kimi agreement, and keep",
                "all candidate conclusions gated on local verification.",
                "",
            ]
        )
    parts.extend(
        [
            "## Kimi Outputs To Review",
            "",
        ]
    )
    outputs = _successful_kimi_outputs(completed)
    if standalone_advisory:
        parts.extend(
            [
                "No successful Kimi output is available for this explicit MiniMax-only",
                "advisory run. Treat this as independent review input, not paired",
                "confirmation.",
                "",
            ]
        )
    else:
        parts.extend(
            [
                "MiniMax must review concrete Kimi outputs below. If this section contains only",
                "dry-run markers, return NEEDS_MORE_SOURCE and do not invent candidate content.",
                "",
            ]
        )
    if not outputs:
        marker = "DRY_RUN_NO_KIMI_OUTPUT" if dry_run else "NO_SUCCESSFUL_KIMI_OUTPUT"
        parts.append(f"- {marker}")
    for kimi_row in outputs:
        path = Path(str(kimi_row["provider_output_path"]))
        parts.extend(
            [
                f"### {kimi_row['task_id']}",
                f"- output_path: {path}",
                "```text",
                _read_bounded(path, limit=10000),
                "```",
                "",
            ]
        )
    out.write_text("\n".join(parts), encoding="utf-8")
    return out


def _refresh_mcp_context(
    *,
    workspace: Path,
    row: dict[str, Any],
    run_dir: Path,
    refresh_cmd: Path,
) -> dict[str, Any]:
    task_id = str(row["task_id"])
    out_dir = run_dir / "mcp_refresh"
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{task_id}.stdout"
    stderr_path = out_dir / f"{task_id}.stderr"
    if not refresh_cmd.is_file():
        return {
            "status": "missing-refresh-command",
            "command": str(refresh_cmd),
            "receipt": _receipt_snapshot(workspace),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
        proc = subprocess.run(
            ["bash", str(refresh_cmd)],
            cwd=str(workspace),
            stdout=stdout_fh,
            stderr=stderr_fh,
            text=True,
            check=False,
        )
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "command": str(refresh_cmd),
        "receipt": _receipt_snapshot(workspace),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _provider_limit(provider: str, args: argparse.Namespace) -> int:
    if provider == "kimi":
        return max(1, int(args.kimi_parallel))
    if provider == "minimax":
        return max(1, int(args.minimax_parallel))
    return max(1, int(args.parallel))


def _can_start(row: dict[str, Any], running: list[RunningTask], args: argparse.Namespace) -> bool:
    provider = str(row["provider"])
    provider_running = sum(1 for task in running if str(task.row["provider"]) == provider)
    return len(running) < int(args.parallel) and provider_running < _provider_limit(provider, args)


def run_queue(args: argparse.Namespace) -> dict[str, Any]:
    workspace = args.workspace.expanduser().resolve()
    if args.minimax_standalone_advisory and args.provider != "minimax":
        raise SystemExit(
            "[v3-provider-fanout-runner] --minimax-standalone-advisory requires --provider minimax"
        )
    queue_path = (
        args.queue.expanduser().resolve()
        if args.queue is not None
        else _default_queue(workspace, args.campaign_id)
    )
    manifest = _load_manifest(queue_path)
    rows = _selected_rows(
        manifest["rows"],
        provider=args.provider,
        start_index=max(1, int(args.start_index)),
        limit=max(0, int(args.limit)),
    )
    if not rows:
        raise SystemExit("[v3-provider-fanout-runner] no queue rows selected")

    if not args.dry_run and args.mock_dispatcher is None:
        if not args.operator_live_network_consent and os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1":
            raise SystemExit(
                "[v3-provider-fanout-runner] live provider dispatch requires "
                "--operator-live-network-consent or AUDITOOOR_LLM_NETWORK_CONSENT=1"
            )
        if not os.environ.get("AUDITOOOR_MCP_SESSION_TOKEN"):
            raise SystemExit(
                "[v3-provider-fanout-runner] live provider dispatch requires "
                "AUDITOOOR_MCP_SESSION_TOKEN because queue rows forward --require-mcp-receipt"
            )

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = (
        args.out_dir.expanduser().resolve()
        if args.out_dir is not None
        else queue_path.parent / "runs" / run_id
    )
    stdout_dir = run_dir / "stdout"
    stderr_dir = run_dir / "stderr"
    outputs_dir = run_dir / "provider_outputs"
    llm_audit_root = run_dir / "llm_dispatch_audit"
    for directory in (stdout_dir, stderr_dir, outputs_dir, llm_audit_root):
        directory.mkdir(parents=True, exist_ok=True)

    pending = list(rows)
    running: list[RunningTask] = []
    completed: list[dict[str, Any]] = []
    base_env = os.environ.copy()
    live_consent = bool(args.operator_live_network_consent or os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1")
    should_refresh_mcp = bool(
        args.refresh_mcp_before_row
        or (not args.no_refresh_mcp_before_row and not args.dry_run and args.mock_dispatcher is None)
    )

    while pending or running:
        started_any = False
        for row in list(pending):
            provider = str(row["provider"])
            if provider == "minimax" and any(str(item.get("provider")) == "kimi" for item in pending):
                continue
            if provider == "minimax" and any(str(task.row.get("provider")) == "kimi" for task in running):
                continue
            standalone_advisory = bool(
                provider == "minimax"
                and args.provider == "minimax"
                and args.minimax_standalone_advisory
                and not _successful_kimi_outputs(completed)
            )
            if (
                provider == "minimax"
                and not args.dry_run
                and not _successful_kimi_outputs(completed)
                and not standalone_advisory
            ):
                pending.remove(row)
                completed.append(
                    {
                        "index": row.get("index"),
                        "task_id": row.get("task_id"),
                        "provider": provider,
                        "template": row.get("template"),
                        "returncode": 4,
                        "status": "blocked_kimi_outputs_missing",
                        "kimi_unavailable": True,
                        "local_verification_required": True,
                        "standalone_advisory": False,
                        "prompt_path": row.get("prompt_path"),
                        "provider_output_path": None,
                        "stdout_path": None,
                        "stderr_path": None,
                        "env_summary": {},
                        "mcp_refresh": None,
                    }
                )
                continue
            if not _can_start(row, running, args):
                continue
            pending.remove(row)
            task_id = str(row["task_id"])
            row_for_dispatch = dict(row)
            if provider == "minimax":
                row_for_dispatch["prompt_path"] = str(
                    _materialize_minimax_prompt(
                        row=row,
                        run_dir=run_dir,
                        completed=completed,
                        dry_run=bool(args.dry_run),
                        standalone_advisory=standalone_advisory,
                    )
                )
                if standalone_advisory:
                    row_for_dispatch["kimi_unavailable"] = True
                    row_for_dispatch["local_verification_required"] = True
                    row_for_dispatch["standalone_advisory"] = True
            mcp_refresh = None
            if should_refresh_mcp:
                mcp_refresh = _refresh_mcp_context(
                    workspace=workspace,
                    row=row_for_dispatch,
                    run_dir=run_dir,
                    refresh_cmd=args.mcp_refresh_cmd.expanduser().resolve(),
                )
                if mcp_refresh.get("status") != "ok":
                    blocked_row = {
                        "index": row.get("index"),
                        "task_id": task_id,
                        "provider": provider,
                        "template": row.get("template"),
                        "returncode": 4,
                        "status": "blocked_mcp_refresh_failed",
                        "prompt_path": row_for_dispatch.get("prompt_path"),
                        "provider_output_path": None,
                        "stdout_path": None,
                        "stderr_path": None,
                        "env_summary": {},
                        "mcp_refresh": mcp_refresh,
                    }
                    if provider == "minimax":
                        blocked_row.update(
                            {
                                "kimi_unavailable": bool(row_for_dispatch.get("kimi_unavailable", False)),
                                "local_verification_required": bool(
                                    row_for_dispatch.get(
                                        "local_verification_required",
                                        row.get("local_verification_required", True),
                                    )
                                ),
                                "standalone_advisory": bool(row_for_dispatch.get("standalone_advisory", False)),
                            }
                        )
                    completed.append(blocked_row)
                    continue
            output_path = outputs_dir / f"{task_id}.out.txt"
            stdout_path = stdout_dir / f"{task_id}.stdout"
            stderr_path = stderr_dir / f"{task_id}.stderr"
            llm_audit_dir = llm_audit_root / task_id
            cmd = _build_command(
                row_for_dispatch,
                workspace=workspace,
                dispatch_preflight=args.dispatch_preflight.expanduser().resolve(),
                dry_run=bool(args.dry_run),
                mock_dispatcher=args.mock_dispatcher.expanduser().resolve() if args.mock_dispatcher else None,
                timeout_override=args.timeout,
                llm_audit_dir=llm_audit_dir,
                output_path=output_path,
            )
            env, env_summary = _make_child_env(
                base_env=base_env,
                manifest=manifest,
                row=row_for_dispatch,
                live_consent=live_consent,
            )
            with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(ROOT),
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    text=True,
                    env=env,
                )
            running.append(
                RunningTask(
                    row=row_for_dispatch,
                    proc=proc,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    started_at=time.time(),
                    env_summary=env_summary,
                )
            )
            running[-1].env_summary["mcp_refresh_status"] = str(
                (mcp_refresh or {}).get("status", "not-run")
            )
            if mcp_refresh:
                running[-1].env_summary["mcp_receipt_sha256_16"] = str(
                    mcp_refresh.get("receipt", {}).get("sha256_16", "")
                )
            started_any = True

        for task in list(running):
            rc = task.proc.poll()
            if rc is None:
                continue
            running.remove(task)
            elapsed_ms = int((time.time() - task.started_at) * 1000)
            task_id = str(task.row["task_id"])
            provider_output = outputs_dir / f"{task_id}.out.txt"
            completed_row = {
                "index": task.row.get("index"),
                "task_id": task_id,
                "provider": task.row.get("provider"),
                "template": task.row.get("template"),
                "returncode": int(rc),
                "status": "ok" if rc == 0 else "failed",
                "elapsed_ms": elapsed_ms,
                "prompt_path": task.row.get("prompt_path"),
                "provider_output_path": str(provider_output),
                "stdout_path": str(task.stdout_path),
                "stderr_path": str(task.stderr_path),
                "env_summary": task.env_summary,
                "mcp_receipt": _receipt_snapshot(workspace),
            }
            if task.row.get("provider") == "minimax":
                completed_row.update(
                    {
                        "kimi_unavailable": bool(task.row.get("kimi_unavailable", False)),
                        "local_verification_required": bool(
                            task.row.get("local_verification_required", True)
                        ),
                        "standalone_advisory": bool(task.row.get("standalone_advisory", False)),
                    }
                )
            completed.append(completed_row)

        if running and not started_any:
            time.sleep(0.25)

    summary: dict[str, int] = {}
    for row in completed:
        status = str(row["status"])
        summary[status] = summary.get(status, 0) + 1
    run_manifest: dict[str, Any] = {
        "schema": "auditooor.v3_provider_fanout_run.v1",
        "run_id": run_id,
        "generated_at": _utc_now_iso(),
        "queue": str(queue_path),
        "campaign_id": manifest.get("campaign_id") or args.campaign_id,
        "workspace": str(workspace),
        "run_dir": str(run_dir),
        "dry_run": bool(args.dry_run),
        "mock_dispatcher": str(args.mock_dispatcher) if args.mock_dispatcher else None,
        "operator_live_network_consent": bool(args.operator_live_network_consent),
        "minimax_standalone_advisory": bool(args.minimax_standalone_advisory),
        "minimax_standalone_advisory_scope": "provider=minimax" if args.minimax_standalone_advisory else None,
        "kimi_unavailable": bool(
            args.minimax_standalone_advisory
            and args.provider == "minimax"
            and not _successful_kimi_outputs(completed)
        ),
        "local_verification_required": True,
        "mcp_refresh_before_row": should_refresh_mcp,
        "parallel": int(args.parallel),
        "kimi_parallel": int(args.kimi_parallel),
        "minimax_parallel": int(args.minimax_parallel),
        "summary": dict(sorted(summary.items())),
        "rows": completed,
    }
    (run_dir / "v3_provider_fanout_run.json").write_text(
        json.dumps(run_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return run_manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--queue", type=Path, default=None)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dispatch-preflight", type=Path, default=DEFAULT_DISPATCH_PREFLIGHT)
    parser.add_argument("--provider", choices=("kimi", "minimax"), default=None)
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--limit", type=int, default=0, help="0 means all selected rows")
    parser.add_argument("--parallel", type=int, default=16)
    parser.add_argument("--kimi-parallel", type=int, default=8)
    parser.add_argument("--minimax-parallel", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--mock-dispatcher", type=Path, default=None)
    parser.add_argument("--operator-live-network-consent", action="store_true")
    parser.add_argument(
        "--minimax-standalone-advisory",
        action="store_true",
        help=(
            "Allow explicit MiniMax-only advisory rows when Kimi is unavailable. "
            "Requires --provider minimax and preserves local verification requirements."
        ),
    )
    parser.add_argument("--refresh-mcp-before-row", action="store_true")
    parser.add_argument("--no-refresh-mcp-before-row", action="store_true")
    parser.add_argument("--mcp-refresh-cmd", type=Path, default=DEFAULT_MCP_REFRESH)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = run_queue(args)
    if args.print_json:
        print(
            json.dumps(
                {
                    "run_dir": manifest["run_dir"],
                    "summary": manifest["summary"],
                    "dry_run": manifest["dry_run"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0 if manifest["summary"].get("failed", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
