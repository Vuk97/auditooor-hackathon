#!/usr/bin/env python3
"""Close out a Hackerman V3 provider fanout run.

Provider outputs are useful only after they are accounted for. This tool turns
a run manifest from ``v3-provider-fanout-runner.py`` into a bounded receipt:
what ran, which model produced output, which rows are killed/blocked, and
which rows still require local verification before they can affect hunting.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
CAMPAIGN_DISPATCH_LOG = ROOT / "tools" / "calibration" / "campaign_dispatch_log.jsonl"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return workspace / ".auditooor" / "provider_fanout" / campaign_id


def _latest_run_manifest(workspace: Path, campaign_id: str) -> Path:
    runs_dir = _default_campaign_dir(workspace, campaign_id) / "runs"
    candidates = sorted(runs_dir.glob("*/v3_provider_fanout_run.json"))
    if not candidates:
        raise SystemExit(f"[v3-provider-fanout-closeout] no run manifests under {runs_dir}")
    return candidates[-1]


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _read_text(path: Path, limit: int = 200000) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated by closeout]"


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _json_shape(text: str) -> str:
    if not text.strip():
        return "empty"
    candidate = _strip_code_fence(text)
    try:
        json.loads(candidate)
        return "json"
    except json.JSONDecodeError:
        pass
    if re.search(r"(?i)\b(KEEP_FOR_LOCAL_VERIFICATION|REJECT_|NEEDS_MORE_SOURCE)\b", text):
        return "verdict_text"
    return "text"


def _load_llm_audit(run_dir: Path, task_id: str) -> dict[str, Any]:
    audit_dir = run_dir / "llm_dispatch_audit" / task_id
    candidates = sorted(audit_dir.glob("llm_dispatch_*.json"))
    if not candidates:
        return {}
    return _load_json(candidates[-1])


def _load_campaign_dispatch_row(run_dir: Path, task_id: str) -> dict[str, Any]:
    if not CAMPAIGN_DISPATCH_LOG.is_file():
        return {}
    prefix = str(run_dir / "llm_dispatch_audit" / task_id)
    latest: dict[str, Any] = {}
    for raw in CAMPAIGN_DISPATCH_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        audit_path = str(row.get("audit_path") or "")
        if audit_path.startswith(prefix):
            latest = row
    return latest


def _classify_row(row: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    task_id = str(row.get("task_id", ""))
    output_path = Path(str(row.get("provider_output_path") or ""))
    llm_audit = _load_llm_audit(run_dir, task_id)
    receipt = row.get("mcp_receipt") if isinstance(row.get("mcp_receipt"), dict) else {}
    output_text = _read_text(output_path)
    shape = _json_shape(output_text)
    campaign_row = _load_campaign_dispatch_row(run_dir, task_id)

    if not receipt or not receipt.get("present"):
        status = "blocked_no_mcp_receipt"
    elif row.get("returncode") != 0:
        status = str(row.get("status") or "failed")
    elif not llm_audit.get("model"):
        status = "blocked_missing_model"
    elif not output_path.is_file() or output_path.stat().st_size == 0:
        status = "dispatched_no_output"
    elif shape == "empty":
        status = "dispatched_no_output"
    elif shape == "text":
        status = "malformed_provider_output"
    elif row.get("provider") == "minimax" and re.search(r"(?i)\b(REJECT_|BLOCKER|killed_by)\b", output_text):
        status = "killed_by_minimax"
    else:
        status = "needs_local_verification"

    return {
        "task_id": task_id,
        "provider": row.get("provider"),
        "template": row.get("template"),
        "status": status,
        "output_shape": shape,
        "prompt_path": row.get("prompt_path"),
        "provider_output_path": str(output_path) if output_path else None,
        "provider_output_bytes": output_path.stat().st_size if output_path.is_file() else 0,
        "model": llm_audit.get("model") or campaign_row.get("model"),
        "tokens_used": llm_audit.get("tokens_used", campaign_row.get("tokens_used", 0)),
        "llm_audit_path": str((run_dir / "llm_dispatch_audit" / task_id)) if llm_audit else None,
        "campaign_dispatch_audit_path": campaign_row.get("audit_path"),
        "mcp_receipt": {
            "path": receipt.get("path"),
            "sha256_16": receipt.get("sha256_16"),
            "context_pack_id": receipt.get("context_pack_id"),
            "context_pack_hash": receipt.get("context_pack_hash"),
        },
        "local_verification_required": True,
        "provider_output_is_advisory_only": True,
        "kimi_unavailable": bool(row.get("kimi_unavailable", False)),
        "standalone_advisory": bool(row.get("standalone_advisory", False)),
    }


def _summarize(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_provider: dict[str, dict[str, int]] = {}
    tokens_by_provider: dict[str, int] = {}
    for row in rows:
        status = str(row["status"])
        provider = str(row["provider"])
        by_status[status] = by_status.get(status, 0) + 1
        by_provider.setdefault(provider, {})
        by_provider[provider][status] = by_provider[provider].get(status, 0) + 1
        tokens_by_provider[provider] = tokens_by_provider.get(provider, 0) + int(row.get("tokens_used") or 0)
    return {
        "by_status": dict(sorted(by_status.items())),
        "by_provider": {k: dict(sorted(v.items())) for k, v in sorted(by_provider.items())},
        "tokens_by_provider": dict(sorted(tokens_by_provider.items())),
        "total_tokens": sum(tokens_by_provider.values()),
    }


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hackerman V3 Provider Fanout Closeout",
        "",
        f"- run_id: `{payload['run_id']}`",
        f"- run_manifest: `{payload['run_manifest']}`",
        f"- total_rows: `{len(payload['rows'])}`",
        f"- summary: `{payload['summary']['by_status']}`",
        f"- tokens_by_provider: `{payload['summary']['tokens_by_provider']}`",
        "",
        "Provider output remains advisory-only. Rows marked `needs_local_verification` must be",
        "converted into local source checks, tests, or explicit `NO_ACTION` before closeout.",
        "",
        "| Provider | Task | Status | Model | Tokens | Output |",
        "|---|---|---|---|---:|---|",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| `{row['provider']}` | `{row['task_id']}` | `{row['status']}` | "
            f"`{row.get('model') or ''}` | {int(row.get('tokens_used') or 0)} | "
            f"`{row.get('provider_output_path') or ''}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _append_learning_ledger(payload: dict[str, Any], workspace: Path) -> Path:
    ledger = workspace / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple[str, str, str, str]] = set()
    if ledger.is_file():
        for raw in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                existing = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(existing, dict):
                continue
            seen.add(
                (
                    str(existing.get("source") or ""),
                    str(existing.get("campaign_id") or ""),
                    str(existing.get("run_id") or ""),
                    str(existing.get("task_id") or ""),
                )
            )
    with ledger.open("a", encoding="utf-8") as fh:
        for row in payload["rows"]:
            key = (
                "v3-provider-fanout-closeout",
                str(payload["campaign_id"]),
                str(payload["run_id"]),
                str(row["task_id"]),
            )
            if key in seen:
                continue
            seen.add(key)
            record = {
                "schema": "auditooor.agent_learning_ledger.v1",
                "ts": payload["generated_at"],
                "source": "v3-provider-fanout-closeout",
                "campaign_id": payload["campaign_id"],
                "run_id": payload["run_id"],
                "task_id": row["task_id"],
                "provider": row["provider"],
                "model": row.get("model"),
                "terminal_kind": "hacker_question" if row["status"] == "needs_local_verification" else "NO_ACTION",
                "evidence_tier": "secondary",
                "quarantine": True,
                "local_verification_required": True,
                "kimi_unavailable": bool(row.get("kimi_unavailable", False)),
                "standalone_advisory": bool(row.get("standalone_advisory", False)),
                "provider_output_path": row.get("provider_output_path"),
                "status": row["status"],
                "reason": "provider_output_advisory_only",
            }
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return ledger


def closeout(args: argparse.Namespace) -> dict[str, Any]:
    workspace = args.workspace.expanduser().resolve()
    run_manifest = (
        args.run.expanduser().resolve()
        if args.run is not None
        else _latest_run_manifest(workspace, args.campaign_id)
    )
    run_payload = _load_json(run_manifest)
    run_dir = Path(str(run_payload["run_dir"]))
    rows = [_classify_row(row, run_dir) for row in run_payload.get("rows", []) if isinstance(row, dict)]
    payload: dict[str, Any] = {
        "schema": "auditooor.v3_provider_fanout_closeout.v1",
        "generated_at": _utc_now_iso(),
        "campaign_id": run_payload.get("campaign_id") or args.campaign_id,
        "run_id": run_payload.get("run_id"),
        "run_manifest": str(run_manifest),
        "run_dir": str(run_dir),
        "summary": _summarize(rows),
        "rows": rows,
    }
    out_json = args.out_json.expanduser().resolve() if args.out_json else run_dir / "fanout_closeout.json"
    out_md = args.out_md.expanduser().resolve() if args.out_md else run_dir / "fanout_closeout.md"
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(_render_markdown(payload), encoding="utf-8")
    if args.append_learning_ledger:
        payload["learning_ledger_path"] = str(_append_learning_ledger(payload, workspace))
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--run", type=Path, default=None, help="Path to v3_provider_fanout_run.json")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--append-learning-ledger", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = closeout(args)
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "run_dir": payload["run_dir"]}, indent=2, sort_keys=True))
    blockers = {
        "blocked_no_mcp_receipt",
        "blocked_missing_model",
        "dispatched_no_output",
        "malformed_provider_output",
    }
    statuses = set(payload["summary"]["by_status"])
    return 1 if statuses & blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
