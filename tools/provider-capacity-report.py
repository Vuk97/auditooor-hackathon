#!/usr/bin/env python3
"""Report Kimi/Minimax capacity from existing calibration plus safe probes."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
LLM_DISPATCH = ROOT / "tools" / "llm-dispatch.py"
LLM_PREFLIGHT_AUTH = ROOT / "tools" / "llm-preflight-auth.py"
LLM_CALIBRATION = ROOT / "tools" / "llm-calibration-log.py"
SOURCE_MINING = ROOT / "tools" / "source-mining-campaign.py"
BUDGET_CONFIG = ROOT / "tools" / "calibration" / "llm_budget.json"
BUDGET_LOG = ROOT / "tools" / "calibration" / "llm_budget_log.jsonl"
DISPATCH_AUDIT_ROOTS = (ROOT / "agent_outputs", ROOT / ".audit_logs")


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _auth_rows() -> list[dict[str, Any]]:
    proc = subprocess.run(
        [sys.executable, str(LLM_PREFLIGHT_AUTH), "--provider", "all", "--dry-run", "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    rows: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    if proc.returncode != 0 and not rows:
        rows.append({"provider": "all", "usable": False, "error_class": "auth-preflight-failed"})
    return rows


def _configured_defaults() -> dict[str, Any]:
    dispatch = _load_module(LLM_DISPATCH, "capacity_llm_dispatch")
    source_mining = _load_module(SOURCE_MINING, "capacity_source_mining")
    return {
        "llm_dispatch": {
            "default_max_tokens": getattr(dispatch, "DEFAULT_MAX_TOKENS", None),
            "smoke_test_max_tokens": getattr(dispatch, "SMOKE_TEST_MAX_TOKENS", None),
            "thinking_only_retry_limit": getattr(dispatch, "THINKING_ONLY_RETRY_LIMIT", None),
            "default_models": getattr(dispatch, "_DEFAULT_MODELS", {}),
            "default_base_url_hosts": {
                k: v.split("//", 1)[-1].split("/", 1)[0]
                for k, v in getattr(dispatch, "_DEFAULT_BASE_URLS", {}).items()
            },
        },
        "source_mining": {
            "kimi_packet_char_cap": getattr(source_mining, "KIMI_PACKET_CHAR_CAP", None),
            "minimax_packet_char_cap": getattr(source_mining, "MINIMAX_PACKET_CHAR_CAP", None),
            "minimax_truncation_threshold": getattr(source_mining, "MINIMAX_TRUNCATION_THRESHOLD", None),
            "default_max_tokens": getattr(source_mining, "DEFAULT_MAX_TOKENS", None),
        },
    }


def _model_registry(configured: dict[str, Any], budget: dict[str, Any]) -> dict[str, Any]:
    dispatch_defaults = configured.get("llm_dispatch") if isinstance(configured, dict) else {}
    dispatch_defaults = dispatch_defaults if isinstance(dispatch_defaults, dict) else {}
    default_models = dispatch_defaults.get("default_models") if isinstance(dispatch_defaults.get("default_models"), dict) else {}
    default_hosts = dispatch_defaults.get("default_base_url_hosts") if isinstance(dispatch_defaults.get("default_base_url_hosts"), dict) else {}
    budget_providers = budget.get("providers") if isinstance(budget, dict) else {}
    budget_providers = budget_providers if isinstance(budget_providers, dict) else {}
    # DEEPSEEK-INTEGRATION-CORE (2026-05-26): deepseek-flash + deepseek-pro
    # added. R36 pathspec via tools/agent-pathspec-register.py (lane-DEEPSEEK-
    # INTEGRATION-CORE entry in agent_pathspec.json).
    env_vars = {
        "kimi": ("KIMI_MODEL", "KIMI_ANTHROPIC_BASE_URL"),
        "minimax": ("MINIMAX_MODEL", "MINIMAX_ANTHROPIC_BASE_URL"),
        "anthropic": ("ANTHROPIC_MODEL", "ANTHROPIC_BASE_URL"),
        "deepseek-flash": ("DEEPSEEK_FLASH_MODEL", "DEEPSEEK_BASE_URL"),
        "deepseek-pro": ("DEEPSEEK_PRO_MODEL", "DEEPSEEK_BASE_URL"),
    }
    registry: dict[str, Any] = {}
    for provider, (model_env, base_url_env) in env_vars.items():
        provider_budget = budget_providers.get(provider) if isinstance(budget_providers.get(provider), dict) else {}
        entry: dict[str, Any] = {
            "default_model": default_models.get(provider),
            "active_model": os.environ.get(model_env) or default_models.get(provider),
            "model_env_var": model_env,
            "default_base_url_host": default_hosts.get(provider),
            "base_url_env_var": base_url_env,
            "budget_window_minutes": provider_budget.get("window_minutes"),
            "budget_max_calls": provider_budget.get("max_calls"),
            "budget_max_tokens": provider_budget.get("max_tokens"),
            "budget_soft_ratio": provider_budget.get("soft_ratio"),
            "upgrade_note": "After changing this model, rerun provider-capacity-report plus a mixed advisory calibration slice before trusting old provider-task observations.",
        }
        if provider in ("deepseek-flash", "deepseek-pro"):
            entry.update({
                "cost_usd_per_month_cap": provider_budget.get("cost_usd_per_month_cap"),
                "cost_usd_per_month_alert": provider_budget.get("cost_usd_per_month_alert"),
                "context_window": provider_budget.get("context_window"),
                "max_output_tokens": provider_budget.get("max_output_tokens"),
                "concurrency_limit": provider_budget.get("concurrency_limit"),
                "pricing_table_version": provider_budget.get("pricing_table_version"),
                "api_key_env_var": "DEEPSEEK_API_KEY",
            })
        registry[provider] = entry
    return registry


def _recent_dispatch_model_summary(limit: int = 500) -> dict[str, Any]:
    paths: list[Path] = []
    for root in DISPATCH_AUDIT_ROOTS:
        if root.is_dir():
            paths.extend(root.glob("**/llm_dispatch_*.json"))
    paths = sorted(paths, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)[:limit]
    by_provider_model: dict[str, dict[str, Any]] = {}
    malformed = 0
    for path in paths:
        obj = _load_json(path)
        if not isinstance(obj, dict):
            malformed += 1
            continue
        provider = str(obj.get("provider") or "unknown")
        model = str(obj.get("model") or "unknown")
        key = f"{provider}:{model}"
        rec = by_provider_model.setdefault(
            key,
            {
                "provider": provider,
                "model": model,
                "calls": 0,
                "outcomes": {},
                "task_types": {},
                "latest_timestamp": "",
                "max_response_length": 0,
                "max_timing_ms": 0,
            },
        )
        rec["calls"] += 1
        outcome = str(obj.get("outcome") or "unknown")
        rec["outcomes"][outcome] = int(rec["outcomes"].get(outcome, 0)) + 1
        task_type = str(obj.get("task_type") or "unknown")
        rec["task_types"][task_type] = int(rec["task_types"].get(task_type, 0)) + 1
        rec["latest_timestamp"] = max(str(rec.get("latest_timestamp") or ""), str(obj.get("timestamp") or ""))
        rec["max_response_length"] = max(int(rec.get("max_response_length") or 0), int(obj.get("response_length") or 0))
        rec["max_timing_ms"] = max(int(rec.get("max_timing_ms") or 0), int(obj.get("timing_ms") or 0))
    return {
        "paths_scanned": len(paths),
        "malformed_rows": malformed,
        "by_provider_model": dict(sorted(by_provider_model.items())),
        "source_roots": [str(path) for path in DISPATCH_AUDIT_ROOTS],
    }


def _routing_rows() -> list[dict[str, Any]]:
    calibration = _load_module(LLM_CALIBRATION, "capacity_llm_calibration")
    rows: list[dict[str, Any]] = []
    for provider, task_type in (
        ("kimi", "source-extraction"),
        ("minimax", "adversarial-kill"),
        ("minimax", "contradiction-search"),
        ("minimax", "oos-review"),
    ):
        if calibration is None or not hasattr(calibration, "routing_status"):
            rows.append({"provider": provider, "task_type": task_type, "primary_allowed": False, "advisory_only": True, "reason": "calibration-tool-unavailable"})
        else:
            rows.append(calibration.routing_status(provider, task_type))
    return rows


# DEEPSEEK-INTEGRATION-CORE (2026-05-26): per-task + monthly cost tracking.
# R36 pathspec via tools/agent-pathspec-register.py (lane-DEEPSEEK-INTEGRATION-
# CORE entry in agent_pathspec.json).
def _deepseek_cost_summary(
    *,
    limit: int = 5000,
    month_iso: str | None = None,
) -> dict[str, Any]:
    """Aggregate DeepSeek per-call cost_estimate from llm_dispatch_*.json.

    Returns a dict shaped:
      {
        "month": <YYYY-MM>,
        "per_provider": {
          "deepseek-flash": {
            "calls": N,
            "live_calls": N_live,
            "mocked_calls": N_mock,
            "cost_usd_total": <float>,
            "cost_usd_cap": <float>,
            "cost_usd_alert": <float>,
            "alert_fired": bool,
            "cap_fired": bool,
            "by_task_type": { <task_type>: {"calls": N, "cost_usd": F} },
            "latest_ts": <iso>,
          },
          ...
        }
      }
    """
    month = month_iso or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
    budget = _load_json(BUDGET_CONFIG) or {}
    budget_providers = budget.get("providers") if isinstance(budget, dict) else {}
    budget_providers = budget_providers if isinstance(budget_providers, dict) else {}
    paths: list[Path] = []
    for root in DISPATCH_AUDIT_ROOTS:
        if root.is_dir():
            paths.extend(root.glob("**/llm_dispatch_*.json"))
    paths = sorted(paths, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)[:limit]
    summary: dict[str, dict[str, Any]] = {}
    for provider in ("deepseek-flash", "deepseek-pro"):
        provider_budget = budget_providers.get(provider) if isinstance(budget_providers.get(provider), dict) else {}
        summary[provider] = {
            "calls": 0,
            "live_calls": 0,
            "mocked_calls": 0,
            "cost_usd_total": 0.0,
            "cost_usd_cap": float(provider_budget.get("cost_usd_per_month_cap") or 0.0),
            "cost_usd_alert": float(provider_budget.get("cost_usd_per_month_alert") or 0.0),
            "alert_fired": False,
            "cap_fired": False,
            "by_task_type": {},
            "latest_ts": "",
        }
    for path in paths:
        obj = _load_json(path)
        if not isinstance(obj, dict):
            continue
        provider = str(obj.get("provider") or "")
        if provider not in summary:
            continue
        ts = str(obj.get("timestamp") or "")
        if month and not ts.startswith(month):
            continue
        rec = summary[provider]
        rec["calls"] += 1
        if bool(obj.get("mock_mode")):
            rec["mocked_calls"] += 1
        else:
            rec["live_calls"] += 1
        cost = obj.get("cost_estimate")
        cost_val = 0.0
        if isinstance(cost, dict):
            try:
                cost_val = float(cost.get("cost_total_usd") or 0.0)
            except (TypeError, ValueError):
                cost_val = 0.0
        rec["cost_usd_total"] += cost_val
        task_type = str(obj.get("task_type") or "unspecified")
        tt_row = rec["by_task_type"].setdefault(task_type, {"calls": 0, "cost_usd": 0.0})
        tt_row["calls"] += 1
        tt_row["cost_usd"] += cost_val
        rec["latest_ts"] = max(rec["latest_ts"], ts)
    for provider, rec in summary.items():
        rec["cost_usd_total"] = round(rec["cost_usd_total"], 6)
        for tt_row in rec["by_task_type"].values():
            tt_row["cost_usd"] = round(tt_row["cost_usd"], 6)
        if rec["cost_usd_alert"] > 0 and rec["cost_usd_total"] >= rec["cost_usd_alert"]:
            rec["alert_fired"] = True
        if rec["cost_usd_cap"] > 0 and rec["cost_usd_total"] >= rec["cost_usd_cap"]:
            rec["cap_fired"] = True
    return {
        "month": month,
        "per_provider": summary,
        "audit_roots": [str(p) for p in DISPATCH_AUDIT_ROOTS],
    }


def _budget_log_summary() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    if BUDGET_LOG.is_file():
        for raw in BUDGET_LOG.read_text(encoding="utf-8").splitlines():
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    by_provider: dict[str, dict[str, Any]] = {}
    for row in rows:
        provider = str(row.get("provider") or "unknown")
        rec = by_provider.setdefault(provider, {"calls": 0, "successes": 0, "failures": 0, "tokens_used": 0, "latest_ts": ""})
        rec["calls"] += 1
        rec["successes"] += 1 if row.get("success") is True else 0
        rec["failures"] += 1 if row.get("success") is False else 0
        rec["tokens_used"] += int(row.get("tokens_used") or 0)
        rec["latest_ts"] = max(rec["latest_ts"], str(row.get("ts") or ""))
    return {"path": str(BUDGET_LOG), "rows": len(rows), "by_provider": by_provider}


def _learned_profile() -> dict[str, Any]:
    return {
        "source_documents": [
            "docs/PROVIDER_DISPATCH_TEMPLATES.md",
            "docs/V5_P0_CLAUDE_EXECUTION_PLAN_2026-04-27.md",
            "docs/CAPABILITY_V3_ITER_009_RESULTS.md",
            "docs/SOURCE_MINING_RUNBOOK.md",
            "tools/llm-calibration-log.py",
            "tools/llm-preflight-auth.py",
            "tools/coverage-introspect.py",
            "tools/zkbugs-provider-loop.py",
            "tools/calibration/llm_calibration_log.jsonl",
            "tools/calibration/llm_budget.json",
            "tools/calibration/llm_budget_log.jsonl",
        ],
        "kimi": {
            "best_use": "bounded long-context source/spec reading and line-cited candidate harvesting",
            "weaknesses": [
                "drifts without exact target files, hypotheses, prior attempts, and output shape",
                "can emit shape-valid but semantically invalid patches; prefer extraction over patch generation",
                "novelty/missing-pattern claims require local grep/M14 verification",
            ],
            "context_observation": "operator CLI observed roughly 250k context; API packets remain bounded and logged",
        },
        "minimax": {
            "best_use": "adversarial kill/OOS/duplicate/false-positive/missing-production-path pressure",
            "weaknesses": [
                "can infer absence from truncated input unless truncation state is explicit",
                "needs contradiction citations and independent smoke/grep confirmation",
                "KEEP_FOR_LOCAL_VERIFICATION is not approval",
            ],
            "context_observation": "operator CLI observed roughly 1M context; use bounded packets with truncation flags",
        },
    }


def _fanout_from_budget(budget: dict[str, Any]) -> dict[str, Any]:
    providers = budget.get("providers") if isinstance(budget, dict) else {}
    providers = providers if isinstance(providers, dict) else {}
    kimi = providers.get("kimi") if isinstance(providers.get("kimi"), dict) else {}
    minimax = providers.get("minimax") if isinstance(providers.get("minimax"), dict) else {}
    kc = int(kimi.get("max_calls") or 0)
    mc = int(minimax.get("max_calls") or 0)
    return {
        "kimi_source_extract": max(1, min(24, kc // 8)) if kc else 0,
        "minimax_adversarial_kill": max(1, min(32, mc // 8)) if mc else 0,
        "kimi_hourly_calls": kc,
        "minimax_hourly_calls": mc,
        "kimi_hourly_tokens": int(kimi.get("max_tokens") or 0),
        "minimax_hourly_tokens": int(minimax.get("max_tokens") or 0),
        "soft_ratio": {"kimi": kimi.get("soft_ratio"), "minimax": minimax.get("soft_ratio")},
        "budget_profile": "paid-tier-aggressive-audited" if kc >= 100 or mc >= 100 else "default-conservative",
    }


def _workspace_readiness(workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return {
            "checked": False,
            "status": "not_requested",
            "reason": "pass --workspace to include semantic-provider-batch readiness",
        }
    ws = workspace.expanduser().resolve()
    graph = ws / ".auditooor" / "semantic_graph.json"
    worklist = ws / ".auditooor" / "semantic_detector_worklist.json"
    out_dir = ws / ".auditooor" / "provider_assist" / "semantic_batch"
    ready = graph.is_file() and worklist.is_file()
    if not graph.is_file():
        status = "blocked_missing_semantic_graph"
        next_command = f"make semantic-graph WS={ws}"
    elif not worklist.is_file():
        status = "blocked_missing_semantic_worklist"
        next_command = f"python3 tools/semantic-detector-worklist.py --workspace {ws} --out-json {worklist}"
    else:
        status = "ready_for_offline_batch"
        next_command = f"python3 tools/semantic-provider-batch.py --workspace {ws} --worklist {worklist} --out-dir {out_dir} --large-batch --dry-run"
    return {
        "checked": True,
        "status": status,
        "ready_for_semantic_provider_batch": ready,
        "workspace": str(ws),
        "semantic_graph": str(graph),
        "semantic_graph_exists": graph.is_file(),
        "semantic_worklist": str(worklist),
        "semantic_worklist_exists": worklist.is_file(),
        "next_command": next_command,
        "safe_large_batch_command": f"python3 tools/semantic-provider-batch.py --workspace {ws} --worklist {worklist} --out-dir {out_dir} --large-batch --mock",
        "live_requires_consent": "AUDITOOOR_LLM_NETWORK_CONSENT=1",
        "advisory_only": True,
    }


def _live_smoke(provider: str, *, timeout: int, audit_dir: Path) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".prompt.md", delete=False) as fh:
        fh.write('Return exactly {"status":"ok"} and no prose.\n')
        prompt = Path(fh.name)
    started = dt.datetime.now(dt.timezone.utc)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(LLM_DISPATCH),
                "--provider",
                provider,
                "--prompt-file",
                str(prompt),
                "--smoke-test",
                "--timeout",
                str(timeout),
                "--retry-on-429",
                "0",
                "--audit-dir",
                str(audit_dir),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout + 15,
        )
    except subprocess.TimeoutExpired:
        return {"provider": provider, "status": "timeout", "returncode": None}
    finally:
        try:
            prompt.unlink()
        except OSError:
            pass
    elapsed = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)
    tail = proc.stderr.strip()[-500:]
    status = "ok" if proc.returncode == 0 else "failed"
    if "429" in tail or "rate" in tail.lower():
        status = "rate-limited"
    elif "timeout" in tail.lower():
        status = "timeout"
    return {"provider": provider, "status": status, "returncode": proc.returncode, "timing_ms": elapsed, "stdout_len": len(proc.stdout), "stderr_tail": tail}


def build_report(*, out_dir: Path, live_probe: bool, timeout: int, workspace: Path | None = None) -> dict[str, Any]:
    consent = {
        "AUDITOOOR_LLM_NETWORK_CONSENT": os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1",
        "ADVERSARIAL_LIVE_CONSENT": os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1",
    }
    live_allowed = any(consent.values())
    auth = _auth_rows()
    auth_by_provider = {str(row.get("provider")): row for row in auth}
    budget = _load_json(BUDGET_CONFIG) or {}
    configured = _configured_defaults()
    planned = _fanout_from_budget(budget)
    smoke: list[dict[str, Any]] = []
    if live_probe and live_allowed:
        for provider in ("kimi", "minimax"):
            if auth_by_provider.get(provider, {}).get("usable"):
                smoke.append(_live_smoke(provider, timeout=timeout, audit_dir=out_dir / "live_smoke_audit"))
            else:
                smoke.append({"provider": provider, "status": "skipped-no-usable-auth"})
    elif live_probe:
        smoke = [{"provider": p, "status": "blocked-no-network-consent", "blocker": "set AUDITOOOR_LLM_NETWORK_CONSENT=1"} for p in ("kimi", "minimax")]
    rate_or_timeout = any(row.get("status") in {"rate-limited", "timeout"} for row in smoke)
    usable_kimi = bool(auth_by_provider.get("kimi", {}).get("usable"))
    usable_minimax = bool(auth_by_provider.get("minimax", {}).get("usable"))
    if not live_allowed:
        fanout = {
            "live_executable_kimi_source_extract": 0,
            "live_executable_minimax_adversarial_kill": 0,
            "planned_when_consent_present": planned,
            "reason": "live dispatch blocked by missing network consent",
        }
        parallel_safe = False
    elif rate_or_timeout:
        fanout = {
            "live_executable_kimi_source_extract": 1 if usable_kimi else 0,
            "live_executable_minimax_adversarial_kill": 1 if usable_minimax else 0,
            "planned_when_stable": planned,
            "reason": "fresh live probe showed rate-limit/timeout; keep serial until stable",
        }
        parallel_safe = False
    else:
        fanout = {
            "live_executable_kimi_source_extract": planned["kimi_source_extract"] if usable_kimi else 0,
            "live_executable_minimax_adversarial_kill": planned["minimax_adversarial_kill"] if usable_minimax else 0,
            "active_budget": planned,
            "reason": "active paid-tier audited budget; every call remains preflighted/logged/advisory-only",
        }
        parallel_safe = usable_kimi and usable_minimax
    next_commands: list[dict[str, str]] = []
    if not live_allowed:
        next_commands.append(
            {
                "reason": "live_provider_dispatch_requires_operator_consent",
                "command": "AUDITOOOR_LLM_NETWORK_CONSENT=1 make provider-capacity-report LIVE_PROBE=1 JSON=1",
            }
        )
    workspace_readiness = _workspace_readiness(workspace)
    if workspace_readiness.get("checked") and not workspace_readiness.get("ready_for_semantic_provider_batch"):
        next_commands.append(
            {
                "reason": str(workspace_readiness.get("status")),
                "command": str(workspace_readiness.get("next_command")),
            }
        )
    return {
        "schema": "auditooor.provider_capacity_report.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "advisory_only": True,
        "promotion_authority": False,
        "available_providers": [p for p in ("kimi", "minimax") if auth_by_provider.get(p, {}).get("usable")],
        "auth_status": auth,
        "network_consent": consent,
        "model_registry": _model_registry(configured, budget),
        "recent_dispatch_model_summary": _recent_dispatch_model_summary(),
        "learned_provider_profile": _learned_profile(),
        "configured_defaults": configured,
        "calibration_routing": _routing_rows(),
        "budget_config": budget,
        # R36 pathspec via tools/agent-pathspec-register.py (lane-DEEPSEEK-
        # INTEGRATION-CORE entry in agent_pathspec.json).
        "budget_log_summary": _budget_log_summary(),
        "deepseek_cost_summary": _deepseek_cost_summary(),
        "budget_profile_note": "tools/calibration/llm_budget.json is active operator-approved capacity; historical 30/h Kimi + 60/h Minimax values are default-conservative only when this config is not patched.",
        "observed_live_smoke": smoke,
        "parallel_dispatch_safe": parallel_safe,
        "recommended_per_loop_fanout": fanout,
        "workspace_readiness": workspace_readiness,
        "next_commands": next_commands,
        "blockers": [] if live_allowed else ["missing AUDITOOOR_LLM_NETWORK_CONSENT=1 or ADVERSARIAL_LIVE_CONSENT=1 for live probes"],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Provider Capacity Report",
        "",
        "Advisory-only provider capacity snapshot. Provider output has no promotion authority.",
        "",
        f"- available providers: `{', '.join(report['available_providers']) or 'none'}`",
        f"- network consent: `{json.dumps(report['network_consent'], sort_keys=True)}`",
        f"- parallel dispatch safe: `{str(report['parallel_dispatch_safe']).lower()}`",
        f"- recommended fanout: `{json.dumps(report['recommended_per_loop_fanout'], sort_keys=True)}`",
        f"- workspace readiness: `{json.dumps(report['workspace_readiness'], sort_keys=True)}`",
        f"- budget note: {report['budget_profile_note']}",
        "",
        "## Auth",
    ]
    for row in report["auth_status"]:
        lines.append(f"- `{row.get('provider')}` usable={row.get('usable')} path={row.get('resolution_path')} error={row.get('error_class')}")
    lines.extend(["", "## Current Models"])
    for provider, row in report.get("model_registry", {}).items():
        lines.append(
            f"- `{provider}` active_model={row.get('active_model')} default_model={row.get('default_model')} "
            f"model_env={row.get('model_env_var')} host={row.get('default_base_url_host')} "
            f"budget={row.get('budget_max_calls')}/h calls, {row.get('budget_max_tokens')}/h tokens"
        )
    lines.extend(["", "## Recent Model Telemetry"])
    summary = report.get("recent_dispatch_model_summary", {})
    by_model = summary.get("by_provider_model") if isinstance(summary, dict) else {}
    if not by_model:
        lines.append("- no recent dispatch audit rows found")
    else:
        for key, row in by_model.items():
            lines.append(
                f"- `{key}` calls={row.get('calls')} outcomes={json.dumps(row.get('outcomes'), sort_keys=True)} "
                f"task_types={json.dumps(row.get('task_types'), sort_keys=True)} "
                f"max_response_length={row.get('max_response_length')} max_timing_ms={row.get('max_timing_ms')}"
            )
    lines.extend(["", "## Learned Profile"])
    for provider in ("kimi", "minimax"):
        profile = report["learned_provider_profile"][provider]
        lines.append(f"- `{provider}` best use: {profile['best_use']}")
        lines.append(f"- `{provider}` context: {profile['context_observation']}")
        for weakness in profile["weaknesses"]:
            lines.append(f"- `{provider}` weakness: {weakness}")
    lines.extend(["", "## Calibration"])
    for row in report["calibration_routing"]:
        lines.append(f"- `{row.get('provider')}/{row.get('task_type')}` advisory_only={row.get('advisory_only')} reason={row.get('reason')}")
    lines.extend(["", "## Live Smoke"])
    if not report["observed_live_smoke"]:
        lines.append("- not requested")
    for row in report["observed_live_smoke"]:
        lines.append(f"- `{row.get('provider')}` status={row.get('status')} rc={row.get('returncode')} timing_ms={row.get('timing_ms')} blocker={row.get('blocker', '')}")
    lines.extend(["", "## Budget Evidence"])
    lines.append(f"- budget config: `{json.dumps(report['budget_config'], sort_keys=True)}`")
    lines.append(f"- budget log: `{json.dumps(report['budget_log_summary'], sort_keys=True)}`")
    # R36 pathspec via tools/agent-pathspec-register.py (lane-DEEPSEEK-
    # INTEGRATION-CORE entry in agent_pathspec.json).
    ds_summary = report.get("deepseek_cost_summary", {})
    if isinstance(ds_summary, dict) and ds_summary:
        lines.extend(["", "## DeepSeek Cost Summary (Monthly)"])
        lines.append(f"- month: `{ds_summary.get('month')}`")
        per_provider = ds_summary.get("per_provider", {})
        for provider, rec in per_provider.items():
            lines.append(
                f"- `{provider}` calls={rec.get('calls')} "
                f"(live={rec.get('live_calls')}/mocked={rec.get('mocked_calls')}) "
                f"cost_usd={rec.get('cost_usd_total')} "
                f"alert_at=${rec.get('cost_usd_alert')} cap=${rec.get('cost_usd_cap')} "
                f"alert_fired={rec.get('alert_fired')} cap_fired={rec.get('cap_fired')}"
            )
    if report["blockers"]:
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {b}" for b in report["blockers"])
    if report.get("next_commands"):
        lines.extend(["", "## Next Commands"])
        for row in report["next_commands"]:
            lines.append(f"- `{row.get('reason')}`: `{row.get('command')}`")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / ".audit_logs" / "provider_capacity")
    parser.add_argument("--workspace", type=Path, help="Optional workspace readiness check for semantic-provider-batch")
    parser.add_argument("--live-probe", action="store_true")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(out_dir=out_dir, live_probe=args.live_probe, timeout=args.timeout, workspace=args.workspace)
    (out_dir / "provider_capacity_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "provider_capacity_report.md").write_text(render_md(report), encoding="utf-8")
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
