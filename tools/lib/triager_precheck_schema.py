"""Schema helpers for the local P4 triager precheck.

This module intentionally describes a rules-only advisory precheck. Local
silent-kill predictions are deterministic hardening hints only; this is not the
provider-backed triager simulator from PLAN-P4.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.triager_precheck_rules.v1"
MODE = "rules_mvp"
LOCAL_RULES_STATUS_DEFAULT: dict[str, Any] = {
    "state": "completed",
    "engine": "deterministic_local_rules",
    "provider_backed": False,
    "provider_call_made": False,
    "simulation_scope": "deterministic_local_rules_only",
    "predicted_verdict_supported": False,
    "silent_kill_predictions_supported": True,
}

PROVIDER_STATUS_DEFAULT: dict[str, str] = {
    "state": "unknown",
    "provider": "none",
    "reason": "local rules MVP; no LLM provider was called",
}

NO_MATCH_WARNING: dict[str, str] = {
    "code": "triager_precheck_no_match",
    "severity": "advisory",
    "message": (
        "No local triager rejection pattern matched. This is not an approval; "
        "continue normal pre-submit, scope, originality, and severity checks."
    ),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def blank_class_votes() -> dict[str, int]:
    return {
        "A_rubric_mismatch": 0,
        "B_non_core_scope": 0,
        "C_designed_as_intended": 0,
        "D_oos_infra_or_deployment": 0,
        "E_production_grade_evidence_gap": 0,
        "F_no_fund_impact_or_actor_model": 0,
        "F_prime_reachability_realism": 0,
        "G_duplicate_or_acknowledged": 0,
    }


def blank_silent_kill_votes() -> dict[str, int]:
    return {
        "duplicate": 0,
        "no_fund_impact": 0,
        "dos": 0,
        "design_intended": 0,
        "event_only": 0,
        "user_error": 0,
        "reachability": 0,
    }


def _settings_env() -> dict[str, Any]:
    path = Path.home() / ".claude" / "settings.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    env = payload.get("env")
    return env if isinstance(env, dict) else {}


def _has_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _latest_provider_prereq_report(repo_root: Path) -> tuple[Path | None, dict[str, Any] | None]:
    candidates = sorted(repo_root.glob("reports/**/provider_prereq_resolution.json"))
    if not candidates:
        return None, None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return latest, None
    return latest, payload if isinstance(payload, dict) else None


def detect_provider_status(repo_root: Path) -> dict[str, Any]:
    """Best-effort local provider/env truth for advisory status only."""
    configured: list[str] = []
    settings_env = _settings_env()
    kimi_auth = bool(
        os.environ.get("KIMI_API_KEY")
        or _has_nonempty_string(settings_env.get("KIMI_API_KEY"))
        or (Path.home() / ".kimi" / "credentials" / "kimi-code.json").is_file()
    )
    minimax_auth = bool(
        os.environ.get("MINIMAX_API_KEY")
        or _has_nonempty_string(settings_env.get("MINIMAX_API_KEY"))
    )
    anthropic_auth = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        or _has_nonempty_string(settings_env.get("ANTHROPIC_API_KEY"))
        or _has_nonempty_string(settings_env.get("ANTHROPIC_AUTH_TOKEN"))
    )
    if kimi_auth:
        configured.append("kimi")
    if minimax_auth:
        configured.append("minimax")
    if anthropic_auth:
        configured.append("anthropic")

    report_path, report = _latest_provider_prereq_report(repo_root)
    blockers: list[str] = []
    if isinstance(report, dict):
        if report.get("p4_can_run_now") is False:
            provider_auth = report.get("provider_auth")
            if isinstance(provider_auth, dict):
                for provider in ("kimi", "minimax", "anthropic"):
                    row = provider_auth.get(provider)
                    if isinstance(row, dict) and row.get("usable_dry_run") is False:
                        blockers.append(f"{provider}_auth_unusable_dry_run")
                    if isinstance(row, dict) and row.get("usable_live_smoke") is False:
                        err = str(row.get("live_smoke_error_class") or "unusable")
                        if err != "not-attempted-no-dry-run-auth":
                            blockers.append(f"{provider}_live_smoke_{err}")
            deps = report.get("local_dependency_blockers")
            if isinstance(deps, list):
                for row in deps[:6]:
                    if isinstance(row, dict) and row.get("blocker"):
                        blockers.append(str(row["blocker"]))
            net = report.get("network_consent")
            if isinstance(net, dict):
                live_calls_required = net.get("required_for_live_calls")
                if live_calls_required is None:
                    live_calls_required = (
                        "AUDITOOOR_LLM_NETWORK_CONSENT" in net
                        or "ADVERSARIAL_LIVE_CONSENT" in net
                    )
            else:
                live_calls_required = False
            if live_calls_required:
                if not net.get("AUDITOOOR_LLM_NETWORK_CONSENT") and not net.get("ADVERSARIAL_LIVE_CONSENT"):
                    blockers.append("live_network_consent_missing")
            if not blockers:
                blockers.append("p4_can_run_now_false_reported")
            blockers = list(dict.fromkeys(blockers))

    if blockers:
        state = "blocked"
        reason = "local rules MVP; provider-backed triager simulation blocked by local evidence; no LLM provider was called"
    elif configured:
        state = "configured"
        reason = "local rules MVP; provider env appears configured but no LLM provider was called"
    else:
        state = "not_configured"
        reason = "local rules MVP; no provider credentials detected and no LLM provider was called"

    payload: dict[str, Any] = {
        "state": state,
        "provider": "+".join(configured) if configured else "none",
        "reason": reason,
    }
    if report_path is not None:
        payload["evidence_report"] = str(report_path)
    if blockers:
        payload["blockers"] = blockers[:8]
    return payload


def recommended_action(
    matched_patterns: list[dict[str, Any]],
    disposition_evidence: dict[str, Any] | None = None,
) -> str:
    confidence = 0.0
    if isinstance(disposition_evidence, dict):
        try:
            confidence = float(disposition_evidence.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
    if 0.0 < confidence < 0.55:
        return "manual_review_local_classifier_low_confidence_no_provider_readiness_claim"
    if not matched_patterns:
        return "proceed_with_normal_pre_submit_checks"
    class_votes = blank_class_votes()
    for pattern in matched_patterns:
        key = str(pattern.get("outcome_class_key") or "")
        if key in class_votes:
            class_votes[key] += int(pattern.get("score") or 1)
    if class_votes["G_duplicate_or_acknowledged"] > 0:
        return "add_or_update_originality_and_dupe_distinction_before_filing"
    if class_votes["E_production_grade_evidence_gap"] > 0:
        return "upgrade_production_path_evidence_before_filing"
    if class_votes["F_no_fund_impact_or_actor_model"] > 0:
        return "strengthen_non_self_impact_or_actor_model_before_filing"
    if class_votes["F_prime_reachability_realism"] > 0:
        return "justify_realistic_reachability_before_filing"
    return "review_matched_triager_patterns_before_filing"


def build_packet(
    *,
    draft_path: Path,
    workspace_path: Path,
    warnings: list[dict[str, Any]],
    matched_patterns: list[dict[str, Any]],
    class_votes: dict[str, int],
    source_refs: list[str],
    repo_root: Path,
    severity: str | None = None,
    local_rules_status: dict[str, Any] | None = None,
    disposition_evidence: dict[str, Any] | None = None,
    silent_kill_predictions: list[dict[str, Any]] | None = None,
    silent_kill_summary: dict[str, Any] | None = None,
    mind_model_checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "mode": MODE,
        "local_rules_status": dict(local_rules_status or LOCAL_RULES_STATUS_DEFAULT),
        "provider_status": detect_provider_status(repo_root),
        "generated_at": utc_now(),
        "draft_path": relpath(draft_path, repo_root),
        "workspace_path": relpath(workspace_path, repo_root),
        "claimed_severity": severity,
        "warnings": warnings,
        "matched_patterns": matched_patterns,
        "class_votes": class_votes,
        "mind_model_checks": mind_model_checks or [],
        "silent_kill_predictions": silent_kill_predictions or [],
        "silent_kill_summary": silent_kill_summary or {},
        "disposition_evidence": disposition_evidence,
        "recommended_action": recommended_action(matched_patterns, disposition_evidence),
        "source_refs": source_refs,
    }
