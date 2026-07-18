#!/usr/bin/env python3
"""Offline readiness probe for provider-backed P4 triager simulation.

This tool does not make live provider calls. It separates local-code readiness
from provider-auth and live-consent readiness so P4 status reports do not
conflate missing code with operator/environment blockers.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "auditooor.p4_provider_readiness_probe.v1"
KNOWN_PROVIDERS = ("kimi", "minimax", "anthropic")
LIVE_CONSENT_VARS = ("AUDITOOOR_LLM_NETWORK_CONSENT", "ADVERSARIAL_LIVE_CONSENT")
TRUTHY = {"1", "true", "yes", "on"}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _marker_check(root: Path, rel_path: str, markers: Sequence[str], check_id: str) -> dict[str, Any]:
    path = root / rel_path
    text = _read_text(path)
    missing = [marker for marker in markers if marker not in text]
    passed = path.is_file() and not missing
    row = {
        "check_id": check_id,
        "path": rel_path,
        "status": "pass" if passed else "fail",
        "exists": path.is_file(),
        "required_markers": list(markers),
        "missing_markers": missing,
    }
    if not passed:
        row["blocker_category"] = "local_code"
    return row


def local_code_readiness(root: Path) -> dict[str, Any]:
    checks = [
        _marker_check(
            root,
            "tools/triager-pre-filing-simulator.py",
            (
                "def build_provider_simulation(",
                "tools/llm-dispatch.py",
                "--provider-backed",
                "PROVIDER_CAPABILITY_BOUNDARY",
            ),
            "provider_simulation_builder",
        ),
        _marker_check(
            root,
            "tools/vault-mcp-server.py",
            (
                "def vault_triager_simulate",
                "provider_backed",
                "build_provider_simulation",
            ),
            "mcp_provider_backed_wrapper",
        ),
        _marker_check(
            root,
            "tools/vault-mcp-server.py",
            ("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER",),
            "test_dispatcher_override_is_gated",
        ),
        {
            "check_id": "dispatch_backend_present",
            "path": "tools/llm-dispatch.py",
            "status": "pass" if (root / "tools" / "llm-dispatch.py").is_file() else "fail",
            "exists": (root / "tools" / "llm-dispatch.py").is_file(),
        },
        {
            "check_id": "triager_precheck_schema_present",
            "path": "tools/lib/triager_precheck_schema.py",
            "status": "pass" if (root / "tools" / "lib" / "triager_precheck_schema.py").is_file() else "fail",
            "exists": (root / "tools" / "lib" / "triager_precheck_schema.py").is_file(),
        },
        {
            "check_id": "triager_pattern_catalog_present",
            "path": "reference/triager_patterns.json",
            "status": "pass" if (root / "reference" / "triager_patterns.json").is_file() else "fail",
            "exists": (root / "reference" / "triager_patterns.json").is_file(),
        },
    ]
    blockers = [
        {
            "blocker": f"{row['check_id']}_missing_or_incomplete",
            "path": row["path"],
            "missing_markers": row.get("missing_markers") or [],
        }
        for row in checks
        if row["status"] != "pass"
    ]
    return {
        "ready": not blockers,
        "checks": checks,
        "blockers": blockers,
    }


def dependency_readiness() -> dict[str, Any]:
    optional = []
    for module_name in ("yaml", "numpy", "sklearn"):
        present = importlib.util.find_spec(module_name) is not None
        optional.append(
            {
                "module": module_name,
                "present": present,
                "blocks_provider_backed_triager_runtime": False,
                "scope": "historical_classifier_rebuild" if module_name in {"numpy", "sklearn"} else "artifact_parsing",
            }
        )
    return {
        "direct_provider_backed_runtime": {
            "requires_nonstdlib_python_packages": False,
            "blockers": [],
            "reason": "provider-backed P4 shells through tools/llm-dispatch.py; live auth/consent is checked by that dispatcher",
        },
        "optional_classifier_dependencies": optional,
        "optional_dependency_blockers": [
            {
                "module": row["module"],
                "scope": row["scope"],
                "blocks_provider_backed_triager_runtime": row["blocks_provider_backed_triager_runtime"],
            }
            for row in optional
            if not row["present"]
        ],
    }


def _candidate_preflight_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in (
        "reports/v3_iter_2026-05-24/lane_P4*/**/llm_preflight_*.json",
        "reports/v3_iter_2026-05-24/lane_V3_P4*/**/llm_preflight_*.json",
        "reports/v3_iter_2026-05-23/lane_P4*/**/llm_preflight_*.json",
        "reports/v3_iter_2026-05-23/lane_V3_P4*/**/llm_preflight_*.json",
    ):
        paths.extend(root.glob(pattern))
    offline_paths = [path for path in paths if path.is_file() and "raw_live" not in path.parts]
    return sorted(set(offline_paths), key=lambda p: p.stat().st_mtime, reverse=True)


def _extract_preflight_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return [row for row in payload["records"] if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("auth_status"), list):
        return [row for row in payload["auth_status"] if isinstance(row, dict)]
    return []


def provider_auth_readiness(root: Path, preflight_paths: Sequence[Path] | None = None) -> dict[str, Any]:
    paths = list(preflight_paths or [])
    if not paths:
        paths = _candidate_preflight_paths(root)

    selected_path: Path | None = None
    records: list[dict[str, Any]] = []
    for path in paths:
        payload = _read_json(path)
        candidate = _extract_preflight_records(payload)
        if any(bool(row.get("dry_run", True)) for row in candidate):
            selected_path = path
            records = [row for row in candidate if bool(row.get("dry_run", True))]
            break

    by_provider: dict[str, dict[str, Any]] = {}
    for row in records:
        provider = str(row.get("provider") or "").strip().lower()
        if provider in KNOWN_PROVIDERS and provider not in by_provider:
            by_provider[provider] = {
                "provider": provider,
                "usable_dry_run": bool(row.get("usable")) and bool(row.get("dry_run", True)),
                "resolution_path": str(row.get("resolution_path") or "none"),
                "error_class": row.get("error_class"),
                "dry_run": bool(row.get("dry_run", True)),
            }

    status = []
    blockers = []
    for provider in KNOWN_PROVIDERS:
        row = by_provider.get(provider)
        if row is None:
            status.append(
                {
                    "provider": provider,
                    "usable_dry_run": False,
                    "resolution_path": "unknown",
                    "error_class": "no-preflight-record",
                    "evidence": "missing_offline_preflight_record",
                }
            )
            blockers.append(f"{provider}_auth_not_checked_offline")
            continue
        status.append(row)
        if not row["usable_dry_run"]:
            err = str(row.get("error_class") or "unusable")
            blockers.append(f"{provider}_auth_unusable_dry_run:{err}")

    any_provider_usable = any(row.get("usable_dry_run") for row in status)
    return {
        "minimum_one_provider_dry_run_usable": any_provider_usable,
        "all_configured_providers_dry_run_usable": all(row.get("usable_dry_run") for row in status),
        "provider_status": status,
        "provider_auth_blockers": blockers,
        "evidence_source": _rel(selected_path, root) if selected_path is not None else "not_found",
    }


def live_consent_readiness(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env_map = dict(os.environ if env is None else env)
    vars_status = {
        name: str(env_map.get(name) or "").strip().lower() in TRUTHY
        for name in LIVE_CONSENT_VARS
    }
    present = any(vars_status.values())
    return {
        "present": present,
        "vars": vars_status,
        "blockers": [] if present else ["live_network_consent_missing"],
        "live_calls_performed": False,
    }


def _verdict(local_code: dict[str, Any], auth: dict[str, Any], consent: dict[str, Any]) -> str:
    if not local_code["ready"]:
        return "blocked_by_local_code"
    if not auth["minimum_one_provider_dry_run_usable"]:
        return "local_code_ready_blocked_by_provider_auth"
    if not consent["present"]:
        return "local_code_ready_blocked_by_live_consent"
    return "local_code_and_offline_auth_ready_live_smoke_required"


def build_report(
    root: Path,
    *,
    preflight_paths: Sequence[Path] | None = None,
    env: Mapping[str, str] | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    local_code = local_code_readiness(root)
    deps = dependency_readiness()
    auth = provider_auth_readiness(root, preflight_paths=preflight_paths)
    consent = live_consent_readiness(env)
    verdict = _verdict(local_code, auth, consent)
    blocking_categories = {
        "local_code": local_code["blockers"],
        "local_dependency": deps["direct_provider_backed_runtime"]["blockers"],
        "provider_auth": [] if auth["minimum_one_provider_dry_run_usable"] else auth["provider_auth_blockers"],
        "provider_auth_nonblocking_provider_gaps": auth["provider_auth_blockers"]
        if auth["minimum_one_provider_dry_run_usable"]
        else [],
        "live_consent": consent["blockers"],
    }
    return {
        "schema": SCHEMA,
        "generated_at_utc": generated_at_utc
        or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "live_provider_calls_run": False,
        "verdict": verdict,
        "provider_backed_p4_still_blocked": verdict
        != "local_code_and_offline_auth_ready_live_smoke_required",
        "ready_to_attempt_live_provider_smoke": verdict
        == "local_code_and_offline_auth_ready_live_smoke_required",
        "provider_backed_p4_runnable_now_without_live_call": False,
        "local_code_readiness": local_code,
        "dependency_readiness": deps,
        "provider_auth_readiness": auth,
        "live_consent_readiness": consent,
        "blocking_categories": blocking_categories,
        "source_refs": [
            "tools/p4-provider-readiness-probe.py",
            "tools/triager-pre-filing-simulator.py",
            "tools/vault-mcp-server.py",
            "tools/llm-dispatch.py",
            auth["evidence_source"],
        ],
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    local = report["local_code_readiness"]
    auth = report["provider_auth_readiness"]
    consent = report["live_consent_readiness"]
    categories = report["blocking_categories"]
    lines = [
        "# P4 Provider Readiness Probe",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        f"Verdict: `{report['verdict']}`",
        "",
        "No live provider calls were run.",
        "",
        "## Readiness Split",
        "",
        f"- Local provider-backed code ready: `{str(local['ready']).lower()}`",
        f"- Minimum one provider dry-run auth usable: `{str(auth['minimum_one_provider_dry_run_usable']).lower()}`",
        f"- Live network consent present: `{str(consent['present']).lower()}`",
        f"- Ready to attempt live smoke: `{str(report['ready_to_attempt_live_provider_smoke']).lower()}`",
        "",
        "## Blocking Categories",
        "",
    ]
    for category in ("local_code", "local_dependency", "provider_auth", "live_consent"):
        blockers = categories.get(category) or []
        lines.append(f"- `{category}`: `{len(blockers)}`")
        for blocker in blockers:
            lines.append(f"  - `{blocker}`")
    nonblocking = categories.get("provider_auth_nonblocking_provider_gaps") or []
    if nonblocking:
        lines.extend(["", "Provider auth gaps that do not block a one-provider attempt:"])
        for blocker in nonblocking:
            lines.append(f"- `{blocker}`")
    lines.extend(["", "## Provider Dry-Run Status", ""])
    for row in auth["provider_status"]:
        error = row.get("error_class")
        lines.append(
            "- `{provider}` usable=`{usable}` path=`{path}` error=`{error}`".format(
                provider=row["provider"],
                usable=str(row.get("usable_dry_run")).lower(),
                path=row.get("resolution_path"),
                error="null" if error is None else error,
            )
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument(
        "--preflight-json",
        action="append",
        default=[],
        help="Optional existing llm-preflight JSON artifact to consume. May repeat.",
    )
    parser.add_argument("--out", help="Write JSON report to this path.")
    parser.add_argument("--markdown-out", help="Write Markdown report to this path.")
    parser.add_argument("--generated-at-utc", help="Override generated_at_utc for reproducible artifacts.")
    parser.add_argument("--print-json", action="store_true", help="Print JSON report to stdout.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).expanduser().resolve()
    preflight_paths = [Path(path).expanduser().resolve() for path in args.preflight_json]
    report = build_report(root, preflight_paths=preflight_paths, generated_at_utc=args.generated_at_utc)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_out:
        md = Path(args.markdown_out)
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(render_markdown(report), encoding="utf-8")
    if args.print_json or not (args.out or args.markdown_out):
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
