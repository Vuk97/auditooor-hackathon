#!/usr/bin/env python3
"""Emit the remaining source-miner backlog actions without claiming closure."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLOSURE_SUMMARY = (
    REPO_ROOT
    / "reports"
    / "v3_iter_2026-05-24"
    / "lane_V3_REMAINING_SOURCE_MINERS_CLOSURE"
    / "summary.json"
)
DEFAULT_DASHBOARD = REPO_ROOT / ".auditooor" / "mining_coverage_dashboard.json"
DEFAULT_REPORT = (
    REPO_ROOT
    / "reports"
    / "v3_iter_2026-05-24"
    / "lane_V3_SOURCE_MINER_BACKLOG_ACTIONS"
    / "summary.json"
)

SCHEMA = "auditooor.source_miner_backlog_actions.v1"

# Wave-2 W2.4: the 7 remaining audit-firm PDF deep-mine ETLs, now wired to
# Makefile producers (hackerman-etl-from-audit-firm-pdf-<firm>). They surface
# as actionable refresh sources exactly like pashov/sb_security.
_FIRM_PDF_FAMILIES = (
    "zellic",
    "tob",
    "chainsecurity",
    "cyfrin",
    "openzeppelin",
    "sherlock",
    "spearbit",
)

TARGET_SOURCE_IDS = {
    "solodit": "solodit_high_plus_findings",
    "defimon": "defimon_delta_blocked_no_live_source",
    "map_butter": "map_butter_bridge_incident_2026_05",
    "pashov": "pashov_public_audits",
    "sb_security": "sb_security_public_audits",
    **{f: f"{f}_public_audits" for f in _FIRM_PDF_FAMILIES},
}

SOURCE_ALIASES = {
    "solodit": "solodit",
    "defimon": "defimon",
    "map_butter_bridge_incident_2026_05": "map_butter",
    "pashov_public_audits": "pashov",
    "sb_security_public_audits": "sb_security",
    **{f"{f}_public_audits": f for f in _FIRM_PDF_FAMILIES},
}

COMMANDS = {
    "solodit": (
        "python3 tools/solodit-rest-direct.py --plan-language-backlog "
        "--planning-manifest-out reports/solodit_additional_language_plan_2026-05-24.json"
    ),
    "defimon": (
        "python3 tools/defimon-nextjs-blog-miner.py --max-posts 12 --json-only "
        "--timeout-seconds 8"
    ),
    "map_butter": (
        "make external-intel-refresh SOURCE=map_butter_bridge_incident_2026_05 "
        "ALLOW_LIVE_FETCH=1 FETCH_SINGLE_INCIDENT=1 JSON=1 "
        "OUT=.auditooor/external_intel_single_incident_map_butter_bridge_incident_2026_05.json"
    ),
    "pashov": "make hackerman-etl-from-audit-firm-pdf-pashov JSON=1",
    "sb_security": "make hackerman-etl-from-audit-firm-pdf-sb-security JSON=1",
    **{f: f"make hackerman-etl-from-audit-firm-pdf-{f} JSON=1" for f in _FIRM_PDF_FAMILIES},
}

COMMAND_BOUNDARIES = {
    "solodit": (
        "Offline planning only. Live REST language filters remain blocked until "
        "huff, leo, and cairo-zk enum evidence exists; corpus assembly is covered "
        "by Solodit's Yul API filter."
    ),
    "defimon": (
        "Blog-only Next.js SSG check. This does not prove stable RSS/API/feed/cursor "
        "or Telegram machine-feed coverage."
    ),
    "map_butter": (
        "Bounded live/source collection. This does not promote source-code root cause "
        "without helper selector and exploit-time implementation proof."
    ),
    "pashov": "Freshness refresh command for an already fresh source.",
    "sb_security": "Freshness refresh command for an already fresh source.",
    **{f: "Freshness refresh command for an already fresh source." for f in _FIRM_PDF_FAMILIES},
}

OPERATOR_AUTHORIZED_SOURCE_CLOSURES = {
    "defimon": {
        "blocker_id": "BLK-V3-SOURCE-DEFIMON-NO-LIVE-SOURCE",
        "authorized_on": "2026-05-24",
        "authority": "operator_confirmation",
        "status_bucket": "operator_authorized_source_closure",
        "summary": (
            "Operator confirmed the public Defimon Telegram mirror is a live source "
            "and accepted Telegram plus blog coverage as sufficient source-miner evidence."
        ),
        "source_refs": ["https://t.me/s/defimon_alerts", "https://defimon.xyz/blog"],
        "closure_boundary": (
            "Closes the source-miner live-source blocker only. This is not external "
            "platform outcome evidence and does not expand any mined incident beyond "
            "the source-backed Telegram/blog facts."
        ),
    },
    "map_butter": {
        "blocker_id": "BLK-V3-SOURCE-RECENT-BRIDGE-OPEN-OBLIGATIONS",
        "authorized_on": "2026-05-24",
        "authority": "operator_confirmation",
        "status_bucket": "operator_authorized_source_closure",
        "summary": (
            "Operator authorized MAP/Butter source-miner unblock without another "
            "source-evidence gate, using the locally inferrable on-chain/corpus evidence."
        ),
        "source_refs": [
            "audit/corpus_tags/tags/bridge_incidents/map_butter_bridge_2026_05/record.yaml",
            "audit/corpus_tags/tags/bridge_incidents/map_butter_bridge_2026_05/SOURCE_COLLECTION_TODO.md",
        ],
        "closure_boundary": (
            "Closes the source-miner source-evidence gate only. This is not external "
            "platform outcome evidence, not a verified helper ABI/source claim, and not "
            "source-code root-cause promotion for the exploit-time implementation."
        ),
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _dashboard_rows(dashboard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = dashboard.get("rows")
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("source_id"), str):
            out[row["source_id"]] = row
    return out


def _closure_obligations(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    obligations = summary.get("remaining_source_obligations")
    if not isinstance(obligations, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for item in obligations:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        if isinstance(source, str):
            out[SOURCE_ALIASES.get(source, source)] = item
    return out


def _open_dashboard_obligations(row: dict[str, Any]) -> list[dict[str, Any]]:
    obligations = row.get("source_obligations")
    if not isinstance(obligations, list):
        return []
    return [
        item
        for item in obligations
        if isinstance(item, dict) and str(item.get("status") or "").lower() != "closed"
    ]


def _open_text_obligations(closure_item: dict[str, Any]) -> list[str]:
    obligations = closure_item.get("open_obligations")
    if isinstance(obligations, list):
        return [item for item in obligations if isinstance(item, str) and item.strip()]
    return []


def _operator_authorized_closure(
    family: str,
    open_text_obligations: list[str],
    open_dashboard_obligations: list[dict[str, Any]],
) -> dict[str, Any] | None:
    authorization = OPERATOR_AUTHORIZED_SOURCE_CLOSURES.get(family)
    if authorization is None:
        return None
    source_obligation_ids = [
        str(item.get("obligation_id"))
        for item in open_dashboard_obligations
        if item.get("obligation_id")
    ]
    return {
        **authorization,
        "formerly_blocking_open_obligations": open_text_obligations,
        "formerly_blocking_source_obligation_ids": source_obligation_ids,
        "formerly_blocking_source_obligations": open_dashboard_obligations,
    }


def _status_bucket(
    family: str,
    dashboard_row: dict[str, Any],
    closure_item: dict[str, Any],
    open_dashboard_obligations: list[dict[str, Any]],
    open_text_obligations: list[str],
    operator_authorized_closure: dict[str, Any] | None = None,
) -> str:
    if operator_authorized_closure is not None:
        return str(operator_authorized_closure["status_bucket"])
    if open_dashboard_obligations or open_text_obligations:
        return "active_backlog"
    if family in {"pashov", "sb_security", *_FIRM_PDF_FAMILIES} and dashboard_row.get("status") == "fresh":
        return "fresh_no_backlog"
    return str(dashboard_row.get("status") or closure_item.get("status") or "unknown")


def build_report(
    closure_summary: dict[str, Any],
    dashboard: dict[str, Any],
    *,
    generated_on: str | None = None,
) -> dict[str, Any]:
    rows = _dashboard_rows(dashboard)
    closure = _closure_obligations(closure_summary)

    sources: list[dict[str, Any]] = []
    next_action_rows: list[dict[str, Any]] = []
    for family, source_id in TARGET_SOURCE_IDS.items():
        row = rows.get(source_id, {})
        closure_item = closure.get(family, {})
        raw_open_dashboard = _open_dashboard_obligations(row)
        raw_open_text = _open_text_obligations(closure_item)
        operator_authorized_closure = _operator_authorized_closure(
            family,
            raw_open_text,
            raw_open_dashboard,
        )
        open_dashboard = [] if operator_authorized_closure else raw_open_dashboard
        open_text = [] if operator_authorized_closure else raw_open_text
        status_bucket = _status_bucket(
            family,
            row,
            closure_item,
            open_dashboard,
            open_text,
            operator_authorized_closure,
        )
        source_status = row.get("status") or closure_item.get("status") or "unknown"

        action_required = status_bucket == "active_backlog"
        next_action = {
            "action_id": f"source_miner:{family}:refresh",
            "family": family,
            "source_id": source_id,
            "action_required": action_required,
            "command_kind": "source_refresh",
            "command": COMMANDS[family],
            "command_boundary": COMMAND_BOUNDARIES[family],
            "requires_external_state": bool(
                closure_item.get("external_state_required")
                if "external_state_required" in closure_item
                else row.get("network_required")
            ),
            "machine_check": {
                "status_bucket": status_bucket,
                "closure_claim_allowed": False,
                "operator_authorized_source_closure": bool(operator_authorized_closure),
            },
        }

        source_payload = {
            "family": family,
            "source_id": source_id,
            "name": row.get("name") or closure_item.get("source") or source_id,
            "source_status": source_status,
            "obligation_status": closure_item.get("status"),
            "status_bucket": status_bucket,
            "external_state_required": bool(
                closure_item.get("external_state_required")
                if "external_state_required" in closure_item
                else row.get("network_required")
            ),
            "next_command": COMMANDS[family],
            "command_boundary": COMMAND_BOUNDARIES[family],
            "mined_record_count": row.get("mined_record_count"),
            "cursor_value": row.get("cursor_value"),
            "last_mined_at": row.get("last_mined_at"),
            "open_obligations": open_text,
            "open_source_obligations": open_dashboard,
            "nonblocking_former_open_obligations": raw_open_text if operator_authorized_closure else [],
            "nonblocking_former_source_obligations": (
                raw_open_dashboard if operator_authorized_closure else []
            ),
            "operator_authorized_closure": operator_authorized_closure,
            "closed_or_narrowed": closure_item.get("closed_or_narrowed") or [],
            "next_action": next_action,
        }
        sources.append(source_payload)
        next_action_rows.append(next_action)

    active = [item for item in sources if item["status_bucket"] == "active_backlog"]
    active_action_rows = [item["next_action"] for item in active]
    return {
        "schema": SCHEMA,
        "generated_on": generated_on or date.today().isoformat(),
        "inputs": {
            "closure_summary_schema": closure_summary.get("schema"),
            "dashboard_schema": dashboard.get("schema"),
            "dashboard_generated_at": dashboard.get("generated_at"),
        },
        "read_only": True,
        "closure_claim": False,
        "overall_status": "open_backlog" if active else "no_active_backlog_detected",
        "dashboard_summary": dashboard.get("summary") or {},
        "closure_verdict": closure_summary.get("verdict") or {},
        "active_backlog_count": len(active),
        "active_backlog_items": active,
        "next_action_rows": next_action_rows,
        "active_next_action_ids": [item["action_id"] for item in active_action_rows],
        "sources": sources,
    }


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Source Miner Backlog Actions",
        "",
        f"- schema: `{report['schema']}`",
        f"- generated_on: `{report['generated_on']}`",
        f"- read_only: `{str(report['read_only']).lower()}`",
        f"- closure_claim: `{str(report['closure_claim']).lower()}`",
        f"- overall_status: `{report['overall_status']}`",
        f"- active_backlog_count: `{report['active_backlog_count']}`",
        "",
        "## Source Actions",
        "",
        "| Source | Status | Backlog | Next command | Boundary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["sources"]:
        backlog = "yes" if item["status_bucket"] == "active_backlog" else "no"
        lines.append(
            "| "
            + " | ".join(
                [
                    item["source_id"],
                    str(item["source_status"]),
                    backlog,
                    f"`{item['next_command']}`",
                    item["command_boundary"],
                ]
            )
            + " |"
        )
    lines.extend(["", "## Active Backlog Items", ""])
    if not report["active_backlog_items"]:
        lines.append("No active backlog items detected.")
    for item in report["active_backlog_items"]:
        lines.append(f"### {item['source_id']}")
        for obligation in item["open_obligations"]:
            lines.append(f"- {obligation}")
        for obligation in item["open_source_obligations"]:
            oid = obligation.get("obligation_id") or "source-obligation"
            evidence = obligation.get("required_evidence") or ""
            lines.append(f"- {oid}: {evidence}")
        lines.append("")
    authorized = [item for item in report["sources"] if item.get("operator_authorized_closure")]
    if authorized:
        lines.extend(["## Operator-Authorized Source Closures", ""])
        for item in authorized:
            closure = item["operator_authorized_closure"]
            lines.append(f"### {item['source_id']}")
            lines.append(f"- blocker_id: `{closure['blocker_id']}`")
            lines.append(f"- authority: `{closure['authority']}` on `{closure['authorized_on']}`")
            lines.append(f"- summary: {closure['summary']}")
            lines.append(f"- boundary: {closure['closure_boundary']}")
            for obligation in closure["formerly_blocking_open_obligations"]:
                lines.append(f"- formerly_blocking: {obligation}")
            for obligation_id in closure["formerly_blocking_source_obligation_ids"]:
                lines.append(f"- formerly_blocking_source_obligation: `{obligation_id}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure-summary", type=Path, default=DEFAULT_CLOSURE_SUMMARY)
    parser.add_argument("--dashboard", type=Path, default=DEFAULT_DASHBOARD)
    parser.add_argument("--out", type=Path, default=None, help="optional JSON report output path")
    parser.add_argument("--markdown-out", type=Path, default=None, help="optional Markdown report output path")
    parser.add_argument("--generated-on", default=None)
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_report(
        _load_json(args.closure_summary),
        _load_json(args.dashboard),
        generated_on=args.generated_on,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(format_markdown(report), encoding="utf-8")

    if args.json or not (args.out or args.markdown_out):
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
