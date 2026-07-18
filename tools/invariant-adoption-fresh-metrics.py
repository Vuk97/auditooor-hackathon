#!/usr/bin/env python3
"""Import and validate fresh-engagement invariant adoption metrics.

P0-0 cannot close from one workspace. This tool turns independent fresh
engagement adoption outputs into a single workspace-local metrics artifact that
`invariant-adoption-closure-readiness.py` can consume. It is intentionally
evidence-only: it never promotes severity, exploit impact, or submission
readiness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.invariant_adoption_fresh_engagement_metrics.v1"
MIN_ADOPTION_RATE = 0.80


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("workspaces", "source_workspaces", "rows", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _as_path(value: Any, *, base: Path) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def _terminal_generated_review_count(payload: dict[str, Any]) -> tuple[int, int]:
    review = payload.get("generated_review") if isinstance(payload.get("generated_review"), dict) else {}
    terminal = int(review.get("terminal_review_count") or 0)
    unreviewed = int(review.get("unreviewed_missing_count") or 0)
    return terminal, unreviewed


def _ledger_status(ws: Path, adoption: dict[str, Any]) -> dict[str, Any]:
    ledger_path = ws / ".auditooor" / "invariant_ledger.json"
    ledger = _read_json(ledger_path)
    rows = []
    if isinstance(ledger, dict):
        rows = [row for row in ledger.get("rows", []) if isinstance(row, dict)]
    errors = []
    if not ledger_path.is_file():
        errors.append("invariant_ledger_missing")
    if ledger_path.is_file() and not isinstance(ledger, dict):
        errors.append("invariant_ledger_unreadable")
    if ledger_path.is_file() and not rows:
        errors.append("invariant_ledger_empty")
    adopted = bool(adoption.get("adopted_to_canonical_invariant_ledger"))
    return {
        "path": str(ledger_path),
        "row_count": len(rows),
        "check_passed": adopted and ledger_path.is_file() and not errors,
        "errors": errors,
    }


def _row_for_workspace(ws: Path, *, engagement_id: str | None = None) -> dict[str, Any]:
    adoption_path = ws / ".auditooor" / "invariant_discovery_adoption.json"
    adoption = _read_json(adoption_path)
    if not isinstance(adoption, dict):
        return {
            "engagement_id": engagement_id or ws.name,
            "workspace": str(ws),
            "status": "invalid_missing_invariant_discovery_adoption",
            "valid": False,
            "adoption_rate": 0.0,
            "high_critical_route_family_count": 0,
            "high_critical_route_family_adopted_count": 0,
            "invariant_ledger_check_passed": False,
            "blockers": ["missing_invariant_discovery_adoption"],
            "artifact_path": str(adoption_path),
        }

    units = [row for row in adoption.get("route_family_units", []) if isinstance(row, dict)]
    adopted_units = [
        row for row in units
        if str(row.get("review_state") or "").startswith("blocked_")
        and bool(row.get("next_commands"))
    ]
    terminal_generated, unreviewed_generated = _terminal_generated_review_count(adoption)
    total = len(units)
    adopted_count = len(adopted_units)
    adoption_rate = (adopted_count / total) if total else 0.0
    ledger = _ledger_status(ws, adoption)
    blockers: list[str] = []
    if total <= 0:
        blockers.append("no_high_critical_route_family_units")
    if adoption_rate < MIN_ADOPTION_RATE:
        blockers.append("adoption_rate_below_threshold")
    if adopted_count < total:
        blockers.append("not_all_route_families_have_blocker_rows")
    if unreviewed_generated:
        blockers.append("generated_invariant_reviews_unreviewed")
    if not ledger["check_passed"]:
        blockers.append("invariant_ledger_check_not_passed")
    if bool(adoption.get("promotion_allowed")):
        blockers.append("promotion_allowed_must_be_false_for_metrics")

    valid = not blockers
    return {
        "engagement_id": engagement_id or str(adoption.get("engagement_id") or ws.name),
        "workspace": str(ws),
        "status": "fresh_engagement_adoption_metric_valid" if valid else "fresh_engagement_adoption_metric_invalid",
        "valid": valid,
        "artifact_path": str(adoption_path),
        "adoption_rate": round(adoption_rate, 6),
        "minimum_adoption_rate": MIN_ADOPTION_RATE,
        "high_critical_route_family_count": total,
        "high_critical_route_family_adopted_count": adopted_count,
        "terminal_generated_review_count": terminal_generated,
        "unreviewed_generated_review_count": unreviewed_generated,
        "invariant_ledger_check_passed": bool(ledger["check_passed"]),
        "invariant_ledger_path": ledger["path"],
        "invariant_ledger_row_count": ledger["row_count"],
        "blockers": blockers,
        "proof_boundary": (
            "Fresh-engagement adoption metrics prove invariant row/blocker adoption only; "
            "they do not prove exploit impact, severity, OOS, production path, or submission readiness."
        ),
    }


def _manifest_workspaces(path: Path) -> list[tuple[Path, str | None]]:
    payload = _read_json(path)
    out: list[tuple[Path, str | None]] = []
    for idx, row in enumerate(_records(payload)):
        raw = row.get("workspace") or row.get("path") or row.get("workspace_path")
        ws = _as_path(raw, base=path.parent)
        if ws:
            out.append((ws, str(row.get("engagement_id") or row.get("id") or f"fresh-{idx + 1}")))
    return out


def run(workspace: Path, sources: list[tuple[Path, str | None]]) -> dict[str, Any]:
    rows = [_row_for_workspace(ws, engagement_id=engagement_id) for ws, engagement_id in sources]
    valid_rows = [row for row in rows if row.get("valid")]
    invalid_rows = [row for row in rows if not row.get("valid")]
    payload = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "status": (
            "fresh_engagement_adoption_metrics_ready"
            if len(valid_rows) >= 3 else "fresh_engagement_adoption_metrics_insufficient"
        ),
        "required_fresh_engagement_count": 3,
        "minimum_adoption_rate": MIN_ADOPTION_RATE,
        "fresh_engagement_count": len(rows),
        "valid_fresh_engagement_count": len(valid_rows),
        "invalid_fresh_engagement_count": len(invalid_rows),
        "missing_fresh_engagement_count": max(0, 3 - len(valid_rows)),
        "rows": rows,
        "blockers": (
            [] if len(valid_rows) >= 3
            else ["fresh_engagement_adoption_metrics_missing_or_below_threshold"]
        ),
        "next_commands": [
            "make invariant-discovery-adoption WS=<fresh-workspace> ADOPT_LEDGER=1 JSON=1",
            "make invariant-ledger-check WS=<fresh-workspace>",
            "make invariant-adoption-fresh-metrics WS=<workspace> SOURCE_WS=<fresh-workspace>",
            "make invariant-adoption-closure-readiness WS=<workspace> JSON=1",
        ],
        "proof_boundary": (
            "This artifact is only adoption-rate evidence for P0-0. It does not claim "
            "finding proof, severity, OOS clearance, production-path proof, or submit readiness."
        ),
    }
    out = workspace / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.json"
    _write_json(out, payload)
    md = [
        "# Invariant Adoption Fresh Engagement Metrics",
        "",
        f"- Status: `{payload['status']}`",
        f"- Valid fresh engagements: `{len(valid_rows)}/3`",
        f"- Total rows: `{len(rows)}`",
        f"- Invalid rows: `{len(invalid_rows)}`",
        "",
        "| Engagement | Status | Adoption | Route Families | Ledger Check | Blockers |",
        "|---|---|---:|---:|---|---|",
    ]
    for row in rows:
        blockers = ", ".join(row.get("blockers") or []) or "none"
        md.append(
            f"| `{row['engagement_id']}` | `{row['status']}` | `{row['adoption_rate']}` | "
            f"`{row['high_critical_route_family_adopted_count']}/{row['high_critical_route_family_count']}` | "
            f"`{row['invariant_ledger_check_passed']}` | {blockers} |"
        )
    if not rows:
        md.append("| _none_ | `missing` | `0` | `0/0` | `False` | add fresh engagement workspaces |")
    md.extend(["", "## Boundary", "", payload["proof_boundary"], ""])
    (workspace / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.md").write_text(
        "\n".join(md), encoding="utf-8"
    )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace that receives the metrics artifact")
    parser.add_argument(
        "--source-workspace",
        action="append",
        default=[],
        help="Fresh engagement workspace to import; repeat for multiple workspaces",
    )
    parser.add_argument("--manifest", help="JSON manifest with workspaces/source_workspaces rows")
    parser.add_argument("--print-json", action="store_true", help="Print JSON summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    sources: list[tuple[Path, str | None]] = []
    for raw in args.source_workspace:
        path = _as_path(raw, base=Path.cwd())
        if path:
            sources.append((path, None))
    if args.manifest:
        sources.extend(_manifest_workspaces(Path(args.manifest).expanduser().resolve()))
    payload = run(workspace, sources)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[invariant-adoption-fresh-metrics] "
            f"{payload['status']}: valid={payload['valid_fresh_engagement_count']}/"
            f"{payload['required_fresh_engagement_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
