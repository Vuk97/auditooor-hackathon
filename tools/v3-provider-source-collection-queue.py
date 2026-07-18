#!/usr/bin/env python3
"""Build deterministic closure packets from V3 provider verifier rows.

Provider output is advisory only. This queue does not promote any claim; it
turns ``needs_more_source`` rows into bounded acquisition tasks with registry
context and local next commands so operators can collect sources mechanically
before spending more LLM tokens.

Rows that already have local evidence but still lack a terminal outcome are
also packetized for bounded Kimi/MiniMax/local review. These packets never call
providers or infer a final terminal judgment.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - exercised when PyYAML is installed.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.v3_provider_source_collection_queue.v1"
TERMINAL_PACKET_SCHEMA = "auditooor.v3_provider_terminal_judgment_packet.v1"
DEFAULT_OUT_JSON = ROOT / ".auditooor" / "provider_source_collection_queue.json"
DEFAULT_OUT_MD = ROOT / ".auditooor" / "provider_source_collection_queue.md"
SOURCE_FAMILY_TO_REGISTRY = {
    "defillama": "defillama_hacks_tvl",
    "rekt": "rekt_news_incidents",
    "darknavy": "darknavy_web3_pages",
    "solodit": "solodit_high_plus_findings",
    "pashov": "pashov_public_audits",
    "defimon": "defimon_delta_blocked_no_live_source",
    "verus": "verus_bridge_incident_2026_05",
    "map_butter": "map_butter_bridge_incident_2026_05",
}
SOURCE_FAMILY_PRIORITY = (
    "defimon",
    "map_butter",
    "verus",
    "darknavy",
    "pashov",
    "solodit",
    "defillama",
    "rekt",
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _flatten(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child)
    else:
        yield value


def _norm_text(value: Any, *, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _read_registry(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text) or {}
    else:
        data = _minimal_registry_parse(text)
    sources = data.get("sources") if isinstance(data, dict) else []
    out: dict[str, dict[str, Any]] = {}
    for row in sources or []:
        if not isinstance(row, dict):
            continue
        source_id = str(row.get("source_id") or "")
        if source_id:
            out[source_id] = row
    return out


def _minimal_registry_parse(text: str) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    parent_stack: list[str] = []
    for raw in text.splitlines():
        if raw.strip().startswith("#") or not raw.strip():
            continue
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if stripped.startswith("- source_id:"):
            if current:
                sources.append(current)
            current = {"source_id": stripped.split(":", 1)[1].strip().strip("'\"")}
            parent_stack = []
            continue
        if current is None or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        value = value.strip().strip("'\"")
        if indent == 4:
            parent_stack = [key]
            current[key] = value if value else {}
        elif indent == 6 and parent_stack:
            parent = current.setdefault(parent_stack[-1], {})
            if isinstance(parent, dict):
                parent[key] = value
        elif indent == 2:
            current[key] = value
    if current:
        sources.append(current)
    return {"sources": sources}


def _discovered_result_paths(root: Path) -> list[Path]:
    paths = list(root.glob(".auditooor/**/v3_provider_local_verification_result.json"))
    backfill = root / ".auditooor" / "provider_keep_verification_backfill_result.json"
    if backfill.is_file():
        paths.append(backfill)
    return sorted({path.resolve() for path in paths})


def _gate_result_paths(root: Path) -> list[Path]:
    gate_paths = [
        root / ".auditooor" / "provider_campaign_completeness_gate.json",
        root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
    ]
    out: list[Path] = []
    for gate_path in gate_paths:
        try:
            data = _read_json(gate_path) if gate_path.is_file() else {}
        except (OSError, json.JSONDecodeError, ValueError):
            data = {}
        artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
        verification_path = Path(str(artifacts.get("local_verification") or ""))
        if verification_path.is_file():
            out.append(verification_path.resolve())
    return sorted(set(out))


def _result_paths(root: Path, explicit: list[Path], *, include_all_results: bool = False) -> list[Path]:
    if explicit:
        return sorted({path.expanduser().resolve() for path in explicit if path.expanduser().is_file()})
    gate_results = _gate_result_paths(root)
    discovered = _discovered_result_paths(root)
    if include_all_results:
        return sorted({*gate_results, *discovered})
    if gate_results:
        return gate_results
    return discovered


def _needs_source(row: dict[str, Any]) -> bool:
    return bool(
        row.get("source_collection_required")
        or row.get("verification_status") == "needs_more_source"
        or row.get("terminal_outcome") == "needs_more_source"
    )


def _needs_terminal_judgment(row: dict[str, Any]) -> bool:
    return bool(
        row.get("terminal_judgment_required")
        or (
            row.get("verification_status") == "verified"
            and not row.get("terminal_outcome")
            and not row.get("terminal_safe")
        )
    )


def _source_family(row: dict[str, Any]) -> str:
    source_provider = row.get("source_provider_row") if isinstance(row.get("source_provider_row"), dict) else {}
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    haystack = " ".join(
        _norm_text(value, limit=400)
        for value in [
            row.get("task_id"),
            row.get("route"),
            claim.get("summary"),
            claim.get("provider_claim_id"),
            source_provider.get("provider_output_path"),
            source_provider.get("template"),
            row.get("verification"),
            row.get("grep_hits"),
            row.get("source_ref_checks"),
        ]
    ).lower()
    if any(marker in haystack for marker in ("map/butter", "map protocol", "mapprotocol", "butter", "mapo", "omniserviceproxy")):
        return "map_butter"
    for family in SOURCE_FAMILY_PRIORITY:
        if family != "map_butter" and family in haystack:
            return family
    route = str(row.get("route") or "").lower()
    if route == "fixture_needed":
        return "fixture"
    if route == "kill_review":
        return "kill_review"
    if route == "local_source_review":
        return "local_source"
    return "uncategorized"


def _registry_hint(registry_row: dict[str, Any] | None) -> dict[str, Any]:
    if not registry_row:
        return {}
    miner = registry_row.get("miner") if isinstance(registry_row.get("miner"), dict) else {}
    cursor = registry_row.get("cursor") if isinstance(registry_row.get("cursor"), dict) else {}
    quality = registry_row.get("quality_gate") if isinstance(registry_row.get("quality_gate"), dict) else {}
    promotion = registry_row.get("promotion_target") if isinstance(registry_row.get("promotion_target"), dict) else {}
    return {
        "source_id": registry_row.get("source_id"),
        "url_or_api": registry_row.get("url_or_api"),
        "miner_tool": miner.get("tool_path"),
        "miner_mode": miner.get("mode"),
        "makefile_target": miner.get("makefile_target"),
        "auth_env": miner.get("auth_env") or [],
        "cursor_path": cursor.get("path"),
        "cursor_field": cursor.get("field"),
        "ttl": registry_row.get("ttl"),
        "output_subtree": registry_row.get("output_subtree") or promotion.get("corpus_subtree"),
        "required_fields": quality.get("required_fields") or [],
        "reject_if": quality.get("reject_if") or [],
        "minimum_verification_tier": quality.get("minimum_verification_tier"),
        "downstream": promotion.get("downstream") or [],
    }


def _next_command(family: str, registry: dict[str, Any]) -> str:
    output = registry.get("output_subtree") or "audit/corpus_tags/tags/<source_delta>"
    if family == "defillama":
        return f"make hackerman-etl-post-mortem SOURCE=defillama FETCH=1 APPLY=1 MAX_PAGES=50 JSON=1 OUT_DIR={output}"
    if family == "rekt":
        return f"make hackerman-etl-post-mortem SOURCE=rekt FETCH=1 APPLY=1 MAX_PAGES=10 JSON=1 OUT_DIR={output}"
    if family == "darknavy":
        target = registry.get("makefile_target") or "darknavy-web3-mine"
        return f"make {target} FETCH=1 APPLY=1 MAX_PAGES=8 JSON=1 OUT_DIR={output}"
    if family == "solodit":
        return (
            "SOLODIT_API_KEY=\"$SOLODIT_API_KEY\" python3 tools/solodit-rest-direct.py "
            f"--min-severity HIGH --page-size 100 --max-pages 5 --out-dir {output} --no-update-cursor"
        )
    if family == "pashov":
        return "make hackerman-etl-from-audit-firm-pdf-pashov JSON=1"
    if family == "defimon":
        return (
            "python3 tools/defimon-nextjs-blog-miner.py --max-posts 12 --json-only "
            "--timeout-seconds 8"
        )
    if family == "verus":
        source_id = registry.get("source_id") or "verus_bridge_incident_2026_05"
        return (
            f"make external-intel-refresh SOURCE={source_id} ALLOW_LIVE_FETCH=1 "
            "FETCH_SINGLE_INCIDENT=1 JSON=1 "
            f"OUT=.auditooor/external_intel_single_incident_{source_id}.json"
        )
    if family == "map_butter":
        source_id = registry.get("source_id") or "map_butter_bridge_incident_2026_05"
        return (
            f"make external-intel-refresh SOURCE={source_id} ALLOW_LIVE_FETCH=1 "
            "FETCH_SINGLE_INCIDENT=1 JSON=1 "
            f"OUT=.auditooor/external_intel_single_incident_{source_id}.json"
        )
    if family == "fixture":
        return "create vulnerable/clean fixture pair and deterministic local smoke command"
    if family == "kill_review":
        return "collect exact contradiction citation or keep row pending"
    if family == "local_source":
        return "extract exact local line refs into a source artifact, then rerun v3-provider-local-verify"
    return "collect primary URL/date/txhash or exact local source artifact"


def _source_collection_lanes(family: str, provider: str) -> list[str]:
    lanes = ["local"]
    if family in {"verus", "map_butter"}:
        if provider == "minimax":
            lanes.append("minimax")
        return lanes
    if family != "kill_review" or provider == "kimi":
        lanes.append("kimi")
    if family == "kill_review" or provider == "minimax":
        lanes.append("minimax")
    return lanes


def _lane_assignments(lanes: Iterable[str]) -> dict[str, str]:
    descriptions = {
        "local": "verify exact local refs and keep provider output quarantined",
        "kimi": "source_extraction",
        "minimax": "adversarial_kill",
    }
    return {lane: descriptions[lane] for lane in ("local", "kimi", "minimax") if lane in set(lanes)}


def _append_lanes(item: dict[str, Any], lanes: Iterable[str]) -> None:
    existing = set(item.get("review_lanes") or [])
    existing.update(lanes)
    ordered = [lane for lane in ("local", "kimi", "minimax") if lane in existing]
    item["review_lanes"] = ordered
    item["lane_assignments"] = _lane_assignments(ordered)


def _row_fingerprint(row: dict[str, Any], family: str) -> str:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    basis = "|".join(
        [
            family,
            str(row.get("route") or ""),
            _norm_text(claim.get("summary"), limit=180),
        ]
    )
    return re.sub(r"[^a-zA-Z0-9_.:-]+", "-", basis.lower()).strip("-")[:180] or "source-task"


def _terminal_family(row: dict[str, Any]) -> str:
    route = str(row.get("route") or "").strip() or "verified"
    if route in {"kill_review", "local_source_review", "fixture_needed"}:
        return route
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    haystack = " ".join(
        _norm_text(value, limit=300).lower()
        for value in [
            route,
            row.get("task_id"),
            claim.get("kind"),
            claim.get("summary"),
            row.get("grep_hits"),
            row.get("source_ref_checks"),
        ]
    )
    if "kill" in haystack or "reject" in haystack or "oos" in haystack:
        return "kill_review"
    if "fixture" in haystack or "harness" in haystack or "clean control" in haystack:
        return "fixture_needed"
    return "local_source_review"


def _terminal_review_lanes(family: str, provider: str) -> list[str]:
    lanes = ["local"]
    if family == "kill_review" or provider == "minimax":
        lanes.append("minimax")
    if family in {"local_source_review", "fixture_needed"} or provider == "kimi":
        lanes.append("kimi")
    return lanes


def _terminal_next_action(family: str) -> str:
    if family == "kill_review":
        return "local reviewer selects rejected_* / verified_no_action only with exact contradiction citation; otherwise keep pending"
    if family == "fixture_needed":
        return "local reviewer confirms vulnerable/clean fixture evidence before selecting verified_actionable or verified_no_action"
    if family == "local_source_review":
        return "local reviewer maps exact evidence refs to one allowed terminal_outcome; otherwise keep terminal_judgment_required"
    return "local reviewer chooses one allowed terminal_outcome from local evidence, not provider text"


def _terminal_fingerprint(row: dict[str, Any], family: str) -> str:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    basis = "|".join(
        [
            family,
            str(row.get("route") or ""),
            str(row.get("task_id") or ""),
            _norm_text(claim.get("summary"), limit=140),
        ]
    )
    return re.sub(r"[^a-zA-Z0-9_.:-]+", "-", basis.lower()).strip("-")[:180] or "terminal-task"


def _compact_row(row: dict[str, Any], result_path: Path, root: Path) -> dict[str, Any]:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    source_provider = row.get("source_provider_row") if isinstance(row.get("source_provider_row"), dict) else {}
    verification = row.get("verification") if isinstance(row.get("verification"), dict) else {}
    return {
        "result_path": _safe_rel(result_path, root),
        "queue_id": row.get("queue_id"),
        "row_id": row.get("row_id"),
        "task_id": row.get("task_id"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "route": row.get("route"),
        "verification_status": row.get("verification_status"),
        "terminal_outcome": row.get("terminal_outcome"),
        "claim_kind": claim.get("kind"),
        "claim_id": claim.get("provider_claim_id"),
        "claim_summary": _norm_text(claim.get("summary"), limit=360),
        "provider_output_path": source_provider.get("provider_output_path"),
        "template": source_provider.get("template"),
        "source_ref_checks": (row.get("source_ref_checks") or [])[:8],
        "verification_commands": (verification.get("commands") or [])[:6],
        "grep_hits": (row.get("grep_hits") or [])[:8],
    }


def _compact_terminal_row(row: dict[str, Any], result_path: Path, root: Path) -> dict[str, Any]:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    source_provider = row.get("source_provider_row") if isinstance(row.get("source_provider_row"), dict) else {}
    verification = row.get("verification") if isinstance(row.get("verification"), dict) else {}
    return {
        "result_path": _safe_rel(result_path, root),
        "queue_id": row.get("queue_id"),
        "row_id": row.get("row_id"),
        "task_id": row.get("task_id"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "route": row.get("route"),
        "verification_status": row.get("verification_status"),
        "terminal_outcome": row.get("terminal_outcome"),
        "terminal_safe": row.get("terminal_safe"),
        "terminal_outcome_options": row.get("terminal_outcome_options") or [],
        "claim_kind": claim.get("kind"),
        "claim_id": claim.get("provider_claim_id"),
        "claim_summary": _norm_text(claim.get("summary"), limit=360),
        "provider_output_path": source_provider.get("provider_output_path"),
        "template": source_provider.get("template"),
        "evidence_refs": (verification.get("evidence_refs") or [])[:8],
        "source_ref_checks": (row.get("source_ref_checks") or [])[:8],
        "grep_hits": (row.get("grep_hits") or [])[:8],
        "required_local_decision": "select_terminal_outcome_or_keep_pending",
    }


def build_queue(root: Path, result_paths: list[Path], registry_path: Path) -> dict[str, Any]:
    registry = _read_registry(registry_path)
    grouped: dict[str, dict[str, Any]] = {}
    terminal_grouped: dict[str, dict[str, Any]] = {}
    source_rows = 0
    terminal_rows = 0
    rows_seen = 0
    by_family: Counter[str] = Counter()
    by_terminal_family: Counter[str] = Counter()
    by_terminal_reviewer: Counter[str] = Counter()
    by_source_reviewer: Counter[str] = Counter()
    by_route: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    for result_path in result_paths:
        data = _read_json(result_path)
        for row in data.get("rows") or []:
            if not isinstance(row, dict):
                continue
            rows_seen += 1
            if not _needs_source(row):
                continue
            source_rows += 1
            family = _source_family(row)
            provider = str(row.get("provider") or "unknown")
            lanes = _source_collection_lanes(family, provider)
            by_family[family] += 1
            for lane in lanes:
                by_source_reviewer[lane] += 1
            by_route[str(row.get("route") or "unknown")] += 1
            by_status[str(row.get("verification_status") or "unknown")] += 1
            key = _row_fingerprint(row, family)
            registry_id = SOURCE_FAMILY_TO_REGISTRY.get(family)
            registry_hint = _registry_hint(registry.get(registry_id or ""))
            if key not in grouped:
                grouped[key] = {
                    "source_collection_id": f"V3-SC-{len(grouped) + 1:03d}",
                    "packet_kind": "source_collection",
                    "fingerprint": key,
                    "source_family": family,
                    "review_lanes": [],
                    "lane_assignments": {},
                    "registry": registry_hint,
                    "next_command": _next_command(family, registry_hint),
                    "source_state": "needs_collection",
                    "promotion_blockers": [
                        "provider_output_is_advisory_only",
                        "primary_source_or_exact_local_artifact_required",
                    ],
                    "rows": [],
                }
            _append_lanes(grouped[key], lanes)
            grouped[key]["rows"].append(_compact_row(row, result_path, root))
        for row in data.get("rows") or []:
            if not isinstance(row, dict) or not _needs_terminal_judgment(row):
                continue
            terminal_rows += 1
            family = _terminal_family(row)
            provider = str(row.get("provider") or "unknown")
            lanes = _terminal_review_lanes(family, provider)
            by_terminal_family[family] += 1
            for lane in lanes:
                by_terminal_reviewer[lane] += 1
            key = _terminal_fingerprint(row, family)
            if key not in terminal_grouped:
                terminal_grouped[key] = {
                    "schema": TERMINAL_PACKET_SCHEMA,
                    "terminal_judgment_id": f"V3-TJ-{len(terminal_grouped) + 1:03d}",
                    "fingerprint": key,
                    "judgment_family": family,
                    "review_lanes": lanes,
                    "next_action": _terminal_next_action(family),
                    "terminal_state": "needs_local_judgment",
                    "promotion_blockers": [
                        "provider_output_is_advisory_only",
                        "local_terminal_outcome_required",
                        "no_learning_until_terminal_outcome",
                    ],
                    "rows": [],
                }
            terminal_grouped[key]["rows"].append(_compact_terminal_row(row, result_path, root))

    items = sorted(
        grouped.values(),
        key=lambda item: (-len(item["rows"]), str(item["source_family"]), str(item["source_collection_id"])),
    )
    terminal_items = sorted(
        terminal_grouped.values(),
        key=lambda item: (-len(item["rows"]), str(item["judgment_family"]), str(item["terminal_judgment_id"])),
    )
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "root": str(root),
        "registry_path": _safe_rel(registry_path, root),
        "result_paths": [_safe_rel(path, root) for path in result_paths],
        "summary": {
            "results_scanned": len(result_paths),
            "rows_seen": rows_seen,
            "source_rows": source_rows,
            "deduped_items": len(items),
            "terminal_judgment_rows": terminal_rows,
            "terminal_judgment_items": len(terminal_items),
            "by_family": dict(sorted(by_family.items())),
            "by_source_reviewer": dict(sorted(by_source_reviewer.items())),
            "by_terminal_family": dict(sorted(by_terminal_family.items())),
            "by_terminal_reviewer": dict(sorted(by_terminal_reviewer.items())),
            "by_route": dict(sorted(by_route.items())),
            "by_status": dict(sorted(by_status.items())),
        },
        "items": items,
        "terminal_judgment_items": terminal_items,
        "advisory_only": True,
        "promotion_authority": False,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# V3 Provider Source Collection Queue",
        "",
        "Provider output is advisory only. These rows collect missing primary sources or exact local artifacts before any promotion.",
        "",
        f"- results scanned: `{payload['summary']['results_scanned']}`",
        f"- source rows: `{payload['summary']['source_rows']}`",
        f"- deduped items: `{payload['summary']['deduped_items']}`",
        f"- by_family: `{payload['summary']['by_family']}`",
        f"- by_source_reviewer: `{payload['summary'].get('by_source_reviewer', {})}`",
        f"- terminal judgment rows: `{payload['summary'].get('terminal_judgment_rows', 0)}`",
        f"- terminal judgment items: `{payload['summary'].get('terminal_judgment_items', 0)}`",
        f"- by_terminal_family: `{payload['summary'].get('by_terminal_family', {})}`",
        "",
        "| ID | Family | Review Lanes | Rows | Next Command |",
        "|---|---|---|---:|---|",
    ]
    for item in payload["items"]:
        lines.append(
            f"| `{item['source_collection_id']}` | `{item['source_family']}` | "
            f"`{','.join(item.get('review_lanes') or [])}` | {len(item['rows'])} | `{item['next_command']}` |"
        )
    terminal_items = payload.get("terminal_judgment_items") or []
    if terminal_items:
        lines.extend(
            [
                "",
                "## Terminal Judgment Packets",
                "",
                "| ID | Family | Review Lanes | Rows | Next Action |",
                "|---|---|---|---:|---|",
            ]
        )
        for item in terminal_items:
            lines.append(
                f"| `{item['terminal_judgment_id']}` | `{item['judgment_family']}` | "
                f"`{','.join(item['review_lanes'])}` | {len(item['rows'])} | `{item['next_action']}` |"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--result", type=Path, action="append", default=[])
    parser.add_argument(
        "--include-all-results",
        action="store_true",
        help="When no --result is provided, include every local verification result instead of only the gate-selected campaign result.",
    )
    parser.add_argument("--registry", type=Path, default=ROOT / "reference" / "external_intel_sources.yaml")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.expanduser().resolve()
    result_paths = _result_paths(root, args.result, include_all_results=args.include_all_results)
    payload = build_queue(root, result_paths, args.registry.expanduser().resolve())
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    else:
        summary = payload["summary"]
        print(
            "v3-provider-source-collection-queue: "
            f"{summary['source_rows']} source rows -> {summary['deduped_items']} deduped items; "
            f"{summary['terminal_judgment_rows']} terminal rows -> "
            f"{summary['terminal_judgment_items']} terminal items"
        )
        print(f"  json -> {args.out_json}")
        print(f"  md   -> {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
