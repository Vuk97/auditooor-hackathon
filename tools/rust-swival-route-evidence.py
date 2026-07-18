#!/usr/bin/env python3
"""Route Swival Rust stdlib corpus rows into auditooor work families.

This is an accounting/routing layer, not exploit proof. It consumes the
``rust-corpus-ingest.py`` index when present, plus older normalized Swival JSON
shapes, and emits per-finding evidence for detector, invariant, replay/runtime,
cross-crate semantic, or OOS/not-applicable routing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.rust_swival_route_evidence.v1"
EXPECTED_SWIVAL_RUST_STDLIB_TOTAL = 151
EXPECTED_SWIVAL_SEVERITIES = {"High": 27, "Medium": 115, "Low": 9}

ROUTE_DETECTOR = "detector_candidate"
ROUTE_INVARIANT = "invariant_family"
ROUTE_REPLAY = "replay_poc_task"
ROUTE_CROSS_CRATE = "cross_crate_semantic_blocker"
ROUTE_RUNTIME_DLT = "runtime_dlt_relevance"
ROUTE_OOS = "oos_not_applicable"
ROUTE_BLOCKED = "blocked_missing_corpus"


@dataclass(frozen=True)
class RouteRow:
    route_id: str
    item_id: str
    title: str
    corpus_severity: str
    component: str
    primary_route: str
    route_family: str
    detector_lane: str
    invariant_family: str
    replay_or_poc_task: str
    cross_crate_blocker: str
    runtime_dlt_relevance: str
    oos_reason: str
    fixture_backed: bool
    patch_backed: bool
    poc_backed: bool
    replay_command_present: bool
    source_pointers: list[str]
    patch_pointers: list[str]
    fixture_pointers: list[str]
    replay_commands: list[str]
    signals: list[str]
    blockers: list[str]
    source_artifact: str
    rel_path: str
    severity: str = "none"
    selected_impact: str = ""
    submission_posture: str = "NOT_SUBMIT_READY"
    impact_contract_required: bool = True


def _slug(text: str, fallback: str = "swival-route") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug or fallback)[:100]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _as_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("records", "rows", "findings", "bugs", "items", "candidates", "advisories"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        if any(key in payload for key in ("id", "item_id", "title", "name")):
            return [payload]
    return []


def _text(row: dict[str, Any], *keys: str) -> str:
    parts: list[str] = []
    for key in keys:
        value = row.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(v) for v in value if isinstance(v, (str, int, float)))
        elif isinstance(value, dict):
            parts.extend(str(v) for v in value.values() if isinstance(v, (str, int, float)))
    return "\n".join(parts)


def _list(row: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
        elif isinstance(value, list):
            out.extend(str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip())
        elif isinstance(value, dict):
            out.extend(str(v).strip() for v in value.values() if isinstance(v, (str, int, float)) and str(v).strip())
    return sorted(set(out))


def _item_id(row: dict[str, Any], index: int) -> str:
    for key in ("item_id", "id", "bug_id", "finding_id", "advisory_id", "source_id", "name", "title"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"swival-rust-stdlib-{index:03d}"


def _title(row: dict[str, Any], fallback: str) -> str:
    for key in ("title", "name", "summary", "bug", "vulnerability", "description"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().splitlines()[0][:200]
    return fallback


def _severity(row: dict[str, Any], hay: str) -> str:
    for key in ("corpus_severity", "severity", "impact_severity", "swival_severity"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip().title()
            return "Informational" if normalized == "Info" else normalized
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        if re.search(rf"\b{sev}\b", hay, re.I):
            return sev
    return "unknown"


def _component(row: dict[str, Any], hay: str) -> str:
    for key in ("component", "crate", "module", "package", "affected_package"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return _slug(value, "unknown").replace("-", "_")
    checks = (
        ("alloc", r"\balloc\b|vec|box|string|capacity"),
        ("io", r"\bio\b|read|write|cursor|buf|decode|parse"),
        ("sync", r"\bsync\b|atomic|mutex|thread|lock|ordering"),
        ("collections", r"hashmap|btree|vecdeque|collections|iterator"),
        ("net", r"\bnet\b|socket|tcp|udp"),
        ("fs_path", r"\bfs\b|path|file|symlink|canonical"),
        ("runtime_consensus", r"consensus|reth|evm|engine api|state root|finality|block"),
        ("crypto_zk", r"\bzk\b|snark|stark|proof|verifier|signature|hash"),
    )
    for name, pattern in checks:
        if re.search(pattern, hay, re.I):
            return name
    return "unknown"


def _signal_matches(hay: str) -> list[str]:
    checks = (
        ("patch_or_fix_signal", r"\bpatch\b|\.patch\b|diff --git|fixed by|fixes\b"),
        ("unsafe_memory_signal", r"\bunsafe\b|from_raw_parts|set_len|get_unchecked|transmute|assume_init|ffi|pointer"),
        ("integer_length_signal", r"overflow|underflow|truncat|usize|u64|u128|length|capacity|index|off.by.one"),
        ("parser_decode_signal", r"snappy|zstd|brotli|lz4|decode|decompress|inflate|parser|serde|bincode"),
        ("concurrency_signal", r"race|atomic|relaxed|ordering|deadlock|lock|mutex|concurrent|thread"),
        ("trait_macro_cfg_signal", r"\btrait\b|dyn\b|impl\b|generic|macro|cfg|feature|cross-crate|cross crate"),
        ("runtime_dlt_signal", r"consensus|reth|evm|fork|finality|state root|engine api|node|liveness|blockchain|dlt"),
        ("crypto_zk_signal", r"\bzk\b|snark|stark|proof|verifier|constraint|circuit|signature|hash"),
        ("host_oos_signal", r"path traversal|windows-only|terminal|unicode|cargo workflow|host-only|test-only|stdlib internal only"),
    )
    return [name for name, pattern in checks if re.search(pattern, hay, re.I)]


def _route(row: dict[str, Any], hay: str, signals: list[str]) -> tuple[str, str, str, str, str, str, str]:
    existing_route = str(row.get("route") or "").lower()
    existing_family = str(row.get("family") or row.get("category") or "")
    if "host_oos_signal" in signals:
        return (ROUTE_OOS, "host_or_stdlib_only", "", "", "", "", "host-only/std-only/test-only signal is not directly project-runtime applicable")
    if existing_route == "replay" or "runtime_dlt_signal" in signals:
        return (ROUTE_RUNTIME_DLT, "rust_runtime_or_dlt_semantics", "", "", "derive project-bound runtime replay/PoC task", "requires_runtime_semantic_adjudication", "")
    if "crypto_zk_signal" in signals:
        return (ROUTE_REPLAY, "rust_crypto_or_zk_replay", "", "", "derive proof/verifier replay or invariant harness", "", "")
    if "trait_macro_cfg_signal" in signals or "trait" in existing_family or "cfg" in existing_family:
        return (ROUTE_CROSS_CRATE, "rust_trait_macro_cfg_resolution", "", "cross_crate_trait_macro_cfg_invariant", "", "requires_cross_crate_trait_macro_cfg_resolution", "")
    if existing_route == "invariant" or "concurrency_signal" in signals:
        return (ROUTE_INVARIANT, "rust_state_or_concurrency_invariant", "", "rust_state_concurrency_invariant", "", "", "")
    if existing_route == "detector" or any(sig in signals for sig in ("unsafe_memory_signal", "integer_length_signal", "parser_decode_signal")):
        if "unsafe_memory_signal" in signals:
            lane = "rust_unsafe_memory_boundary_detector"
            family = "rust_unsafe_memory_boundary"
        elif "parser_decode_signal" in signals:
            lane = "rust_decode_or_parser_boundary_detector"
            family = "rust_decode_or_parser_boundary"
        else:
            lane = "rust_integer_or_length_boundary_detector"
            family = "rust_integer_or_length_boundary"
        return (ROUTE_DETECTOR, family, lane, "", "", "", "")
    return (ROUTE_INVARIANT, "rust_manual_semantic_invariant_review", "", "rust_manual_semantic_review", "", "", "")


def _row_from_record(record: dict[str, Any], artifact: Path, index: int) -> RouteRow:
    sid = _item_id(record, index)
    title = _title(record, sid)
    rel_path = str(record.get("rel_path") or record.get("path") or record.get("source_path") or "")
    sources = _list(record, "source_pointers", "source_path", "source_file", "source_files", "path", "file", "location")
    patches = _list(record, "patch_pointers", "patch", "patches", "fix", "diff")
    fixtures = _list(record, "fixture_pointers", "fixture", "fixtures", "test", "tests", "reproducer", "reproduction")
    pocs = _list(record, "poc_pointers", "poc", "pocs", "proof", "exploit")
    replay_commands = _list(record, "replay_commands", "replay_command", "command", "commands", "test_command")
    hay = "\n".join(
        [
            sid,
            title,
            rel_path,
            _text(record, "description", "summary", "details", "root_cause", "impact", "category", "family", "component"),
            "\n".join(sources + patches + fixtures + pocs + replay_commands),
        ]
    )
    signals = _signal_matches(hay)
    severity = _severity(record, hay)
    component = _component(record, hay)
    primary, family, detector, invariant, replay_task, cross_blocker, oos_reason = _route(record, hay, signals)
    patch_backed = bool(patches) or "patch_or_fix_signal" in signals
    poc_backed = bool(pocs)
    fixture_backed = bool(fixtures or pocs or replay_commands or patch_backed or record.get("fixture_backed"))
    replay_present = bool(replay_commands)
    blockers = [str(v) for v in (record.get("blockers") or []) if isinstance(v, str)]
    if not sources and not rel_path:
        blockers.append("missing_source_pointer")
    if primary not in {ROUTE_OOS, ROUTE_BLOCKED} and not fixture_backed:
        blockers.append("missing_fixture_patch_poc_or_replay_backing")
    if primary in {ROUTE_REPLAY, ROUTE_RUNTIME_DLT} and not replay_present:
        blockers.append("missing_project_bound_replay_command")
    if primary == ROUTE_CROSS_CRATE and not cross_blocker:
        cross_blocker = "requires_cross_crate_trait_macro_cfg_resolution"
    if primary == ROUTE_RUNTIME_DLT and not cross_blocker:
        cross_blocker = "requires_runtime_semantic_adjudication"
    return RouteRow(
        route_id=f"swival-route-{_slug(sid)}",
        item_id=sid,
        title=title,
        corpus_severity=severity,
        component=component,
        primary_route=primary,
        route_family=family,
        detector_lane=detector,
        invariant_family=invariant,
        replay_or_poc_task=replay_task,
        cross_crate_blocker=cross_blocker,
        runtime_dlt_relevance="yes" if primary == ROUTE_RUNTIME_DLT else "candidate" if "runtime_dlt_signal" in signals else "no",
        oos_reason=oos_reason,
        fixture_backed=fixture_backed,
        patch_backed=patch_backed,
        poc_backed=poc_backed,
        replay_command_present=replay_present,
        source_pointers=sources or ([rel_path] if rel_path else []),
        patch_pointers=patches,
        fixture_pointers=sorted(set(fixtures + pocs)),
        replay_commands=replay_commands,
        signals=signals,
        blockers=sorted(set(blockers)),
        source_artifact=str(artifact),
        rel_path=rel_path,
    )


def _missing_blocker(workspace: Path, inputs: list[Path]) -> dict[str, Any]:
    return {
        "blocker_id": "swival-rust-stdlib-local-checkout-or-ingest-missing",
        "status": "terminal_missing_swival_route_input",
        "workspace": str(workspace),
        "requested_inputs": [str(path) for path in inputs],
        "required_input": "local Swival/security-audits rust-stdlib checkout ingested with rust-corpus-ingest, or normalized Swival JSON",
        "expected_corpus": {
            "url": "https://github.com/Swival/security-audits/tree/main/rust-stdlib",
            "expected_total": EXPECTED_SWIVAL_RUST_STDLIB_TOTAL,
            "expected_severities": EXPECTED_SWIVAL_SEVERITIES,
        },
        "why_not_closed": "cannot prove all 151 Swival Rust stdlib findings mined, routed, and fixture-backed without a local corpus/index",
        "next_commands": [
            "git clone https://github.com/Swival/security-audits /path/to/security-audits",
            "make rust-corpus-ingest WS=<workspace> RUST_CORPUS_ROOT=/path/to/security-audits/rust-stdlib",
            "make rust-swival-route-evidence WS=<workspace>",
        ],
    }


def _discover_inputs(workspace: Path) -> list[Path]:
    candidates = [
        workspace / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_index.json",
        workspace / ".auditooor" / "rust_corpus_mining_coverage.json",
    ]
    candidates.extend(workspace.glob("**/rust_swival_stdlib_findings.json"))
    candidates.extend(workspace.glob("**/swival_findings_normalized.json"))
    seen: set[Path] = set()
    out: list[Path] = []
    for path in candidates:
        resolved = path.expanduser().resolve()
        if resolved.is_file() and resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


def load_rows(paths: Iterable[Path]) -> list[RouteRow]:
    rows: list[RouteRow] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        payload = _read_json(path)
        for index, record in enumerate(_as_records(payload), 1):
            row = _row_from_record(record, path, index)
            key = (row.item_id, row.source_artifact)
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    rows.sort(key=lambda row: (row.primary_route, row.route_family, row.item_id))
    return rows


def summarize(rows: list[RouteRow], blockers: list[dict[str, Any]], inputs: list[Path], expected_total: int) -> dict[str, Any]:
    by_route: dict[str, int] = {}
    by_family: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        by_route[row.primary_route] = by_route.get(row.primary_route, 0) + 1
        by_family[row.route_family] = by_family.get(row.route_family, 0) + 1
        by_severity[row.corpus_severity] = by_severity.get(row.corpus_severity, 0) + 1
    return {
        "input_count": len(inputs),
        "row_count": len(rows),
        "expected_swival_rust_stdlib_total": expected_total,
        "coverage_complete_for_expected_swival_total": len(rows) == expected_total,
        "expected_swival_severities": EXPECTED_SWIVAL_SEVERITIES,
        "by_corpus_severity": dict(sorted(by_severity.items())),
        "by_primary_route": dict(sorted(by_route.items())),
        "by_route_family": dict(sorted(by_family.items())),
        "detector_candidate_count": by_route.get(ROUTE_DETECTOR, 0),
        "invariant_family_count": by_route.get(ROUTE_INVARIANT, 0),
        "replay_poc_task_count": by_route.get(ROUTE_REPLAY, 0),
        "cross_crate_semantic_blocker_count": by_route.get(ROUTE_CROSS_CRATE, 0),
        "runtime_dlt_relevance_count": by_route.get(ROUTE_RUNTIME_DLT, 0),
        "oos_not_applicable_count": by_route.get(ROUTE_OOS, 0),
        "fixture_backed_count": sum(1 for row in rows if row.fixture_backed),
        "patch_backed_count": sum(1 for row in rows if row.patch_backed),
        "poc_backed_count": sum(1 for row in rows if row.poc_backed),
        "replay_command_present_count": sum(1 for row in rows if row.replay_command_present),
        "items_with_blockers": sum(1 for row in rows if row.blockers),
        "blocker_count": len(blockers),
    }


def build_payload(workspace: Path, inputs: list[Path], expected_total: int = EXPECTED_SWIVAL_RUST_STDLIB_TOTAL) -> dict[str, Any]:
    resolved_inputs = [path.expanduser().resolve() for path in inputs if path.expanduser().is_file()]
    rows = load_rows(resolved_inputs)
    blockers: list[dict[str, Any]] = []
    if not rows:
        blockers.append(_missing_blocker(workspace, inputs))
    elif len(rows) != expected_total:
        blockers.append(
            {
                "blocker_id": "swival-rust-stdlib-route-coverage-incomplete",
                "status": "non_terminal_incomplete_route_coverage",
                "expected_total": expected_total,
                "observed_total": len(rows),
                "why_not_closed": "route evidence exists but does not account for every expected Swival rust-stdlib finding",
                "next_commands": [
                    "verify the local Swival checkout is complete",
                    "rerun make rust-corpus-ingest WS=<workspace> RUST_CORPUS_ROOT=/path/to/security-audits/rust-stdlib",
                    "rerun make rust-swival-route-evidence WS=<workspace>",
                ],
            }
        )
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "inputs": [str(path) for path in resolved_inputs],
        "summary": summarize(rows, blockers, resolved_inputs, expected_total),
        "blockers": blockers,
        "rows": [asdict(row) for row in rows],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Swival Rust Stdlib Route Evidence",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "Rows are advisory routing evidence only. They do not select severity,",
        "impact, or submission readiness without a separate impact contract and",
        "executed proof.",
        "",
        "## Summary",
        "",
        f"- inputs: `{summary['input_count']}`",
        f"- rows routed: `{summary['row_count']}`",
        f"- expected Swival rust-stdlib total: `{summary['expected_swival_rust_stdlib_total']}`",
        f"- complete for expected total: `{summary['coverage_complete_for_expected_swival_total']}`",
        f"- detector candidates: `{summary['detector_candidate_count']}`",
        f"- invariant families: `{summary['invariant_family_count']}`",
        f"- replay/PoC tasks: `{summary['replay_poc_task_count']}`",
        f"- cross-crate semantic blockers: `{summary['cross_crate_semantic_blocker_count']}`",
        f"- runtime/DLT relevant: `{summary['runtime_dlt_relevance_count']}`",
        f"- OOS/not applicable: `{summary['oos_not_applicable_count']}`",
        f"- fixture/patch/PoC/replay backed: `{summary['fixture_backed_count']}`",
        f"- patch-backed: `{summary['patch_backed_count']}`",
        f"- PoC-backed: `{summary['poc_backed_count']}`",
        f"- replay command present: `{summary['replay_command_present_count']}`",
        f"- items with blockers: `{summary['items_with_blockers']}`",
        "",
    ]
    if payload["blockers"]:
        lines.extend(["## Exact Blockers", ""])
        for blocker in payload["blockers"]:
            lines.append(f"- `{blocker['blocker_id']}`: {blocker['why_not_closed']}")
        lines.append("")
    lines.extend(["## Route Counts", ""])
    for key, count in sorted(summary["by_primary_route"].items()):
        lines.append(f"- `{key}`: `{count}`")
    lines.append("")
    lines.extend(["## Routed Rows", ""])
    if not payload["rows"]:
        lines.append("_No Swival Rust stdlib rows were routed._")
    else:
        lines.append("| Item | Severity | Component | Route | Family | Backed | Blockers | Title |")
        lines.append("|---|---|---|---|---|---:|---|---|")
        for row in payload["rows"][:300]:
            blockers = ", ".join(row.get("blockers") or []) or "(none)"
            title = str(row.get("title", "")).replace("|", "\\|")
            backed = "yes" if row.get("fixture_backed") else "no"
            lines.append(
                f"| `{row['item_id']}` | `{row['corpus_severity']}` | `{row['component']}` | `{row['primary_route']}` | "
                f"`{row['route_family']}` | `{backed}` | {blockers} | {title} |"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--input", type=Path, action="append", default=[], help="Rust corpus index or normalized Swival JSON. Repeatable.")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--expected-total", type=int, default=EXPECTED_SWIVAL_RUST_STDLIB_TOTAL)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-swival-route-evidence] workspace not found: {workspace}", file=sys.stderr)
        return 2
    inputs = list(args.input) or _discover_inputs(workspace)
    payload = build_payload(workspace, inputs, args.expected_total)
    out_dir = (args.out_dir or (workspace / ".audit_logs" / "rust_corpus_mining")).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "rust_swival_route_evidence.json"
    md_path = out_dir / "rust_swival_route_evidence.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    auditooor = workspace / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "rust_swival_route_evidence.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (auditooor / "rust_swival_route_evidence.md").write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "blockers": payload["blockers"]}, indent=2, sort_keys=True))
    else:
        print(f"[rust-swival-route-evidence] wrote {json_path}")
        print(f"[rust-swival-route-evidence] rows={payload['summary']['row_count']} blockers={payload['summary']['blocker_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
