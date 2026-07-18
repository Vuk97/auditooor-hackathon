#!/usr/bin/env python3
"""Generate advisory fixture/replay tasks from the Swival Rust corpus index.

The generator consumes ``rust-corpus-ingest.py`` output when it contains
actionable records. If the local Swival checkout is still missing and the index
is absent or blocker-only, it uses a tiny hermetic fixture so downstream task
formatting and grouping can be tested without fabricating proof for the real
151 findings.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.rust_corpus_fixture_tasks.v1"
DEFAULT_OUT_DIR = Path(".audit_logs") / "rust_corpus_mining"
DEFAULT_INDEX = DEFAULT_OUT_DIR / "rust_corpus_index.json"
AUDITOOOR_INDEX = Path(".auditooor") / "rust_corpus_mining_coverage.json"
EXPECTED_SWIVAL_TOTAL = 151


@dataclass(frozen=True)
class FixtureTask:
    task_id: str
    source_item_id: str
    title: str
    bug_family: str
    route: str
    feasibility: str
    task_kind: str
    evidence_types: list[str]
    source_pointers: list[str]
    patch_pointers: list[str]
    poc_pointers: list[str]
    writeup_pointers: list[str]
    replay_commands: list[str]
    fixture_plan: list[str]
    blockers: list[str]
    proof_status: str = "not_proved"
    terminal_state: str = "planned_not_executed"
    severity: str = "none"
    selected_impact: str = ""
    submission_posture: str = "NOT_SUBMIT_READY"


HERMETIC_RECORDS: list[dict[str, Any]] = [
    {
        "item_id": "fixture-swival-unsafe-len",
        "title": "Hermetic unsafe length primitive with patch and PoC pointers",
        "family": "rust_unsafe_memory_boundary",
        "route": "detector",
        "source_pointers": ["hermetic/unsafe_len/writeup.md"],
        "patch_pointers": ["hermetic/unsafe_len/fix.patch"],
        "poc_pointers": ["hermetic/unsafe_len/poc.rs"],
        "replay_commands": ["cargo test unsafe_len_repro"],
        "fixture_pointers": ["hermetic/unsafe_len/poc.rs"],
        "source_kind": "md",
    },
    {
        "item_id": "fixture-swival-decode-bomb",
        "title": "Hermetic decoder resource-boundary writeup with reproducer",
        "family": "rust_decode_or_parser_boundary",
        "route": "replay",
        "source_pointers": ["hermetic/decode_bomb/writeup.md"],
        "patch_pointers": [],
        "poc_pointers": ["hermetic/decode_bomb/repro.rs"],
        "replay_commands": ["cargo test decode_bomb_repro"],
        "fixture_pointers": ["hermetic/decode_bomb/repro.rs"],
        "source_kind": "md",
    },
    {
        "item_id": "fixture-swival-cfg-trait",
        "title": "Hermetic cfg trait divergence writeup needing cross-crate adjudication",
        "family": "rust_trait_macro_cfg_resolution",
        "route": "invariant",
        "source_pointers": ["hermetic/cfg_trait/writeup.md"],
        "patch_pointers": [],
        "poc_pointers": [],
        "replay_commands": [],
        "fixture_pointers": [],
        "source_kind": "md",
    },
]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _default_index_path(workspace: Path) -> Path | None:
    for rel in (DEFAULT_INDEX, AUDITOOOR_INDEX):
        path = workspace / rel
        if path.is_file():
            return path
    return None


def _records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    records = payload.get("records")
    if isinstance(records, list):
        return [row for row in records if isinstance(row, dict)]
    return []


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _writeup_pointers(record: dict[str, Any]) -> list[str]:
    pointers: set[str] = set()
    source_kind = str(record.get("source_kind") or "").lower()
    if source_kind in {"md", "txt"}:
        pointers.update(_as_list(record.get("rel_path")))
    for pointer in _as_list(record.get("rel_path")) + _as_list(record.get("source_pointers")):
        if pointer.lower().endswith((".md", ".txt")):
            pointers.add(pointer)
    return sorted(pointers)


def _evidence_types(record: dict[str, Any]) -> list[str]:
    types: list[str] = []
    if _as_list(record.get("patch_pointers")):
        types.append("patch")
    if _as_list(record.get("poc_pointers")) or _as_list(record.get("fixture_pointers")):
        types.append("poc_or_fixture")
    if _writeup_pointers(record):
        types.append("writeup")
    if _as_list(record.get("replay_commands")):
        types.append("replay_command")
    return types


def _feasibility(record: dict[str, Any], evidence_types: list[str]) -> str:
    family = str(record.get("family") or "")
    route = str(record.get("route") or "")
    if "poc_or_fixture" in evidence_types and ("patch" in evidence_types or "replay_command" in evidence_types):
        return "high"
    if "poc_or_fixture" in evidence_types or ("patch" in evidence_types and "writeup" in evidence_types):
        return "medium"
    if "writeup" in evidence_types and route in {"detector", "invariant", "replay"}:
        return "low"
    if "trait" in family or "cfg" in family or "runtime" in family:
        return "blocked_semantic_resolution"
    return "blocked_missing_artifact"


def _task_kind(route: str, evidence_types: list[str]) -> str:
    if "replay_command" in evidence_types or route == "replay":
        return "replay_task"
    if route == "detector":
        return "fixture_pair_task"
    if route == "invariant":
        return "invariant_fixture_task"
    return "manual_source_review_task"


def _fixture_plan(task_kind: str, record: dict[str, Any]) -> list[str]:
    source = ", ".join(_as_list(record.get("source_pointers"))[:3]) or "source pointer missing"
    if task_kind == "fixture_pair_task":
        return [
            f"source-read {source} and extract the vulnerable predicate",
            "create minimal vulnerable Rust fixture that triggers only the mined predicate",
            "create clean Rust fixture from patch/fix behavior or an explicit negative control",
            "run detector smoke and keep stdout/stderr with no severity or impact claim",
        ]
    if task_kind == "replay_task":
        return [
            f"source-read {source} and verify the replay preconditions",
            "wire the PoC/reproducer into an isolated Rust test or command",
            "record execution with poc-execution-record only after the command actually runs",
        ]
    if task_kind == "invariant_fixture_task":
        return [
            f"source-read {source} and write the invariant in one sentence",
            "build a vulnerable/clean pair or kill the row with exact source evidence",
            "do not promote until cross-crate/cfg/runtime semantics are locally resolved",
        ]
    return [f"source-read {source} and classify whether a fixture, invariant, or replay is justified"]


def _blockers(record: dict[str, Any], evidence_types: list[str], feasibility: str) -> list[str]:
    blockers: set[str] = set(_as_list(record.get("blockers")))
    if "writeup" not in evidence_types:
        blockers.add("missing_writeup_pointer")
    if "patch" not in evidence_types and "poc_or_fixture" not in evidence_types:
        blockers.add("missing_patch_or_poc_pointer")
    if feasibility.startswith("blocked"):
        blockers.add(feasibility)
    if "trait" in str(record.get("family") or "") or "cfg" in str(record.get("family") or ""):
        blockers.add("requires_cross_crate_trait_macro_cfg_resolution")
    blockers.add("not_executed_no_proof")
    return sorted(blockers)


def task_from_record(record: dict[str, Any], ordinal: int) -> FixtureTask | None:
    evidence_types = _evidence_types(record)
    if not evidence_types:
        return None
    route = str(record.get("route") or "manual")
    feasibility = _feasibility(record, evidence_types)
    task_kind = _task_kind(route, evidence_types)
    item_id = str(record.get("item_id") or record.get("id") or f"rust-corpus-{ordinal:04d}")
    family = str(record.get("family") or record.get("category") or "rust_manual_semantic_review")
    return FixtureTask(
        task_id=f"rust-fixture-{ordinal:04d}-{item_id.lower().replace('_', '-').replace(' ', '-')[:48]}",
        source_item_id=item_id,
        title=str(record.get("title") or item_id),
        bug_family=family,
        route=route,
        feasibility=feasibility,
        task_kind=task_kind,
        evidence_types=evidence_types,
        source_pointers=_as_list(record.get("source_pointers")),
        patch_pointers=_as_list(record.get("patch_pointers")),
        poc_pointers=sorted(set(_as_list(record.get("poc_pointers")) + _as_list(record.get("fixture_pointers")))),
        writeup_pointers=_writeup_pointers(record),
        replay_commands=_as_list(record.get("replay_commands")),
        fixture_plan=_fixture_plan(task_kind, record),
        blockers=_blockers(record, evidence_types, feasibility),
    )


def _counts(tasks: list[FixtureTask]) -> dict[str, dict[str, int]]:
    groups: dict[str, dict[str, int]] = {
        "by_family": {},
        "by_feasibility": {},
        "by_task_kind": {},
        "by_route": {},
    }
    for task in tasks:
        for key, value in (
            ("by_family", task.bug_family),
            ("by_feasibility", task.feasibility),
            ("by_task_kind", task.task_kind),
            ("by_route", task.route),
        ):
            groups[key][value] = groups[key].get(value, 0) + 1
    return {key: dict(sorted(value.items())) for key, value in groups.items()}


def build_payload(workspace: Path, index_path: Path | None = None, allow_fixture: bool = True) -> dict[str, Any]:
    selected_index = index_path or _default_index_path(workspace)
    payload = _read_json(selected_index) if selected_index else None
    records = _records_from_payload(payload)
    input_mode = "rust_corpus_index" if records else "hermetic_fixture"
    blockers: list[dict[str, Any]] = []
    if not records and allow_fixture:
        records = HERMETIC_RECORDS
        blockers.append(
            {
                "blocker_id": "rust-corpus-index-missing-or-empty",
                "status": "using_hermetic_fixture_only",
                "why_not_closed": "real Swival corpus indexing is still blocked until a local checkout produces non-empty rust_corpus_index records",
                "expected_real_swival_findings": EXPECTED_SWIVAL_TOTAL,
                "index_path_checked": str(selected_index) if selected_index else "",
                "next_commands": [
                    "git clone https://github.com/Swival/security-audits /path/to/security-audits",
                    "make rust-corpus-ingest WS=<workspace> RUST_CORPUS_ROOT=/path/to/security-audits/rust-stdlib",
                    "make rust-corpus-fixture-tasks WS=<workspace>",
                ],
            }
        )
    elif not records:
        blockers.append(
            {
                "blocker_id": "rust-corpus-index-empty",
                "status": "blocked_no_records",
                "why_not_closed": "no corpus records were available and hermetic fallback was disabled",
            }
        )
    tasks = [task for idx, record in enumerate(records, 1) if (task := task_from_record(record, idx))]
    excluded = len(records) - len(tasks)
    counts = _counts(tasks)
    summary = {
        "input_mode": input_mode,
        "index_path": str(selected_index) if selected_index else "",
        "expected_real_swival_findings": EXPECTED_SWIVAL_TOTAL,
        "source_record_count": len(records),
        "task_count": len(tasks),
        "excluded_record_count": excluded,
        "blocker_count": len(blockers) + sum(1 for task in tasks if task.blockers),
        "proof_claims": 0,
        **counts,
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "summary": summary,
        "blockers": blockers,
        "tasks": [asdict(task) for task in tasks],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Rust Corpus Fixture/Replay Tasks",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "Rows are advisory task seeds only. They do not prove a vulnerability,",
        "severity, exploitability, or project impact.",
        "",
        "## Exact Counts",
        "",
        f"- input mode: `{summary['input_mode']}`",
        f"- source records considered: `{summary['source_record_count']}`",
        f"- task rows emitted: `{summary['task_count']}`",
        f"- records excluded for missing patch/writeup/PoC evidence: `{summary['excluded_record_count']}`",
        f"- blocker-bearing rows plus global blockers: `{summary['blocker_count']}`",
        f"- proof claims made: `{summary['proof_claims']}`",
        f"- expected real Swival findings: `{summary['expected_real_swival_findings']}`",
        "",
    ]
    for label, key in (
        ("By Family", "by_family"),
        ("By Feasibility", "by_feasibility"),
        ("By Task Kind", "by_task_kind"),
    ):
        lines.extend([f"## {label}", ""])
        rows = summary[key]
        if rows:
            for name, count in rows.items():
                lines.append(f"- `{name}`: `{count}`")
        else:
            lines.append("_No rows._")
        lines.append("")
    if payload["blockers"]:
        lines.extend(["## Global Blockers", ""])
        for blocker in payload["blockers"]:
            lines.append(f"- `{blocker['blocker_id']}`: {blocker['why_not_closed']}")
        lines.append("")
    lines.extend(["## Task Rows", ""])
    if not payload["tasks"]:
        lines.append("_No task rows emitted._")
    else:
        lines.append("| Task | Family | Feasibility | Kind | Evidence | Blockers | Title |")
        lines.append("|---|---|---|---|---|---|---|")
        for task in payload["tasks"]:
            evidence = ", ".join(task["evidence_types"])
            blockers = ", ".join(task["blockers"])
            title = str(task["title"]).replace("|", "\\|")
            lines.append(
                f"| `{task['task_id']}` | `{task['bug_family']}` | `{task['feasibility']}` | "
                f"`{task['task_kind']}` | {evidence or '(none)'} | {blockers or '(none)'} | {title} |"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--rust-corpus-index", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--no-hermetic-fixture", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-corpus-fixture-tasks] workspace not found: {workspace}")
        return 2
    index_path = args.rust_corpus_index.expanduser().resolve() if args.rust_corpus_index else None
    payload = build_payload(workspace, index_path, allow_fixture=not args.no_hermetic_fixture)
    out_dir = (args.out_dir or (workspace / DEFAULT_OUT_DIR)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "rust_corpus_fixture_tasks.json"
    out_md = out_dir / "rust_corpus_fixture_tasks.md"
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "blockers": payload["blockers"]}, indent=2, sort_keys=True))
    else:
        print(f"[rust-corpus-fixture-tasks] wrote {out_json}")
        print(f"[rust-corpus-fixture-tasks] tasks={payload['summary']['task_count']} input={payload['summary']['input_mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
