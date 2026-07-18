#!/usr/bin/env python3
"""Build a corpus-to-detectorization inventory for PR #560 Lane 4.

This is a mechanical routing tool, not a vulnerability finder. It reads mined
corpus artifacts when present (Swival Rust, ZKBugs, ReCon/deep-counterexample
outputs, and source-mining survivors) and emits detector/harness-task candidate
rows with terminal states:

* ``detectorized``  -  an existing detector/scanner family should cover the row.
* ``harness_task``  -  keep as a harness/source-proof task candidate.
* ``killed``  -  not useful for the current detectorization lane.
* ``blocked_missing_source``  -  a corpus row exists but lacks enough source or
  artifact evidence to route safely.

Every row is impact-neutral: ``selected_impact=""``, ``severity="none"``,
``submission_posture="NOT_SUBMIT_READY"``, and
``impact_contract_required=true``. Downstream tools must create an exact
impact contract before PoC/harness/report work can claim severity.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "auditooor.corpus_detectorization_inventory.v1"

TERMINAL_STATES = {
    "detectorized",
    "harness_task",
    "killed",
    "blocked_missing_source",
}

SWIVAL_DETECTOR_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b(snappy|decompress|decode[-_ ]?bomb|inflate|zstd|brotli|lz4)\b", re.I),
        "rust-decode-bomb-scan",
        "decode-bomb / unbounded decompression",
    ),
    (
        re.compile(r"\b(integer|overflow|underflow|truncat|u64|u128|usize|length[-_ ]?prefix|size|index)\b", re.I),
        "base-rust-swival-shape-scan",
        "integer/length validation shape",
    ),
    (
        re.compile(r"\b(unsafe|set_len|from_raw_parts|get_unchecked|assume_init|pointer)\b", re.I),
        "base-rust-swival-shape-scan",
        "unsafe length/pointer primitive",
    ),
    (
        re.compile(r"\b(relaxed|atomic|ordering|race|lifecycle|state transition)\b", re.I),
        "base-rust-swival-shape-scan",
        "atomic/lifecycle state transition",
    ),
    (
        re.compile(r"\b(version|fork|capability|cfg|feature|unguarded decode|schema guard)\b", re.I),
        "base-rust-swival-shape-scan",
        "decode/capability guard shape",
    ),
]

KILL_RULE = re.compile(
    r"\b(path traversal|windows-only|terminal|unicode|cargo workflow|host-only|"
    r"test-only|stdlib internal only)\b",
    re.I,
)


@dataclass
class InventoryRow:
    row_id: str
    corpus: str
    source_artifact: str
    source_id: str
    title: str
    source_family: str
    terminal_state: str
    detector_or_lane: str
    harness_task: str
    blocker: str = ""
    selected_impact: str = ""
    severity: str = "none"
    submission_posture: str = "NOT_SUBMIT_READY"
    submit_status: str = "NOT_SUBMIT_READY"
    impact_contract_required: bool = True
    impact_contract_id: str = ""
    candidate_kind: str = "detector_or_harness_task_candidate"


def _slug(text: str, fallback: str = "row") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug or fallback)[:96]


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fall back to JSON Lines (one JSON object per line). Real corpus
        # artifacts such as reference/findings_go_swival.jsonl ship as .jsonl,
        # which a single json.loads() cannot parse.
        rows: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows or None


def _as_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("records", "rows", "findings", "bugs", "candidates", "survivors"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def _text(record: dict[str, Any], *keys: str) -> str:
    parts: list[str] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(v) for v in value if isinstance(v, (str, int, float)))
        elif isinstance(value, dict):
            parts.extend(str(v) for v in value.values() if isinstance(v, (str, int, float)))
    return "\n".join(parts)


def _source_id(record: dict[str, Any], index: int) -> str:
    for key in ("id", "item_id", "bug_id", "candidate_id", "finding_id", "title", "name"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"row-{index:04d}"


def _title(record: dict[str, Any], fallback: str) -> str:
    for key in ("title", "name", "bug_shape", "vulnerability", "description", "summary", "bug_class"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _has_source_pointer(record: dict[str, Any]) -> bool:
    for key in (
        "source_path",
        "source_file",
        "source_files",
        "location_path",
        "config_path",
        "rel_path",
        "file",
        "path",
        "replay_command",
        "counterexample_path",
    ):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, list) and any(isinstance(v, str) and v.strip() for v in value):
            return True
    # Nested provenance/location pointers (e.g. swival JSONL rows carry the
    # source citation under provenance.affected_location / report_path).
    for outer in ("provenance", "location", "source"):
        nested = record.get(outer)
        if isinstance(nested, dict):
            for key in ("affected_location", "report_path", "patch_path", "source_path", "path", "file"):
                value = nested.get(key)
                if isinstance(value, str) and value.strip():
                    return True
    for key in ("source_links", "location_path"):
        value = record.get(key)
        if isinstance(value, list) and any(isinstance(v, str) and v.strip() for v in value):
            return True
    return False


def _make_row(
    *,
    corpus: str,
    artifact: Path,
    source_id: str,
    title: str,
    family: str,
    terminal_state: str,
    lane: str,
    harness_task: str,
    blocker: str = "",
) -> InventoryRow:
    assert terminal_state in TERMINAL_STATES
    return InventoryRow(
        row_id=f"{corpus}-{_slug(source_id)}",
        corpus=corpus,
        source_artifact=str(artifact),
        source_id=source_id,
        title=title,
        source_family=family,
        terminal_state=terminal_state,
        detector_or_lane=lane,
        harness_task=harness_task,
        blocker=blocker,
    )


def classify_swival(record: dict[str, Any], artifact: Path, index: int) -> InventoryRow:
    sid = _source_id(record, index)
    title = _title(record, sid)
    hay = _text(
        record,
        "title",
        "name",
        "bug_shape",
        "description",
        "root_cause",
        "category",
        "family",
        "source_swival_family",
        "path",
        "source_path",
        "bug_class",
        "summary",
        "provenance",
    )
    if KILL_RULE.search(hay):
        return _make_row(
            corpus="swival_rust",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="killed_not_base_relevant",
            terminal_state="killed",
            lane="none",
            harness_task="",
            blocker="killed by non-production or non-security corpus family",
        )
    if not _has_source_pointer(record):
        return _make_row(
            corpus="swival_rust",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="missing_source_pointer",
            terminal_state="blocked_missing_source",
            lane="source-needed",
            harness_task="",
            blocker="missing source path / citation for detector fixture extraction",
        )
    for pattern, detector, family in SWIVAL_DETECTOR_RULES:
        if pattern.search(hay):
            return _make_row(
                corpus="swival_rust",
                artifact=artifact,
                source_id=sid,
                title=title,
                family=family,
                terminal_state="detectorized",
                lane=detector,
                harness_task=(
                    "Run scanner, then create a bounded harness task only "
                    "after an exact impact_contract exists."
                ),
            )
    return _make_row(
        corpus="swival_rust",
        artifact=artifact,
        source_id=sid,
        title=title,
        family="manual_rust_harness_candidate",
        terminal_state="harness_task",
        lane="rust-harness-task",
        harness_task=(
            "Create a source-cited harness task or kill with evidence; do not "
            "select severity without impact_contract proof."
        ),
    )


def classify_zkbugs(record: dict[str, Any], artifact: Path, index: int) -> InventoryRow:
    sid = _source_id(record, index)
    title = _title(record, sid)
    hay = _text(record, "title", "dsl", "vulnerability", "root_cause", "short_vulnerability")
    if not _has_source_pointer(record):
        return _make_row(
            corpus="zkbugs",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="missing_zk_source_pointer",
            terminal_state="blocked_missing_source",
            lane="source-needed",
            harness_task="",
            blocker="missing zkBugs source/config/report pointer",
        )
    detector = _zkbugs_detector_for(hay)
    if detector:
        return _make_row(
            corpus="zkbugs",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="zkbugs_existing_detector_family",
            terminal_state="detectorized",
            lane=detector,
            harness_task="Run the detector fixture pair; impact contract still required for filing.",
        )
    return _make_row(
        corpus="zkbugs",
        artifact=artifact,
        source_id=sid,
        title=title,
        family="zkbugs_harness_or_detector_backlog",
        terminal_state="harness_task",
        lane="zkbugs-detector-backlog",
        harness_task="Extract a minimal positive/negative fixture or mark killed with source evidence.",
    )


def classify_rust_corpus(record: dict[str, Any], artifact: Path, index: int) -> InventoryRow:
    sid = _source_id(record, index)
    title = _title(record, sid)
    route = str(record.get("route") or "")
    family = str(record.get("family") or "rust_corpus")
    blockers = [str(v) for v in (record.get("blockers") or []) if isinstance(v, str)]
    if route == "detector" and bool(record.get("fixture_backed")):
        return _make_row(
            corpus="rust_corpus",
            artifact=artifact,
            source_id=sid,
            title=title,
            family=family,
            terminal_state="detectorized",
            lane="rust-detector-fixture-task",
            harness_task="Materialize detector/fixture smoke, then require exact impact contract before promotion.",
        )
    if route == "replay":
        return _make_row(
            corpus="rust_corpus",
            artifact=artifact,
            source_id=sid,
            title=title,
            family=family,
            terminal_state="harness_task" if not blockers else "blocked_missing_source",
            lane="rust-runtime-replay-task",
            harness_task="Convert corpus reproducer into project-bound replay and record poc-execution manifest.",
            blocker=", ".join(blockers),
        )
    if route == "invariant":
        return _make_row(
            corpus="rust_corpus",
            artifact=artifact,
            source_id=sid,
            title=title,
            family=family,
            terminal_state="harness_task" if not blockers else "blocked_missing_source",
            lane="rust-invariant-adoption-task",
            harness_task="Adopt as invariant-ledger row or kill with source evidence.",
            blocker=", ".join(blockers),
        )
    return _make_row(
        corpus="rust_corpus",
        artifact=artifact,
        source_id=sid,
        title=title,
        family=family,
        terminal_state="blocked_missing_source",
        lane="rust-corpus-ingest",
        harness_task="",
        blocker=", ".join(blockers) or "rust corpus row missing route/fixture/proof evidence",
    )


def _zkbugs_detector_for(text: str) -> str:
    low = text.lower()
    checks = (
        ("bellperson", "detectors/rust_wave1/zkbugs_bellperson_unconstrained_zero_default.py"),
        ("fixed point", "detectors/rust_wave1/zkbugs_unsound_fixed_point_addition.py"),
        ("num2bits", "detectors/circom_wave1/zkbugs_num2bits_254_state_alias.py"),
        ("nullifier", "detectors/circom_wave1/zkbugs_zswap_nullifier_verification_disabled.py"),
        ("babyjubjub", "detectors/circom_wave1/zkbugs_babyjubjub_suborder_tag.py"),
        ("blake3", "detectors/circom_wave1/zkbugs_blake3novatreepath_checkdepth_comparator_range.py"),
        ("erc20", "detectors/circom_wave1/zkbugs_erc20_sum_input_keyed_outflow.py"),
        ("comparison", "detectors/circom_wave1/zkbugs_unirep_comparison_range_checks.py"),
    )
    for needle, rel in checks:
        if needle in low and (ROOT / rel).is_file():
            return rel
    return ""


def classify_recon(record: dict[str, Any], artifact: Path, index: int) -> InventoryRow:
    sid = _source_id(record, index)
    title = _title(record, sid)
    status = _text(record, "status", "result", "kind").lower()
    if not _has_source_pointer(record):
        return _make_row(
            corpus="recon",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="missing_replay_source",
            terminal_state="blocked_missing_source",
            lane="source-needed",
            harness_task="",
            blocker="missing replay command/counterexample/source path",
        )
    terminal = "harness_task" if "counterexample" in status or "fail" in status else "blocked_missing_source"
    return _make_row(
        corpus="recon",
        artifact=artifact,
        source_id=sid,
        title=title,
        family="recon_counterexample_or_run",
        terminal_state=terminal,
        lane="recon-harness-task" if terminal == "harness_task" else "source-needed",
        harness_task=(
            "Convert ReCon/Chimera evidence to deterministic replay or mark "
            "blocked; impact contract required before severity."
        ),
        blocker="" if terminal == "harness_task" else "no counterexample/fail status to route",
    )


def classify_source_mining(record: dict[str, Any], artifact: Path, index: int) -> InventoryRow:
    sid = _source_id(record, index)
    title = _title(record, sid)
    if not _has_source_pointer(record):
        return _make_row(
            corpus="source_mining",
            artifact=artifact,
            source_id=sid,
            title=title,
            family="missing_line_citation",
            terminal_state="blocked_missing_source",
            lane="source-needed",
            harness_task="",
            blocker="source-mining survivor missing line-cited source pointer",
        )
    return _make_row(
        corpus="source_mining",
        artifact=artifact,
        source_id=sid,
        title=title,
        family="source_mining_survivor",
        terminal_state="harness_task",
        lane="source-mining-harness-task",
        harness_task=(
            "Create exact impact_contract and local source verification before "
            "PoC/harness/report work."
        ),
    )


def rows_from_json(path: Path, corpus: str) -> list[InventoryRow]:
    records = _as_records(_read_json(path))
    rows: list[InventoryRow] = []
    for idx, record in enumerate(records, 1):
        if corpus == "swival_rust":
            rows.append(classify_swival(record, path, idx))
        elif corpus == "rust_corpus":
            rows.append(classify_rust_corpus(record, path, idx))
        elif corpus == "zkbugs":
            rows.append(classify_zkbugs(record, path, idx))
        elif corpus == "recon":
            rows.append(classify_recon(record, path, idx))
        elif corpus == "source_mining":
            rows.append(classify_source_mining(record, path, idx))
    return rows


def _existing(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        p = path.expanduser().resolve()
        # Skip nested worktree / vendored mirrors that would double-count corpus rows.
        if any(part in {".claude", ".git", "node_modules", "__pycache__"} for part in p.parts):
            continue
        if p.is_file() and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def discover_inputs(workspace: Path | None) -> dict[str, list[Path]]:
    roots = [ROOT]
    if workspace is not None:
        roots.insert(0, workspace)
    swival: list[Path] = []
    rust_corpus: list[Path] = []
    zkbugs: list[Path] = []
    recon: list[Path] = []
    source_mining: list[Path] = []
    for root in roots:
        # swival: normalized JSON if present, plus the real shipped JSONL corpora
        # (reference/findings_go_swival.jsonl, rust swival stdlib findings).
        swival.extend(root.glob("**/swival_findings_normalized.json"))
        swival.extend(root.glob("**/rust_swival_stdlib_findings.json"))
        swival.extend(root.glob("reference/findings_*swival*.jsonl"))
        swival.extend(root.glob("**/findings_*swival*.jsonl"))
        # rust corpus mining index (legacy + current locations)
        rust_corpus.extend(root.glob(".audit_logs/rust_corpus_mining/rust_corpus_index.json"))
        rust_corpus.extend(root.glob(".auditooor/rust_corpus_mining_coverage.json"))
        rust_corpus.extend(root.glob("**/rust_corpus_index.json"))
        # zkBugs: the unified index is the real artifact under audit/zkbugs/.
        zkbugs.extend(root.glob(".audit_logs/zkbugs_farming/zkbugs_index.json"))
        zkbugs.extend(root.glob("audit/zkbugs/zkbugs_index_unified.json"))
        zkbugs.extend(root.glob("**/zkbugs_index*.json"))
        # recon / deep counterexamples
        recon.extend(root.glob(".audit_logs/**/recon*.json"))
        recon.extend(root.glob("deep_counterexamples/*.deep_counterexample.v1.json"))
        recon.extend(root.glob("**/*.deep_counterexample.v1.json"))
        source_mining.extend(root.glob("source_mining/**/survivors.json"))
        source_mining.extend(root.glob("**/source_mining/**/survivors.json"))
    return {
        "swival_rust": _existing(swival),
        "rust_corpus": _existing(rust_corpus),
        "zkbugs": _existing(zkbugs),
        "recon": _existing(recon),
        "source_mining": _existing(source_mining),
    }


def summarize(rows: list[InventoryRow], inputs: dict[str, list[Path]]) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    by_corpus: dict[str, int] = {name: 0 for name in inputs}
    for row in rows:
        by_state[row.terminal_state] = by_state.get(row.terminal_state, 0) + 1
        by_corpus[row.corpus] = by_corpus.get(row.corpus, 0) + 1
    return {
        "row_count": len(rows),
        "by_terminal_state": by_state,
        "by_corpus": by_corpus,
        "input_counts": {k: len(v) for k, v in inputs.items()},
    }


def build_inventory(
    *,
    workspace: Path | None,
    swival_json: list[Path],
    rust_corpus_index: list[Path],
    zkbugs_index: list[Path],
    recon_json: list[Path],
    source_mining_json: list[Path],
) -> dict[str, Any]:
    explicit_mode = any([swival_json, rust_corpus_index, zkbugs_index, recon_json, source_mining_json])
    discovered = {name: [] for name in ("swival_rust", "rust_corpus", "zkbugs", "recon", "source_mining")}
    if not explicit_mode:
        discovered = discover_inputs(workspace)
    inputs = {
        "swival_rust": _existing(swival_json) or discovered["swival_rust"],
        "rust_corpus": _existing(rust_corpus_index) or discovered["rust_corpus"],
        "zkbugs": _existing(zkbugs_index) or discovered["zkbugs"],
        "recon": _existing(recon_json) or discovered["recon"],
        "source_mining": _existing(source_mining_json) or discovered["source_mining"],
    }
    rows: list[InventoryRow] = []
    for corpus, paths in inputs.items():
        for path in paths:
            rows.extend(rows_from_json(path, corpus))
    rows.sort(key=lambda r: (r.corpus, r.terminal_state, r.row_id))
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace) if workspace else "",
        "summary": summarize(rows, inputs),
        "inputs": {k: [str(p) for p in v] for k, v in inputs.items()},
        "rows": [asdict(row) for row in rows],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Corpus Detectorization Inventory",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "All rows are impact-neutral detector/harness-task candidates. No row is "
        "submit-ready or severity-selected until an exact impact contract proves "
        "the selected program impact sentence.",
        "",
        "## Summary",
        "",
    ]
    summary = payload["summary"]
    lines.append(f"- rows: `{summary['row_count']}`")
    for corpus, count in sorted(summary["by_corpus"].items()):
        lines.append(f"- `{corpus}` rows: `{count}`")
    lines.append("")
    lines.append("## Rows")
    lines.append("")
    if not payload["rows"]:
        lines.append("_No corpus rows discovered._")
    else:
        lines.append("| Corpus | Source ID | State | Lane | Severity | Selected Impact | Title |")
        lines.append("|---|---|---|---|---|---|---|")
        for row in payload["rows"]:
            title = str(row.get("title", "")).replace("|", "\\|")
            lines.append(
                "| `{corpus}` | `{sid}` | `{state}` | `{lane}` | `{sev}` | `{impact}` | {title} |".format(
                    corpus=row["corpus"],
                    sid=row["source_id"],
                    state=row["terminal_state"],
                    lane=row["detector_or_lane"],
                    sev=row["severity"],
                    impact=row["selected_impact"] or "(none)",
                    title=title,
                )
            )
    lines.append("")
    return "\n".join(lines)


def default_out_dir(workspace: Path | None) -> Path:
    return (workspace / ".auditooor") if workspace else (ROOT / ".auditooor")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument("--swival-json", type=Path, action="append", default=[])
    parser.add_argument("--rust-corpus-index", type=Path, action="append", default=[])
    parser.add_argument("--zkbugs-index", type=Path, action="append", default=[])
    parser.add_argument("--recon-json", type=Path, action="append", default=[])
    parser.add_argument("--source-mining-json", type=Path, action="append", default=[])
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve() if args.workspace else None
    if workspace is not None and not workspace.is_dir():
        print(f"[corpus-detectorization-inventory] workspace not found: {workspace}", file=sys.stderr)
        return 2
    payload = build_inventory(
        workspace=workspace,
        swival_json=args.swival_json,
        rust_corpus_index=args.rust_corpus_index,
        zkbugs_index=args.zkbugs_index,
        recon_json=args.recon_json,
        source_mining_json=args.source_mining_json,
    )
    out_dir = (args.out_dir or default_out_dir(workspace)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "corpus_detectorization_inventory.json"
    md_path = out_dir / "corpus_detectorization_inventory.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[corpus-detectorization-inventory] wrote {json_path}")
        print(f"[corpus-detectorization-inventory] wrote {md_path}")
        print(f"[corpus-detectorization-inventory] rows={payload['summary']['row_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
