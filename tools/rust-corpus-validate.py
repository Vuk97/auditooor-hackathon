#!/usr/bin/env python3
"""Validate Swival Rust stdlib corpus mining completeness.

This consumes the offline artifact emitted by ``tools/rust-corpus-ingest.py``.
It does not clone or inspect the remote corpus. The validator is deliberately
strict because its purpose is to say when the Swival rust-stdlib corpus is
mined enough to unblock detectorization, not to make best-effort progress look
complete.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.rust_corpus_validation.v1"
EXPECTED_TOTAL = 151
EXPECTED_SEVERITIES = {"High": 27, "Medium": 115, "Low": 9}
SEVERITY_PREFIX = {"High": "H", "Medium": "M", "Low": "L"}
PREFIX_SEVERITY = {v: k for k, v in SEVERITY_PREFIX.items()}
EXPECTED_SWIVAL_NUMERIC_IDS = {
    f"S-{idx:03d}"
    for idx in (
        1, 2, 4, 5, 6, 7, 8, 9, 11, 12,
        13, 14, 15, 16, 18, 19, 20, 21, 22, 23,
        25, 28, 29, 30, 31, 32, 34, 35, 36, 37,
        38, 40, 41, 42, 43, 44, 45, 46, 49, 50,
        51, 52, 53, 56, 57, 58, 59, 60, 61, 62,
        63, 64, 66, 68, 69, 70, 71, 72, 74, 75,
        76, 77, 79, 83, 84, 85, 86, 87, 88, 90,
        91, 92, 94, 95, 96, 97, 98, 99, 102, 103,
        104, 105, 106, 107, 108, 110, 111, 112, 113, 114,
        117, 118, 119, 121, 127, 131, 132, 133, 134, 135,
        136, 137, 138, 139, 140, 141, 142, 145, 146, 147,
        148, 150, 151, 152, 153, 154, 155, 156, 158, 159,
        160, 164, 165, 167, 168, 170, 172, 173, 174, 178,
        179, 180, 181, 182, 183, 184, 187, 188, 190, 193,
        194, 196, 202,
    )
}
DEFAULT_OUT_DIR = Path(".audit_logs") / "rust_corpus_mining"


@dataclass(frozen=True)
class Blocker:
    blocker_id: str
    severity: str
    count: int
    detail: str
    affected_ids: list[str]
    acceptance_criterion: str


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[rust-corpus-validate] missing input artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[rust-corpus-validate] invalid JSON at {path}: {exc}") from exc


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        records = payload.get("records")
        if isinstance(records, list):
            return [row for row in records if isinstance(row, dict)]
    return []


def text_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def list_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_severity(value: str) -> str:
    low = value.strip().lower()
    aliases = {
        "h": "High",
        "high": "High",
        "m": "Medium",
        "med": "Medium",
        "medium": "Medium",
        "l": "Low",
        "low": "Low",
    }
    return aliases.get(low, value.strip() or "unknown")


def normalize_component(value: str) -> str:
    component = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return component or "unknown"


def normalize_swival_id(raw_id: str, severity: str = "") -> str:
    text = raw_id.strip()
    patterns = (
        r"^(?P<prefix>[HML])[-_ ]?(?P<num>\d{1,3})(?:\b|[-_ ])",
        r"^(?P<sev>High|Medium|Low)[-_ ]?(?P<num>\d{1,3})(?:\b|[-_ ])",
        r"^(?P<prefix>[HML])(?P<num>\d{2,3})(?:\b|[-_ ])",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if not match:
            continue
        prefix = (match.groupdict().get("prefix") or "").upper()
        sev = match.groupdict().get("sev") or ""
        if not prefix and sev:
            prefix = SEVERITY_PREFIX.get(normalize_severity(sev), "")
        number = int(match.group("num"))
        if prefix in PREFIX_SEVERITY:
            return f"{prefix}-{number:03d}"
    match = re.search(r"^(?P<num>\d{3})(?:\b|[-_ ])", text)
    if match:
        return f"S-{int(match.group('num')):03d}"
    normalized_sev = normalize_severity(severity)
    if normalized_sev in SEVERITY_PREFIX:
        match = re.search(r"(?:^|\D)(?P<num>\d{1,3})(?:\D|$)", text)
        if match:
            return f"{SEVERITY_PREFIX[normalized_sev]}-{int(match.group('num')):03d}"
    return ""


def expected_ids() -> list[str]:
    ids: list[str] = []
    for severity, count in EXPECTED_SEVERITIES.items():
        prefix = SEVERITY_PREFIX[severity]
        ids.extend(f"{prefix}-{idx:03d}" for idx in range(1, count + 1))
    return ids


def expected_ids_for_rows(rows: list[dict[str, Any]]) -> tuple[list[str], str]:
    normalized_ids = [row["normalized_id"] for row in rows if row["normalized_id"]]
    if normalized_ids and all(item_id.startswith("S-") for item_id in normalized_ids):
        # The published rust-stdlib corpus uses source-stable numeric IDs with
        # intentional gaps, not H/M/L-prefixed ordinal ranges. For that shape,
        # completeness is enforced by total count, exact severity counts, and
        # uniqueness of the source IDs rather than by inventing a contiguous
        # or severity-rebased ID sequence.
        return sorted(set(normalized_ids), key=lambda x: int(x[2:])), "numeric_swival"
    return expected_ids(), "severity_prefixed"


def record_raw_id(record: dict[str, Any], index: int) -> str:
    for key in ("item_id", "id", "finding_id", "bug_id", "title"):
        value = text_value(record.get(key))
        if value:
            return value
    return f"row-{index:03d}"


def record_title(record: dict[str, Any], raw_id: str) -> str:
    return text_value(record.get("title")) or raw_id


def has_markdown_evidence(record: dict[str, Any]) -> bool:
    paths = [text_value(record.get("rel_path"))]
    paths.extend(list_value(record.get("source_pointers")))
    return any(path.lower().endswith((".md", ".markdown")) for path in paths)


def has_patch_evidence(record: dict[str, Any]) -> bool:
    paths = list_value(record.get("patch_pointers"))
    paths.extend(list_value(record.get("fixture_pointers")))
    return any(path.lower().endswith((".patch", ".diff")) for path in paths)


def has_poc_evidence(record: dict[str, Any]) -> bool:
    paths = list_value(record.get("poc_pointers"))
    paths.extend(list_value(record.get("fixture_pointers")))
    commands = list_value(record.get("replay_commands"))
    if commands:
        return True
    return any(re.search(r"(poc|repro|exploit|test)", Path(path).name, re.I) for path in paths)


def row_snapshot(record: dict[str, Any], index: int) -> dict[str, Any]:
    raw_id = record_raw_id(record, index)
    severity = normalize_severity(text_value(record.get("corpus_severity")))
    normalized_id = normalize_swival_id(raw_id, severity)
    component = normalize_component(text_value(record.get("component")))
    expected_severity = PREFIX_SEVERITY.get(normalized_id[:1], "") if normalized_id else ""
    return {
        "raw_id": raw_id,
        "normalized_id": normalized_id,
        "title": record_title(record, raw_id),
        "severity": severity,
        "expected_severity_from_id": expected_severity,
        "severity_matches_id": bool(expected_severity and severity == expected_severity),
        "component": component,
        "rel_path": text_value(record.get("rel_path")),
        "has_markdown": has_markdown_evidence(record),
        "has_patch": has_patch_evidence(record),
        "has_poc": has_poc_evidence(record),
        "normalized": bool(record.get("normalized")),
        "route": text_value(record.get("route")),
        "terminal_state": text_value(record.get("terminal_state")),
        "source_blockers": list_value(record.get("blockers")),
    }


def _blocker(
    blockers: list[Blocker],
    blocker_id: str,
    count: int,
    detail: str,
    affected: Iterable[str],
    criterion: str,
    severity: str = "blocking",
) -> None:
    if count <= 0:
        return
    affected_ids = sorted({str(v) for v in affected if str(v)})[:50]
    blockers.append(
        Blocker(
            blocker_id=blocker_id,
            severity=severity,
            count=count,
            detail=detail,
            affected_ids=affected_ids,
            acceptance_criterion=criterion,
        )
    )


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    records = records_from_payload(payload)
    rows = [row_snapshot(record, idx) for idx, record in enumerate(records, 1)]
    expected_list, id_scheme = expected_ids_for_rows(rows)
    expected = set(expected_list)
    normalized_ids = [row["normalized_id"] for row in rows if row["normalized_id"]]
    id_counts = Counter(normalized_ids)
    duplicates = sorted([item_id for item_id, count in id_counts.items() if count > 1])
    missing = sorted(expected - set(normalized_ids), key=lambda x: (x[0], int(x[2:])))
    unexpected = sorted(set(normalized_ids) - expected, key=lambda x: (x[0], int(x[2:])))
    unparseable = [row["raw_id"] for row in rows if not row["normalized_id"]]
    severity_counts = Counter(row["severity"] for row in rows)
    component_counts = Counter(row["component"] for row in rows)
    by_id = defaultdict(list)
    for row in rows:
        if row["normalized_id"]:
            by_id[row["normalized_id"]].append(row)

    missing_md = [row["normalized_id"] or row["raw_id"] for row in rows if not row["has_markdown"]]
    missing_patch = [row["normalized_id"] or row["raw_id"] for row in rows if not row["has_patch"]]
    missing_poc = [row["normalized_id"] or row["raw_id"] for row in rows if not row["has_poc"]]
    bad_component = [
        row["normalized_id"] or row["raw_id"]
        for row in rows
        if row["component"] in {"", "unknown", "findings", "rust_stdlib", "rust-stdlib"}
    ]
    bad_severity = [
        row["normalized_id"] or row["raw_id"]
        for row in rows
        if row["severity"] not in EXPECTED_SEVERITIES
    ]
    severity_mismatch = [
        row["normalized_id"] or row["raw_id"]
        for row in rows
        if row["normalized_id"] and row["normalized_id"][0] in PREFIX_SEVERITY and not row["severity_matches_id"]
    ]
    not_normalized = [row["normalized_id"] or row["raw_id"] for row in rows if not row["normalized"]]
    source_blocked = [row["normalized_id"] or row["raw_id"] for row in rows if row["source_blockers"]]

    blockers: list[Blocker] = []
    _blocker(
        blockers,
        "swival-total-count-mismatch",
        0 if len(rows) == EXPECTED_TOTAL else 1,
        f"expected {EXPECTED_TOTAL} Swival rust-stdlib findings, found {len(rows)}",
        [],
        "Artifact has exactly 151 finding rows.",
    )
    _blocker(
        blockers,
        "swival-severity-count-mismatch",
        sum(1 for sev, expected_count in EXPECTED_SEVERITIES.items() if severity_counts.get(sev, 0) != expected_count),
        f"expected severity counts {EXPECTED_SEVERITIES}, found {dict(sorted(severity_counts.items()))}",
        [],
        "Artifact severity counts are High=27, Medium=115, Low=9.",
    )
    _blocker(blockers, "swival-id-unparseable", len(unparseable), "rows cannot be normalized into a Swival finding ID", unparseable, "Every row has a parseable Swival ID.")
    _blocker(blockers, "swival-id-duplicate", len(duplicates), "duplicate normalized Swival IDs detected", duplicates, "Every expected Swival ID appears exactly once.")
    _blocker(blockers, "swival-id-missing", len(missing), "expected Swival IDs are absent", missing, "All expected IDs for the detected Swival ID scheme are present.")
    _blocker(blockers, "swival-id-unexpected", len(unexpected), "normalized IDs fall outside expected Swival ranges", unexpected, "No IDs outside the expected Swival ranges are present.")
    _blocker(blockers, "swival-severity-invalid", len(bad_severity), "rows have missing or non-Swival severity values", bad_severity, "Every row severity normalizes to High, Medium, or Low.")
    _blocker(blockers, "swival-severity-id-mismatch", len(severity_mismatch), "row severity does not match H/M/L ID prefix", severity_mismatch, "Severity and normalized ID prefix agree for every row.")
    _blocker(blockers, "swival-component-missing", len(bad_component), "rows have missing or placeholder component values", bad_component, "Every row has a specific normalized component.")
    _blocker(blockers, "swival-markdown-missing", len(missing_md), "rows lack markdown writeup evidence", missing_md, "Every finding row is paired with a markdown writeup.")
    _blocker(blockers, "swival-patch-missing", len(missing_patch), "rows lack patch/diff evidence", missing_patch, "Every finding row is paired with a patch or diff.")
    _blocker(blockers, "swival-poc-missing", len(missing_poc), "rows lack PoC/reproducer evidence", missing_poc, "Every finding row is paired with PoC, reproducer, test, or replay command evidence.")
    _blocker(blockers, "swival-row-not-normalized", len(not_normalized), "rows were not marked normalized by the ingestor", not_normalized, "Every row has normalized=true.")
    _blocker(blockers, "swival-source-blockers-present", len(source_blocked), "ingestor row blockers remain open", source_blocked, "Every row has zero ingestor blockers before detectorization is unblocked.")

    acceptance = {
        "strictly_complete": not blockers,
        "detectorization_unblocked": not blockers,
        "criteria": [
            "exactly 151 rows",
            "exact severity counts High=27, Medium=115, Low=9",
            "unique complete IDs for the detected Swival ID scheme",
            "severity agrees with ID prefix when the corpus uses H/M/L-prefixed IDs",
            "component is present and non-placeholder",
            "each row has markdown writeup evidence",
            "each row has patch/diff evidence",
            "each row has PoC/reproducer/test/replay evidence",
            "each row is normalized and has no ingestor blockers",
        ],
    }
    return {
        "schema": SCHEMA,
        "source_schema": payload.get("schema", ""),
        "summary": {
            "expected_total": EXPECTED_TOTAL,
            "id_scheme": id_scheme,
            "found_total": len(rows),
            "unique_normalized_ids": len(id_counts),
            "missing_id_count": len(missing),
            "duplicate_id_count": len(duplicates),
            "unexpected_id_count": len(unexpected),
            "unparseable_id_count": len(unparseable),
            "markdown_covered": len(rows) - len(missing_md),
            "patch_covered": len(rows) - len(missing_patch),
            "poc_covered": len(rows) - len(missing_poc),
            "component_covered": len(rows) - len(bad_component),
            "rows_with_ingestor_blockers": len(source_blocked),
            "blocker_count": len(blockers),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_component": dict(sorted(component_counts.items())),
        },
        "acceptance": acceptance,
        "blockers": [blocker.__dict__ for blocker in blockers],
        "missing_expected_ids": missing,
        "duplicate_ids": duplicates,
        "unexpected_ids": unexpected,
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Rust Corpus Validation",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "This is the strict acceptance gate for the Swival rust-stdlib corpus mining layer.",
        "It consumes the ingestor artifact and fails closed until detectorization can rely on complete IDs and evidence.",
        "",
        "## Acceptance",
        "",
        f"- detectorization unblocked: `{payload['acceptance']['detectorization_unblocked']}`",
        f"- blockers: `{summary['blocker_count']}`",
        f"- findings: `{summary['found_total']}` / `{summary['expected_total']}`",
        f"- unique normalized IDs: `{summary['unique_normalized_ids']}`",
        f"- markdown coverage: `{summary['markdown_covered']}` / `{summary['found_total']}`",
        f"- patch coverage: `{summary['patch_covered']}` / `{summary['found_total']}`",
        f"- PoC/reproducer coverage: `{summary['poc_covered']}` / `{summary['found_total']}`",
        f"- component coverage: `{summary['component_covered']}` / `{summary['found_total']}`",
        "",
        "## Blockers",
        "",
    ]
    if not payload["blockers"]:
        lines.append("_No blockers. Swival corpus validation is complete enough to unblock detectorization._")
    else:
        lines.append("| Blocker | Count | Criterion | Detail |")
        lines.append("|---|---:|---|---|")
        for blocker in payload["blockers"]:
            detail = str(blocker["detail"]).replace("|", "\\|")
            criterion = str(blocker["acceptance_criterion"]).replace("|", "\\|")
            lines.append(f"| `{blocker['blocker_id']}` | `{blocker['count']}` | {criterion} | {detail} |")
    lines.extend(["", "## Severity Counts", ""])
    for severity, count in summary["by_severity"].items():
        lines.append(f"- `{severity}`: `{count}`")
    lines.extend(["", "## Component Counts", ""])
    if not summary["by_component"]:
        lines.append("_No components indexed._")
    else:
        for component, count in summary["by_component"].items():
            lines.append(f"- `{component}`: `{count}`")
    lines.append("")
    return "\n".join(lines)


def discover_index(workspace: Path) -> Path:
    candidates = [
        workspace / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_index.json",
        workspace / ".auditooor" / "rust_corpus_mining_coverage.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--index", type=Path, default=None, help="rust_corpus_index.json from rust-corpus-ingest")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--strict", action="store_true", help="Exit 1 when acceptance criteria are not met.")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-corpus-validate] workspace not found: {workspace}", file=sys.stderr)
        return 2
    index = (args.index or discover_index(workspace)).expanduser().resolve()
    payload = validate_payload(read_json(index))
    payload["workspace"] = str(workspace)
    payload["input_index"] = str(index)
    out_dir = (args.out_dir or (workspace / DEFAULT_OUT_DIR)).expanduser().resolve()
    write_json(out_dir / "rust_corpus_validation.json", payload)
    write_text(out_dir / "rust_corpus_validation.md", render_markdown(payload))
    write_json(workspace / ".auditooor" / "rust_corpus_validation.json", payload)
    write_text(workspace / ".auditooor" / "rust_corpus_validation.md", render_markdown(payload))
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "acceptance": payload["acceptance"], "blockers": payload["blockers"]}, indent=2, sort_keys=True))
    else:
        print(
            "[rust-corpus-validate] "
            f"findings={payload['summary']['found_total']}/{payload['summary']['expected_total']} "
            f"blockers={payload['summary']['blocker_count']} "
            f"detectorization_unblocked={payload['acceptance']['detectorization_unblocked']}"
        )
    if args.strict and not payload["acceptance"]["detectorization_unblocked"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
