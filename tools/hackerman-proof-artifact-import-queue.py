#!/usr/bin/env python3
"""Validate proof-artifact missing-record import queues into review packets.

This tool is deliberately non-mutating. It reads
``auditooor.hackerman_missing_record_import_queue.v1`` rows and emits reviewer
packets that say whether each queued submission is ready for manual Hackerman
record creation. It never creates records and never writes proof_artifact_path.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Iterable


QUEUE_SCHEMA = "auditooor.hackerman_missing_record_import_queue.v1"
RECONCILIATION_SCHEMA = "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1"
PACKET_SCHEMA = "auditooor.hackerman_missing_record_review_packet.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_missing_record_review_packet_summary.v1"
DEFAULT_QUEUE = Path("reports") / "proof_artifact_missing_record_import_queue_slice10.jsonl"
DEFAULT_OUT = Path("reports") / "proof_artifact_missing_record_review_packets.jsonl"
SAFE_RELATIVE_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)

KIND_EXTENSIONS = {
    "execution-output": {".log", ".txt", ".json", ".jsonl", ".out"},
    "poc-tests": {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".sh", ".bash", ".zsh"},
    "proof-note": {".md", ".txt"},
    "test-file": {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py"},
}


def _clean_path(raw: str) -> str:
    value = str(raw or "").strip().strip("'\"").replace("\\", "/")
    if not value or not SAFE_RELATIVE_PATH_RE.match(value):
        return ""
    if any(part in {"", ".", ".."} for part in Path(value).parts):
        return ""
    return value


def _resolve_artifact_path(path_text: str, *, audits_root: Path, repo_root: Path) -> Path:
    parts = Path(path_text).parts
    if len(parts) >= 2 and parts[0] == "audits":
        return audits_root / Path(*parts[1:])
    return repo_root / path_text


def _artifact_priority(candidate: dict[str, Any]) -> tuple[int, str]:
    """Prefer concrete PoC/test artifacts over broad logs and source files."""
    path = _clean_path(str(candidate.get("candidate_proof_path") or ""))
    kind = str(candidate.get("candidate_artifact_kind") or "")
    lowered = path.lower()
    is_testish = (
        "/test/" in lowered
        or "/tests/" in lowered
        or "/poc" in lowered
        or lowered.endswith(("_test.go", ".t.sol", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
    )
    if kind in {"poc-tests", "test-file"} and is_testish:
        return (0, path)
    if kind == "execution-output":
        return (1, path)
    if kind == "proof-note":
        return (2, path)
    if kind in {"poc-tests", "test-file"}:
        return (3, path)
    return (4, path)


def _extract_submission_title(submission_path: str, *, audits_root: Path, repo_root: Path) -> str:
    clean = _clean_path(submission_path)
    if not clean:
        return ""
    resolved = _resolve_artifact_path(clean, audits_root=audits_root, repo_root=repo_root)
    if not resolved.is_file():
        return ""
    try:
        text = resolved.read_text(encoding="utf-8", errors="ignore")[:24000]
    except OSError:
        return ""

    patterns = [
        r"(?im)^\s*-\s*\*\*Title field:\*\*\s*`?([^`\n]+)`?\s*$",
        r"(?im)^\s*Title field:\s*`?([^`\n]+)`?\s*$",
        r"(?ims)^#{2,4}\s*Finding Title[^\n]*\n\s*```[^\n]*\n\s*([^`\n]+?)\s*\n\s*```",
        r"(?im)^#{1,4}\s+(.{12,160})$",
    ]
    generic = re.compile(r"(?i)\b(verified poc|ready submission|immunefi ready|submission \d+|finding title|report body|target|severity)\b")
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            title = re.sub(r"\s+", " ", match.group(1)).strip(" `#*-:\t\r\n")
            if title and not generic.search(title):
                return title[:240]
    return ""


def _engagement_from_audit_path(path_text: str) -> str:
    parts = Path(path_text).parts
    if len(parts) >= 2 and parts[0] == "audits":
        return parts[1]
    return ""


def _slugify_record_hint(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return slug[:96] or "missing-hackerman-record"


def _artifact_kind_blocker(kind: str, path_text: str) -> str:
    if not kind:
        return "artifact_kind_missing"
    allowed = KIND_EXTENSIONS.get(kind)
    if allowed is None:
        return "artifact_kind_unknown"
    if Path(path_text).suffix.lower() not in allowed:
        return "artifact_kind_mismatch"
    return ""


def _newer_submission_sibling(submission_path: str, *, audits_root: Path, repo_root: Path) -> str:
    clean = _clean_path(submission_path)
    if not clean:
        return ""
    resolved = _resolve_artifact_path(clean, audits_root=audits_root, repo_root=repo_root)
    if not resolved.is_file():
        return ""
    stem = resolved.stem
    parent = resolved.parent
    try:
        current_mtime = resolved.stat().st_mtime
    except OSError:
        return ""
    for sibling in sorted(parent.glob(f"{stem}*{resolved.suffix}")):
        if sibling == resolved:
            continue
        sibling_stem = sibling.stem
        if not re.match(rf"^{re.escape(stem)}(?:[-_]?v\d+|[-_]?final|[-_]?amended)", sibling_stem, re.I):
            continue
        try:
            if sibling.stat().st_mtime > current_mtime:
                return sibling.as_posix()
        except OSError:
            continue
    return ""


def _load_queue_rows(queue_path: Path) -> tuple[list[dict[str, Any]], Counter[str]]:
    rows: list[dict[str, Any]] = []
    errors: Counter[str] = Counter()
    if not queue_path.is_file():
        errors["queue_missing"] += 1
        return rows, errors
    for line in queue_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors["invalid_json"] += 1
            continue
        if not isinstance(row, dict):
            errors["row_not_object"] += 1
            continue
        rows.append(row)
    return rows, errors


def _candidate_path_counts(rows: Iterable[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        candidates = row.get("proof_artifact_candidates")
        if not isinstance(candidates, list):
            continue
        seen_in_row: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            clean = _clean_path(str(candidate.get("candidate_proof_path") or ""))
            if clean:
                seen_in_row.add(clean)
        counts.update(seen_in_row)
    return counts


def _validate_candidate(
    candidate: dict[str, Any],
    *,
    engagement: str,
    audits_root: Path,
    repo_root: Path,
    path_counts: Counter[str],
) -> OrderedDict[str, Any]:
    blockers: list[str] = []
    raw_path = str(candidate.get("candidate_proof_path") or "")
    clean_path = _clean_path(raw_path)
    if not clean_path:
        blockers.append("unsafe_candidate_proof_path")
        resolved_path = ""
        exists = False
    else:
        resolved = _resolve_artifact_path(clean_path, audits_root=audits_root, repo_root=repo_root)
        resolved_path = resolved.as_posix()
        exists = resolved.is_file() and resolved.stat().st_size > 0
        if not exists:
            blockers.append("candidate_artifact_missing")
        path_engagement = _engagement_from_audit_path(clean_path)
        if engagement and path_engagement and path_engagement != engagement:
            blockers.append("engagement_mismatch")
        if path_counts.get(clean_path, 0) > 1:
            blockers.append("duplicate_candidate_proof_path")

    kind = str(candidate.get("candidate_artifact_kind") or "")
    kind_blocker = _artifact_kind_blocker(kind, clean_path or raw_path)
    if kind_blocker:
        blockers.append(kind_blocker)

    return OrderedDict(
        [
            ("candidate_proof_path", clean_path),
            ("raw_candidate_proof_path", raw_path),
            ("resolved_path", resolved_path),
            ("exists", exists),
            ("candidate_artifact_kind", kind),
            ("candidate_path_occurrence", int(candidate.get("candidate_path_occurrence") or 0)),
            ("promotion_review_reason", str(candidate.get("promotion_review_reason") or "")),
            ("blockers", blockers),
        ]
    )


def build_review_packets(
    queue_path: Path,
    *,
    out_path: Path,
    audits_root: Path,
    repo_root: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    queue_rows, load_errors = _load_queue_rows(queue_path)
    path_counts = _candidate_path_counts(queue_rows)
    packets: list[OrderedDict[str, Any]] = []
    blocker_counts: Counter[str] = Counter(load_errors)
    status_counts: Counter[str] = Counter()

    for row in queue_rows:
        row_blockers: list[str] = []
        if row.get("schema") != QUEUE_SCHEMA:
            row_blockers.append("schema_mismatch")

        engagement = str(row.get("engagement") or "")
        submission_path = _clean_path(str(row.get("submission_path") or ""))
        if not submission_path:
            row_blockers.append("unsafe_submission_path")
        else:
            submission_engagement = _engagement_from_audit_path(submission_path)
            if engagement and submission_engagement and submission_engagement != engagement:
                row_blockers.append("submission_engagement_mismatch")
            newer = _newer_submission_sibling(submission_path, audits_root=audits_root, repo_root=repo_root)
            if newer:
                row_blockers.append("stale_submission_newer_sibling")
        candidates_raw = row.get("proof_artifact_candidates")
        if not isinstance(candidates_raw, list) or not candidates_raw:
            candidates_raw = []
            row_blockers.append("proof_artifact_candidates_missing")
        else:
            candidates_raw = sorted(
                [candidate for candidate in candidates_raw if isinstance(candidate, dict)],
                key=_artifact_priority,
            )

        candidate_packets = [
            _validate_candidate(
                candidate,
                engagement=engagement,
                audits_root=audits_root,
                repo_root=repo_root,
                path_counts=path_counts,
            )
            for candidate in candidates_raw
            if isinstance(candidate, dict)
        ]
        for candidate in candidate_packets:
            row_blockers.extend(candidate["blockers"])

        if int(row.get("candidate_count") or 0) != len(candidate_packets):
            row_blockers.append("candidate_count_mismatch")

        blockers = sorted(set(row_blockers))
        status = "ready_for_manual_record_creation" if not blockers else "blocked"
        status_counts[status] += 1
        blocker_counts.update(blockers)
        packets.append(
            OrderedDict(
                [
                    ("schema", PACKET_SCHEMA),
                    ("source_queue_path", str(queue_path)),
                    ("queue_key", str(row.get("queue_key") or "")),
                    ("engagement", engagement),
                    ("submission_path", submission_path),
                    ("submission_status", str(row.get("submission_status") or "")),
                    ("submission_title", str(row.get("submission_title") or "")),
                    ("suggested_record_slug", str(row.get("suggested_record_slug") or "")),
                    ("suggested_source_audit_ref", str(row.get("suggested_source_audit_ref") or "")),
                    ("validation_status", status),
                    ("recommended_next_action", "manual_create_hackerman_record" if status == "ready_for_manual_record_creation" else "fix_blockers"),
                    ("blockers", blockers),
                    ("artifact_candidates", candidate_packets),
                ]
            )
        )

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for packet in packets:
                handle.write(json.dumps(packet, sort_keys=True) + "\n")

    return OrderedDict(
        [
            ("schema", SUMMARY_SCHEMA),
            ("queue_schema", QUEUE_SCHEMA),
            ("packet_schema", PACKET_SCHEMA),
            ("queue_path", str(queue_path)),
            ("review_packets_out", str(out_path)),
            ("dry_run", dry_run),
            ("queue_rows", len(queue_rows)),
            ("packets", len(packets)),
            ("ready_for_manual_record_creation", status_counts.get("ready_for_manual_record_creation", 0)),
            ("blocked", status_counts.get("blocked", 0)),
            ("status_counts", dict(sorted(status_counts.items()))),
            ("blocker_counts", dict(sorted(blocker_counts.items()))),
            ("sample_packets", packets[:5]),
        ]
    )


def build_review_packets_from_status_only_reconciliation(
    queue_path: Path,
    *,
    out_path: Path,
    audits_root: Path,
    repo_root: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Convert report-only status reconciliation rows into review packets.

    ``status_only_reconciliation_queue`` deliberately refuses mutation because
    the matching Hackerman record is missing. This adapter keeps that posture:
    it only emits the same reviewer packet schema used by the normal
    missing-record queue, and only for ``record_creation_candidate`` rows whose
    referenced artifacts validate locally.
    """
    queue_rows, load_errors = _load_queue_rows(queue_path)
    path_counts = _candidate_path_counts(
        {"proof_artifact_candidates": row.get("proof_artifact_candidates")}
        for row in queue_rows
    )
    packets: list[OrderedDict[str, Any]] = []
    blocker_counts: Counter[str] = Counter(load_errors)
    status_counts: Counter[str] = Counter()
    skipped_counts: Counter[str] = Counter()

    for row in queue_rows:
        row_blockers: list[str] = []
        if row.get("schema") != RECONCILIATION_SCHEMA:
            row_blockers.append("schema_mismatch")
        if row.get("reconciliation_status") != "record_creation_candidate":
            skipped_counts[str(row.get("reconciliation_status") or "not_record_creation_candidate")] += 1
            continue
        if row.get("mutation_allowed") is True:
            row_blockers.append("unexpected_mutation_allowed")

        engagement = str(row.get("engagement") or "")
        submission_path = _clean_path(str(row.get("submission_path") or ""))
        if not submission_path:
            row_blockers.append("unsafe_submission_path")
        else:
            submission_engagement = _engagement_from_audit_path(submission_path)
            if engagement and submission_engagement and submission_engagement != engagement:
                row_blockers.append("submission_engagement_mismatch")
            newer = _newer_submission_sibling(submission_path, audits_root=audits_root, repo_root=repo_root)
            if newer:
                row_blockers.append("stale_submission_newer_sibling")

        candidates_raw = row.get("proof_artifact_candidates")
        if not isinstance(candidates_raw, list) or not candidates_raw:
            candidates_raw = []
            row_blockers.append("proof_artifact_candidates_missing")
        else:
            candidates_raw = sorted(
                [candidate for candidate in candidates_raw if isinstance(candidate, dict)],
                key=_artifact_priority,
            )

        candidate_packets = [
            _validate_candidate(
                candidate,
                engagement=engagement,
                audits_root=audits_root,
                repo_root=repo_root,
                path_counts=path_counts,
            )
            for candidate in candidates_raw
            if isinstance(candidate, dict)
        ]
        for candidate in candidate_packets:
            row_blockers.extend(candidate["blockers"])

        if int(row.get("candidate_count") or 0) != len(candidate_packets):
            row_blockers.append("candidate_count_mismatch")

        blockers = sorted(set(row_blockers))
        status = "ready_for_manual_record_creation" if not blockers else "blocked"
        status_counts[status] += 1
        blocker_counts.update(blockers)
        title = (
            _extract_submission_title(submission_path, audits_root=audits_root, repo_root=repo_root)
            or str(row.get("submission_title") or "")
        )
        submission_ref = str(row.get("submission_ref") or _submission_ref_from_path(submission_path) or "")
        packets.append(
            OrderedDict(
                [
                    ("schema", PACKET_SCHEMA),
                    ("source_queue_path", str(queue_path)),
                    ("queue_key", str(row.get("queue_key") or submission_ref or submission_path)),
                    ("engagement", engagement),
                    ("submission_path", submission_path),
                    ("submission_status", str(row.get("submission_status") or "")),
                    ("submission_title", title),
                    ("suggested_record_slug", _slugify_record_hint(title or submission_ref or submission_path)),
                    ("suggested_source_audit_ref", submission_ref),
                    ("validation_status", status),
                    ("recommended_next_action", "manual_create_hackerman_record" if status == "ready_for_manual_record_creation" else "fix_blockers"),
                    ("blockers", blockers),
                    ("artifact_candidates", candidate_packets),
                ]
            )
        )

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for packet in packets:
                handle.write(json.dumps(packet, sort_keys=True) + "\n")

    return OrderedDict(
        [
            ("schema", SUMMARY_SCHEMA),
            ("queue_schema", RECONCILIATION_SCHEMA),
            ("packet_schema", PACKET_SCHEMA),
            ("queue_path", str(queue_path)),
            ("review_packets_out", str(out_path)),
            ("dry_run", dry_run),
            ("queue_rows", len(queue_rows)),
            ("packets", len(packets)),
            ("ready_for_manual_record_creation", status_counts.get("ready_for_manual_record_creation", 0)),
            ("blocked", status_counts.get("blocked", 0)),
            ("status_counts", dict(sorted(status_counts.items()))),
            ("blocker_counts", dict(sorted(blocker_counts.items()))),
            ("skipped_counts", dict(sorted(skipped_counts.items()))),
            ("sample_packets", packets[:5]),
        ]
    )


def _submission_ref_from_path(path_text: str) -> str:
    clean = _clean_path(path_text)
    if not clean:
        return ""
    parts = Path(clean).parts
    if len(parts) >= 4 and parts[0] == "audits" and parts[2] == "submissions":
        return Path(*parts[3:]).as_posix()
    return ""


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", default=str(DEFAULT_QUEUE))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument(
        "--from-status-only-reconciliation",
        action="store_true",
        help="Read auditooor.hackerman_proof_artifact_status_only_reconciliation.v1 rows instead of the missing-record import queue schema.",
    )
    parser.add_argument("--audits-root", default=str(Path.home() / "audits"))
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    builder = (
        build_review_packets_from_status_only_reconciliation
        if args.from_status_only_reconciliation
        else build_review_packets
    )
    payload = builder(
        Path(args.queue).expanduser(),
        out_path=Path(args.out).expanduser(),
        audits_root=Path(args.audits_root).expanduser(),
        repo_root=Path(args.repo_root).expanduser(),
        dry_run=args.dry_run,
    )
    if args.json_summary:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"packets={payload['packets']} "
            f"ready={payload['ready_for_manual_record_creation']} "
            f"blocked={payload['blocked']} "
            f"out={payload['review_packets_out']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
