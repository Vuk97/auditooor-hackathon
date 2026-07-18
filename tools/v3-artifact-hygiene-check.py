#!/usr/bin/env python3
"""Fail-closed V3 submission artifact hygiene checker.

The checker scans a bounded submission folder for paste/export artifacts that
can drift after review:

* platform paste files must have a current hash sidecar;
* plain text exports must be newer than, and hash-consistent with, their draft;
* claimed test counts must match attached transcript/log counts;
* platform paste text must not leak internal gate/process labels.

Output is always JSON. Exit codes:

* 0: no blockers
* 1: at least one hygiene blocker
* 2: invocation/configuration error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.v3_artifact_hygiene_check.v1"

PASTE_DIR_MARKERS = {
    "paste-ready",
    "paste_ready",
    "cantina_paste",
    "final_cantina_paste",
    "final_paste",
    "platform_paste",
}

PLAIN_EXPORT_MARKERS = {
    "plain",
    "hackenproof-plain",
    "platform-export",
    "platform_export",
}

TRANSCRIPT_MARKERS = {
    "transcript",
    "test-output",
    "test_output",
    "test-log",
    "test_log",
}

HASH_FIELDS = (
    "paste_content_hash",
    "hash",
    "sha256",
    "content_sha256",
)

DRAFT_HASH_FIELDS = (
    "draft_sha256",
    "source_sha256",
    "source_hash",
    "input_sha256",
)

DRAFT_PATH_FIELDS = (
    "draft",
    "draft_path",
    "source",
    "source_path",
    "input",
    "input_path",
)

INTERNAL_LEAK_PATTERNS: list[tuple[str, str]] = [
    (r"<!--", "html_comment"),
    (r"/Users/[A-Za-z0-9_.-]+/", "local_absolute_path"),
    (r"\bagent_outputs/", "agent_outputs_path"),
    (r"\bsubmissions/(?:staging|held|internal_sidecars|paste_ready)/", "internal_submission_path"),
    (r"\.auditooor/", "internal_auditooor_path"),
    (r"\bWorker[-\s]+[A-Z]\b", "worker_label"),
    (r"\bworker[-\s]+[a-z]\b", "worker_label"),
    (r"\bGate[-\s]+(?:R|L)?\d{1,3}\b", "gate_label"),
    (r"\bpre-submit\s+Check\s+\d{1,3}\b", "pre_submit_check_label"),
    (r"\bSTRICT\s*=\s*1\b", "strict_env_label"),
    (r"\blesson-pack receipt\b", "lesson_pack_receipt"),
    (r"\bsource-first row gate\b", "source_first_row_gate"),
    (r"\bcontext_pack_(?:id|hash)\b", "context_pack_label"),
    (r"\bvault_[a-z_]+_context\b", "vault_context_label"),
    (r"\bnext-loop\b", "next_loop_label"),
    (r"\bRG-KILL-\d+\b", "internal_rg_kill_label"),
    (r"\bRG-N\d+(?:-S\d+)?\b", "internal_rg_n_label"),
]


@dataclass(frozen=True)
class Blocker:
    code: str
    path: str
    detail: str
    rule: str
    extra: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        row = {
            "code": self.code,
            "rule": self.rule,
            "path": self.path,
            "detail": self.detail,
        }
        if self.extra:
            row.update(self.extra)
        return row


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _is_sidecar(path: Path) -> bool:
    return path.suffix in {".hash", ".paste_hash"} or path.name.endswith((".hash", ".paste_hash"))


def _is_text_artifact(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in {".md", ".txt", ".text"}


def _has_marker(path: Path, markers: set[str]) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return bool(parts & markers) or any(marker in name for marker in markers)


def _discover_files(root: Path, explicit: list[Path] | None, predicate) -> list[Path]:
    if explicit:
        return sorted({path.resolve() for path in explicit})
    if root.is_file():
        return [root.resolve()] if predicate(root) else []
    return sorted(
        path.resolve()
        for path in root.rglob("*")
        if predicate(path) and not _is_sidecar(path)
    )


def discover_pastes(root: Path, explicit: list[Path] | None = None) -> list[Path]:
    def predicate(path: Path) -> bool:
        if not _is_text_artifact(path):
            return False
        lower = path.name.lower()
        if lower.endswith((".scrub-ledger.json", ".json")):
            return False
        return _has_marker(path, PASTE_DIR_MARKERS) or "final_paste" in lower or "paste" in lower

    return _discover_files(root, explicit, predicate)


def discover_plain_exports(root: Path, explicit: list[Path] | None = None) -> list[Path]:
    def predicate(path: Path) -> bool:
        return _is_text_artifact(path) and _has_marker(path, PLAIN_EXPORT_MARKERS)

    return _discover_files(root, explicit, predicate)


def discover_transcripts(root: Path, explicit: list[Path] | None = None) -> list[Path]:
    def predicate(path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() not in {".log", ".txt", ".out"}:
            return False
        return _has_marker(path, TRANSCRIPT_MARKERS)

    return _discover_files(root, explicit, predicate)


def _sidecar_candidates(paste: Path) -> list[Path]:
    return [
        paste.with_suffix(paste.suffix + ".hash"),
        paste.with_suffix(paste.suffix + ".paste_hash"),
        paste.with_name(paste.name + ".hash"),
        paste.with_name(paste.name + ".paste_hash"),
    ]


def _extract_hash_from_json(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for field in HASH_FIELDS:
            value = obj.get(field)
            if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()):
                return value.strip().lower()
        for value in obj.values():
            nested = _extract_hash_from_json(value)
            if nested:
                return nested
    elif isinstance(obj, list):
        for value in obj:
            nested = _extract_hash_from_json(value)
            if nested:
                return nested
    return None


def read_sidecar_hash(path: Path) -> str | None:
    text = _read_text(path).strip()
    if not text:
        return None
    if text.startswith("{") or text.startswith("["):
        try:
            return _extract_hash_from_json(json.loads(text))
        except json.JSONDecodeError:
            return None
    match = re.search(r"\b([a-fA-F0-9]{64})\b", text)
    return match.group(1).lower() if match else None


def check_hash_sidecars(pastes: list[Path], root: Path) -> list[Blocker]:
    blockers: list[Blocker] = []
    for paste in pastes:
        sidecars = [path for path in _sidecar_candidates(paste) if path.is_file()]
        if not sidecars:
            blockers.append(
                Blocker(
                    code="paste_hash_sidecar_missing",
                    rule="paste_hash_sidecar_match",
                    path=_rel(paste, root),
                    detail="platform paste artifact has no .hash or .paste_hash sidecar",
                )
            )
            continue
        current = _sha256(paste)
        matched = False
        unreadable = False
        for sidecar in sidecars:
            recorded = read_sidecar_hash(sidecar)
            if not recorded:
                unreadable = True
                continue
            if recorded == current:
                matched = True
                break
        if matched:
            continue
        code = "paste_hash_sidecar_unreadable" if unreadable else "paste_hash_sidecar_stale"
        blockers.append(
            Blocker(
                code=code,
                rule="paste_hash_sidecar_match",
                path=_rel(paste, root),
                detail="no sidecar digest matches current platform paste bytes",
                extra={
                    "current_sha256": current,
                    "sidecars": [_rel(path, root) for path in sidecars],
                },
            )
        )
    return blockers


def _load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        obj = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _find_json_sidecars(path: Path) -> list[Path]:
    candidates = [
        path.with_suffix(path.suffix + ".json"),
        path.with_suffix(".json"),
        path.with_name(path.name + ".json"),
    ]
    return [candidate for candidate in candidates if candidate.is_file()]


def _resolve_candidate_path(raw: str, root: Path, base: Path) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate
    for prefix in (base.parent, root):
        resolved = (prefix / candidate).resolve()
        if resolved.exists():
            return resolved
    return (base.parent / candidate).resolve()


def _metadata_for_export(export: Path) -> tuple[dict[str, Any], Path | None]:
    for sidecar in _find_json_sidecars(export):
        obj = _load_json_if_present(sidecar)
        if obj is not None:
            return obj, sidecar
    return {}, None


def _find_nested_str(obj: Any, fields: tuple[str, ...]) -> str | None:
    if isinstance(obj, dict):
        for field in fields:
            value = obj.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in obj.values():
            nested = _find_nested_str(value, fields)
            if nested:
                return nested
    elif isinstance(obj, list):
        for value in obj:
            nested = _find_nested_str(value, fields)
            if nested:
                return nested
    return None


def _infer_draft_for_export(export: Path, root: Path, metadata: dict[str, Any]) -> Path | None:
    raw_path = _find_nested_str(metadata, DRAFT_PATH_FIELDS)
    if raw_path:
        candidate = _resolve_candidate_path(raw_path, root, export)
        if candidate.is_file():
            return candidate

    name = export.name
    suffixes = [
        ".hackenproof-plain.txt",
        ".plain.txt",
        ".platform-export.txt",
        ".platform_export.txt",
        ".txt",
    ]
    for suffix in suffixes:
        if name.endswith(suffix):
            candidate = export.with_name(name[: -len(suffix)] + ".md")
            if candidate.is_file():
                return candidate
    return None


def _expected_draft_hash(metadata: dict[str, Any]) -> str | None:
    value = _find_nested_str(metadata, DRAFT_HASH_FIELDS)
    if value and re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return value.lower()
    return None


def check_plain_exports(exports: list[Path], root: Path) -> tuple[list[Blocker], list[dict[str, Any]]]:
    blockers: list[Blocker] = []
    warnings: list[dict[str, Any]] = []
    for export in exports:
        metadata, metadata_path = _metadata_for_export(export)
        draft = _infer_draft_for_export(export, root, metadata)
        if draft is None:
            warnings.append(
                {
                    "code": "plain_export_unpaired",
                    "path": _rel(export, root),
                    "detail": "plain export has no inferable draft path; skipped freshness comparison",
                }
            )
            continue

        expected_hash = _expected_draft_hash(metadata)
        current_hash = _sha256(draft)
        if expected_hash and expected_hash != current_hash:
            blockers.append(
                Blocker(
                    code="plain_export_draft_hash_stale",
                    rule="plain_export_fresh_after_draft_edit",
                    path=_rel(export, root),
                    detail="plain export metadata hash does not match current draft hash",
                    extra={
                        "draft": _rel(draft, root),
                        "metadata": _rel(metadata_path, root) if metadata_path else None,
                        "recorded_draft_sha256": expected_hash,
                        "current_draft_sha256": current_hash,
                    },
                )
            )

        if not expected_hash and draft.stat().st_mtime > export.stat().st_mtime + 1e-6:
            warnings.append(
                {
                    "code": "plain_export_older_than_draft",
                    "rule": "plain_export_fresh_after_draft_edit",
                    "path": _rel(export, root),
                    "detail": "source draft has a newer mtime than the plain export",
                    "draft": _rel(draft, root),
                    "draft_mtime": draft.stat().st_mtime,
                    "export_mtime": export.stat().st_mtime,
                }
            )
    return blockers, warnings


CLAIM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?im)^\s*(?:claimed[_ -]?)?test[_ -]?count\s*[:=]\s*(\d+)\b"),
    re.compile(r"(?im)^\s*claimed\s+tests?\s*[:=]\s*(\d+)\b"),
    re.compile(r"(?im)\bclaims?\s+(\d+)\s+tests?\b"),
]

GENERIC_PASSED_CLAIM_RE = re.compile(r"(?im)\b(\d+)\s+tests?\s+passed\b")

TRANSCRIPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?im)\btest result:\s+ok\.\s+(\d+)\s+passed\b"),
    re.compile(r"(?im)\bRan\s+\d+\s+test suites?:\s+(\d+)\s+tests?\s+passed\b"),
    re.compile(r"(?im)\bRan\s+(\d+)\s+tests?\s+for\b"),
    re.compile(r"(?im)\bRan\s+(\d+)\s+tests?\b"),
    re.compile(r"(?im)\b(\d+)\s+passed(?:[,;\s]|$)"),
    re.compile(r"(?im)^\s*PASS\s+\[[^\]]+\]\s+.+$", re.MULTILINE),
]


def _claimed_counts(text: str) -> list[int]:
    counts: list[int] = []
    for pattern in CLAIM_PATTERNS:
        counts.extend(int(match.group(1)) for match in pattern.finditer(text))
    counts.extend(int(match.group(1)) for match in GENERIC_PASSED_CLAIM_RE.finditer(text))
    return counts


def _transcript_counts(text: str) -> list[int]:
    counts: list[int] = []
    for pattern in TRANSCRIPT_PATTERNS:
        matches = list(pattern.finditer(text))
        if not matches:
            continue
        if pattern.pattern.startswith("(?im)^\\s*PASS"):
            counts.append(len(matches))
        else:
            counts.extend(int(match.group(1)) for match in matches)
    return counts


def check_transcript_counts(
    claim_files: list[Path],
    transcripts: list[Path],
    root: Path,
) -> tuple[list[Blocker], list[dict[str, Any]]]:
    blockers: list[Blocker] = []
    warnings: list[dict[str, Any]] = []
    if not transcripts:
        claim_count = 0
        for claim_file in claim_files:
            claim_count += len(_claimed_counts(_read_text(claim_file)))
        if claim_count:
            warnings.append(
                {
                    "code": "claimed_test_count_without_transcript",
                    "claim_count": claim_count,
                    "detail": "claimed test counts exist but no transcript/log artifact was discovered",
                }
            )
        return blockers, warnings

    transcript_counts_by_path: dict[Path, list[int]] = {
        transcript: _transcript_counts(_read_text(transcript)) for transcript in transcripts
    }
    parsed_counts = [count for counts in transcript_counts_by_path.values() for count in counts]
    if not parsed_counts:
        blockers.append(
            Blocker(
                code="transcript_test_count_unparseable",
                rule="transcript_claimed_test_count_match",
                path=_rel(transcripts[0], root),
                detail="transcript/log artifacts exist but no executed/passed test count was parseable",
                extra={"transcripts": [_rel(path, root) for path in transcripts]},
            )
        )
        return blockers, warnings

    unique_transcript_counts = sorted(set(parsed_counts))
    if len(unique_transcript_counts) != 1:
        warnings.append(
            {
                "code": "transcript_count_ambiguous",
                "detail": "multiple transcript test counts were parsed; skipped hard claimed-count comparison",
                "transcripts": {
                    _rel(path, root): counts
                    for path, counts in transcript_counts_by_path.items()
                },
            }
        )
        return blockers, warnings

    transcript_count = unique_transcript_counts[0]
    for claim_file in claim_files:
        counts = _claimed_counts(_read_text(claim_file))
        unique = sorted(set(counts))
        if not unique:
            continue
        mismatches = [count for count in unique if count != transcript_count]
        if mismatches:
            blockers.append(
                Blocker(
                    code="transcript_claimed_test_count_mismatch",
                    rule="transcript_claimed_test_count_match",
                    path=_rel(claim_file, root),
                    detail="claimed test count does not match attached transcript/log count",
                    extra={
                        "claimed_counts": unique,
                        "transcript_count": transcript_count,
                        "transcripts": {
                            _rel(path, root): counts
                            for path, counts in transcript_counts_by_path.items()
                        },
                    },
                )
            )
    return blockers, warnings


def _line_for_offset(text: str, offset: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return line_no, text[start:end].strip()


def check_internal_leaks(pastes: list[Path], root: Path) -> list[Blocker]:
    blockers: list[Blocker] = []
    for paste in pastes:
        text = _read_text(paste)
        hits: list[dict[str, Any]] = []
        for pattern, label in INTERNAL_LEAK_PATTERNS:
            for match in re.finditer(pattern, text):
                line_no, line = _line_for_offset(text, match.start())
                hits.append({"label": label, "line": line_no, "snippet": line[:180]})
        if hits:
            blockers.append(
                Blocker(
                    code="platform_paste_internal_label_leak",
                    rule="strip_internal_gate_labels_from_platform_paste",
                    path=_rel(paste, root),
                    detail="platform paste contains internal-only gate/process labels",
                    extra={"hits": hits},
                )
            )
    return blockers


def build_report(
    root: Path,
    *,
    paste_files: list[Path] | None = None,
    plain_exports: list[Path] | None = None,
    transcript_files: list[Path] | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    pastes = discover_pastes(root, paste_files)
    exports = discover_plain_exports(root, plain_exports)
    transcripts = discover_transcripts(root, transcript_files)

    blockers: list[Blocker] = []
    warnings: list[dict[str, Any]] = []

    blockers.extend(check_hash_sidecars(pastes, root))
    export_blockers, export_warnings = check_plain_exports(exports, root)
    blockers.extend(export_blockers)
    warnings.extend(export_warnings)
    transcript_blockers, transcript_warnings = check_transcript_counts(pastes + exports, transcripts, root)
    blockers.extend(transcript_blockers)
    warnings.extend(transcript_warnings)
    blockers.extend(check_internal_leaks(pastes, root))

    blocker_rows = [blocker.to_json() for blocker in blockers]
    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "root": str(root),
        "verdict": "fail" if blocker_rows else "pass",
        "summary": {
            "paste_files": len(pastes),
            "plain_exports": len(exports),
            "transcripts": len(transcripts),
            "blockers": len(blocker_rows),
            "warnings": len(warnings),
        },
        "checked_files": {
            "paste_files": [_rel(path, root) for path in pastes],
            "plain_exports": [_rel(path, root) for path in exports],
            "transcripts": [_rel(path, root) for path in transcripts],
        },
        "blockers": blocker_rows,
        "warnings": warnings,
    }


def _parse_paths(values: list[str] | None) -> list[Path] | None:
    if not values:
        return None
    return [Path(value) for value in values]


def _explicit_path_errors(values: list[str] | None, label: str) -> list[str]:
    if not values:
        return []
    return [f"{label}: {value}" for value in values if not Path(value).is_file()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("submission_folder", type=Path, help="submission folder or artifact to check")
    parser.add_argument("--paste", action="append", help="explicit platform paste file; repeatable")
    parser.add_argument("--plain-export", action="append", help="explicit plain/platform export file; repeatable")
    parser.add_argument("--transcript", action="append", help="explicit transcript/log file; repeatable")
    parser.add_argument("--json", action="store_true", help="emit JSON (default)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    args = parser.parse_args(argv)

    root = args.submission_folder.resolve()
    if not root.exists():
        payload = {
            "schema": SCHEMA,
            "generated_at": _utc_now(),
            "verdict": "error",
            "error": f"submission folder not found: {root}",
        }
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
        return 2

    explicit_errors = (
        _explicit_path_errors(args.paste, "paste")
        + _explicit_path_errors(args.plain_export, "plain_export")
        + _explicit_path_errors(args.transcript, "transcript")
    )
    if explicit_errors:
        payload = {
            "schema": SCHEMA,
            "generated_at": _utc_now(),
            "verdict": "error",
            "error": "explicit artifact path does not exist or is not a file",
            "missing": explicit_errors,
        }
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
        return 2

    report = build_report(
        root,
        paste_files=_parse_paths(args.paste),
        plain_exports=_parse_paths(args.plain_export),
        transcript_files=_parse_paths(args.transcript),
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 1 if report["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
