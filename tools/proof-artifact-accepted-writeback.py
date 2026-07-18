#!/usr/bin/env python3
"""Emit proof-artifact sidecar rows from accepted outcome records.

Two write modes:
  --output (default)      Write a standalone sidecar JSONL using the
                          proof_artifact_accepted_writeback.v1 schema.
  --target-index PATH     Idempotently merge accepted tier-1 rows into
                          proof_artifact_index.jsonl using the canonical
                          hackerman_proof_artifact_index.v1 schema.
                          Deduplicates by platform_finding_id (or
                          outcome_id / proof_path+title when no platform
                          ID is present).  Rows with no real proof
                          artifact are NEVER written to the index
                          (confirm-gated; use --include-missing only with
                          --output, not with --target-index).

F1 spec (HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md, Lane F):
  When a finding is filed and accepted, write its source refs + proof
  shell into proof_artifact_index.jsonl at tier-1-verified-realtime-api
  with the platform finding ID.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.proof_artifact_accepted_writeback.v1"
SUMMARY_SCHEMA = "auditooor.proof_artifact_accepted_writeback_summary.v1"
INDEX_SCHEMA = "auditooor.hackerman_proof_artifact_index.v1"
DEFAULT_OUTCOMES = Path("reference") / "outcomes.jsonl"
DEFAULT_OUTPUT = Path("audit") / "corpus_tags" / "derived" / "proof_artifact_accepted_writeback.jsonl"
DEFAULT_TARGET_INDEX = Path("audit") / "corpus_tags" / "derived" / "proof_artifact_index.jsonl"
PROOF_PATH_FIELDS = ("proof_artifact", "proof_path", "poc_path", "submission_path", "artifact_path")
SOURCE_REF_FIELDS = ("source_refs", "source_ref", "source", "outcome_evidence_path")
WORKSPACE_PATH_FIELDS = ("workspace_path", "workspace_root", "source_workspace_path")
PROOF_EVIDENCE_FIELDS = (
    "proof_evidence",
    "proof_evidence_lines",
    "pass_evidence_lines",
    "harness_evidence",
    "harness_command",
    "harness_commands",
    "proof_command",
    "proof_commands",
    "test_command",
    "test_commands",
    "test_transcript",
    "poc_transcript",
    "transcript",
    "validation",
    "validation_output",
    "tests_run",
)
BLOCKER_FIELDS = (
    "promotion_blockers",
    "blockers",
    "blocked_by",
    "blocked_reason",
    "blocker_reason",
    "kill_reason",
    "fp_reason",
)
NEGATIVE_STATUS_RE = re.compile(
    r"\b(duplicate|dupe|rejected|declined|oos|out[-_ ]?of[-_ ]?scope|not[-_ ]?a[-_ ]?bug|"
    r"false[-_ ]?positive|pending|in[-_ ]?review|withdrawn|superseded)\b",
    re.I,
)
POSITIVE_STATUS_RE = re.compile(
    r"\b(accepted|paid|payout|reward(?:ed)?|bounty[-_ ]?paid|resolved[-_ ]?positive|"
    r"positive[-_ ]?resolved|triaged[-_ ]?accepted)\b",
    re.I,
)
CONCRETE_PROOF_RE = re.compile(
    r"(--- PASS:|Suite result:\s*ok|\bok\b|forge test|go test|cargo test|pytest|unittest|"
    r"PASS\b|assert(?:Eq|Equal|True|False)?\(|before/after|harness|poc)",
    re.I | re.M,
)
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
BLOCKER_MARKER_RE = re.compile(
    r"\b(NOT_SUBMIT_READY|EXECUTION_BLOCKED|blocked|blocker|advisory[-_ ]?only|"
    r"operator[-_ ]?required|no[-_ ]?safe[-_ ]?writeback)\b",
    re.I,
)


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        for item in value:
            found = _first_string(item)
            if found:
                return found
    if isinstance(value, dict):
        for key in ("path", "file", "href", "url", "source_ref"):
            found = _first_string(value.get(key))
            if found:
                return found
    return ""


def _string_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, bool):
        return [str(value).lower()]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_string_values(item))
        return values
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(_string_values(item))
        return values
    return []


def _is_truthy_marker(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = _clean_text(value).lower()
    return text in {"1", "true", "yes", "y", "blocked", "advisory", "not_submit_ready"}


def _workspace_root(workspace_path: Path | None = None) -> Path:
    root = workspace_path if workspace_path is not None else Path.cwd()
    return root.expanduser().resolve(strict=False)


def _strip_line_suffix(value: str) -> str:
    text = value.strip().strip("'\"")
    if re.search(r":\d+$", text):
        return text.rsplit(":", 1)[0]
    return text


def _path_from_ref(ref: str, root: Path) -> Path | None:
    text = _strip_line_suffix(ref)
    if not text:
        return None
    if text.startswith("workspace:"):
        text = text[len("workspace:") :]
    if URL_RE.match(text):
        return None
    if text.startswith("vault://"):
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve(strict=False)


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _explicit_source_refs(row: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for field in SOURCE_REF_FIELDS:
        refs.extend(_string_values(row.get(field)))
    return refs


def _current_existing_refs(refs: list[str], root: Path) -> list[str]:
    current: list[str] = []
    for ref in refs:
        path = _path_from_ref(ref, root)
        if path is not None and _is_under(path, root) and path.exists():
            current.append(ref)
    return current


def _workspace_path_reasons(row: dict[str, Any], root: Path) -> list[str]:
    reasons: list[str] = []
    for field in WORKSPACE_PATH_FIELDS:
        for value in _string_values(row.get(field)):
            path = _path_from_ref(value, root)
            if path is None or not _is_under(path, root) or not path.exists():
                reasons.append("stale_workspace")
                return reasons
    return reasons


def _current_existing_path(value: str, root: Path) -> Path | None:
    path = _path_from_ref(value, root)
    if path is None or not _is_under(path, root) or not path.is_file():
        return None
    return path


def _has_concrete_proof_evidence(row: dict[str, Any], proof_file: Path | None) -> bool:
    evidence_values: list[str] = []
    for field in PROOF_EVIDENCE_FIELDS:
        evidence_values.extend(_string_values(row.get(field)))
    if any(CONCRETE_PROOF_RE.search(value) for value in evidence_values):
        return True
    if proof_file is None:
        return False
    try:
        body = proof_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(CONCRETE_PROOF_RE.search(body))


def _blocker_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for field in BLOCKER_FIELDS:
        values = _string_values(row.get(field))
        if any(BLOCKER_MARKER_RE.search(value) or value.strip() for value in values):
            reasons.append("blocker_marker_present")
            break
    for field in ("advisory_only", "not_submit_ready"):
        if _is_truthy_marker(row.get(field)):
            reasons.append("advisory_only_marker")
            break
    for field in ("submission_posture", "promotion_review_status", "writeback_status"):
        values = _string_values(row.get(field))
        if any(BLOCKER_MARKER_RE.search(value) for value in values):
            reasons.append("blocker_marker_present")
            break
    return reasons


def acceptance_reasons(
    row: dict[str, Any],
    outcomes_path: Path,
    line_no: int,
    *,
    workspace_path: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    root = _workspace_root(workspace_path)
    reasons: list[str] = []
    proof_path, proof_field = resolve_proof_artifact_path(row)
    source_refs = _explicit_source_refs(row)
    current_source_refs = _current_existing_refs(source_refs, root)
    proof_file = _current_existing_path(proof_path, root) if proof_path else None

    if not is_positive_outcome(row):
        reasons.append("non_positive_status")
    if not source_refs:
        reasons.append("missing_source_refs")
    elif not current_source_refs:
        reasons.append("stale_workspace_source_refs")
    reasons.extend(_workspace_path_reasons(row, root))
    if not proof_path:
        reasons.append("missing_proof_artifact_blocked")
    if proof_path and proof_file is None:
        reasons.append("proof_artifact_not_current_workspace")
    if not _has_concrete_proof_evidence(row, proof_file):
        reasons.append("missing_proof_evidence")
    reasons.extend(_blocker_reasons(row))

    metadata = {
        "workspace_root": root,
        "proof_path": proof_path,
        "proof_field": proof_field,
        "proof_file": proof_file,
        "source_refs": source_refs,
        "current_source_refs": current_source_refs,
        "fallback_source_ref": source_ref(row, outcomes_path, line_no),
    }
    return list(OrderedDict.fromkeys(reasons)), metadata


def _status_values(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in ("status", "outcome", "outcome_class", "final_triager_outcome", "resolution", "verdict"):
        value = _clean_text(row.get(field))
        if value:
            values.append(value)
    return values


def is_positive_outcome(row: dict[str, Any]) -> bool:
    haystack = " ".join(_status_values(row))
    if not haystack:
        return False
    if NEGATIVE_STATUS_RE.search(haystack):
        return False
    return bool(POSITIVE_STATUS_RE.search(haystack))


def resolve_proof_artifact_path(row: dict[str, Any]) -> tuple[str, str]:
    for field in PROOF_PATH_FIELDS:
        value = _first_string(row.get(field))
        if value:
            return value, field
    return "", ""


def _stable_value(row: dict[str, Any], fields: Iterable[str]) -> str:
    for field in fields:
        value = _first_string(row.get(field))
        if value:
            return value
    return ""


def _stable_platform_finding_id(row: dict[str, Any]) -> str:
    for field in ("platform_finding_id", "finding_id", "submission_id"):
        value = _first_string(row.get(field))
        if value:
            return value
    return ""


def dedupe_identity(row: dict[str, Any], proof_path: str) -> tuple[str, str]:
    platform_id = _stable_platform_finding_id(row)
    if platform_id:
        return "platform_finding_id", platform_id
    outcome_id = _stable_value(row, ("outcome_id", "report_id", "draft_id"))
    if outcome_id:
        return "outcome_id", outcome_id
    title = _clean_text(row.get("title"))
    return "proof_path_title", f"{proof_path}\x1f{title}"


def source_ref(row: dict[str, Any], outcomes_path: Path, line_no: int) -> str:
    for field in ("source_ref", "source", "outcome_evidence_path", "url"):
        value = _first_string(row.get(field))
        if value:
            return value
    return f"{outcomes_path.as_posix()}:{line_no}"


def read_jsonl(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], Counter[str]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    skipped: Counter[str] = Counter()
    if not path.is_file():
        skipped["outcomes_missing"] += 1
        return rows, skipped
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            skipped["invalid_json"] += 1
            continue
        if not isinstance(parsed, dict):
            skipped["row_not_object"] += 1
            continue
        rows.append((line_no, parsed))
    return rows, skipped


def build_writeback_rows(
    outcomes_path: Path,
    *,
    include_missing: bool = False,
    workspace_path: Path | None = None,
) -> tuple[list[OrderedDict[str, Any]], dict[str, Any]]:
    generated_at = now_utc()
    source_rows, skipped = read_jsonl(outcomes_path)
    output_rows: list[OrderedDict[str, Any]] = []
    seen: set[str] = set()
    accepted_count = 0
    rejected_count = 0

    for line_no, row in source_rows:
        reasons, metadata = acceptance_reasons(row, outcomes_path, line_no, workspace_path=workspace_path)
        proof_path = metadata["proof_path"]
        proof_field = metadata["proof_field"]

        dedupe_basis, dedupe_value = dedupe_identity(row, proof_path)
        dedupe_key = f"{dedupe_basis}:{dedupe_value}"
        if not reasons:
            if dedupe_key in seen:
                reasons.append("duplicate")
            else:
                seen.add(dedupe_key)
        if reasons:
            rejected_count += 1
            for reason in reasons:
                skipped[reason] += 1
        else:
            accepted_count += 1

        platform_finding_id = _stable_platform_finding_id(row)
        outcome_id = _stable_value(row, ("outcome_id", "draft_id"))
        report_id = _stable_value(row, ("report_id",))
        status = _stable_value(row, ("status", "outcome", "outcome_class", "final_triager_outcome"))
        bug_class = _stable_value(row, ("bug_class", "class", "category", "attack_class"))
        title = _clean_text(row.get("title"))
        workspace = _stable_value(row, ("engagement", "workspace"))
        artifact_exists = metadata["proof_file"] is not None
        accepted = not reasons
        review_reason = (
            "accepted positive outcome with current-workspace source refs and proof evidence"
            if accepted
            else "rejected outcome candidate: " + ", ".join(reasons)
        )

        output_rows.append(
            OrderedDict(
                [
                    ("schema", SCHEMA),
                    ("generated_at", generated_at),
                    ("outcome_id", outcome_id),
                    ("platform_finding_id", platform_finding_id),
                    ("report_id", report_id),
                    ("engagement", workspace),
                    ("workspace", workspace),
                    ("status", status),
                    ("bug_class", bug_class),
                    ("title", title),
                    ("proof_artifact_path", proof_path),
                    ("proof_artifact_field", proof_field),
                    ("candidate_proof_path", proof_path),
                    ("candidate_artifact_exists", artifact_exists),
                    ("candidate_artifact_kind", "accepted-proof-artifact" if accepted else "rejected-proof-artifact-candidate"),
                    ("submission_path", proof_path),
                    ("submission_status", "accepted_outcome" if accepted else "rejected_outcome"),
                    ("submission_title", title),
                    ("confidence", "high" if accepted else "blocked"),
                    ("confidence_score", 1.0 if accepted else 0.0),
                    ("match_method", "accepted-outcome-strict-gate" if accepted else "accepted-outcome-strict-rejection"),
                    ("promotion_ready", accepted),
                    ("promotion_review_status", "ready" if accepted else "rejected"),
                    ("promotion_review_reason", review_reason),
                    ("promotion_rejection_reasons", reasons),
                    ("source_ref", metadata["fallback_source_ref"]),
                    ("source_refs", metadata["source_refs"]),
                    ("current_workspace_source_refs", metadata["current_source_refs"]),
                    ("writeback_tier", "accepted_outcome" if accepted else "rejected_outcome"),
                    ("verification_tier", "tier-1-verified-realtime-api" if accepted else "not-accepted"),
                    ("dedupe_basis", dedupe_basis),
                    ("dedupe_key", dedupe_key),
                    ("source_outcomes_path", outcomes_path.as_posix()),
                    ("source_row_line", line_no),
                    (
                        "source_status_fields",
                        {field: row.get(field) for field in ("status", "outcome", "outcome_class", "final_triager_outcome") if row.get(field) is not None},
                    ),
                ]
            )
        )

    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": generated_at,
        "outcomes_path": outcomes_path.as_posix(),
        "rows_seen": len(source_rows),
        "rows_written": len(output_rows),
        "rows_accepted": accepted_count,
        "rows_rejected": rejected_count,
        "include_missing": include_missing,
        "skipped_counts": dict(sorted(skipped.items())),
    }
    return output_rows, summary


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# F1 writeback path: build index-schema rows and merge into proof_artifact_index.jsonl
# ---------------------------------------------------------------------------

def _index_dedupe_key(row: dict[str, Any]) -> str:
    """Stable deduplication key for proof_artifact_index rows."""
    pfid = _stable_platform_finding_id(row)
    if pfid:
        return f"platform_finding_id:{pfid}"
    oid = _stable_value(row, ("outcome_id", "draft_id"))
    if oid:
        return f"outcome_id:{oid}"
    proof_path = _first_string(row.get("candidate_proof_path") or row.get("proof_artifact_path") or "")
    title = _clean_text(row.get("submission_title") or row.get("title"))
    return f"proof_path_title:{proof_path}\x1f{title}"


def build_index_rows(
    outcomes_path: Path,
    *,
    workspace_path: Path | None = None,
) -> tuple[list[OrderedDict[str, Any]], dict[str, Any]]:
    """Build proof_artifact_index.jsonl-compatible rows from accepted outcomes.

    Only rows that pass the strict accepted-outcome gate are emitted. Rows
    with stale source refs, missing proof evidence, or blocker markers are
    counted as skipped and are never written as tier-1 accepted artifacts.
    """
    generated_at = now_utc()
    source_rows, skipped = read_jsonl(outcomes_path)
    output_rows: list[OrderedDict[str, Any]] = []
    seen: set[str] = set()

    for line_no, row in source_rows:
        reasons, metadata = acceptance_reasons(row, outcomes_path, line_no, workspace_path=workspace_path)
        if reasons:
            for reason in reasons:
                skipped[reason] += 1
            continue
        proof_path = metadata["proof_path"]
        proof_field = metadata["proof_field"]

        dedupe_basis, dedupe_value = dedupe_identity(row, proof_path)
        dedupe_key = f"{dedupe_basis}:{dedupe_value}"
        if dedupe_key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(dedupe_key)

        platform_finding_id = _stable_platform_finding_id(row)
        outcome_id = _stable_value(row, ("outcome_id", "draft_id"))
        report_id = _stable_value(row, ("report_id",))
        status = _stable_value(row, ("status", "outcome", "outcome_class", "final_triager_outcome"))
        title = _clean_text(row.get("title"))
        workspace = _stable_value(row, ("engagement", "workspace"))
        artifact_exists = metadata["proof_file"] is not None
        sref = metadata["fallback_source_ref"]

        output_rows.append(
            OrderedDict(
                [
                    ("schema", INDEX_SCHEMA),
                    ("generated_at", generated_at),
                    # --- fields matching hackerman_proof_artifact_index.v1 ---
                    ("engagement", workspace),
                    ("submission_path", proof_path),
                    ("submission_status", "filed_accepted"),
                    ("submission_title", title),
                    ("candidate_proof_path", proof_path),
                    ("candidate_artifact_exists", artifact_exists),
                    ("candidate_artifact_kind", "accepted-proof-artifact"),
                    ("candidate_path_occurrence", 1),
                    ("candidate_path_specificity", 1.0),
                    ("confidence", "high"),
                    ("confidence_score", 1.0),
                    ("match_method", "accepted-outcome-proof-field"),
                    ("promotion_ready", True),
                    ("promotion_review_status", "ready"),
                    ("promotion_review_reason", "accepted positive outcome with current-workspace source refs and proof evidence"),
                    ("promotion_gate_version", "proof-artifact-accepted-writeback-v1"),
                    ("promotion_blockers", []),
                    ("source_reasons", ["accepted_outcome", f"proof_field:{proof_field}"]),
                    ("source_refs", metadata["source_refs"]),
                    ("current_workspace_source_refs", metadata["current_source_refs"]),
                    ("token_overlap", []),
                    # --- tier and provenance (F1 requirement) ---
                    ("verification_tier", "tier-1-verified-realtime-api"),
                    ("platform_finding_id", platform_finding_id),
                    ("outcome_id", outcome_id),
                    ("report_id", report_id),
                    ("status", status),
                    ("source_ref", sref),
                    ("writeback_tier", "accepted_outcome"),
                    ("dedupe_basis", dedupe_basis),
                    ("dedupe_key", dedupe_key),
                    ("source_outcomes_path", outcomes_path.as_posix()),
                    ("source_row_line", line_no),
                ]
            )
        )

    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": generated_at,
        "outcomes_path": outcomes_path.as_posix(),
        "rows_seen": len(source_rows),
        "rows_written": len(output_rows),
        "include_missing": False,
        "skipped_counts": dict(sorted(skipped.items())),
    }
    return output_rows, summary


def merge_into_index(
    index_path: Path,
    new_rows: list[dict[str, Any]],
) -> tuple[int, int, int]:
    """Idempotently merge new_rows into index_path.

    Reads the existing index, builds a dedupe set, appends only rows whose
    dedupe key is not already present.  Returns (existing_count,
    appended_count, skipped_dupe_count).
    """
    existing_rows: list[dict[str, Any]] = []
    existing_keys: set[str] = set()
    if index_path.is_file():
        for line in index_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                existing_rows.append(row)
                existing_keys.add(_index_dedupe_key(row))

    appended: list[dict[str, Any]] = []
    skipped = 0
    for row in new_rows:
        k = _index_dedupe_key(row)
        if k in existing_keys:
            skipped += 1
            continue
        existing_keys.add(k)
        appended.append(row)

    if appended:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        with index_path.open("a", encoding="utf-8") as fh:
            for row in appended:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return len(existing_rows), len(appended), skipped


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcomes", type=Path, default=DEFAULT_OUTCOMES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--target-index",
        type=Path,
        metavar="PATH",
        help=(
            "F1 writeback: merge accepted tier-1 rows into this proof_artifact_index.jsonl "
            "(default: %(default)s). Mutually exclusive with --include-missing."
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root used to validate source refs and proof artifacts (default: current directory).",
    )
    parser.add_argument("--include-missing", action="store_true")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)

    if args.target_index is not None:
        # F1 writeback path: merge into proof_artifact_index.jsonl
        index_path = args.target_index
        rows, summary = build_index_rows(args.outcomes, workspace_path=args.workspace)
        existing, appended, skipped_dupe = merge_into_index(index_path, rows)
        summary["mode"] = "f1-index-writeback"
        summary["target_index_path"] = index_path.as_posix()
        summary["existing_index_rows"] = existing
        summary["rows_appended"] = appended
        summary["rows_skipped_dupe"] = skipped_dupe
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    # Default path: standalone sidecar
    rows, summary = build_writeback_rows(args.outcomes, include_missing=args.include_missing, workspace_path=args.workspace)
    write_jsonl(args.output, rows)
    summary["output_path"] = args.output.as_posix()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
