#!/usr/bin/env python3
"""Backfill proof_artifact_path on verdict-derived Hackerman records.

Two crawlers:

1. `backfill()` - lifts already-present poc_path / proof_artifact_path lines
   from source tag yamls into the matching hackerman record yaml.

2. `crawl_engagements()` - scans operator-local engagement workspaces
   (~/audits/<eng>/) for PoC artifacts (paste-ready md files, poc-tests/
   lead directories, in-tree *_poc_test.go / hackerman_*_test.go) and emits
   candidate (record_id, proof_path) pairs to a JSONL candidates file.
   Operator runs a separate `--apply` pass to write back.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.hackerman_proof_artifact_path_backfill.v1"
CRAWL_SCHEMA = "auditooor.hackerman_proof_artifact_path_crawl_candidate.v1"
SIDECAR_SCHEMA = "auditooor.hackerman_proof_artifact_path_sidecar_candidate.v1"
DEFAULT_TAG_DIR = Path("audit") / "corpus_tags" / "tags"
DEFAULT_CANDIDATES_OUT = Path(".auditooor") / "proof_artifact_backfill_candidates.jsonl"
DEFAULT_PROOF_HARDENING_SIDECAR = Path("audit") / "corpus_tags" / "derived" / "proof_hardening.jsonl"
DEFAULT_PROOF_ARTIFACT_INDEX = Path("audit") / "corpus_tags" / "derived" / "proof_artifact_index.jsonl"
DEFAULT_PROMOTION_REVIEW_PLAN = Path(".auditooor") / "proof_artifact_promotion_review_plan.jsonl"
DEFAULT_MISSING_RECORD_IMPORT_QUEUE = Path(".auditooor") / "proof_artifact_missing_record_import_queue.jsonl"
DEFAULT_STATUS_ONLY_REVIEW = Path(".auditooor") / "proof_artifact_status_only_review_queue.jsonl"
DEFAULT_STATUS_ONLY_RECONCILIATION_QUEUE = Path(".auditooor") / "proof_artifact_status_only_reconciliation_queue.jsonl"
DEFAULT_STATUS_ONLY_PROMOTION_REVIEW_PLAN = (
    Path(".auditooor") / "proof_artifact_promotion_review_status_only_resolved.jsonl"
)
SUBMISSION_REF_RESOLUTION_SIDECARS = (
    "detector_relationship_records.jsonl",
    "exploit_predicates.jsonl",
)
PROMOTION_PLAN_SCHEMA = "auditooor.hackerman_proof_artifact_promotion_review_plan.v1"
MISSING_RECORD_IMPORT_QUEUE_SCHEMA = "auditooor.hackerman_missing_record_import_queue.v1"
STATUS_ONLY_REVIEW_SCHEMA = "auditooor.hackerman_proof_artifact_status_only_review.v1"
STATUS_ONLY_RECONCILIATION_SCHEMA = "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1"
HACKERMAN_SCHEMA_RE = re.compile(
    r"^(?:schema|schema_version):\s+['\"]?auditooor\.hackerman_record\.v1(?:\.1)?['\"]?\s*$",
    re.MULTILINE,
)
SOURCE_TAG_RE = re.compile(r"^#\s*source_tag_file:\s*(.+?)\s*$", re.MULTILINE)
SOURCE_PROOF_RE = re.compile(r"^(?:poc_path|proof_artifact_path):\s*(.+?)\s*$", re.MULTILINE)
FIELD_RE_TEMPLATE = r"^{field}:\s*(.+?)\s*$"
RECORD_ID_RE = re.compile(r"^record_id:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", re.MULTILINE)
TARGET_COMPONENT_RE = re.compile(r"^target_component:\s*(.+?)\s*$", re.MULTILINE)
ATTACK_CLASS_RE = re.compile(r"^attack_class:\s*(.+?)\s*$", re.MULTILINE)
BUG_CLASS_RE = re.compile(r"^bug_class:\s*(.+?)\s*$", re.MULTILINE)
TARGET_REPO_RE = re.compile(r"^target_repo:\s*(.+?)\s*$", re.MULTILINE)
SAFE_PROOF_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)
CONFIDENT_MATCH_MAX_PATH_FANOUT = 10
FANOUT_REPORT_LIMIT = 8
PROMOTION_READY_MAX_PATH_FANOUT = 3
PROMOTION_REVIEW_PLAN_DEFAULT_LIMIT = 25
PROMOTION_REVIEW_PLAN_MAX_LIMIT = 50
PROMOTION_APPLY_MAX_ROWS = 10
STATUS_ONLY_REVIEW_STATUSES = {"packaged", "ready", "submitted"}
STATUS_ONLY_RECORD_CREATION_CANDIDATE_STATUSES = {"ready", "submitted"}

# Paste-ready md `source-proof:` / `proof_artifact:` lines.
PASTE_READY_PROOF_RE = re.compile(
    r"(?:^|\n)[-*\s]*(?:source[- ]proof|proof[_ ]artifact|poc[_ ]path)\s*:\s*`?([A-Za-z0-9._/\-]+\.(?:go|rs|sol|ts|tsx|js|mjs|py))`?",
    re.IGNORECASE,
)
# Filename token splitter: extract identifier tokens from a filename.
FILENAME_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
STOPWORD_TOKENS = {
    "go", "rs", "sol", "ts", "tsx", "js", "mjs", "py", "test", "poc",
    "tests", "spec", "hackerman", "lead", "loop", "and", "the", "of",
    "to", "a", "an", "v1", "v2", "v3",
}


def _local_absolute_to_relative(value: str) -> str:
    path = value.replace("\\", "/")
    if path.startswith("/audits/"):
        return "audits/" + path[len("/audits/") :]
    home = Path.home().as_posix().rstrip("/")
    if home and path.startswith(home + "/"):
        return path[len(home) + 1 :]
    cwd = Path.cwd().resolve().as_posix().rstrip("/")
    if cwd and path.startswith(cwd + "/"):
        return path[len(cwd) + 1 :]
    return value


def _clean_path(raw: str) -> str:
    value = _local_absolute_to_relative(raw.strip().strip("'\"")).replace("\\", "/")
    return value if SAFE_PROOF_PATH_RE.match(value) else ""


def _source_proof_path(source_text: str) -> str:
    match = SOURCE_PROOF_RE.search(source_text)
    return _clean_path(match.group(1)) if match else ""


def _field_value(text: str, field: str) -> str:
    match = re.search(FIELD_RE_TEMPLATE.format(field=re.escape(field)), text, re.MULTILINE)
    return match.group(1).strip().strip("'\"") if match else ""


def _target_guard(record_text: str, source_text: str) -> tuple[bool, str, str, str]:
    record_target = _field_value(record_text, "target_repo")
    source_target = _field_value(source_text, "target_repo")
    if not record_target or not source_target:
        return False, "target_repo_missing", record_target, source_target
    if record_target != source_target:
        return False, "target_repo_mismatch", record_target, source_target
    return True, "target_repo_match", record_target, source_target


def _insert_proof_path(record_text: str, proof_path: str) -> str:
    line = f"proof_artifact_path: {proof_path}\n"
    if "proof_artifact_path:" in record_text:
        return record_text
    marker = "\ncross_language_analogues:"
    if marker in record_text:
        return record_text.replace(marker, "\n" + line + "cross_language_analogues:", 1)
    year_match = re.search(r"^year:\s*[0-9]{4}\s*$", record_text, re.MULTILINE)
    if year_match:
        insert_at = year_match.end()
        return record_text[:insert_at] + "\n" + line.rstrip("\n") + record_text[insert_at:]
    if record_text.endswith("\n"):
        return record_text + line
    return record_text + "\n" + line


def _is_hackerman_record(text: str) -> bool:
    return bool(HACKERMAN_SCHEMA_RE.search(text))


def _record_id(text: str) -> str:
    match = RECORD_ID_RE.search(text)
    return match.group(1).strip() if match else ""


def _source_ref_to_record_path(source_ref: str, tag_dir: Path) -> Path | None:
    """Resolve a proof-hardening source_ref to a tag YAML under tag_dir."""
    source_ref = source_ref.strip()
    if not source_ref or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", source_ref):
        return None
    ref_path = Path(source_ref)
    candidates = [
        ref_path,
        tag_dir / ref_path.name,
        tag_dir.parent / ref_path,
    ]
    tag_root = tag_dir.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(tag_root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            return resolved
    return None


# ---------------------------------------------------------------------------
# Engagement crawler (operator-local PoC discovery)
# ---------------------------------------------------------------------------

def _filename_tokens(name: str) -> set[str]:
    """Extract lowercase identifier tokens from a filename, minus stopwords."""
    stem = name.rsplit(".", 1)[0].lower()
    tokens = {tok for tok in FILENAME_TOKEN_RE.findall(stem) if len(tok) > 1 and tok not in STOPWORD_TOKENS}
    return tokens

def _record_tokens(text: str) -> set[str]:
    """Extract candidate-matching tokens from a hackerman record yaml."""
    tokens: set[str] = set()
    for regex in (RECORD_ID_RE, TARGET_COMPONENT_RE, ATTACK_CLASS_RE, BUG_CLASS_RE, TARGET_REPO_RE):
        match = regex.search(text)
        if match:
            tokens |= _filename_tokens(match.group(1))
    return tokens


def _match_confidence(score: float, path_fanout: int, high_confidence: float) -> tuple[str, str]:
    """Return conservative confidence level and reason code."""
    if score < high_confidence:
        return "low", "score_below_threshold"
    if path_fanout > CONFIDENT_MATCH_MAX_PATH_FANOUT:
        return "low", "path_fanout_too_broad"
    return "high", "path_specificity_passed"


def _promotion_annotation(row: dict[str, Any]) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if row.get("match_confidence") != "high":
        blockers.append(str(row.get("match_confidence_reason") or "confidence_not_high"))
    path_fanout = int(row.get("candidate_path_occurrence") or 0)
    if path_fanout <= 0:
        blockers.append("candidate_path_occurrence_missing")
    elif path_fanout > PROMOTION_READY_MAX_PATH_FANOUT:
        blockers.append("path_fanout_above_promotion_limit")
    return not blockers, blockers


def _normalize_engagement_path(absolute: Path, engagement_root: Path, engagement_name: str) -> str:
    """Render the candidate path relative to repo-root convention.

    Convention: ``audits/<engagement>/<path-inside-engagement>``.
    Never returns an absolute path containing /Users/... or $HOME.
    """
    try:
        relative = absolute.resolve().relative_to(engagement_root.resolve())
    except ValueError:
        # Fall back to the raw path components after the engagement name if present.
        parts = absolute.as_posix().split("/")
        if engagement_name in parts:
            idx = parts.index(engagement_name)
            relative = Path(*parts[idx + 1 :])
        else:
            relative = Path(absolute.name)
    return f"audits/{engagement_name}/{relative.as_posix()}"


def _scan_paste_ready_proof_lines(engagement_root: Path, engagement_name: str) -> list[tuple[set[str], str, str]]:
    """Return [(token_set, candidate_path, source_md)] from paste-ready md files."""
    out: list[tuple[set[str], str, str]] = []
    paste_dirs = [
        engagement_root / "submissions" / "paste_ready",
        engagement_root / "submissions" / "paste_ready" / "filed",
    ]
    for d in paste_dirs:
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*.md")):
            try:
                text = md.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            md_tokens = _filename_tokens(md.name)
            for match in PASTE_READY_PROOF_RE.finditer(text):
                raw_path = match.group(1).strip()
                if not raw_path:
                    continue
                # Heuristic: if the path is absolute, keep as-is; otherwise normalize
                # relative paths against the engagement root.
                if raw_path.startswith("/"):
                    abs_path = Path(raw_path)
                elif raw_path.startswith("audits/"):
                    abs_path = Path.home() / raw_path
                else:
                    abs_path = engagement_root / raw_path
                candidate = _normalize_engagement_path(abs_path, engagement_root, engagement_name)
                token_set = set()
                token_set.update(md_tokens)
                token_set.update(_filename_tokens(raw_path))
                out.append((token_set, candidate, md.name))
    return out


def _scan_poc_test_files(engagement_root: Path, engagement_name: str) -> list[tuple[set[str], str, str]]:
    """Return [(token_set, candidate_path, source_kind)] from poc-tests/ + external/."""
    out: list[tuple[set[str], str, str]] = []
    poc_root = engagement_root / "poc-tests"
    if poc_root.is_dir():
        for lead_dir in sorted(p for p in poc_root.iterdir() if p.is_dir()):
            lead_tokens = _filename_tokens(lead_dir.name)
            for f in sorted(lead_dir.rglob("*")):
                if not f.is_file():
                    continue
                if f.suffix not in {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py"}:
                    continue
                token_blob = set(lead_tokens)
                token_blob.update(_filename_tokens(f.name))
                candidate = _normalize_engagement_path(f, engagement_root, engagement_name)
                out.append((token_blob, candidate, "poc-tests"))
    # In-tree PoC files: external/*/protocol/.../{*_poc_test.go,hackerman_*_test.go}.
    external = engagement_root / "external"
    if external.is_dir():
        for pattern in ("*_poc_test.go", "hackerman_*_test.go"):
            for f in external.rglob(pattern):
                if not f.is_file():
                    continue
                token_blob = set(_filename_tokens(f.name) | _filename_tokens(f.parent.name))
                candidate = _normalize_engagement_path(f, engagement_root, engagement_name)
                out.append((token_blob, candidate, "in-tree-poc"))
    return out


def _score_match(record_tokens: set[str], cand_tokens: set[str]) -> float:
    """Jaccard-like overlap on filename/path/record tokens, 0..1."""
    if not record_tokens:
        return 0.0
    if not cand_tokens:
        return 0.0
    intersection = record_tokens & cand_tokens
    if not intersection:
        return 0.0
    union = record_tokens | cand_tokens
    return len(intersection) / len(union)


def crawl_engagements(
    tag_dir: Path,
    engagements: list[Path],
    *,
    out_path: Path,
    min_score: float = 0.20,
    high_confidence: float = 0.45,
    limit: int = 0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Crawl operator-local engagement workspaces for PoC artifacts.

    Emits candidates JSONL at ``out_path``. Each row:
      {"record_id", "candidate_proof_path", "engagement", "match_score",
       "match_method", "source_yaml", "source_artifact"}
    """
    # Build PoC candidate index keyed by engagement.
    eng_index: dict[str, list[tuple[set[str], str, str]]] = {}
    for eng_root in engagements:
        eng_root = Path(eng_root).expanduser()
        if not eng_root.is_dir():
            continue
        name = eng_root.name
        bundle = _scan_paste_ready_proof_lines(eng_root, name) + _scan_poc_test_files(eng_root, name)
        if bundle:
            eng_index[name] = bundle

    candidates: list[dict[str, Any]] = []
    scanned = 0
    skipped_existing = 0
    matched_records = 0
    high_confidence_count = 0

    for path in sorted(tag_dir.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _is_hackerman_record(text):
            continue
        scanned += 1
        if "proof_artifact_path:" in text:
            skipped_existing += 1
            continue
        rec_id_match = RECORD_ID_RE.search(text)
        if not rec_id_match:
            continue
        record_id = rec_id_match.group(1).strip()
        rec_tokens = _record_tokens(text)
        if not rec_tokens:
            continue
        # Pre-filter to engagements whose name appears as a record token,
        # falling back to all engagements when no obvious bind.
        target_engs = [eng for eng in eng_index if eng in rec_tokens]
        if not target_engs:
            target_engs = list(eng_index.keys())
        best_row: dict[str, Any] | None = None
        for eng_name in target_engs:
            for token_set, candidate_path, source_artifact in eng_index[eng_name]:
                score = _score_match(rec_tokens, token_set)
                if score < min_score:
                    continue
                row = {
                    "schema": CRAWL_SCHEMA,
                    "record_id": record_id,
                    "record_yaml": path.name,
                    "candidate_proof_path": candidate_path,
                    "engagement": eng_name,
                    "candidate_token_count": len(token_set),
                    "record_token_count": len(rec_tokens),
                    "match_token_overlap": len(rec_tokens & token_set),
                    "match_score": round(score, 4),
                    "match_method": "jaccard-filename-tokens",
                    "match_confidence": "low",
                    "match_confidence_reason": "pending_review",
                    "source_artifact": source_artifact,
                }
                if best_row is None or row["match_score"] > best_row["match_score"]:
                    best_row = row
        if best_row is not None:
            candidates.append(best_row)
            matched_records += 1
            if best_row["match_confidence"] == "high":
                high_confidence_count += 1
            if limit and matched_records >= limit:
                break

    path_fanout = Counter(row["candidate_proof_path"] for row in candidates)
    promotion_blocker_counts: Counter[str] = Counter()
    for row in candidates:
        path_count = path_fanout[row["candidate_proof_path"]]
        row["candidate_path_occurrence"] = path_count
        row["candidate_path_specificity"] = round(1.0 / path_count, 4) if path_count else 0.0
        confidence, reason = _match_confidence(
            float(row["match_score"]),
            path_count,
            high_confidence,
        )
        row["match_confidence"] = confidence
        row["match_confidence_reason"] = reason
        promotion_ready, promotion_blockers = _promotion_annotation(row)
        row["promotion_ready"] = promotion_ready
        row["promotion_blockers"] = promotion_blockers
        promotion_blocker_counts.update(promotion_blockers)
    high_confidence_count = sum(1 for row in candidates if row["match_confidence"] == "high")
    promotion_ready_count = sum(1 for row in candidates if row["promotion_ready"])

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in candidates:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    path_fanout_top = [
        {"candidate_proof_path": k, "occurrences": v}
        for k, v in path_fanout.most_common(FANOUT_REPORT_LIMIT)
    ]

    return {
        "schema": SCHEMA + "+crawl",
        "tag_dir": str(tag_dir),
        "engagements_scanned": list(eng_index.keys()),
        "engagement_artifact_count": {k: len(v) for k, v in eng_index.items()},
        "scanned_hackerman_records": scanned,
        "skipped_existing": skipped_existing,
        "matched_records": matched_records,
        "high_confidence_matches": high_confidence_count,
        "promotion_ready_candidates": promotion_ready_count,
        "promotion_ready_max_path_fanout": PROMOTION_READY_MAX_PATH_FANOUT,
        "promotion_blocker_counts": dict(sorted(promotion_blocker_counts.items())),
        "min_score": min_score,
        "high_confidence_threshold": high_confidence,
        "path_fanout_limit": CONFIDENT_MATCH_MAX_PATH_FANOUT,
        "path_fanout_top": path_fanout_top,
        "candidates_out": str(out_path),
        "dry_run": dry_run,
        "sample_candidates": candidates[:10],
    }


def mine_proof_hardening_sidecar(
    tag_dir: Path,
    sidecar_path: Path,
    *,
    out_path: Path,
    limit: int = 0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Mine proof_artifact_path candidates from proof-hardening sidecar rows.

    This path is candidates-only. It uses the sidecar's direct ``source_ref``
    pointer instead of legacy ``# source_tag_file`` comments, validates the
    sidecar ``record_id`` against the target YAML, and emits JSONL rows for a
    later human-reviewed apply step.
    """
    scanned_sidecar_rows = 0
    sidecar_rows_with_proof = 0
    resolved_source_refs = 0
    scanned_hackerman_records = 0
    skipped_existing = 0
    skipped_missing_source_ref = 0
    skipped_mismatch = 0
    skipped_unsafe = 0
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    if not sidecar_path.is_file():
        return {
            "schema": SCHEMA + "+sidecar",
            "candidate_schema": SIDECAR_SCHEMA,
            "tag_dir": str(tag_dir),
            "sidecar_path": str(sidecar_path),
            "candidates_out": str(out_path),
            "dry_run": dry_run,
            "sidecar_found": False,
            "scanned_sidecar_rows": 0,
            "sidecar_rows_with_proof": 0,
            "resolved_source_refs": 0,
            "scanned_hackerman_records": 0,
            "skipped_existing": 0,
            "skipped_missing_source_ref": 0,
            "skipped_record_id_mismatch": 0,
            "skipped_unsafe": 0,
            "candidate_count": 0,
            "sample_candidates": [],
        }

    for line in sidecar_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_sidecar_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        proof_artifacts = row.get("proof_artifacts")
        if not isinstance(proof_artifacts, list) or not proof_artifacts:
            continue
        sidecar_rows_with_proof += 1
        source_ref = str(row.get("source_ref") or "").strip()
        record_path = _source_ref_to_record_path(source_ref, tag_dir)
        if record_path is None:
            skipped_missing_source_ref += 1
            continue
        resolved_source_refs += 1
        try:
            record_text = record_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            skipped_missing_source_ref += 1
            continue
        if not _is_hackerman_record(record_text):
            continue
        scanned_hackerman_records += 1
        if "proof_artifact_path:" in record_text:
            skipped_existing += 1
            continue
        sidecar_record_id = str(row.get("record_id") or "").strip()
        yaml_record_id = _record_id(record_text)
        if not sidecar_record_id or not yaml_record_id or sidecar_record_id != yaml_record_id:
            skipped_mismatch += 1
            continue
        for raw in proof_artifacts:
            raw_proof_path = str(raw or "").strip()
            proof_path = _clean_path(raw_proof_path)
            if not proof_path:
                skipped_unsafe += 1
                continue
            dedupe_key = (yaml_record_id, record_path.name, proof_path)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            candidates.append(
                {
                    "schema": SIDECAR_SCHEMA,
                    "record_id": yaml_record_id,
                    "record_yaml": record_path.name,
                    "candidate_proof_path": proof_path,
                    "raw_proof_artifact_path": raw_proof_path,
                    "match_method": "proof-hardening-source-ref-record-id",
                    "match_confidence": "direct",
                    "source_sidecar": str(sidecar_path),
                    "sidecar_source_ref": source_ref,
                    "proof_maturity_score": row.get("proof_maturity_score"),
                    "evidence_class": row.get("evidence_class"),
                }
            )
            if limit and len(candidates) >= limit:
                break
        if limit and len(candidates) >= limit:
            break

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in candidates:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": SCHEMA + "+sidecar",
        "candidate_schema": SIDECAR_SCHEMA,
        "tag_dir": str(tag_dir),
        "sidecar_path": str(sidecar_path),
        "candidates_out": str(out_path),
        "dry_run": dry_run,
        "sidecar_found": True,
        "scanned_sidecar_rows": scanned_sidecar_rows,
        "sidecar_rows_with_proof": sidecar_rows_with_proof,
        "resolved_source_refs": resolved_source_refs,
        "scanned_hackerman_records": scanned_hackerman_records,
        "skipped_existing": skipped_existing,
        "skipped_missing_source_ref": skipped_missing_source_ref,
        "skipped_record_id_mismatch": skipped_mismatch,
        "skipped_unsafe": skipped_unsafe,
        "candidate_count": len(candidates),
        "sample_candidates": candidates[:10],
    }


def _bounded_review_limit(limit: int) -> int:
    if limit <= 0:
        return PROMOTION_REVIEW_PLAN_DEFAULT_LIMIT
    return min(limit, PROMOTION_REVIEW_PLAN_MAX_LIMIT)


def _resolve_plan_record(row: dict[str, Any], tag_dir: Path) -> tuple[Path | None, str]:
    """Resolve an optional exact record pointer from an index/plan row."""
    record_yaml = str(row.get("record_yaml") or "").strip()
    if record_yaml:
        if Path(record_yaml).name != record_yaml or not record_yaml.endswith(".yaml"):
            return None, "record_yaml_not_basename"
        candidate = tag_dir / record_yaml
        if candidate.is_file():
            return candidate, "record_yaml"
        return None, "record_yaml_missing"

    source_ref = str(row.get("source_ref") or row.get("sidecar_source_ref") or "").strip()
    if source_ref:
        record_path = _source_ref_to_record_path(source_ref, tag_dir)
        if record_path is not None:
            return record_path, "source_ref"
        return None, "source_ref_unresolved"

    return None, "needs_record_yaml"


def _submission_ref_from_submission_path(submission_path: str) -> str:
    path = _clean_path(submission_path)
    if not path:
        return ""
    parts = Path(path).parts
    if len(parts) < 4 or parts[0] != "audits" or parts[2] != "submissions":
        return ""
    return Path(*parts[3:]).as_posix()


def _load_submission_ref_resolution_map(tag_dir: Path) -> dict[str, dict[str, str]]:
    derived_dir = tag_dir.parent / "derived"
    candidates: dict[str, dict[str, set[str]]] = {}

    def ref_aliases(ref: str) -> list[str]:
        aliases = [ref]
        if ref.startswith("submission-derived:"):
            parts = ref.split(":", 2)
            if len(parts) == 3 and parts[2]:
                aliases.append(parts[2])
        if "/submissions/" in ref:
            aliases.append(ref.split("/submissions/", 1)[1])
        out: list[str] = []
        seen: set[str] = set()
        for alias in aliases:
            cleaned = alias.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                out.append(cleaned)
        return out

    for sidecar_name in SUBMISSION_REF_RESOLUTION_SIDECARS:
        sidecar_path = derived_dir / sidecar_name
        if not sidecar_path.is_file():
            continue
        for line in sidecar_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            ref = str(row.get("source_audit_ref") or row.get("source_ref") or "").strip()
            tag_file = str(row.get("tag_file") or row.get("file_name") or "").strip()
            record_id = str(row.get("record_id") or "").strip()
            if not ref or not tag_file:
                continue
            if Path(tag_file).name != tag_file or not tag_file.endswith(".yaml"):
                continue
            if not (tag_dir / tag_file).is_file():
                continue
            for ref_key in ref_aliases(ref):
                bucket = candidates.setdefault(ref_key, {"record_yaml": set(), "record_id": set(), "sources": set()})
                bucket["record_yaml"].add(tag_file)
                if record_id:
                    bucket["record_id"].add(record_id)
                bucket["sources"].add(sidecar_name)

    resolved: dict[str, dict[str, str]] = {}
    for ref, bucket in candidates.items():
        record_yamls = bucket["record_yaml"]
        record_ids = bucket["record_id"]
        if len(record_yamls) != 1:
            continue
        if len(record_ids) > 1:
            continue
        resolved[ref] = {
            "record_yaml": next(iter(record_yamls)),
            "record_id": next(iter(record_ids)) if record_ids else "",
            "resolution_source": "+".join(sorted(bucket["sources"])),
        }
    return resolved


def _record_proof_artifact_paths(record_text: str) -> list[str]:
    paths: list[str] = []
    scalar_path = _clean_path(_field_value(record_text, "proof_artifact_path"))
    if scalar_path:
        paths.append(scalar_path)

    in_list = False
    for line in record_text.splitlines():
        if re.match(r"^all_proof_artifact_paths:\s*$", line):
            in_list = True
            continue
        if not in_list:
            continue
        if line and not line.startswith((" ", "\t")):
            break
        match = re.match(r"^\s*-\s+(.+?)\s*$", line)
        if not match:
            continue
        cleaned = _clean_path(match.group(1).strip().strip("'\"`"))
        if cleaned:
            paths.append(cleaned)

    out: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _proof_path_resolution_keys(value: str) -> list[str]:
    cleaned = _clean_path(value)
    if not cleaned:
        return []
    parts = Path(cleaned).parts
    keys = [cleaned]
    if len(parts) >= 3 and parts[0] == "audits":
        keys.append(Path(*parts[2:]).as_posix())
    if len(parts) > 1:
        for index in range(max(0, len(parts) - 6), len(parts) - 1):
            suffix = Path(*parts[index:]).as_posix()
            if "/" in suffix:
                keys.append(suffix)
    out: list[str] = []
    seen: set[str] = set()
    for key in keys:
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _load_proof_path_resolution_map(tag_dir: Path) -> dict[str, dict[str, str]]:
    candidates: dict[str, dict[str, set[str]]] = {}
    for tag_path in sorted(tag_dir.glob("*.yaml")):
        try:
            record_text = tag_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _is_hackerman_record(record_text):
            continue
        record_id = _record_id(record_text)
        for proof_path in _record_proof_artifact_paths(record_text):
            for key in _proof_path_resolution_keys(proof_path):
                bucket = candidates.setdefault(key, {"record_yaml": set(), "record_id": set(), "sources": set()})
                bucket["record_yaml"].add(tag_path.name)
                if record_id:
                    bucket["record_id"].add(record_id)
                bucket["sources"].add("proof_artifact_path")

    resolved: dict[str, dict[str, str]] = {}
    for key, bucket in candidates.items():
        record_yamls = bucket["record_yaml"]
        record_ids = bucket["record_id"]
        if len(record_yamls) != 1:
            continue
        if len(record_ids) > 1:
            continue
        resolved[key] = {
            "record_yaml": next(iter(record_yamls)),
            "record_id": next(iter(record_ids)) if record_ids else "",
            "resolution_source": "+".join(sorted(bucket["sources"])),
        }
    return resolved


def _resolve_record_by_proof_path(
    proof_path: str,
    proof_path_resolution_map: dict[str, dict[str, str]],
) -> tuple[dict[str, str] | None, str]:
    for key in _proof_path_resolution_keys(proof_path):
        resolved = proof_path_resolution_map.get(key)
        if resolved:
            return resolved, key
    return None, ""


def _slugify_record_hint(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:96] or "missing-hackerman-record"


def _missing_record_queue_candidate(plan_row: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_proof_path": plan_row["candidate_proof_path"],
        "raw_candidate_proof_path": plan_row["raw_candidate_proof_path"],
        "candidate_artifact_kind": plan_row["candidate_artifact_kind"],
        "candidate_path_occurrence": plan_row["candidate_path_occurrence"],
        "promotion_review_reason": plan_row["promotion_review_reason"],
    }


def _add_missing_record_import_queue_row(
    queue_rows_by_key: dict[str, dict[str, Any]],
    plan_row: dict[str, Any],
) -> None:
    submission_ref = _submission_ref_from_submission_path(str(plan_row.get("submission_path") or ""))
    queue_key = submission_ref or str(plan_row.get("submission_path") or "") or str(plan_row.get("candidate_proof_path") or "")
    if not queue_key:
        return

    title = str(plan_row.get("submission_title") or "")
    submission_path = str(plan_row.get("submission_path") or "")
    record_hint_source = title or Path(submission_path).stem or queue_key
    row = queue_rows_by_key.get(queue_key)
    if row is None:
        row = {
            "schema": MISSING_RECORD_IMPORT_QUEUE_SCHEMA,
            "import_status": "pending_review",
            "source": "proof_artifact_index_promotion_review",
            "queue_key": queue_key,
            "suggested_source_audit_ref": submission_ref,
            "suggested_record_slug": _slugify_record_hint(record_hint_source),
            "engagement": str(plan_row.get("engagement") or ""),
            "submission_path": submission_path,
            "submission_status": str(plan_row.get("submission_status") or ""),
            "submission_title": title,
            "record_resolution": str(plan_row.get("record_resolution") or ""),
            "review_plan_apply_status": str(plan_row.get("apply_status") or ""),
            "blockers": list(plan_row.get("blockers") or []),
            "safety_flags": [
                "record_yaml_missing",
                "manual_record_creation_required",
                "no_yaml_write_performed",
            ],
            "proof_artifact_candidates": [],
            "candidate_count": 0,
        }
        queue_rows_by_key[queue_key] = row

    candidate = _missing_record_queue_candidate(plan_row)
    existing_keys = {
        (item.get("candidate_proof_path"), item.get("raw_candidate_proof_path"))
        for item in row["proof_artifact_candidates"]
    }
    candidate_key = (candidate["candidate_proof_path"], candidate["raw_candidate_proof_path"])
    if candidate_key not in existing_keys:
        row["proof_artifact_candidates"].append(candidate)
        row["candidate_count"] = len(row["proof_artifact_candidates"])


def _promotion_index_row_blockers(row: dict[str, Any], proof_path: str, submission_path: str) -> list[str]:
    blockers: list[str] = []
    seen: set[str] = set()

    def add(reason: str) -> None:
        if reason and reason not in seen:
            seen.add(reason)
            blockers.append(reason)

    if row.get("promotion_ready") is not True:
        add("promotion_ready_not_true")
    if row.get("promotion_review_status") not in ("ready", None, ""):
        add("promotion_review_status_not_ready")
    if row.get("confidence") not in ("high", "direct"):
        add("confidence_not_high")
    if row.get("candidate_artifact_exists") is False:
        add("candidate_artifact_missing")
    promotion_blockers = row.get("promotion_blockers")
    if isinstance(promotion_blockers, list):
        for reason in promotion_blockers:
            add(str(reason))
    elif promotion_blockers:
        add("promotion_blockers_present")
    if not proof_path:
        add("unsafe_candidate_proof_path")
    if row.get("submission_path") and not submission_path:
        add("unsafe_submission_path")
    path_fanout = int(row.get("candidate_path_occurrence") or 0)
    if path_fanout <= 0:
        add("candidate_path_occurrence_missing")
    elif path_fanout > PROMOTION_READY_MAX_PATH_FANOUT:
        add("path_fanout_above_promotion_limit")
    return blockers


def review_proof_artifact_index(
    tag_dir: Path,
    index_path: Path,
    *,
    out_path: Path,
    missing_record_import_queue_out: Path | None = None,
    limit: int = PROMOTION_REVIEW_PLAN_DEFAULT_LIMIT,
    dry_run: bool = False,
    include_blocked_index_rows: bool = False,
) -> dict[str, Any]:
    """Build a bounded promotion review/apply plan from proof_artifact_index rows.

    The refreshed index has submission-level rows, not guaranteed record-level
    write targets. This pass therefore emits review rows by default and only
    marks a row ``ready_to_apply`` when an exact ``record_yaml`` / ``source_ref``
    pointer is present and re-validates against the target YAML. With
    ``include_blocked_index_rows``, the plan also includes non-promotable index
    rows as explanatory ``not_promotable`` dry-run artifacts; apply mode ignores
    them.
    """
    scanned_index_rows = 0
    promotion_ready_rows = 0
    emitted_rows = 0
    invalid_json_rows = 0
    plan_rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    bounded_limit = _bounded_review_limit(limit)
    submission_ref_resolution_map = _load_submission_ref_resolution_map(tag_dir)
    proof_path_resolution_map = _load_proof_path_resolution_map(tag_dir)
    parsed_rows: list[dict[str, Any]] = []
    missing_record_queue_by_key: dict[str, dict[str, Any]] = {}

    if not index_path.is_file():
        return {
            "schema": SCHEMA + "+promotion-review",
            "plan_schema": PROMOTION_PLAN_SCHEMA,
            "tag_dir": str(tag_dir),
            "proof_artifact_index": str(index_path),
            "review_plan_out": str(out_path),
            "missing_record_import_queue_out": str(missing_record_import_queue_out or ""),
            "dry_run": dry_run,
            "index_found": False,
            "scanned_index_rows": 0,
            "promotion_ready_rows": 0,
            "plan_rows": 0,
            "ready_to_apply": 0,
            "review_required": 0,
            "blocked": 0,
            "not_promotable": 0,
            "status_counts": {},
            "blocker_counts": {},
            "missing_record_import_candidates": 0,
            "include_blocked_index_rows": include_blocked_index_rows,
            "limit": bounded_limit,
            "sample_plan_rows": [],
        }

    for line in index_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_index_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            invalid_json_rows += 1
            continue
        submission_ref = _submission_ref_from_submission_path(str(row.get("submission_path") or ""))
        if submission_ref and not row.get("record_yaml"):
            resolved = submission_ref_resolution_map.get(submission_ref)
            if resolved:
                row["record_yaml"] = resolved["record_yaml"]
                if resolved["record_id"] and not row.get("record_id"):
                    row["record_id"] = resolved["record_id"]
                row["source_ref"] = submission_ref
                row["record_resolution_source"] = "derived_submission_ref:" + resolved["resolution_source"]
        if not row.get("record_yaml"):
            proof_resolved, proof_key = _resolve_record_by_proof_path(
                str(row.get("candidate_proof_path") or ""),
                proof_path_resolution_map,
            )
            if proof_resolved:
                row["record_yaml"] = proof_resolved["record_yaml"]
                if proof_resolved["record_id"] and not row.get("record_id"):
                    row["record_id"] = proof_resolved["record_id"]
                row["record_resolution_source"] = (
                    "derived_proof_artifact_path:" + proof_resolved["resolution_source"] + ":" + proof_key
                )
        parsed_rows.append(row)

    distinct_candidate_paths_by_record_yaml: dict[str, set[str]] = {}
    for row in parsed_rows:
        record_yaml = str(row.get("record_yaml") or "").strip()
        candidate_proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
        if not record_yaml or not candidate_proof_path:
            continue
        distinct_candidate_paths_by_record_yaml.setdefault(record_yaml, set()).add(candidate_proof_path)

    auto_resolved_rows = 0
    auto_resolved_unique_refs: set[str] = set()
    auto_resolved_proof_path_rows = 0
    auto_resolved_unique_proof_paths: set[str] = set()
    for row in parsed_rows:
        index_promotion_ready = row.get("promotion_ready") is True
        if not index_promotion_ready and not include_blocked_index_rows:
            continue
        if index_promotion_ready:
            promotion_ready_rows += 1
        if emitted_rows >= bounded_limit:
            continue

        proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
        submission_path = _clean_path(str(row.get("submission_path") or ""))
        blockers = _promotion_index_row_blockers(row, proof_path, submission_path)
        record_path, record_resolution = _resolve_plan_record(row, tag_dir)
        record_id = ""
        existing_proof_path = ""
        record_resolution_source = str(row.get("record_resolution_source") or "")
        if record_resolution_source.startswith("derived_submission_ref:"):
            auto_resolved_rows += 1
            submission_ref = _submission_ref_from_submission_path(str(row.get("submission_path") or ""))
            if submission_ref:
                auto_resolved_unique_refs.add(submission_ref)
        elif record_resolution_source.startswith("derived_proof_artifact_path:"):
            auto_resolved_rows += 1
            auto_resolved_proof_path_rows += 1
            proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
            if proof_path:
                auto_resolved_unique_proof_paths.add(proof_path)
        if record_path is None and index_promotion_ready:
            if not blockers:
                blockers.append(record_resolution)
        elif record_path is not None:
            try:
                record_text = record_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                record_text = ""
                blockers.append("record_yaml_unreadable")
            if record_text:
                if not _is_hackerman_record(record_text):
                    blockers.append("record_yaml_not_hackerman")
                record_id = _record_id(record_text)
                expected_record_id = str(row.get("record_id") or "").strip()
                if expected_record_id and record_id != expected_record_id:
                    blockers.append("record_id_mismatch")
                existing_proof_path = _field_value(record_text, "proof_artifact_path")
                record_yaml = record_path.name
                candidate_path_count = len(distinct_candidate_paths_by_record_yaml.get(record_yaml, set()))
                if not existing_proof_path and candidate_path_count > 1:
                    blockers.append("multiple_candidate_proof_paths_for_record_yaml")

        if not index_promotion_ready:
            apply_status = "not_promotable"
            action = "none"
        elif blockers:
            apply_status = (
                "review_required"
                if blockers == [record_resolution] and record_resolution in {"needs_record_yaml", "source_ref_unresolved"}
                else "blocked"
            )
            action = "manual_review"
        elif existing_proof_path:
            apply_status = "already_has_proof_artifact_path"
            action = "none"
        else:
            apply_status = "ready_to_apply"
            action = "insert_proof_artifact_path"

        plan_row = {
            "schema": PROMOTION_PLAN_SCHEMA,
            "action": action,
            "apply_status": apply_status,
            "blockers": blockers,
            "record_yaml": record_path.name if record_path is not None else str(row.get("record_yaml") or ""),
            "record_id": record_id or str(row.get("record_id") or ""),
            "record_resolution": record_resolution,
            "record_resolution_source": record_resolution_source,
            "candidate_proof_path": proof_path,
            "raw_candidate_proof_path": str(row.get("candidate_proof_path") or ""),
            "candidate_path_occurrence": int(row.get("candidate_path_occurrence") or 0),
            "candidate_artifact_kind": str(row.get("candidate_artifact_kind") or ""),
            "engagement": str(row.get("engagement") or ""),
            "submission_path": submission_path,
            "submission_status": str(row.get("submission_status") or ""),
            "submission_title": str(row.get("submission_title") or ""),
            "promotion_review_reason": str(row.get("promotion_review_reason") or ""),
            "source_index_promotion_ready": index_promotion_ready,
            "source_index_promotion_blockers": row.get("promotion_blockers") if isinstance(row.get("promotion_blockers"), list) else [],
        }
        if existing_proof_path:
            plan_row["existing_proof_artifact_path"] = existing_proof_path
        if (
            apply_status == "review_required"
            and record_resolution in {"needs_record_yaml", "source_ref_unresolved"}
            and proof_path
            and submission_path
        ):
            queue_key = _submission_ref_from_submission_path(submission_path) or submission_path
            plan_row["missing_record_import_candidate"] = True
            plan_row["missing_record_import_key"] = queue_key
            _add_missing_record_import_queue_row(missing_record_queue_by_key, plan_row)
        plan_rows.append(plan_row)
        emitted_rows += 1
        status_counts.update([apply_status])
        blocker_counts.update(blockers)

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in plan_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        if missing_record_import_queue_out is not None:
            missing_record_import_queue_out.parent.mkdir(parents=True, exist_ok=True)
            queue_rows = [missing_record_queue_by_key[key] for key in sorted(missing_record_queue_by_key)]
            with missing_record_import_queue_out.open("w", encoding="utf-8") as fh:
                for row in queue_rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": SCHEMA + "+promotion-review",
        "plan_schema": PROMOTION_PLAN_SCHEMA,
        "missing_record_import_queue_schema": MISSING_RECORD_IMPORT_QUEUE_SCHEMA,
        "tag_dir": str(tag_dir),
        "proof_artifact_index": str(index_path),
        "review_plan_out": str(out_path),
        "missing_record_import_queue_out": str(missing_record_import_queue_out or ""),
        "dry_run": dry_run,
        "index_found": True,
        "scanned_index_rows": scanned_index_rows,
        "invalid_json_rows": invalid_json_rows,
        "promotion_ready_rows": promotion_ready_rows,
        "plan_rows": len(plan_rows),
        "ready_to_apply": status_counts.get("ready_to_apply", 0),
        "already_has_proof_artifact_path": status_counts.get("already_has_proof_artifact_path", 0),
        "review_required": status_counts.get("review_required", 0),
        "blocked": status_counts.get("blocked", 0),
        "not_promotable": status_counts.get("not_promotable", 0),
        "status_counts": dict(sorted(status_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "missing_record_import_candidates": len(missing_record_queue_by_key),
        "auto_resolved_rows": auto_resolved_rows,
        "auto_resolved_unique_submission_refs": len(auto_resolved_unique_refs),
        "auto_resolved_proof_path_rows": auto_resolved_proof_path_rows,
        "auto_resolved_unique_proof_paths": len(auto_resolved_unique_proof_paths),
        "include_blocked_index_rows": include_blocked_index_rows,
        "limit": bounded_limit,
        "sample_plan_rows": plan_rows[:10],
    }


def status_only_blocker_review(
    index_path: Path,
    *,
    out_path: Path,
    limit: int = 0,
    dry_run: bool = False,
    statuses: set[str] | None = None,
) -> dict[str, Any]:
    """Emit a report-only queue for the safest status-only blocked rows.

    This is intentionally non-mutating. Rows here are explicit proof-artifact
    candidates that pass every mechanical promotion signal except the
    submission-status gate. They are not auto-promoted because status
    reconciliation is an operator/record-curation decision.
    """
    allowed_statuses = statuses or STATUS_ONLY_REVIEW_STATUSES
    scanned_index_rows = 0
    invalid_json_rows = 0
    exact_status_only_rows = 0
    eligible_rows: list[dict[str, Any]] = []
    by_status: Counter[str] = Counter()
    by_engagement: Counter[str] = Counter()
    rejected_reasons: Counter[str] = Counter()

    if not index_path.is_file():
        return {
            "schema": SCHEMA + "+status-only-review",
            "row_schema": STATUS_ONLY_REVIEW_SCHEMA,
            "proof_artifact_index": str(index_path),
            "review_queue_out": str(out_path),
            "dry_run": dry_run,
            "index_found": False,
            "scanned_index_rows": 0,
            "invalid_json_rows": 0,
            "exact_status_only_rows": 0,
            "eligible_rows": 0,
            "rows_written": 0,
            "allowed_statuses": sorted(allowed_statuses),
            "by_status": {},
            "by_engagement": {},
            "rejected_reasons": {},
            "sample_rows": [],
        }

    for line in index_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_index_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            invalid_json_rows += 1
            continue
        if not isinstance(row, dict):
            invalid_json_rows += 1
            continue

        blockers = row.get("promotion_blockers")
        if blockers != ["submission_status_not_paste_ready_or_filed"]:
            rejected_reasons["not_exact_status_only_blocker"] += 1
            continue
        exact_status_only_rows += 1

        proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
        submission_path = _clean_path(str(row.get("submission_path") or ""))
        status = str(row.get("submission_status") or "").strip()
        confidence = str(row.get("confidence") or "").strip()
        try:
            path_fanout = int(row.get("candidate_path_occurrence") or 0)
        except (TypeError, ValueError):
            path_fanout = 0

        row_rejections: list[str] = []
        if status not in allowed_statuses:
            row_rejections.append("submission_status_not_in_review_set")
        if row.get("candidate_artifact_exists") is not True:
            row_rejections.append("candidate_artifact_missing")
        if confidence not in {"high", "direct"}:
            row_rejections.append("confidence_not_high")
        if path_fanout <= 0:
            row_rejections.append("candidate_path_occurrence_missing")
        elif path_fanout > PROMOTION_READY_MAX_PATH_FANOUT:
            row_rejections.append("path_fanout_above_promotion_limit")
        if not proof_path:
            row_rejections.append("unsafe_candidate_proof_path")
        if row.get("submission_path") and not submission_path:
            row_rejections.append("unsafe_submission_path")
        if row_rejections:
            rejected_reasons.update(row_rejections)
            continue

        review_row = {
            "schema": STATUS_ONLY_REVIEW_SCHEMA,
            "review_status": "manual_status_reconciliation",
            "status_only_blocker": True,
            "recommended_action": "manual_status_reconciliation",
            "safety_note": (
                "Report-only: do not write proof_artifact_path until the "
                "submission status is reconciled to paste_ready/filed semantics "
                "or a Hackerman record owner confirms promotion."
            ),
            "candidate_proof_path": proof_path,
            "raw_candidate_proof_path": str(row.get("candidate_proof_path") or ""),
            "candidate_artifact_kind": str(row.get("candidate_artifact_kind") or ""),
            "candidate_artifact_exists": True,
            "candidate_path_occurrence": path_fanout,
            "confidence": confidence,
            "confidence_score": row.get("confidence_score"),
            "engagement": str(row.get("engagement") or ""),
            "submission_path": submission_path,
            "submission_status": status,
            "submission_title": str(row.get("submission_title") or ""),
            "promotion_blockers": blockers,
            "promotion_review_reason": str(row.get("promotion_review_reason") or ""),
            "source_reasons": row.get("source_reasons") if isinstance(row.get("source_reasons"), list) else [],
            "raw_reference": str(row.get("raw_reference") or ""),
        }
        eligible_rows.append(review_row)
        by_status[status] += 1
        by_engagement[review_row["engagement"] or "_unknown"] += 1
        if limit and len(eligible_rows) >= limit:
            break

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in eligible_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": SCHEMA + "+status-only-review",
        "row_schema": STATUS_ONLY_REVIEW_SCHEMA,
        "proof_artifact_index": str(index_path),
        "review_queue_out": str(out_path),
        "dry_run": dry_run,
        "index_found": True,
        "scanned_index_rows": scanned_index_rows,
        "invalid_json_rows": invalid_json_rows,
        "exact_status_only_rows": exact_status_only_rows,
        "eligible_rows": len(eligible_rows),
        "rows_written": 0 if dry_run else len(eligible_rows),
        "allowed_statuses": sorted(allowed_statuses),
        "by_status": dict(sorted(by_status.items())),
        "by_engagement": dict(sorted(by_engagement.items())),
        "rejected_reasons": dict(sorted(rejected_reasons.items())),
        "sample_rows": eligible_rows[:10],
    }


def _status_only_reconciliation_status(
    *,
    submission_status: str,
    record_yaml: str,
    record_resolution: str,
) -> tuple[str, str, list[str]]:
    flags = [
        "report_only",
        "no_yaml_write_performed",
        "manual_record_owner_confirmation_required",
    ]
    if record_yaml:
        flags.append("record_yaml_resolved")
        return (
            "record_resolved_needs_owner_confirmation",
            "manual_confirm_existing_record_before_promotion_review",
            flags,
        )
    flags.append("record_yaml_missing")
    if submission_status in STATUS_ONLY_RECORD_CREATION_CANDIDATE_STATUSES:
        flags.append(f"submission_status_{submission_status}")
        return (
            "record_creation_candidate",
            "create_or_link_hackerman_record_before_proof_artifact_path",
            flags,
        )
    flags.append(f"submission_status_{submission_status or 'unknown'}")
    return (
        "status_not_final",
        "wait_for_paste_ready_or_owner_confirmation",
        flags,
    )


def status_only_reconciliation_queue(
    tag_dir: Path,
    index_path: Path,
    *,
    out_path: Path,
    limit: int = 0,
    dry_run: bool = False,
    statuses: set[str] | None = None,
) -> dict[str, Any]:
    """Emit grouped, report-only rows for status-only proof-artifact candidates.

    This converts the low-level status-only review rows into a record-resolution
    work queue. It never writes Hackerman YAML; rows with no exact record stay
    as record-creation/linking candidates, and rows with a resolved record still
    require explicit owner confirmation before a later promotion plan can write.
    """
    allowed_statuses = statuses or STATUS_ONLY_REVIEW_STATUSES
    submission_ref_resolution_map = _load_submission_ref_resolution_map(tag_dir)
    proof_path_resolution_map = _load_proof_path_resolution_map(tag_dir)
    queue_rows_by_key: dict[str, dict[str, Any]] = {}
    scanned_index_rows = 0
    invalid_json_rows = 0
    exact_status_only_rows = 0
    rejected_reasons: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    by_reconciliation_status: Counter[str] = Counter()
    by_engagement: Counter[str] = Counter()

    if not index_path.is_file():
        return {
            "schema": SCHEMA + "+status-only-reconciliation",
            "row_schema": STATUS_ONLY_RECONCILIATION_SCHEMA,
            "tag_dir": str(tag_dir),
            "proof_artifact_index": str(index_path),
            "reconciliation_queue_out": str(out_path),
            "dry_run": dry_run,
            "index_found": False,
            "scanned_index_rows": 0,
            "invalid_json_rows": 0,
            "exact_status_only_rows": 0,
            "queue_rows": 0,
            "candidate_count": 0,
            "allowed_statuses": sorted(allowed_statuses),
            "by_status": {},
            "by_reconciliation_status": {},
            "by_engagement": {},
            "rejected_reasons": {},
            "sample_rows": [],
        }

    for line in index_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_index_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            invalid_json_rows += 1
            continue
        if not isinstance(row, dict):
            invalid_json_rows += 1
            continue

        blockers = row.get("promotion_blockers")
        if blockers != ["submission_status_not_paste_ready_or_filed"]:
            rejected_reasons["not_exact_status_only_blocker"] += 1
            continue
        exact_status_only_rows += 1

        proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
        submission_path = _clean_path(str(row.get("submission_path") or ""))
        status = str(row.get("submission_status") or "").strip()
        confidence = str(row.get("confidence") or "").strip()
        try:
            path_fanout = int(row.get("candidate_path_occurrence") or 0)
        except (TypeError, ValueError):
            path_fanout = 0

        row_rejections: list[str] = []
        if status not in allowed_statuses:
            row_rejections.append("submission_status_not_in_review_set")
        if row.get("candidate_artifact_exists") is not True:
            row_rejections.append("candidate_artifact_missing")
        if confidence not in {"high", "direct"}:
            row_rejections.append("confidence_not_high")
        if path_fanout <= 0:
            row_rejections.append("candidate_path_occurrence_missing")
        elif path_fanout > PROMOTION_READY_MAX_PATH_FANOUT:
            row_rejections.append("path_fanout_above_promotion_limit")
        if not proof_path:
            row_rejections.append("unsafe_candidate_proof_path")
        if row.get("submission_path") and not submission_path:
            row_rejections.append("unsafe_submission_path")
        if row_rejections:
            rejected_reasons.update(row_rejections)
            continue

        submission_ref = _submission_ref_from_submission_path(submission_path)
        record_yaml = str(row.get("record_yaml") or "").strip()
        record_id = str(row.get("record_id") or "").strip()
        record_resolution = "needs_record_yaml"
        record_resolution_source = ""
        if not record_yaml and submission_ref:
            resolved = submission_ref_resolution_map.get(submission_ref)
            if resolved:
                record_yaml = resolved["record_yaml"]
                record_id = resolved["record_id"]
                record_resolution = "record_yaml"
                record_resolution_source = "derived_submission_ref:" + resolved["resolution_source"]
        if not record_yaml:
            proof_resolved, proof_key = _resolve_record_by_proof_path(proof_path, proof_path_resolution_map)
            if proof_resolved:
                record_yaml = proof_resolved["record_yaml"]
                record_id = proof_resolved["record_id"]
                record_resolution = "record_yaml"
                record_resolution_source = (
                    "derived_proof_artifact_path:" + proof_resolved["resolution_source"] + ":" + proof_key
                )
        elif record_yaml:
            record_resolution = "record_yaml"

        reconciliation_status, recommended_action, safety_flags = _status_only_reconciliation_status(
            submission_status=status,
            record_yaml=record_yaml,
            record_resolution=record_resolution,
        )
        queue_key = submission_ref or submission_path or proof_path
        queue_row = queue_rows_by_key.get(queue_key)
        if queue_row is None:
            queue_row = {
                "schema": STATUS_ONLY_RECONCILIATION_SCHEMA,
                "queue_key": queue_key,
                "mutation_allowed": False,
                "reconciliation_status": reconciliation_status,
                "recommended_action": recommended_action,
                "safety_flags": safety_flags,
                "engagement": str(row.get("engagement") or ""),
                "submission_path": submission_path,
                "submission_ref": submission_ref,
                "submission_status": status,
                "submission_title": str(row.get("submission_title") or ""),
                "record_yaml": record_yaml,
                "record_id": record_id,
                "record_resolution": record_resolution,
                "record_resolution_source": record_resolution_source,
                "proof_artifact_candidates": [],
                "candidate_count": 0,
            }
            queue_rows_by_key[queue_key] = queue_row
            by_status[status] += 1
            by_reconciliation_status[reconciliation_status] += 1
            by_engagement[queue_row["engagement"] or "_unknown"] += 1
        candidate = {
            "candidate_proof_path": proof_path,
            "raw_candidate_proof_path": str(row.get("candidate_proof_path") or ""),
            "candidate_artifact_kind": str(row.get("candidate_artifact_kind") or ""),
            "candidate_path_occurrence": path_fanout,
            "confidence": confidence,
            "confidence_score": row.get("confidence_score"),
            "raw_reference": str(row.get("raw_reference") or ""),
            "source_reasons": row.get("source_reasons") if isinstance(row.get("source_reasons"), list) else [],
            "promotion_review_reason": str(row.get("promotion_review_reason") or ""),
        }
        existing = {
            item.get("candidate_proof_path")
            for item in queue_row["proof_artifact_candidates"]
        }
        if candidate["candidate_proof_path"] not in existing:
            queue_row["proof_artifact_candidates"].append(candidate)
            queue_row["candidate_count"] = len(queue_row["proof_artifact_candidates"])
        if limit and len(queue_rows_by_key) >= limit:
            break

    queue_rows = [queue_rows_by_key[key] for key in sorted(queue_rows_by_key)]
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in queue_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": SCHEMA + "+status-only-reconciliation",
        "row_schema": STATUS_ONLY_RECONCILIATION_SCHEMA,
        "tag_dir": str(tag_dir),
        "proof_artifact_index": str(index_path),
        "reconciliation_queue_out": str(out_path),
        "dry_run": dry_run,
        "index_found": True,
        "scanned_index_rows": scanned_index_rows,
        "invalid_json_rows": invalid_json_rows,
        "exact_status_only_rows": exact_status_only_rows,
        "queue_rows": len(queue_rows),
        "candidate_count": sum(int(row.get("candidate_count") or 0) for row in queue_rows),
        "rows_written": 0 if dry_run else len(queue_rows),
        "allowed_statuses": sorted(allowed_statuses),
        "by_status": dict(sorted(by_status.items())),
        "by_reconciliation_status": dict(sorted(by_reconciliation_status.items())),
        "by_engagement": dict(sorted(by_engagement.items())),
        "rejected_reasons": dict(sorted(rejected_reasons.items())),
        "sample_rows": queue_rows[:10],
    }


def status_only_resolved_promotion_review(
    tag_dir: Path,
    reconciliation_path: Path,
    *,
    out_path: Path,
    limit: int = PROMOTION_REVIEW_PLAN_DEFAULT_LIMIT,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Convert resolved status-only reconciliation rows into a confirm-gated plan.

    This is deliberately non-mutating. It only emits normal promotion-review
    plan rows for reconciliation rows where an exact Hackerman record has
    already been resolved and still requires the existing
    --confirm-apply-promotion-ready apply path before any YAML write.
    """
    bounded_limit = _bounded_review_limit(limit)
    scanned_reconciliation_rows = 0
    invalid_json_rows = 0
    resolved_record_rows = 0
    plan_rows: list[dict[str, Any]] = []
    skipped_reconciliation_status: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()

    if not reconciliation_path.is_file():
        return {
            "schema": SCHEMA + "+status-only-resolved-promotion-review",
            "plan_schema": PROMOTION_PLAN_SCHEMA,
            "tag_dir": str(tag_dir),
            "status_only_reconciliation_queue": str(reconciliation_path),
            "review_plan_out": str(out_path),
            "dry_run": dry_run,
            "queue_found": False,
            "scanned_reconciliation_rows": 0,
            "invalid_json_rows": 0,
            "resolved_record_rows": 0,
            "plan_rows": 0,
            "ready_to_apply": 0,
            "already_has_proof_artifact_path": 0,
            "blocked": 0,
            "status_counts": {},
            "blocker_counts": {},
            "skipped_reconciliation_status": {},
            "rows_written": 0,
            "limit": bounded_limit,
            "sample_plan_rows": [],
        }

    for line in reconciliation_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_reconciliation_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            invalid_json_rows += 1
            continue
        if not isinstance(row, dict) or row.get("schema") != STATUS_ONLY_RECONCILIATION_SCHEMA:
            invalid_json_rows += 1
            continue

        reconciliation_status = str(row.get("reconciliation_status") or "").strip()
        if reconciliation_status != "record_resolved_needs_owner_confirmation":
            skipped_reconciliation_status[reconciliation_status or "_unknown"] += 1
            continue
        resolved_record_rows += 1
        if len(plan_rows) >= bounded_limit:
            continue

        blockers: list[str] = []
        record_yaml = str(row.get("record_yaml") or "").strip()
        record_path: Path | None = None
        record_id = ""
        existing_proof_path = ""
        if Path(record_yaml).name != record_yaml or not record_yaml.endswith(".yaml"):
            blockers.append("record_yaml_not_basename")
        else:
            record_path = tag_dir / record_yaml
            if not record_path.is_file():
                blockers.append("record_yaml_missing")
            else:
                try:
                    record_text = record_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    record_text = ""
                    blockers.append("record_yaml_unreadable")
                if record_text:
                    if not _is_hackerman_record(record_text):
                        blockers.append("record_yaml_not_hackerman")
                    record_id = _record_id(record_text)
                    expected_record_id = str(row.get("record_id") or "").strip()
                    if expected_record_id and record_id != expected_record_id:
                        blockers.append("record_id_mismatch")
                    existing_proof_path = _field_value(record_text, "proof_artifact_path")

        if row.get("mutation_allowed") is True:
            blockers.append("mutation_allowed_unexpected_true")

        raw_candidates = row.get("proof_artifact_candidates")
        candidates = raw_candidates if isinstance(raw_candidates, list) else []
        cleaned_candidates: list[dict[str, Any]] = []
        distinct_candidate_paths: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            raw_proof_path = str(
                candidate.get("candidate_proof_path")
                or candidate.get("raw_candidate_proof_path")
                or ""
            )
            proof_path = _clean_path(raw_proof_path)
            if proof_path:
                distinct_candidate_paths.add(proof_path)
            try:
                path_occurrence = int(candidate.get("candidate_path_occurrence") or 0)
            except (TypeError, ValueError):
                path_occurrence = 0
            cleaned_candidates.append(
                {
                    "candidate_proof_path": proof_path,
                    "raw_candidate_proof_path": str(candidate.get("raw_candidate_proof_path") or raw_proof_path),
                    "candidate_artifact_kind": str(candidate.get("candidate_artifact_kind") or ""),
                    "candidate_path_occurrence": path_occurrence,
                    "promotion_review_reason": str(candidate.get("promotion_review_reason") or ""),
                }
            )

        if not cleaned_candidates:
            blockers.append("missing_proof_artifact_candidate")
            selected_candidate = {
                "candidate_proof_path": "",
                "raw_candidate_proof_path": "",
                "candidate_artifact_kind": "",
                "candidate_path_occurrence": 0,
                "promotion_review_reason": "",
            }
        elif len(distinct_candidate_paths) != 1:
            blockers.append("multiple_candidate_proof_paths_for_reconciliation_row")
            selected_candidate = cleaned_candidates[0]
        else:
            selected_candidate = next(
                candidate for candidate in cleaned_candidates if candidate["candidate_proof_path"] in distinct_candidate_paths
            )

        proof_path = str(selected_candidate.get("candidate_proof_path") or "")
        if not proof_path:
            blockers.append("unsafe_candidate_proof_path")
        path_fanout = int(selected_candidate.get("candidate_path_occurrence") or 0)
        if path_fanout <= 0:
            blockers.append("candidate_path_occurrence_missing")
        elif path_fanout > PROMOTION_READY_MAX_PATH_FANOUT:
            blockers.append("path_fanout_above_promotion_limit")

        blockers = list(dict.fromkeys(blockers))
        if blockers:
            apply_status = "blocked"
            action = "manual_review"
        elif existing_proof_path:
            apply_status = "already_has_proof_artifact_path"
            action = "none"
        else:
            apply_status = "ready_to_apply"
            action = "insert_proof_artifact_path"

        plan_row = {
            "schema": PROMOTION_PLAN_SCHEMA,
            "source": "status_only_reconciliation_resolved_record",
            "action": action,
            "apply_status": apply_status,
            "blockers": blockers,
            "owner_confirmation_required": True,
            "safe_to_auto_apply": False,
            "safety_flags": [
                "derived_from_status_only_reconciliation",
                "manual_owner_confirmation_required",
                "confirm_apply_promotion_ready_required_for_yaml_write",
            ],
            "record_yaml": record_path.name if record_path is not None else record_yaml,
            "record_id": record_id or str(row.get("record_id") or ""),
            "record_resolution": str(row.get("record_resolution") or ""),
            "record_resolution_source": str(row.get("record_resolution_source") or ""),
            "candidate_proof_path": proof_path,
            "raw_candidate_proof_path": str(selected_candidate.get("raw_candidate_proof_path") or ""),
            "candidate_path_occurrence": path_fanout,
            "candidate_artifact_kind": str(selected_candidate.get("candidate_artifact_kind") or ""),
            "engagement": str(row.get("engagement") or ""),
            "submission_path": _clean_path(str(row.get("submission_path") or "")),
            "submission_status": str(row.get("submission_status") or ""),
            "submission_title": str(row.get("submission_title") or ""),
            "promotion_review_reason": (
                str(selected_candidate.get("promotion_review_reason") or "")
                or "status-only reconciliation resolved exact Hackerman record"
            ),
            "source_reconciliation_status": reconciliation_status,
            "source_reconciliation_queue_key": str(row.get("queue_key") or ""),
            "source_reconciliation_candidate_count": len(cleaned_candidates),
        }
        if existing_proof_path:
            plan_row["existing_proof_artifact_path"] = existing_proof_path

        plan_rows.append(plan_row)
        status_counts[apply_status] += 1
        blocker_counts.update(blockers)

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in plan_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    return {
        "schema": SCHEMA + "+status-only-resolved-promotion-review",
        "plan_schema": PROMOTION_PLAN_SCHEMA,
        "tag_dir": str(tag_dir),
        "status_only_reconciliation_queue": str(reconciliation_path),
        "review_plan_out": str(out_path),
        "dry_run": dry_run,
        "queue_found": True,
        "scanned_reconciliation_rows": scanned_reconciliation_rows,
        "invalid_json_rows": invalid_json_rows,
        "resolved_record_rows": resolved_record_rows,
        "plan_rows": len(plan_rows),
        "ready_to_apply": status_counts.get("ready_to_apply", 0),
        "already_has_proof_artifact_path": status_counts.get("already_has_proof_artifact_path", 0),
        "blocked": status_counts.get("blocked", 0),
        "status_counts": dict(sorted(status_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "skipped_reconciliation_status": dict(sorted(skipped_reconciliation_status.items())),
        "rows_written": 0 if dry_run else len(plan_rows),
        "limit": bounded_limit,
        "sample_plan_rows": plan_rows[:10],
    }


def apply_promotion_review_plan(
    tag_dir: Path,
    plan_path: Path,
    *,
    dry_run: bool = False,
    limit: int = 1,
    confirm: bool = False,
) -> dict[str, Any]:
    """Apply explicit low-fanout promotion plan rows to tag YAML files."""
    apply_limit = min(max(limit, 1), PROMOTION_APPLY_MAX_ROWS)
    scanned_plan_rows = 0
    updated = 0
    skipped: Counter[str] = Counter()
    updated_files: list[str] = []
    sample_actions: list[dict[str, str]] = []

    if not confirm:
        return {
            "schema": SCHEMA + "+promotion-apply",
            "plan_schema": PROMOTION_PLAN_SCHEMA,
            "tag_dir": str(tag_dir),
            "review_plan": str(plan_path),
            "dry_run": dry_run,
            "confirmed": False,
            "plan_found": plan_path.is_file(),
            "scanned_plan_rows": 0,
            "updated": 0,
            "apply_limit": apply_limit,
            "skipped": {"missing_confirmation": 1},
            "updated_files": [],
            "sample_actions": [],
        }

    if not plan_path.is_file():
        return {
            "schema": SCHEMA + "+promotion-apply",
            "plan_schema": PROMOTION_PLAN_SCHEMA,
            "tag_dir": str(tag_dir),
            "review_plan": str(plan_path),
            "dry_run": dry_run,
            "confirmed": True,
            "plan_found": False,
            "scanned_plan_rows": 0,
            "updated": 0,
            "apply_limit": apply_limit,
            "skipped": {"missing_plan": 1},
            "updated_files": [],
            "sample_actions": [],
        }

    for line in plan_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        scanned_plan_rows += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            skipped.update(["invalid_json"])
            continue
        if row.get("schema") != PROMOTION_PLAN_SCHEMA:
            skipped.update(["schema_mismatch"])
            continue
        if row.get("apply_status") != "ready_to_apply" or row.get("action") != "insert_proof_artifact_path":
            skipped.update(["not_ready_to_apply"])
            continue
        record_yaml = str(row.get("record_yaml") or "").strip()
        if Path(record_yaml).name != record_yaml or not record_yaml.endswith(".yaml"):
            skipped.update(["record_yaml_not_basename"])
            continue
        proof_path = _clean_path(str(row.get("candidate_proof_path") or ""))
        if not proof_path:
            skipped.update(["unsafe_candidate_proof_path"])
            continue
        if int(row.get("candidate_path_occurrence") or 0) > PROMOTION_READY_MAX_PATH_FANOUT:
            skipped.update(["path_fanout_above_promotion_limit"])
            continue
        record_path = tag_dir / record_yaml
        if not record_path.is_file():
            skipped.update(["record_yaml_missing"])
            continue
        record_text = record_path.read_text(encoding="utf-8", errors="ignore")
        if not _is_hackerman_record(record_text):
            skipped.update(["record_yaml_not_hackerman"])
            continue
        expected_record_id = str(row.get("record_id") or "").strip()
        if expected_record_id and _record_id(record_text) != expected_record_id:
            skipped.update(["record_id_mismatch"])
            continue
        if "proof_artifact_path:" in record_text:
            skipped.update(["already_has_proof_artifact_path"])
            continue

        updated += 1
        if len(updated_files) < 20:
            updated_files.append(record_yaml)
        if len(sample_actions) < 10:
            sample_actions.append({"record_yaml": record_yaml, "proof_artifact_path": proof_path})
        if not dry_run:
            record_path.write_text(_insert_proof_path(record_text, proof_path), encoding="utf-8")
        if updated >= apply_limit:
            break

    return {
        "schema": SCHEMA + "+promotion-apply",
        "plan_schema": PROMOTION_PLAN_SCHEMA,
        "tag_dir": str(tag_dir),
        "review_plan": str(plan_path),
        "dry_run": dry_run,
        "confirmed": True,
        "plan_found": True,
        "scanned_plan_rows": scanned_plan_rows,
        "updated": updated,
        "apply_limit": apply_limit,
        "skipped": dict(sorted(skipped.items())),
        "updated_files": updated_files,
        "sample_actions": sample_actions,
    }


def backfill(tag_dir: Path, *, dry_run: bool = False, limit: int = 0, candidate_limit: int = 50) -> dict[str, Any]:
    scanned = 0
    source_tag_records = 0
    source_tags_with_proof = 0
    updated = 0
    skipped_existing = 0
    skipped_unsafe = 0
    skipped_missing_source = 0
    skipped_target_mismatch = 0
    skipped_target_missing = 0
    updated_files: list[str] = []
    skipped_unsafe_files: list[str] = []
    candidates: list[dict[str, str]] = []

    def add_candidate(
        *,
        status: str,
        record_path: Path,
        source_path: Path | None,
        proof_path: str = "",
        raw_proof_path: str = "",
        record_target: str = "",
        source_target: str = "",
        reason: str = "",
    ) -> None:
        if len(candidates) >= max(candidate_limit, 0):
            return
        candidates.append(
            {
                "status": status,
                "record_file": record_path.name,
                "source_file": source_path.name if source_path else "",
                "proof_artifact_path": proof_path,
                "raw_proof_artifact_path": raw_proof_path,
                "record_target_repo": record_target,
                "source_target_repo": source_target,
                "reason": reason,
            }
        )

    for path in sorted(tag_dir.glob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not _is_hackerman_record(text):
            continue
        scanned += 1
        source_match = SOURCE_TAG_RE.search(text)
        if not source_match:
            continue
        source_tag_records += 1
        if "proof_artifact_path:" in text:
            skipped_existing += 1
            continue
        source_path = tag_dir / source_match.group(1).strip()
        if not source_path.is_file():
            skipped_missing_source += 1
            add_candidate(status="skipped", record_path=path, source_path=source_path, reason="missing_source_tag_file")
            continue
        source_text = source_path.read_text(encoding="utf-8", errors="ignore")
        raw_match = SOURCE_PROOF_RE.search(source_text)
        if not raw_match:
            continue
        source_tags_with_proof += 1
        raw_proof_path = raw_match.group(1).strip().strip("'\"")
        target_ok, target_reason, record_target, source_target = _target_guard(text, source_text)
        if not target_ok:
            if target_reason == "target_repo_mismatch":
                skipped_target_mismatch += 1
            else:
                skipped_target_missing += 1
            add_candidate(
                status="skipped",
                record_path=path,
                source_path=source_path,
                proof_path=_clean_path(raw_proof_path),
                raw_proof_path=raw_proof_path,
                record_target=record_target,
                source_target=source_target,
                reason=target_reason,
            )
            continue
        proof_path = _clean_path(raw_proof_path)
        if not proof_path:
            skipped_unsafe += 1
            if len(skipped_unsafe_files) < 20:
                skipped_unsafe_files.append(path.name)
            add_candidate(
                status="skipped",
                record_path=path,
                source_path=source_path,
                raw_proof_path=raw_proof_path,
                record_target=record_target,
                source_target=source_target,
                reason="unsafe_proof_artifact_path",
            )
            continue
        updated += 1
        if len(updated_files) < 50:
            updated_files.append(path.name)
        add_candidate(
            status="would_update" if dry_run else "updated",
            record_path=path,
            source_path=source_path,
            proof_path=proof_path,
            raw_proof_path=raw_proof_path,
            record_target=record_target,
            source_target=source_target,
            reason=target_reason,
        )
        if not dry_run:
            path.write_text(_insert_proof_path(text, proof_path), encoding="utf-8")
        if limit and updated >= limit:
            break

    return {
        "schema": SCHEMA,
        "tag_dir": str(tag_dir),
        "dry_run": dry_run,
        "scanned_hackerman_records": scanned,
        "source_tag_records": source_tag_records,
        "source_tags_with_proof": source_tags_with_proof,
        "updated": updated,
        "skipped_existing": skipped_existing,
        "skipped_unsafe": skipped_unsafe,
        "skipped_missing_source": skipped_missing_source,
        "skipped_target_mismatch": skipped_target_mismatch,
        "skipped_target_missing": skipped_target_missing,
        "updated_files": updated_files,
        "skipped_unsafe_files": skipped_unsafe_files,
        "candidate_limit": max(candidate_limit, 0),
        "candidates": candidates,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--candidate-limit", type=int, default=50)
    parser.add_argument("--json-summary", action="store_true")
    parser.add_argument(
        "--crawl-engagements",
        action="store_true",
        help="Crawl operator-local engagements for PoC artifacts and emit candidate JSONL.",
    )
    parser.add_argument(
        "--mine-proof-hardening-sidecar",
        action="store_true",
        help="Mine proof-hardening sidecar source_ref rows into candidate JSONL without writing tag YAML.",
    )
    parser.add_argument(
        "--review-proof-artifact-index",
        action="store_true",
        help="Build a bounded review/apply plan from promotion-ready proof_artifact_index rows.",
    )
    parser.add_argument(
        "--include-blocked-index-rows",
        action="store_true",
        help=(
            "With --review-proof-artifact-index, include non-promotable index rows "
            "in the review plan with blocker reasons. These rows are never applyable."
        ),
    )
    parser.add_argument(
        "--apply-promotion-review-plan",
        action="store_true",
        help="Explicitly apply low-fanout ready_to_apply rows from a curated promotion review plan.",
    )
    parser.add_argument(
        "--status-only-blocker-review",
        action="store_true",
        help=(
            "Emit a report-only queue for proof_artifact_index rows whose only "
            "promotion blocker is submission status."
        ),
    )
    parser.add_argument(
        "--status-only-reconciliation-queue",
        action="store_true",
        help=(
            "Emit a grouped, report-only reconciliation queue for status-only "
            "proof-artifact candidates and missing/ambiguous Hackerman records."
        ),
    )
    parser.add_argument(
        "--status-only-resolved-promotion-review",
        action="store_true",
        help=(
            "Build a confirm-gated promotion review plan from status-only "
            "reconciliation rows whose Hackerman record is already resolved."
        ),
    )
    parser.add_argument(
        "--confirm-apply-promotion-ready",
        action="store_true",
        help="Required with --apply-promotion-review-plan before any tag YAML writes occur.",
    )
    parser.add_argument(
        "--proof-hardening-sidecar",
        default=str(DEFAULT_PROOF_HARDENING_SIDECAR),
        help="proof_hardening.jsonl path for --mine-proof-hardening-sidecar.",
    )
    parser.add_argument(
        "--proof-artifact-index",
        default=str(DEFAULT_PROOF_ARTIFACT_INDEX),
        help="proof_artifact_index.jsonl path for --review-proof-artifact-index.",
    )
    parser.add_argument(
        "--promotion-review-plan",
        default=str(DEFAULT_PROMOTION_REVIEW_PLAN),
        help="Promotion review plan JSONL input for --apply-promotion-review-plan.",
    )
    parser.add_argument(
        "--status-only-reconciliation",
        default=str(DEFAULT_STATUS_ONLY_RECONCILIATION_QUEUE),
        help=(
            "Status-only reconciliation JSONL input for "
            "--status-only-resolved-promotion-review."
        ),
    )
    parser.add_argument(
        "--missing-record-import-queue",
        default="",
        help=(
            "Optional JSONL output for --review-proof-artifact-index. "
            "Rows that are promotion-ready but lack record_yaml are staged here "
            "for manual Hackerman record creation instead of YAML writes."
        ),
    )
    parser.add_argument(
        "--engagements",
        nargs="+",
        default=[],
        help="Engagement workspace roots to crawl (e.g. ~/audits/dydx).",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_CANDIDATES_OUT),
        help="Candidate JSONL output path.",
    )
    parser.add_argument("--min-score", type=float, default=0.20)
    parser.add_argument("--high-confidence-threshold", type=float, default=0.45)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.status_only_resolved_promotion_review:
        review_out = (
            Path(args.out).expanduser()
            if args.out != str(DEFAULT_CANDIDATES_OUT)
            else DEFAULT_STATUS_ONLY_PROMOTION_REVIEW_PLAN
        )
        payload = status_only_resolved_promotion_review(
            Path(args.tag_dir).expanduser(),
            Path(args.status_only_reconciliation).expanduser(),
            out_path=review_out,
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"plan_rows={payload['plan_rows']} "
                f"resolved_record_rows={payload['resolved_record_rows']} "
                f"ready_to_apply={payload['ready_to_apply']} "
                f"already_has_proof_artifact_path={payload['already_has_proof_artifact_path']} "
                f"blocked={payload['blocked']} "
                f"rows_written={payload['rows_written']} "
                f"out={payload['review_plan_out']}"
            )
        return 0
    if args.status_only_reconciliation_queue:
        queue_out = (
            Path(args.out).expanduser()
            if args.out != str(DEFAULT_CANDIDATES_OUT)
            else DEFAULT_STATUS_ONLY_RECONCILIATION_QUEUE
        )
        payload = status_only_reconciliation_queue(
            Path(args.tag_dir).expanduser(),
            Path(args.proof_artifact_index).expanduser(),
            out_path=queue_out,
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"queue_rows={payload['queue_rows']} "
                f"candidate_count={payload['candidate_count']} "
                f"rows_written={payload['rows_written']} "
                f"out={payload['reconciliation_queue_out']}"
            )
        return 0
    if args.status_only_blocker_review:
        review_out = (
            Path(args.out).expanduser()
            if args.out != str(DEFAULT_CANDIDATES_OUT)
            else DEFAULT_STATUS_ONLY_REVIEW
        )
        payload = status_only_blocker_review(
            Path(args.proof_artifact_index).expanduser(),
            out_path=review_out,
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"eligible={payload['eligible_rows']} "
                f"exact_status_only={payload['exact_status_only_rows']} "
                f"rows_written={payload['rows_written']} "
                f"out={payload['review_queue_out']}"
            )
        return 0
    if args.review_proof_artifact_index:
        review_out = (
            Path(args.out).expanduser()
            if args.out != str(DEFAULT_CANDIDATES_OUT)
            else DEFAULT_PROMOTION_REVIEW_PLAN
        )
        payload = review_proof_artifact_index(
            Path(args.tag_dir),
            Path(args.proof_artifact_index).expanduser(),
            out_path=review_out,
            missing_record_import_queue_out=(
                Path(args.missing_record_import_queue).expanduser()
                if args.missing_record_import_queue
                else None
            ),
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
            include_blocked_index_rows=args.include_blocked_index_rows,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"plan_rows={payload['plan_rows']} "
                f"promotion_ready={payload['promotion_ready_rows']} "
                f"ready_to_apply={payload['ready_to_apply']} "
                f"review_required={payload['review_required']} "
                f"blocked={payload['blocked']} "
                f"not_promotable={payload.get('not_promotable', 0)} "
                f"missing_record_import_candidates={payload.get('missing_record_import_candidates', 0)} "
                f"out={payload['review_plan_out']}"
            )
        return 0
    if args.apply_promotion_review_plan:
        payload = apply_promotion_review_plan(
            Path(args.tag_dir),
            Path(args.promotion_review_plan).expanduser(),
            dry_run=args.dry_run,
            limit=max(args.limit, 1),
            confirm=args.confirm_apply_promotion_ready,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"updated={payload['updated']} "
                f"scanned_plan_rows={payload['scanned_plan_rows']} "
                f"confirmed={payload['confirmed']} "
                f"dry_run={payload['dry_run']}"
            )
        return 0
    if args.mine_proof_hardening_sidecar:
        payload = mine_proof_hardening_sidecar(
            Path(args.tag_dir),
            Path(args.proof_hardening_sidecar).expanduser(),
            out_path=Path(args.out).expanduser(),
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"candidates={payload['candidate_count']} "
                f"sidecar_rows_with_proof={payload['sidecar_rows_with_proof']} "
                f"skipped_existing={payload['skipped_existing']} "
                f"out={payload['candidates_out']}"
            )
        return 0
    if args.crawl_engagements:
        engagements = [Path(p).expanduser() for p in args.engagements]
        payload = crawl_engagements(
            Path(args.tag_dir),
            engagements,
            out_path=Path(args.out).expanduser(),
            min_score=args.min_score,
            high_confidence=args.high_confidence_threshold,
            limit=max(args.limit, 0),
            dry_run=args.dry_run,
        )
        if args.json_summary:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"matched={payload['matched_records']} "
                f"high_confidence={payload['high_confidence_matches']} "
                f"promotion_ready={payload['promotion_ready_candidates']} "
                f"scanned={payload['scanned_hackerman_records']} "
                f"out={payload['candidates_out']}"
            )
        return 0
    payload = backfill(
        Path(args.tag_dir),
        dry_run=args.dry_run,
        limit=max(args.limit, 0),
        candidate_limit=max(args.candidate_limit, 0),
    )
    if args.json_summary:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"updated={payload['updated']} "
            f"source_tags_with_proof={payload['source_tags_with_proof']} "
            f"skipped_unsafe={payload['skipped_unsafe']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
