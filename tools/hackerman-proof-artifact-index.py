#!/usr/bin/env python3
"""Build a read-only proof-artifact candidate index from local engagements.

The index is intentionally a sidecar: it reports candidate proof paths for
later human-reviewed `proof_artifact_path` backfill, but never mutates corpus
tag YAML files.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.hackerman_proof_artifact_index.v1"
DEFAULT_AUDITS_ROOT = Path.home() / "audits"
DEFAULT_OUT = Path("audit") / "corpus_tags" / "derived" / "proof_artifact_index.jsonl"
DEFAULT_REPORT = Path("reports") / "proof_artifact_index_phase_a_2026-05-17.md"
PROMOTION_READY_MAX_FANOUT = 3
PROMOTION_READY_SUBMISSION_STATUSES = {"paste_ready", "filed"}
PROMOTION_GATE_VERSION = "proof-artifact-index-promotion-v1"
PROMOTION_READY_REASON = "explicit high-confidence existing proof artifact with low candidate fanout"
ACCEPTANCE_GATE_VERSION = "proof-artifact-index-acceptance-v1"
ACCEPTANCE_READY_REASON = (
    "accepted proof-backed row with current workspace source refs and concrete proof evidence"
)

PROOF_EXTENSIONS = {
    ".go",
    ".rs",
    ".sol",
    ".t.sol",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".py",
    ".sh",
    ".txt",
    ".log",
    ".md",
}
PROOFISH_RE = re.compile(
    r"(?:poc|proof|repro|exploit|counterexample|forge|foundry|halmos|medusa|test|spec|output|trace|run)",
    re.IGNORECASE,
)
EXPLICIT_REF_RE = re.compile(
    r"(?:^|\n)[-*\s>`]*(?:"
    r"source[-_ ]proof|proof[-_ ]artifact|proof[-_ ]path|poc[-_ ]path|"
    r"reproduction|counterexample|artifact|test|output|trace"
    r")\s*:\s*`?([^`\n]+?)`?(?=\n|$)",
    re.IGNORECASE,
)
INLINE_PATH_RE = re.compile(
    r"`([^`\n]+?\.(?:go|rs|sol|ts|tsx|js|mjs|py|sh|txt|log|md))`",
    re.IGNORECASE,
)
SOURCE_REF_LINE_RE = re.compile(
    r"(?:^|\n)[-*\s>`]*(?:"
    r"source[-_ ]refs?|source[-_ ]citations?|source[-_ ]proof|source[-_ ]path|code[-_ ]refs?"
    r")\s*:\s*`?([^`\n]+?)`?(?=\n|$)",
    re.IGNORECASE,
)
SOURCE_REF_TOKEN_RE = re.compile(
    r"(?:workspace:)?(?:audits/[A-Za-z0-9._@+=-]+/)?"
    r"[A-Za-z0-9._@+=/-]+\.(?:go|rs|sol|ts|tsx|js|mjs|py|move|cairo|vy|c|cpp|h|hpp)"
    r"(?::L?\d+(?:[-:]\d+)?)?",
    re.IGNORECASE,
)
WORKSPACE_SOURCE_REF_RE = re.compile(r"workspace:[^\s`,;)\\\]]+", re.IGNORECASE)
LINE_SUFFIX_RE = re.compile(r"(?::L?\d+(?:[-:]\d+)?)$")
ADVISORY_ONLY_RE = re.compile(
    r"\b(?:advisory[- ]only|review[- ]only|not submission[- ]grade|"
    r"detector telemetry|do not file|informational only)\b",
    re.IGNORECASE,
)
CONCRETE_PROOF_EVIDENCE_RE = re.compile(
    r"(?:--- PASS:|Suite result:\s*ok|^ok\s+\S+|forge test|go test|cargo test|pytest|"
    r"\bfunc\s+Test[A-Za-z0-9_]*\s*\(|\bdef\s+test_[A-Za-z0-9_]*\s*\(|"
    r"\bcontract\s+\w*Test\b|\bit\s*\(|\bassert(?:Eq|True|False|ion)?\b|"
    r"\brequire\.(?:NoError|Equal|True|False)\b)",
    re.IGNORECASE | re.MULTILINE,
)
FILENAME_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
SAFE_RELATIVE_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?!.*(?:^|/)\.\.(?:/|$))(?:[A-Za-z0-9._@+=-]+/)*[A-Za-z0-9._@+=-]+$"
)
STOPWORDS = {
    "a",
    "an",
    "and",
    "audit",
    "bug",
    "by",
    "for",
    "go",
    "high",
    "hold",
    "issue",
    "js",
    "log",
    "low",
    "md",
    "medium",
    "of",
    "output",
    "poc",
    "proof",
    "py",
    "rs",
    "sh",
    "sol",
    "spec",
    "test",
    "tests",
    "the",
    "to",
    "trace",
    "ts",
    "tsx",
    "v1",
    "v2",
    "v3",
}


class ProofArtifact:
    def __init__(self, path: Path, normalized_path: str, tokens: set[str], kind: str) -> None:
        self.path = path
        self.normalized_path = normalized_path
        self.tokens = tokens
        self.kind = kind


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tokens(value: str) -> set[str]:
    raw = {tok.lower() for tok in FILENAME_TOKEN_RE.findall(value)}
    return {tok for tok in raw if len(tok) > 1 and tok not in STOPWORDS}


def _is_safe_relative(value: str) -> bool:
    return bool(SAFE_RELATIVE_PATH_RE.match(value.replace("\\", "/")))


def _normalize_candidate_path(path: Path, engagement_root: Path, engagement_name: str) -> str:
    try:
        rel = path.resolve().relative_to(engagement_root.resolve())
    except (OSError, ValueError):
        rel = Path(path.name)
    candidate = f"audits/{engagement_name}/{rel.as_posix()}"
    return candidate if _is_safe_relative(candidate) else ""


def _path_from_ref(raw_ref: str, engagement_root: Path, engagement_name: str) -> tuple[Path | None, str, str]:
    cleaned = raw_ref.strip().strip("'\"").replace("\\", "/")
    cleaned = cleaned.split("#", 1)[0].strip()
    if not cleaned:
        return None, "", "empty_ref"
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", cleaned):
        return None, cleaned, "unsafe_url"
    if cleaned.startswith("/"):
        path = Path(cleaned)
    elif cleaned.startswith("audits/"):
        path = Path.home() / cleaned
    else:
        path = engagement_root / cleaned
    normalized = _normalize_candidate_path(path, engagement_root, engagement_name)
    if not normalized:
        return None, cleaned, "unsafe_path"
    return path, normalized, "safe"


def _strip_source_line_suffix(value: str) -> str:
    return LINE_SUFFIX_RE.sub("", value.strip())


def _clean_source_ref(raw_ref: str) -> str:
    return _strip_source_line_suffix(raw_ref.strip().strip("'\"`[](){}.,;"))


def _source_ref_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        cleaned = token.strip().strip("'\"`[](){}.,;")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            tokens.append(cleaned)

    for match in SOURCE_REF_LINE_RE.finditer(text):
        raw = match.group(1).strip()
        found = False
        for token_match in SOURCE_REF_TOKEN_RE.finditer(raw):
            add(token_match.group(0))
            found = True
        if not found:
            for part in re.split(r"[\s,]+", raw):
                if SOURCE_REF_TOKEN_RE.fullmatch(part.strip().strip("'\"`[](){}.,;")):
                    add(part)

    for match in WORKSPACE_SOURCE_REF_RE.finditer(text):
        token = match.group(0)
        if SOURCE_REF_TOKEN_RE.fullmatch(token):
            add(token)
    return tokens


def _source_ref_scan(text: str, engagement_root: Path, engagement_name: str) -> dict[str, Any]:
    current: list[str] = []
    stale: list[str] = []
    missing_files: list[str] = []
    unsafe: list[str] = []

    for raw in _source_ref_tokens(text):
        cleaned = _clean_source_ref(raw)
        if cleaned.startswith("workspace:"):
            cleaned = cleaned[len("workspace:") :]
        if not cleaned:
            continue

        if cleaned.startswith("audits/"):
            parts = cleaned.split("/")
            if len(parts) < 3 or parts[1] != engagement_name:
                stale.append(raw)
                continue
            path = engagement_root.joinpath(*parts[2:])
        elif cleaned.startswith("/"):
            path = Path(cleaned)
            try:
                path.resolve().relative_to(engagement_root.resolve())
            except (OSError, ValueError):
                stale.append(raw)
                continue
        else:
            if not _is_safe_relative(cleaned):
                unsafe.append(raw)
                continue
            path = engagement_root / cleaned

        normalized = _normalize_candidate_path(path, engagement_root, engagement_name)
        if not normalized:
            unsafe.append(raw)
            continue
        if path.is_file():
            current.append(normalized)
        else:
            missing_files.append(normalized)

    if current:
        status = "current-workspace"
    elif stale:
        status = "stale-workspace"
    elif missing_files:
        status = "missing-source-file"
    elif unsafe:
        status = "unsafe-source-ref"
    else:
        status = "missing"
    return {
        "source_ref_status": status,
        "current_workspace_source_refs": sorted(set(current)),
        "stale_workspace_source_refs": sorted(set(stale)),
        "missing_source_ref_paths": sorted(set(missing_files)),
        "unsafe_source_refs": sorted(set(unsafe)),
    }


def _proof_evidence_scan(
    *,
    submission_text: str,
    artifact_path: Path | None,
    artifact_kind: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if CONCRETE_PROOF_EVIDENCE_RE.search(submission_text):
        reasons.append("submission_contains_execution_or_assertion_evidence")

    artifact_text = ""
    if artifact_path is not None and artifact_path.is_file():
        try:
            artifact_text = artifact_path.read_text(encoding="utf-8", errors="ignore")[:500_000]
        except OSError:
            artifact_text = ""
    if artifact_text and CONCRETE_PROOF_EVIDENCE_RE.search(artifact_text):
        reasons.append("artifact_contains_concrete_proof_or_harness_evidence")
    if artifact_kind in {"execution-output", "repro-script"} and artifact_text.strip():
        reasons.append(f"{artifact_kind}_artifact_present")

    return bool(reasons), sorted(set(reasons))


def _is_submission_markdown(path: Path) -> bool:
    if path.suffix.lower() != ".md":
        return False
    parts = set(path.parts)
    if "submissions" not in parts:
        return False
    return not path.name.startswith(".") and not path.name.endswith(".hash")


def _artifact_kind(path: Path) -> str:
    parts = set(path.parts)
    name = path.name.lower()
    if "poc-tests" in parts:
        return "poc-tests"
    if name.endswith((".log", ".txt")):
        return "execution-output"
    if name.endswith(".sh"):
        return "repro-script"
    if path.suffix.lower() == ".md":
        return "proof-note"
    return "test-file"


def _is_proof_artifact(path: Path) -> bool:
    if not path.is_file() or path.name.startswith("."):
        return False
    lower_name = path.name.lower()
    suffixes = [s.lower() for s in path.suffixes]
    if ".hash" in suffixes or ".json" in suffixes:
        return False
    has_supported_ext = path.suffix.lower() in PROOF_EXTENSIONS or lower_name.endswith(".t.sol")
    if not has_supported_ext:
        return False
    proofish_path = PROOFISH_RE.search(path.as_posix()) is not None
    under_poc_tests = "poc-tests" in path.parts
    return proofish_path or under_poc_tests


def discover_engagement_roots(roots: Iterable[Path]) -> list[Path]:
    engagements: set[Path] = set()
    for root in roots:
        root = root.expanduser()
        if not root.exists():
            continue
        if (root / "submissions").is_dir():
            engagements.add(root.resolve())
            continue
        for child in sorted(root.iterdir()):
            if child.name.startswith(".") or child.name.startswith("-"):
                continue
            if child.is_dir() and (child / "submissions").is_dir():
                engagements.add(child.resolve())
    return sorted(engagements)


def scan_proof_artifacts(engagement_root: Path) -> list[ProofArtifact]:
    engagement_name = engagement_root.name
    scan_roots = [
        engagement_root / "poc-tests",
        engagement_root / "submissions",
        engagement_root / "agent_outputs",
        engagement_root / ".auditooor",
    ]
    artifacts: list[ProofArtifact] = []
    seen: set[str] = set()
    for scan_root in scan_roots:
        if not scan_root.is_dir():
            continue
        for path in sorted(scan_root.rglob("*")):
            if not _is_proof_artifact(path):
                continue
            normalized = _normalize_candidate_path(path, engagement_root, engagement_name)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            token_blob = _tokens(path.name) | _tokens(path.parent.name) | _tokens(normalized)
            artifacts.append(ProofArtifact(path, normalized, token_blob, _artifact_kind(path)))
    return artifacts


def _submission_status(path: Path) -> str:
    try:
        idx = path.parts.index("submissions")
    except ValueError:
        return "unknown"
    after = path.parts[idx + 1 :]
    if len(after) <= 1:
        return "root"
    return after[0]


def _title_from_text(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()[:160] or fallback
    return fallback


def _best_token_match(submission_tokens: set[str], artifacts: list[ProofArtifact]) -> tuple[ProofArtifact | None, float, set[str]]:
    best: tuple[ProofArtifact | None, float, set[str]] = (None, 0.0, set())
    if not submission_tokens:
        return best
    for artifact in artifacts:
        overlap = submission_tokens & artifact.tokens
        if not overlap:
            continue
        union = submission_tokens | artifact.tokens
        score = len(overlap) / len(union)
        if score > best[1]:
            best = (artifact, score, overlap)
    return best


def _confidence_from_score(score: float, explicit: bool, exists: bool) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if explicit:
        reasons.append("submission_explicit_reference")
        if exists:
            reasons.append("referenced_artifact_exists")
            return "high", reasons
        reasons.append("referenced_artifact_missing_locally")
        return "medium", reasons
    if score >= 0.34:
        reasons.append("strong_filename_token_overlap")
        return "medium", reasons
    reasons.append("weak_filename_token_overlap")
    return "low", reasons


def _candidate_row(
    *,
    engagement_root: Path,
    submission_path: Path,
    submission_title: str,
    candidate_path: str,
    raw_ref: str,
    confidence_score: float,
    confidence: str,
    source_reasons: list[str],
    match_method: str,
    artifact_exists: bool,
    artifact_kind: str,
    token_overlap: set[str],
    source_ref_scan: dict[str, Any],
    advisory_only: bool,
    proof_evidence_present: bool,
    proof_evidence_reasons: list[str],
) -> dict[str, Any]:
    engagement_name = engagement_root.name
    submission_normalized = _normalize_candidate_path(submission_path, engagement_root, engagement_name)
    row = {
        "schema": SCHEMA,
        "engagement": engagement_name,
        "submission_path": submission_normalized,
        "submission_status": _submission_status(submission_path),
        "submission_title": submission_title,
        "candidate_proof_path": candidate_path,
        "candidate_artifact_exists": artifact_exists,
        "candidate_artifact_kind": artifact_kind,
        "confidence": confidence,
        "confidence_score": round(confidence_score, 4),
        "match_method": match_method,
        "source_reasons": source_reasons,
        "token_overlap": sorted(token_overlap),
        "advisory_only": advisory_only,
        "proof_evidence_present": proof_evidence_present,
        "proof_evidence_reasons": proof_evidence_reasons,
        "source_ref_status": source_ref_scan["source_ref_status"],
        "current_workspace_source_refs": source_ref_scan["current_workspace_source_refs"],
        "stale_workspace_source_refs": source_ref_scan["stale_workspace_source_refs"],
        "missing_source_ref_paths": source_ref_scan["missing_source_ref_paths"],
        "unsafe_source_refs": source_ref_scan["unsafe_source_refs"],
    }
    if raw_ref:
        row["raw_reference"] = raw_ref
    return row


def _promotion_annotation(row: dict[str, Any], path_fanout: int) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if row["confidence"] != "high":
        blockers.append("confidence_not_high")
    if not row["candidate_artifact_exists"]:
        blockers.append("candidate_artifact_missing")
    if path_fanout > PROMOTION_READY_MAX_FANOUT:
        blockers.append("path_fanout_above_promotion_limit")
    if row["submission_status"] not in PROMOTION_READY_SUBMISSION_STATUSES:
        blockers.append("submission_status_not_paste_ready_or_filed")
    if row["match_method"] != "submission-explicit-path":
        blockers.append("match_not_explicit_reference")
    return not blockers, blockers


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _promotion_review_fields(promotion_ready: bool, promotion_blockers: list[str]) -> dict[str, Any]:
    review_status = "ready" if promotion_ready else "blocked"
    review_reason = (
        PROMOTION_READY_REASON
        if promotion_ready
        else "blocked: " + (", ".join(promotion_blockers) if promotion_blockers else "unknown")
    )
    return {
        "promotion_gate_version": PROMOTION_GATE_VERSION,
        "promotion_review_status": review_status,
        "promotion_review_reason": review_reason,
    }


def _acceptance_status(blockers: list[str]) -> str:
    if not blockers:
        return "accepted"
    if "advisory_only" in blockers:
        return "advisory"
    if "stale_workspace_source_refs" in blockers:
        return "stale-source"
    if "missing_current_workspace_source_refs" in blockers or "missing_source_ref_files" in blockers:
        return "missing-source"
    return "blocked"


def _acceptance_review_fields(row: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    reasons: list[str] = []
    promotion_blockers = [
        blocker for blocker in row.get("promotion_blockers", []) if isinstance(blocker, str) and blocker
    ]
    blockers.extend(promotion_blockers)

    if row.get("advisory_only"):
        blockers.append("advisory_only")

    if row.get("current_workspace_source_refs"):
        reasons.append("current_workspace_source_refs")
    else:
        blockers.append("missing_current_workspace_source_refs")
    if row.get("stale_workspace_source_refs"):
        blockers.append("stale_workspace_source_refs")
    if row.get("missing_source_ref_paths"):
        blockers.append("missing_source_ref_files")
    if row.get("unsafe_source_refs"):
        blockers.append("unsafe_source_refs")

    if row.get("proof_evidence_present"):
        reasons.append("concrete_proof_or_harness_evidence")
    else:
        blockers.append("missing_concrete_proof_evidence")

    deduped_blockers = list(dict.fromkeys(blockers))
    status = _acceptance_status(deduped_blockers)
    accepted = status == "accepted"
    reason = ACCEPTANCE_READY_REASON if accepted else "blocked: " + ", ".join(deduped_blockers)
    return {
        "proof_acceptance_gate_version": ACCEPTANCE_GATE_VERSION,
        "accepted_proof_artifact": accepted,
        "proof_acceptance_status": status,
        "proof_acceptance_blockers": deduped_blockers,
        "proof_acceptance_reasons": sorted(set(reasons)),
        "proof_acceptance_review_reason": reason,
    }


def build_index(
    roots: list[Path],
    *,
    out_path: Path,
    report_path: Path | None = None,
    limit: int = 0,
    dry_run: bool = False,
) -> dict[str, Any]:
    engagements = discover_engagement_roots(roots)
    rows: list[dict[str, Any]] = []
    skipped_unsafe_refs = 0
    submissions_scanned = 0
    engagement_artifact_counts: dict[str, int] = {}
    generated_at = _utc_now()

    for engagement_root in engagements:
        artifacts = scan_proof_artifacts(engagement_root)
        artifact_by_path = {artifact.normalized_path: artifact for artifact in artifacts}
        engagement_artifact_counts[engagement_root.name] = len(artifacts)
        submissions_root = engagement_root / "submissions"
        for submission_path in sorted(submissions_root.rglob("*.md")):
            if not _is_submission_markdown(submission_path):
                continue
            submissions_scanned += 1
            try:
                text = submission_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            title = _title_from_text(text, submission_path.stem)
            source_scan = _source_ref_scan(text, engagement_root, engagement_root.name)
            advisory_only = ADVISORY_ONLY_RE.search(text) is not None
            emitted_for_submission = False
            explicit_refs = [m.group(1).strip() for m in EXPLICIT_REF_RE.finditer(text)]
            explicit_refs.extend(m.group(1).strip() for m in INLINE_PATH_RE.finditer(text) if PROOFISH_RE.search(m.group(1)))
            seen_refs: set[str] = set()
            for raw_ref in explicit_refs:
                if raw_ref in seen_refs:
                    continue
                seen_refs.add(raw_ref)
                path, normalized, reason = _path_from_ref(raw_ref, engagement_root, engagement_root.name)
                if reason != "safe":
                    skipped_unsafe_refs += 1
                    continue
                artifact = artifact_by_path.get(normalized)
                exists = bool(path and path.is_file())
                kind = artifact.kind if artifact else _artifact_kind(path or Path(normalized))
                artifact_path = artifact.path if artifact else path
                proof_evidence_present, proof_evidence_reasons = _proof_evidence_scan(
                    submission_text=text,
                    artifact_path=artifact_path,
                    artifact_kind=kind,
                )
                confidence, reasons = _confidence_from_score(1.0, explicit=True, exists=exists)
                rows.append(
                    _candidate_row(
                        engagement_root=engagement_root,
                        submission_path=submission_path,
                        submission_title=title,
                        candidate_path=normalized,
                        raw_ref=raw_ref,
                        confidence_score=1.0 if exists else 0.72,
                        confidence=confidence,
                        source_reasons=reasons,
                        match_method="submission-explicit-path",
                        artifact_exists=exists,
                        artifact_kind=kind,
                        token_overlap=_tokens(raw_ref) & (_tokens(submission_path.name) | _tokens(title)),
                        source_ref_scan=source_scan,
                        advisory_only=advisory_only,
                        proof_evidence_present=proof_evidence_present,
                        proof_evidence_reasons=proof_evidence_reasons,
                    )
                )
                emitted_for_submission = True
                if limit and len(rows) >= limit:
                    break
            if limit and len(rows) >= limit:
                break
            if emitted_for_submission:
                continue
            submission_tokens = _tokens(submission_path.name) | _tokens(title)
            artifact, score, overlap = _best_token_match(submission_tokens, artifacts)
            if artifact is None or score < 0.12:
                continue
            confidence, reasons = _confidence_from_score(score, explicit=False, exists=artifact.path.is_file())
            reasons.append(f"token_overlap:{','.join(sorted(overlap))}")
            proof_evidence_present, proof_evidence_reasons = _proof_evidence_scan(
                submission_text=text,
                artifact_path=artifact.path,
                artifact_kind=artifact.kind,
            )
            rows.append(
                _candidate_row(
                    engagement_root=engagement_root,
                    submission_path=submission_path,
                    submission_title=title,
                    candidate_path=artifact.normalized_path,
                    raw_ref="",
                    confidence_score=score,
                    confidence=confidence,
                    source_reasons=reasons,
                    match_method="submission-artifact-token-overlap",
                    artifact_exists=artifact.path.is_file(),
                    artifact_kind=artifact.kind,
                    token_overlap=overlap,
                    source_ref_scan=source_scan,
                    advisory_only=advisory_only,
                    proof_evidence_present=proof_evidence_present,
                    proof_evidence_reasons=proof_evidence_reasons,
                )
            )
            if limit and len(rows) >= limit:
                break
        if limit and len(rows) >= limit:
            break

    path_fanout = Counter(row["candidate_proof_path"] for row in rows)
    promotion_ready_by_engagement: Counter[str] = Counter()
    accepted_by_engagement: Counter[str] = Counter()
    for row in rows:
        path_count = path_fanout[row["candidate_proof_path"]]
        promotion_ready, promotion_blockers = _promotion_annotation(row, path_count)
        row["candidate_path_occurrence"] = path_count
        row["candidate_path_specificity"] = round(1.0 / path_count, 4) if path_count else 0.0
        row["promotion_ready"] = promotion_ready
        row["promotion_blockers"] = promotion_blockers
        row.update(_promotion_review_fields(promotion_ready, promotion_blockers))
        row.update(_acceptance_review_fields(row))
        row["generated_at"] = generated_at
        if promotion_ready:
            promotion_ready_by_engagement[row["engagement"]] += 1
        if row["accepted_proof_artifact"]:
            accepted_by_engagement[row["engagement"]] += 1

    promotion_blocker_histogram = Counter(
        blocker
        for row in rows
        for blocker in row.get("promotion_blockers", [])
        if isinstance(blocker, str) and blocker
    )
    acceptance_blocker_histogram = Counter(
        blocker
        for row in rows
        for blocker in row.get("proof_acceptance_blockers", [])
        if isinstance(blocker, str) and blocker
    )
    acceptance_status_counts = Counter(row["proof_acceptance_status"] for row in rows)

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        if report_path is not None:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(render_report(rows, {
                "generated_at": generated_at,
                "engagements_scanned": [p.name for p in engagements],
                "engagement_artifact_counts": engagement_artifact_counts,
                "submissions_scanned": submissions_scanned,
                "skipped_unsafe_refs": skipped_unsafe_refs,
                "promotion_ready_by_engagement": dict(sorted(promotion_ready_by_engagement.items())),
                "promotion_gate_version": PROMOTION_GATE_VERSION,
                "promotion_blocker_histogram": dict(sorted(promotion_blocker_histogram.items())),
                "accepted_by_engagement": dict(sorted(accepted_by_engagement.items())),
                "accepted_proof_rows": sum(1 for row in rows if row["accepted_proof_artifact"]),
                "acceptance_gate_version": ACCEPTANCE_GATE_VERSION,
                "acceptance_status_counts": dict(sorted(acceptance_status_counts.items())),
                "acceptance_blocker_histogram": dict(sorted(acceptance_blocker_histogram.items())),
                "out_path": str(out_path),
            }), encoding="utf-8")

    path_fanout_top = [
        {"candidate_proof_path": path, "occurrences": count}
        for path, count in path_fanout.most_common(10)
    ]
    return {
        "schema": SCHEMA + ".summary",
        "generated_at": generated_at,
        "engagements_scanned": [p.name for p in engagements],
        "engagement_artifact_counts": engagement_artifact_counts,
        "submissions_scanned": submissions_scanned,
        "candidate_rows": len(rows),
        "confidence_counts": dict(Counter(row["confidence"] for row in rows)),
        "skipped_unsafe_refs": skipped_unsafe_refs,
        "promotion_ready_rows": sum(1 for row in rows if row["promotion_ready"]),
        "promotion_ready_by_engagement": dict(sorted(promotion_ready_by_engagement.items())),
        "promotion_ready_max_fanout": PROMOTION_READY_MAX_FANOUT,
        "promotion_gate_version": PROMOTION_GATE_VERSION,
        "promotion_blocker_histogram": dict(sorted(promotion_blocker_histogram.items())),
        "accepted_proof_rows": sum(1 for row in rows if row["accepted_proof_artifact"]),
        "accepted_by_engagement": dict(sorted(accepted_by_engagement.items())),
        "acceptance_gate_version": ACCEPTANCE_GATE_VERSION,
        "acceptance_status_counts": dict(sorted(acceptance_status_counts.items())),
        "acceptance_blocker_histogram": dict(sorted(acceptance_blocker_histogram.items())),
        "path_fanout_top": path_fanout_top,
        "out_path": str(out_path),
        "report_path": str(report_path) if report_path else "",
        "dry_run": dry_run,
        "sample_rows": rows[:10],
    }


def render_report(rows: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    confidence_counts = Counter(row["confidence"] for row in rows)
    kind_counts = Counter(row["candidate_artifact_kind"] for row in rows)
    engagement_counts = Counter(row["engagement"] for row in rows)
    promotion_ready_count = sum(1 for row in rows if row.get("promotion_ready"))
    accepted_count = sum(1 for row in rows if row.get("accepted_proof_artifact"))
    top_paths = Counter(row["candidate_proof_path"] for row in rows).most_common(10)
    sample_rows = rows[:8]

    lines = [
        "# Proof Artifact Index Phase A - 2026-05-17",
        "",
        "## Scope",
        "",
        "Built a read-only sidecar over local engagement submissions and PoC proof artifacts.",
        "This index reports candidate paths, confidence, and source reasons only; it does not mutate corpus tag YAML.",
        "",
        "## Outputs",
        "",
        f"- `{summary['out_path']}`",
        "- `reports/proof_artifact_index_phase_a_2026-05-17.md`",
        "",
        "## Counts",
        "",
        f"- engagements scanned: {len(summary['engagements_scanned'])}",
        f"- generated at: {summary.get('generated_at', '')}",
        f"- submissions scanned: {summary['submissions_scanned']}",
        f"- candidate rows: {len(rows)}",
        f"- skipped unsafe refs: {summary['skipped_unsafe_refs']}",
        f"- confidence: {dict(sorted(confidence_counts.items()))}",
        f"- promotion-ready rows: {promotion_ready_count} (fanout <= {PROMOTION_READY_MAX_FANOUT}, explicit high-confidence existing refs only)",
        f"- promotion gate: {summary.get('promotion_gate_version', PROMOTION_GATE_VERSION)}",
        f"- promotion blockers: {summary.get('promotion_blocker_histogram', {})}",
        f"- accepted proof rows: {accepted_count}",
        f"- acceptance gate: {summary.get('acceptance_gate_version', ACCEPTANCE_GATE_VERSION)}",
        f"- acceptance status: {summary.get('acceptance_status_counts', {})}",
        f"- acceptance blockers: {summary.get('acceptance_blocker_histogram', {})}",
        f"- artifact kinds: {dict(sorted(kind_counts.items()))}",
        "",
        "## Engagement Candidate Rows",
        "",
    ]
    for engagement, count in engagement_counts.most_common():
        artifacts = summary["engagement_artifact_counts"].get(engagement, 0)
        lines.append(f"- `{engagement}`: {count} rows, {artifacts} indexed artifacts")
    if not engagement_counts:
        lines.append("- none")
    lines.extend(["", "## Top Candidate Paths", ""])
    for path, count in top_paths:
        lines.append(f"- `{path}` ({count})")
    if not top_paths:
        lines.append("- none")
    lines.extend(["", "## Promotion-Ready Rows", ""])
    promotion_ready_rows = [row for row in rows if row.get("promotion_ready")]
    for row in promotion_ready_rows[:8]:
        lines.append(
            f"- `{row['engagement']}` `{row['candidate_proof_path']}` "
            f"from `{row['submission_path']}`"
        )
    if not promotion_ready_rows:
        lines.append("- none")
    lines.extend(["", "## Accepted Proof-Backed Rows", ""])
    accepted_rows = [row for row in rows if row.get("accepted_proof_artifact")]
    for row in accepted_rows[:8]:
        lines.append(
            f"- `{row['engagement']}` `{row['candidate_proof_path']}` "
            f"from `{row['submission_path']}`"
        )
    if not accepted_rows:
        lines.append("- none")
    lines.extend(["", "## Sample Rows", ""])
    for row in sample_rows:
        reasons = ", ".join(row["source_reasons"])
        promotion_note = "promotion-ready" if row.get("promotion_ready") else ",".join(row.get("promotion_blockers", []))
        acceptance_note = row.get("proof_acceptance_status", "unknown")
        lines.append(
            f"- `{row['engagement']}` `{row['confidence']}` `{row['candidate_proof_path']}` "
            f"from `{row['submission_path']}` ({reasons}; {promotion_note}; {acceptance_note})"
        )
    if not sample_rows:
        lines.append("- none")
    lines.extend([
        "",
        "## Limitations",
        "",
        "- Confidence is heuristic and review-only; no row is safe for automatic corpus mutation by this tool.",
        "- Explicit submission references are stronger than filename token matches, but may still point at stale local paths.",
        "- Accepted proof-backed rows require current-workspace source refs and concrete proof or harness evidence.",
        "- The scanner is local-workspace based and only sees artifacts present under engagement roots at run time.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--roots",
        nargs="*",
        default=[str(DEFAULT_AUDITS_ROOT)],
        help="Audit roots or engagement roots to scan. Default: ~/audits",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    summary = build_index(
        [Path(root) for root in args.roots],
        out_path=args.out,
        report_path=args.report,
        limit=args.limit,
        dry_run=args.dry_run,
    )
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"candidate_rows={summary['candidate_rows']} "
            f"promotion_ready={summary['promotion_ready_rows']} "
            f"accepted_proof_rows={summary['accepted_proof_rows']} "
            f"submissions_scanned={summary['submissions_scanned']} "
            f"out={summary['out_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
