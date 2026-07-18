#!/usr/bin/env python3
"""Extract bounded lesson candidates from local agent artifact evidence.

This tool is deliberately conservative.  It reads already-local
``agent_artifact_mining_report.json`` files and workspace ``agent_outputs``
summaries, ranks primary outcomes ahead of generic agent notes, and emits
candidate lessons for human review.  It does not use the network and does not
promote any candidate as true.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = "auditooor.agent_artifact_lesson_candidates.v1"
DEFAULT_LIMIT = 50
MAX_LIMIT = 500

REPORT_CANDIDATES = (
    "agent_artifact_mining_report.json",
    ".auditooor/agent_artifact_mining_report.json",
)

PRIMARY_VERDICT_RE = re.compile(
    r"\b("
    r"POC_PASS|TEST_PASS|PASSING_TEST|EXECUTION_PROOF_READY|PROOF_READY|"
    r"PROVED|EXPLOIT_IMPACT|EXECUTED_WITH_MANIFEST|"
    r"FILED|SUBMITTED|ACCEPTED|REJECTED|REJECTED_OR_OOS|OOS|DUPLICATE|"
    r"TRIAGER|TEAM_FEEDBACK"
    r")\b",
    re.IGNORECASE,
)
PRIMARY_REF_RE = re.compile(
    r"(^|/)(submissions/|SUBMISSIONS\.md$|poc_execution/|execution_manifest\.json$|"
    r"reference/outcomes\.jsonl$|reference/triager_patterns\.(?:json|md)$|"
    r"proof_artifact|impact[_-]?proof|exploit[_-]?proof)",
    re.IGNORECASE,
)
PROOF_RE = re.compile(
    r"(?:--- PASS:|^PASS$|test\s+pass|suite result:\s*ok|"
    r"final_result\s*[:=]\s*proved|proof_status\s*[:=]\s*proved|"
    r"execution_proof_ready|executed_with_manifest|exploit_impact)",
    re.IGNORECASE | re.MULTILINE,
)
SUBMISSION_RE = re.compile(
    r"\b(?:FILED|SUBMITTED|ACCEPTED|REJECTED|REJECTED_OR_OOS|PASTE_READY|IN_REVIEW)\b",
    re.IGNORECASE,
)
TRIAGER_RE = re.compile(r"\b(?:triager|team feedback|closed as|closed for|duplicate|OOS)\b", re.IGNORECASE)
LESSON_LINE_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:Capability\s+lesson|Lesson|Learning|Audit Benefit|Follow[- ]?up|Blocker|Known limitation)\s*[:\-]\s*(.+)$",
    re.IGNORECASE,
)
HEADING_RE = re.compile(r"^#{1,3}\s+(.+?)\s*$", re.MULTILINE)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_text(path: Path, max_chars: int = 400_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _short_hash(text: str, length: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:length]


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)


def _safe_text(value: Any, *, max_chars: int = 600) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:max_chars]


def _normalize_key(*parts: Any) -> str:
    text = " ".join(_safe_text(part, max_chars=400) for part in parts).lower()
    words = re.findall(r"[a-z0-9_]+", text)
    stop = {
        "agent",
        "artifact",
        "candidate",
        "lesson",
        "report",
        "from",
        "with",
        "this",
        "that",
        "proof",
        "local",
    }
    kept = [word for word in words if word not in stop][:18]
    return " ".join(kept) or _short_hash(text)


def _lesson_kind(artifact_type: str, text: str) -> str:
    haystack = text.lower()
    if artifact_type == "proof_artifact_mapping_candidate" or PROOF_RE.search(text):
        return "proof_artifact"
    if artifact_type in {"rejection_pattern", "kill_rubric_entry", "falsification_template"}:
        return "kill_reason"
    if artifact_type == "triager_pattern" or TRIAGER_RE.search(text):
        return "triager_objection"
    if artifact_type == "candidate_hacker_question":
        return "hacker_question"
    if artifact_type in {"harness_template_request"} or "harness" in haystack:
        return "harness_gap"
    if artifact_type in {"roadmap_gap", "known_limitation"}:
        return "workflow_gap"
    if artifact_type == "candidate_detector_pattern":
        return "detector_gap"
    return "typed_lesson"


def _artifact_is_primary(artifact: dict[str, Any]) -> tuple[bool, str]:
    artifact_type = str(artifact.get("artifact_type") or "")
    verdict = str(artifact.get("verdict") or "")
    provenance_ref = str(artifact.get("provenance_ref") or "")
    text = " ".join(
        str(artifact.get(key) or "")
        for key in ("title", "content", "verdict", "provenance_ref")
    )
    has_primary_ref = bool(PRIMARY_REF_RE.search(provenance_ref))
    if artifact_type == "proof_artifact_mapping_candidate" and artifact.get("source_has_local_proof") is True and has_primary_ref:
        return True, "local_proof"
    if PROOF_RE.search(text) and has_primary_ref:
        return True, "proof_transcript"
    if (PRIMARY_VERDICT_RE.search(verdict) or SUBMISSION_RE.search(verdict)) and has_primary_ref:
        return True, "submission_or_triager_outcome"
    if "submissions/" in provenance_ref or provenance_ref == "SUBMISSIONS.md":
        return True, "submission_artifact"
    return False, ""


def _evidence_tier_for_artifact(artifact: dict[str, Any]) -> tuple[str, str]:
    is_primary, primary_type = _artifact_is_primary(artifact)
    if is_primary:
        return "primary", primary_type
    if artifact.get("provider_only") is True or artifact.get("verification_tier") == "tier-5-quarantine":
        return "quarantine", "provider_or_worker_only"
    return "secondary", "agent_artifact"


def _confidence(evidence_tier: str, source_has_local_proof: bool = False) -> tuple[str, float]:
    if evidence_tier == "primary":
        return "high", 0.86
    if evidence_tier == "secondary" and source_has_local_proof:
        return "medium", 0.56
    if evidence_tier == "secondary":
        return "low", 0.38
    return "low", 0.18


def _candidate(
    *,
    title: str,
    lesson_statement: str,
    lesson_kind: str,
    evidence_tier: str,
    primary_outcome_type: str,
    confidence: str,
    confidence_score: float,
    provenance: list[dict[str, Any]],
    source_artifact_types: Iterable[str],
    key: str | None = None,
) -> dict[str, Any]:
    canonical_key = key or _normalize_key(title, lesson_statement)
    return {
        "candidate_id": f"aalc-{_short_hash(canonical_key)}",
        "lesson_kind": lesson_kind,
        "title": _safe_text(title, max_chars=180),
        "lesson_statement": _safe_text(
            "Candidate lesson to review: " + lesson_statement,
            max_chars=700,
        ),
        "evidence_tier": evidence_tier,
        "primary_outcome_type": primary_outcome_type,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "source_artifact_types": sorted({str(t) for t in source_artifact_types if str(t)}),
        "provenance": provenance,
        "required_human_review": True,
        "advisory_only": True,
        "promotion_authority": False,
        "submit_ready": False,
        "candidate_truth_claim": False,
    }


def _candidate_from_artifact(
    artifact: dict[str, Any],
    report_path: Path,
    workspace: Path,
) -> dict[str, Any] | None:
    title = _safe_text(artifact.get("title"), max_chars=180)
    content = _safe_text(artifact.get("content"), max_chars=700)
    if not title and not content:
        return None

    artifact_type = str(artifact.get("artifact_type") or "unknown")
    text = f"{title}. {content}. {artifact.get('verdict') or ''}"
    evidence_tier, primary_type = _evidence_tier_for_artifact(artifact)
    conf, score = _confidence(evidence_tier, evidence_tier == "primary" and artifact.get("source_has_local_proof") is True)
    provenance = [
        {
            "source_type": "agent_artifact_mining_report",
            "path": _rel(report_path, workspace),
            "artifact_id": artifact.get("artifact_id"),
            "artifact_type": artifact_type,
            "artifact_provenance_ref": artifact.get("provenance_ref"),
            "verdict": artifact.get("verdict"),
            "evidence_tier": evidence_tier,
        }
    ]
    return _candidate(
        title=title or artifact_type,
        lesson_statement=content or title,
        lesson_kind=_lesson_kind(artifact_type, text),
        evidence_tier=evidence_tier,
        primary_outcome_type=primary_type,
        confidence=conf,
        confidence_score=score,
        provenance=provenance,
        source_artifact_types=[artifact_type],
        key=_normalize_key(artifact_type, title, content),
    )


def _report_paths(workspace: Path, explicit: Sequence[Path] | None = None) -> list[Path]:
    if explicit:
        paths = [path.expanduser() for path in explicit]
    else:
        paths = [workspace / rel for rel in REPORT_CANDIDATES]
    seen: set[Path] = set()
    result: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.is_file():
            result.append(path)
    return result


def _extract_report_candidates(
    workspace: Path,
    report_paths: Sequence[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    for report_path in report_paths:
        payload = _load_json(report_path)
        if payload is None:
            reports.append({"path": _rel(report_path, workspace), "loaded": False, "reason": "malformed_json"})
            continue
        artifacts_raw = payload.get("artifacts") or []
        artifacts = [item for item in artifacts_raw if isinstance(item, dict)] if isinstance(artifacts_raw, list) else []
        reports.append(
            {
                "path": _rel(report_path, workspace),
                "loaded": True,
                "schema_version": payload.get("schema_version"),
                "total_artifacts": len(artifacts),
            }
        )
        for artifact in artifacts:
            candidate = _candidate_from_artifact(artifact, report_path, workspace)
            if candidate:
                candidates.append(candidate)
    return candidates, reports


def _summary_title(path: Path, text: str) -> str:
    heading = HEADING_RE.search(text)
    if heading:
        return heading.group(1).strip()[:180]
    return path.stem.replace("_", " ").replace("-", " ")[:180]


def _summary_statement(path: Path, text: str, is_primary: bool) -> str:
    for line in text.splitlines():
        match = LESSON_LINE_RE.match(line)
        if match and match.group(1).strip():
            return match.group(1).strip()[:700]
    compact = re.sub(r"\s+", " ", text).strip()
    if is_primary:
        proof_match = PROOF_RE.search(text) or SUBMISSION_RE.search(text) or TRIAGER_RE.search(text)
        if proof_match:
            start = max(0, proof_match.start() - 160)
            end = min(len(text), proof_match.end() + 420)
            return re.sub(r"\s+", " ", text[start:end]).strip()[:700]
    return compact[:700]


def _iter_agent_summary_paths(workspace: Path) -> Iterable[Path]:
    agent_outputs = workspace / "agent_outputs"
    if not agent_outputs.is_dir():
        return []
    paths: list[Path] = []
    for path in sorted(agent_outputs.rglob("*.md")):
        lower = path.name.lower()
        rel = _rel(path, workspace).lower()
        if (
            "summary" in lower
            or "report" in lower
            or "final" in lower
            or "closeout" in lower
            or "capability" in lower
            or "lesson" in lower
            or "handoff" in lower
            or lower == "report.md"
            or "/report.md" in rel
        ):
            paths.append(path)
    return paths


def _candidate_from_summary(path: Path, workspace: Path) -> dict[str, Any] | None:
    text = _read_text(path, max_chars=160_000)
    if not text:
        return None
    has_primary = bool(PROOF_RE.search(text) or SUBMISSION_RE.search(text) or TRIAGER_RE.search(text))
    has_lesson = bool(LESSON_LINE_RE.search(text))
    if not has_primary and not has_lesson:
        return None

    evidence_tier = "secondary"
    primary_type = ""
    if PROOF_RE.search(text):
        primary_type = "agent_summary_proof_signal_unverified"
    elif SUBMISSION_RE.search(text):
        primary_type = "agent_summary_submission_signal_unverified"
    elif TRIAGER_RE.search(text):
        primary_type = "agent_summary_triager_signal_unverified"

    conf, score = _confidence(evidence_tier, source_has_local_proof=False)
    title = _summary_title(path, text)
    statement = _summary_statement(path, text, has_primary)
    provenance = [
        {
            "source_type": "agent_outputs_summary",
            "path": _rel(path, workspace),
            "evidence_tier": evidence_tier,
            "primary_signal": primary_type,
            "primary_signal_unverified": bool(has_primary),
        }
    ]
    kind = _lesson_kind("agent_outputs_summary", f"{title}\n{statement}")
    return _candidate(
        title=title,
        lesson_statement=statement,
        lesson_kind=kind,
        evidence_tier=evidence_tier,
        primary_outcome_type=primary_type,
        confidence=conf,
        confidence_score=score,
        provenance=provenance,
        source_artifact_types=["agent_outputs_summary"],
        key=_normalize_key("agent_outputs_summary", title, statement),
    )


def _rank(candidate: dict[str, Any]) -> tuple[int, float, str]:
    tier_rank = {"primary": 0, "secondary": 1, "quarantine": 2}.get(str(candidate.get("evidence_tier")), 3)
    kind_rank = {
        "proof_artifact": 0,
        "triager_objection": 1,
        "kill_reason": 2,
        "hacker_question": 3,
        "harness_gap": 4,
        "workflow_gap": 5,
        "detector_gap": 6,
        "typed_lesson": 7,
    }.get(str(candidate.get("lesson_kind")), 9)
    return (tier_rank * 10 + kind_rank, -float(candidate.get("confidence_score") or 0.0), str(candidate.get("title") or ""))


def _merge_candidate(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    if _rank(incoming) < _rank(existing):
        winner, other = incoming, existing
    else:
        winner, other = existing, incoming

    provenance = list(winner.get("provenance") or [])
    seen = {json.dumps(item, sort_keys=True, default=str) for item in provenance}
    for item in other.get("provenance") or []:
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker not in seen:
            provenance.append(item)
            seen.add(marker)
    winner = dict(winner)
    winner["provenance"] = provenance[:12]
    winner["source_artifact_types"] = sorted(
        set(winner.get("source_artifact_types") or []) | set(other.get("source_artifact_types") or [])
    )
    winner["candidate_id"] = f"aalc-{_short_hash(_normalize_key(winner.get('title'), winner.get('lesson_statement')))}"
    return winner


def _dedupe(candidates: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        key = _normalize_key(candidate.get("lesson_kind"), candidate.get("title"), candidate.get("lesson_statement"))
        if key in by_key:
            by_key[key] = _merge_candidate(by_key[key], candidate)
        else:
            by_key[key] = candidate
    return sorted(by_key.values(), key=_rank)


def extract_lesson_candidates(
    workspace: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    reports: Sequence[Path] | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    bounded_limit = max(0, min(int(limit), MAX_LIMIT))
    selected_reports = _report_paths(workspace, reports)
    report_candidates, report_summary = _extract_report_candidates(workspace, selected_reports)

    summary_candidates: list[dict[str, Any]] = []
    summary_paths = list(_iter_agent_summary_paths(workspace))
    for path in summary_paths:
        candidate = _candidate_from_summary(path, workspace)
        if candidate:
            summary_candidates.append(candidate)

    all_candidates = _dedupe([*report_candidates, *summary_candidates])
    bounded = all_candidates[:bounded_limit]

    by_tier: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for candidate in bounded:
        by_tier[str(candidate.get("evidence_tier") or "")] = by_tier.get(str(candidate.get("evidence_tier") or ""), 0) + 1
        by_confidence[str(candidate.get("confidence") or "")] = by_confidence.get(str(candidate.get("confidence") or ""), 0) + 1
        by_kind[str(candidate.get("lesson_kind") or "")] = by_kind.get(str(candidate.get("lesson_kind") or ""), 0) + 1

    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at_utc": _utc_now(),
        "advisory_only": True,
        "promotion_authority": False,
        "network_used": False,
        "truth_claims_made": False,
        "required_human_review": True,
        "limit": bounded_limit,
        "bounded": len(all_candidates) > bounded_limit,
        "total_candidates_unbounded": len(all_candidates),
        "total_candidates": len(bounded),
        "reports_considered": report_summary,
        "agent_output_summaries_considered": [_rel(path, workspace) for path in summary_paths],
        "by_evidence_tier": dict(sorted(by_tier.items())),
        "by_confidence": dict(sorted(by_confidence.items())),
        "by_lesson_kind": dict(sorted(by_kind.items())),
        "no_learning_reason": len(bounded) == 0,
        "candidates": bounded,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True, help="Workspace root to scan.")
    parser.add_argument("--report", type=Path, action="append", default=None, help="Explicit mining report path. Repeatable.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum candidates to emit (default {DEFAULT_LIMIT}, max {MAX_LIMIT}).")
    parser.add_argument("--out", type=Path, help="Write JSON to this path instead of stdout.")
    parser.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON to stdout.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser()
    if not workspace.is_dir():
        print(f"ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 2
    payload = extract_lesson_candidates(workspace, limit=args.limit, reports=args.report)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        out = args.out.expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"agent-artifact-lesson-candidates: wrote {payload['total_candidates']} candidates to {out}", file=sys.stderr)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
