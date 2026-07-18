#!/usr/bin/env python3
"""Phase II.6.C semantic predicate gate.

Standalone two-stage verifier for P1 predicate naming overshoot:

1. Stage 1 is the existing live-target report predicate tier. This tool only
   selects rows that are still TOPICAL-MATCH.
2. Stage 2 asks ``tools/llm-dispatch.py`` whether the cited code is a real
   semantic match for the specific invariant/predicate, a broad topical hit,
   or a false positive.

By default the tool emits a JSON sidecar. When ``--apply-to-report`` is passed,
non-dry-run/cache SEMANTIC verdicts are merged back into the live-target report;
FALSE-POSITIVE verdicts are recorded as audit evidence only.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import os
from typing import Any


SCHEMA = "auditooor.semantic_predicate_gate.v1"
TOOL_VERSION = "0.2.0-semantic-apply"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_DISPATCHER = REPO_ROOT / "tools" / "llm-dispatch.py"
DEFAULT_INVARIANT_PATHS = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl",
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl",
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl",
)
VALID_VERDICTS = {"SEMANTIC", "TOPICAL", "FALSE-POSITIVE"}
REPORT_ENTRY_KEYS = ("entry_points", "prioritized_hunt_list", "records", "candidates")


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_code_for_hash(text: str) -> str:
    """Hash source content, not incidental excerpt line numbers."""
    return "\n".join(
        re.sub(r"^\s*\d+:\s?", "", line).rstrip()
        for line in str(text or "").splitlines()
    ).strip()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(value)]


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_live_target_module() -> Any | None:
    path = REPO_ROOT / "tools" / "live-target-intelligence-report.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "auditooor_live_target_report_for_semantic_gate",
        path,
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def load_invariant_index(paths: tuple[pathlib.Path, ...] = DEFAULT_INVARIANT_PATHS) -> dict[str, dict[str, Any]]:
    """Load invariant records by invariant_id.

    Earlier paths win, so the audited pilot subset overrides broader fallback
    rows when the same invariant_id appears in multiple files.
    """
    index: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    inv_id = str(rec.get("invariant_id") or "").strip()
                    if not inv_id or inv_id in index:
                        continue
                    index[inv_id] = rec
        except OSError:
            continue
    return index


def parse_file_line(file_line: str) -> tuple[str, int | None]:
    match = re.match(r"^(.*?):(\d+)(?::\d+)?$", str(file_line or ""))
    if not match:
        return str(file_line or ""), None
    return match.group(1), int(match.group(2))


def read_code_excerpt(
    workspace: pathlib.Path | None,
    entry: dict[str, Any],
    *,
    context_lines: int = 80,
) -> tuple[str, list[str]]:
    """Return cited code for hashing/prompting plus non-fatal warnings."""
    warnings: list[str] = []
    for key in ("source_context", "source_context_excerpt", "code", "code_excerpt"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), warnings

    file_line = str(entry.get("file_line") or entry.get("file_path") or "")
    rel, line_no = parse_file_line(file_line)
    if workspace is not None and rel:
        path = pathlib.Path(rel)
        if not path.is_absolute():
            path = workspace / path
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line_no is None:
                return "\n".join(lines[: max(1, context_lines * 2)]).strip(), warnings
            start = max(1, line_no - context_lines)
            end = min(len(lines), line_no + context_lines)
            excerpt = "\n".join(
                f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1)
            )
            return excerpt.strip(), warnings
        except OSError as exc:
            warnings.append(f"source-read-failed: {path}: {exc}")

    snippet = str(entry.get("snippet") or "").strip()
    if snippet:
        return snippet, warnings
    warnings.append("code-unavailable: no source_context, readable file_line, or snippet")
    return "", warnings


def _entry_rows(report: Any) -> list[dict[str, Any]]:
    if isinstance(report, list):
        return [row for row in report if isinstance(row, dict)]
    if not isinstance(report, dict):
        return []
    for key in REPORT_ENTRY_KEYS:
        rows = report.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _primary_report_entries(report: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    for key in REPORT_ENTRY_KEYS:
        rows = report.get(key)
        if isinstance(rows, list):
            return key, [row for row in rows if isinstance(row, dict)]
    report["entry_points"] = []
    return "entry_points", []


def _as_set(value: Any) -> set[str]:
    return set(_as_list(value))


def _entry_has_predicate(entry: dict[str, Any], predicate_id: str) -> bool:
    predicate_id = str(predicate_id or "").strip()
    if not predicate_id:
        return False
    return predicate_id in (
        _as_set(entry.get("topical_p1_invariants"))
        | _as_set(entry.get("semantic_p1_invariants"))
        | _as_set(entry.get("matched_p1_invariants"))
        | _as_set(entry.get("p1_invariant_hits"))
    )


def _entry_candidate_id(entry: dict[str, Any], predicate_id: str) -> str:
    return "|".join(
        [
            str(entry.get("file_line") or entry.get("file_path") or ""),
            str(entry.get("cluster_id") or entry.get("detector_slug") or ""),
            str(predicate_id or ""),
        ]
    )


def _entry_matches_verdict(entry: dict[str, Any], verdict: dict[str, Any]) -> bool:
    predicate_id = str(verdict.get("predicate_id") or "").strip()
    if not _entry_has_predicate(entry, predicate_id):
        return False
    file_line = str(verdict.get("file_line") or "")
    cluster_id = str(verdict.get("cluster_id") or "")
    if file_line and str(entry.get("file_line") or entry.get("file_path") or "") != file_line:
        return False
    if cluster_id and str(entry.get("cluster_id") or entry.get("detector_slug") or "") != cluster_id:
        return False
    return True


def _find_report_entry(
    entries: list[dict[str, Any]],
    verdict: dict[str, Any],
) -> tuple[int | None, str]:
    predicate_id = str(verdict.get("predicate_id") or "").strip()
    try:
        entry_index = int(verdict.get("entry_index"))
    except (TypeError, ValueError):
        entry_index = -1
    if 0 <= entry_index < len(entries) and _entry_matches_verdict(entries[entry_index], verdict):
        return entry_index, "entry_index"

    candidate_id = str(verdict.get("candidate_id") or "")
    if candidate_id:
        for idx, entry in enumerate(entries):
            if _entry_candidate_id(entry, predicate_id) == candidate_id:
                return idx, "candidate_id"

    for idx, entry in enumerate(entries):
        if _entry_matches_verdict(entry, verdict):
            return idx, "file_line_cluster_predicate"
    return None, "unmatched"


def _append_unique(items: list[str], value: str) -> list[str]:
    if value and value not in items:
        items.append(value)
    return items


def _append_semantic_gate_verdict(
    entry: dict[str, Any],
    verdict: dict[str, Any],
    *,
    applied: bool,
    action: str,
    match_strategy: str,
) -> bool:
    audit_rows = entry.setdefault("semantic_gate_verdicts", [])
    if not isinstance(audit_rows, list):
        audit_rows = []
        entry["semantic_gate_verdicts"] = audit_rows
    row = {
        "predicate_id": str(verdict.get("predicate_id") or ""),
        "verdict": normalize_verdict(verdict.get("verdict")) or "TOPICAL",
        "reason": str(verdict.get("reason") or "")[:1000],
        "evidence": str(verdict.get("evidence") or "")[:1000],
        "source": str(verdict.get("source") or ""),
        "cache_key": str(verdict.get("cache_key") or ""),
        "candidate_id": str(verdict.get("candidate_id") or ""),
        "applied": bool(applied),
        "action": action,
        "match_strategy": match_strategy,
    }
    key = (
        row["predicate_id"],
        row["verdict"],
        row["cache_key"],
        row["candidate_id"],
        row["action"],
    )
    for existing in audit_rows:
        if not isinstance(existing, dict):
            continue
        existing_key = (
            str(existing.get("predicate_id") or ""),
            str(existing.get("verdict") or ""),
            str(existing.get("cache_key") or ""),
            str(existing.get("candidate_id") or ""),
            str(existing.get("action") or ""),
        )
        if existing_key == key:
            return False
    audit_rows.append(row)
    return True


def _bucket_for_score(score: float) -> str:
    high = int(os.environ.get("AUDITOOOR_P5_HIGH_THRESHOLD", "70"))
    medium = int(os.environ.get("AUDITOOOR_P5_MEDIUM_THRESHOLD", "40"))
    if score >= high:
        return "HIGH-PRIORITY-HUNT"
    if score >= medium:
        return "MEDIUM-PRIORITY"
    return "LOW-PRIORITY"


def _bucket_with_composability(score: float, composability_score: int) -> tuple[str, str, bool]:
    threshold = int(os.environ.get("AUDITOOOR_P5_COMPOSABILITY_BUMP", "3"))
    score_bucket = _bucket_for_score(score)
    if composability_score < threshold:
        return score_bucket, score_bucket, False
    if score_bucket == "LOW-PRIORITY":
        return "MEDIUM-PRIORITY", score_bucket, True
    if score_bucket == "MEDIUM-PRIORITY":
        return "HIGH-PRIORITY-HUNT", score_bucket, True
    return score_bucket, score_bucket, False


def _refresh_entry_after_gate(entry: dict[str, Any]) -> None:
    semantic = _as_list(entry.get("semantic_p1_invariants"))
    p3 = [
        pid for pid in _as_list(entry.get("matched_anti_patterns"))
        if not pid.startswith("no-P3-match")
    ]
    entry["composability_score"] = len(p3) + len(semantic)
    try:
        score = float(entry.get("engage_severity_score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    priority, base, bumped = _bucket_with_composability(score, int(entry["composability_score"]))
    entry["hunt_priority"] = priority
    entry["hunt_priority_base"] = base
    entry["composability_bucket_bumped"] = bumped


def _refresh_report_after_gate(report: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    entries.sort(key=lambda e: float(e.get("engage_severity_score") or 0.0), reverse=True)
    report["entry_points"] = entries
    report["prioritized_hunt_list"] = json.loads(json.dumps(entries))
    summary = report.setdefault("summary_card", {})
    if not isinstance(summary, dict):
        summary = {}
        report["summary_card"] = summary
    comp = summary.setdefault("composability", {})
    if not isinstance(comp, dict):
        comp = {}
        summary["composability"] = comp
    scores = [int(entry.get("composability_score") or 0) for entry in entries]
    comp["composability_score_max"] = max(scores) if scores else 0
    comp["composability_score_min"] = min(scores) if scores else 0
    comp["composability_score_avg"] = round(sum(scores) / len(scores), 2) if scores else 0
    comp["entries_bucket_bumped"] = sum(
        1 for entry in entries if entry.get("composability_bucket_bumped")
    )
    comp["p1_match_tier_counts"] = {
        "SEMANTIC-MATCH": sum(
            1 for entry in entries if entry.get("p1_match_tier") == "SEMANTIC-MATCH"
        ),
        "TOPICAL-MATCH": sum(
            1 for entry in entries if entry.get("p1_match_tier") == "TOPICAL-MATCH"
        ),
        "NO-MATCH": sum(1 for entry in entries if entry.get("p1_match_tier") == "NO-MATCH"),
    }
    gap_counts: dict[str, int] = {}
    for entry in entries:
        gaps = entry.get("p1_semantic_invariant_gaps") or []
        if not gaps:
            gap_counts["none"] = gap_counts.get("none", 0) + 1
            continue
        for gap in gaps:
            status = str((gap or {}).get("status") or "unknown")
            gap_counts[status] = gap_counts.get(status, 0) + 1
    comp["p1_semantic_gap_counts"] = gap_counts
    summary["ranked_hunt_list_size"] = len(entries)
    summary["top30_unique_score_count"] = len(
        {float(entry.get("engage_severity_score") or 0.0) for entry in entries[:30]}
    )
    summary["hunt_priority_distribution"] = {
        "HIGH-PRIORITY-HUNT": sum(
            1 for entry in entries if entry.get("hunt_priority") == "HIGH-PRIORITY-HUNT"
        ),
        "MEDIUM-PRIORITY": sum(
            1 for entry in entries if entry.get("hunt_priority") == "MEDIUM-PRIORITY"
        ),
        "LOW-PRIORITY": sum(
            1 for entry in entries if entry.get("hunt_priority") == "LOW-PRIORITY"
        ),
    }
    action_queue = [
        {
            "rank": idx + 1,
            "file_line": entry.get("file_line", ""),
            "cluster_id": entry.get("cluster_id", ""),
            "engage_severity_score": entry.get("engage_severity_score", 0),
            "hunt_priority": entry.get("hunt_priority", ""),
            "next_step": "PoC build + V3-grade evidence per R40",
        }
        for idx, entry in enumerate(entries)
        if entry.get("hunt_priority") == "HIGH-PRIORITY-HUNT"
    ][:25]
    summary["operator_action_queue_size"] = len(action_queue)
    report["operator_action_queue"] = action_queue


def apply_verdicts_to_report(
    report: dict[str, Any],
    gate_payload: dict[str, Any],
    *,
    include_dry_run: bool = False,
) -> dict[str, Any]:
    """Merge semantic-gate verdicts into a live-target report in-place."""
    _primary_key, entries = _primary_report_entries(report)
    summary = {
        "schema": "auditooor.semantic_predicate_gate.apply.v1",
        "tool_version": TOOL_VERSION,
        "applied_at_utc": _utc_now(),
        "semantic_promotions": 0,
        "false_positive_records": 0,
        "topical_records": 0,
        "dry_run_verdicts_skipped": 0,
        "unmatched_verdicts": 0,
        "row_match_strategy_counts": {},
        "false_positive_policy": (
            "record-only; no automatic suppression/removal without operator acceptance"
        ),
    }
    changed = False
    for verdict in gate_payload.get("verdicts") or []:
        if not isinstance(verdict, dict):
            continue
        normalized = normalize_verdict(verdict.get("verdict")) or "TOPICAL"
        source = str(verdict.get("source") or "")
        if source == "dry-run" and not include_dry_run:
            summary["dry_run_verdicts_skipped"] += 1
            continue
        entry_idx, strategy = _find_report_entry(entries, verdict)
        summary["row_match_strategy_counts"][strategy] = (
            summary["row_match_strategy_counts"].get(strategy, 0) + 1
        )
        if entry_idx is None:
            summary["unmatched_verdicts"] += 1
            continue
        entry = entries[entry_idx]
        predicate_id = str(verdict.get("predicate_id") or "").strip()
        if normalized == "SEMANTIC":
            semantic_before = set(_as_list(entry.get("semantic_p1_invariants")))
            matched = _as_list(entry.get("matched_p1_invariants") or entry.get("p1_invariant_hits"))
            semantic = _as_list(entry.get("semantic_p1_invariants"))
            topical = [
                pid for pid in _as_list(entry.get("topical_p1_invariants"))
                if pid != predicate_id
            ]
            entry["matched_p1_invariants"] = _append_unique(matched, predicate_id)
            entry["p1_invariant_hits"] = _append_unique(
                _as_list(entry.get("p1_invariant_hits")),
                predicate_id,
            )
            entry["semantic_p1_invariants"] = _append_unique(semantic, predicate_id)
            entry["topical_p1_invariants"] = topical
            entry["p1_match_tier"] = "SEMANTIC-MATCH"
            entry["p1_semantic_invariant_gaps"] = []
            if predicate_id not in semantic_before:
                try:
                    score = float(entry.get("engage_severity_score") or 0.0)
                except (TypeError, ValueError):
                    score = 0.0
                entry["engage_severity_score"] = round(min(100.0, score + 8.0), 2)
                entry["semantic_gate_score_adjustment"] = {
                    "reason": "semantic-gate-promotion",
                    "delta": 8.0,
                    "predicate_id": predicate_id,
                }
                summary["semantic_promotions"] += 1
            _append_semantic_gate_verdict(
                entry,
                verdict,
                applied=True,
                action="promoted-to-semantic-p1-invariant",
                match_strategy=strategy,
            )
            _refresh_entry_after_gate(entry)
            changed = True
        elif normalized == "FALSE-POSITIVE":
            appended = _append_semantic_gate_verdict(
                entry,
                verdict,
                applied=False,
                action="recorded-only-no-auto-suppression",
                match_strategy=strategy,
            )
            summary["false_positive_records"] += int(appended)
            changed = changed or appended
        else:
            appended = _append_semantic_gate_verdict(
                entry,
                verdict,
                applied=False,
                action="retained-topical",
                match_strategy=strategy,
            )
            summary["topical_records"] += int(appended)
            changed = changed or appended

    if changed:
        _refresh_report_after_gate(report, entries)
    report["semantic_gate_application"] = summary
    provenance = report.setdefault("provenance", {})
    if isinstance(provenance, dict):
        integrations = provenance.setdefault("semantic_gate_integrations", [])
        if isinstance(integrations, list):
            integrations.append(
                {
                    "tool": "tools/semantic-predicate-gate.py",
                    "tool_version": TOOL_VERSION,
                    "semantic_promotions": summary["semantic_promotions"],
                    "false_positive_policy": summary["false_positive_policy"],
                    "applied_at_utc": summary["applied_at_utc"],
                }
            )
    return summary


def topical_predicates(entry: dict[str, Any]) -> list[str]:
    tier = str(entry.get("p1_match_tier") or entry.get("predicate_tier") or "").upper()
    if tier not in {"TOPICAL-MATCH", "TOPICAL"}:
        return []
    topical = _as_list(entry.get("topical_p1_invariants"))
    if topical:
        return topical
    matched = _as_list(entry.get("matched_p1_invariants") or entry.get("p1_invariant_hits"))
    semantic = set(_as_list(entry.get("semantic_p1_invariants")))
    return [pid for pid in matched if pid not in semantic]


def build_candidates(
    report: Any,
    *,
    workspace: pathlib.Path | None,
    invariant_index: dict[str, dict[str, Any]],
    context_lines: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for entry_index, entry in enumerate(_entry_rows(report)):
        for predicate_id in topical_predicates(entry):
            code, warnings = read_code_excerpt(workspace, entry, context_lines=context_lines)
            inv = invariant_index.get(predicate_id, {})
            statement = str(inv.get("statement") or entry.get("predicate_statement") or "")
            predicate_blob = json.dumps(
                {
                    "predicate_id": predicate_id,
                    "statement": statement,
                    "commit_point_pattern": inv.get("commit_point_pattern") or "",
                    "defense_layer": inv.get("defense_layer") or "",
                },
                sort_keys=True,
            )
            code_hash = _sha256(canonical_code_for_hash(code))
            predicate_hash = _sha256(predicate_blob)
            cache_key = _sha256(f"{code_hash}:{predicate_hash}")
            file_line = str(entry.get("file_line") or entry.get("file_path") or "")
            cluster_id = str(entry.get("cluster_id") or entry.get("detector_slug") or "")
            candidate_id = str(
                entry.get("candidate_id")
                or entry.get("id")
                or f"{file_line}|{cluster_id}|{predicate_id}"
            )
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "entry_index": entry_index,
                    "file_line": file_line,
                    "cluster_id": cluster_id,
                    "snippet": str(entry.get("snippet") or "")[:500],
                    "predicate_id": predicate_id,
                    "predicate_statement": statement,
                    "predicate_commit_point": str(inv.get("commit_point_pattern") or ""),
                    "predicate_defense_layer": str(inv.get("defense_layer") or ""),
                    "code_excerpt": code,
                    "code_hash": code_hash,
                    "predicate_hash": predicate_hash,
                    "cache_key": cache_key,
                    "warnings": warnings,
                }
            )
    return candidates


def build_prompt(candidate: dict[str, Any]) -> str:
    payload = {
        "candidate_id": candidate["candidate_id"],
        "file_line": candidate["file_line"],
        "cluster_id": candidate["cluster_id"],
        "predicate_id": candidate["predicate_id"],
        "invariant_statement": candidate["predicate_statement"],
        "commit_point_pattern": candidate["predicate_commit_point"],
        "defense_layer": candidate["predicate_defense_layer"],
        "snippet": candidate["snippet"],
    }
    return (
        "You are a security-audit semantic predicate gate. Classify whether the "
        "cited code is a real semantic match for the specific invariant/predicate.\n\n"
        "Use code behavior, control/data flow, and security semantics. Do not rely "
        "on identifier names matching the invariant vocabulary.\n\n"
        "Verdicts:\n"
        "- SEMANTIC: the visible code materially exhibits the risky condition or "
        "missing defense described by the specific invariant/predicate, so it "
        "should remain a tier-1 human-review lead.\n"
        "- TOPICAL: the code is in the same broad domain, but the visible excerpt is "
        "insufficient or ambiguous for a semantic claim.\n"
        "- FALSE-POSITIVE: the code is unrelated to the invariant, or the visible "
        "code clearly satisfies the invariant/design intent so this topical lead "
        "should be suppressed.\n\n"
        "Return exactly one JSON object with keys: verdict, reason, evidence. "
        "The verdict value must be one of SEMANTIC, TOPICAL, FALSE-POSITIVE.\n\n"
        "Candidate metadata:\n"
        f"{json.dumps(payload, indent=2, sort_keys=True)}\n\n"
        "Cited code:\n"
        "```text\n"
        f"{candidate['code_excerpt'][:12000]}\n"
        "```\n"
    )


def normalize_verdict(value: Any) -> str | None:
    text = str(value or "").strip().upper().replace("_", "-")
    aliases = {
        "SEMANTIC-MATCH": "SEMANTIC",
        "TRUE-POSITIVE": "SEMANTIC",
        "TP": "SEMANTIC",
        "TOPICAL-MATCH": "TOPICAL",
        "INDETERMINATE": "TOPICAL",
        "UNKNOWN": "TOPICAL",
        "FP": "FALSE-POSITIVE",
        "FALSE-POSITIVE-MATCH": "FALSE-POSITIVE",
        "FALSE POSITIVE": "FALSE-POSITIVE",
        "FALSEPOSITIVE": "FALSE-POSITIVE",
    }
    text = aliases.get(text, text)
    return text if text in VALID_VERDICTS else None


def _json_object_from_text(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.S | re.I)
    if fenced:
        stripped = fenced.group(1)
    start = stripped.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(stripped)):
        char = stripped[idx]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(stripped[start: idx + 1])
                except json.JSONDecodeError:
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def parse_llm_response(stdout: str) -> dict[str, Any]:
    obj = _json_object_from_text(stdout or "")
    if obj is None:
        return {
            "verdict": "TOPICAL",
            "reason": "llm-output-unparseable",
            "evidence": (stdout or "")[:500],
        }
    verdict = normalize_verdict(obj.get("verdict"))
    if verdict is None:
        return {
            "verdict": "TOPICAL",
            "reason": f"llm-output-invalid-verdict: {obj.get('verdict')!r}",
            "evidence": json.dumps(obj, sort_keys=True)[:500],
        }
    return {
        "verdict": verdict,
        "reason": str(obj.get("reason") or "")[:1000],
        "evidence": str(obj.get("evidence") or "")[:1000],
    }


def load_cache(path: pathlib.Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"schema": "auditooor.semantic_predicate_gate.cache.v1", "records": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema": "auditooor.semantic_predicate_gate.cache.v1", "records": {}}
    if not isinstance(data, dict):
        return {"schema": "auditooor.semantic_predicate_gate.cache.v1", "records": {}}
    records = data.get("records")
    if not isinstance(records, dict):
        data["records"] = {}
    return data


def save_cache(path: pathlib.Path | None, cache: dict[str, Any]) -> None:
    if path is None:
        return
    cache["updated_at_utc"] = _utc_now()
    write_json(path, cache)


def dispatch_llm(
    prompt: str,
    *,
    dispatcher: pathlib.Path,
    provider: str,
    max_tokens: int,
    timeout: float,
    audit_dir: pathlib.Path | None,
    operator_live_network_consent: bool,
) -> tuple[int, str, str]:
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".semantic-predicate-gate.md",
        prefix="semantic_predicate_gate_",
        delete=False,
        encoding="utf-8",
    ) as fh:
        fh.write(prompt)
        prompt_path = pathlib.Path(fh.name)
    cmd = [
        sys.executable,
        str(dispatcher),
        "--prompt-file",
        str(prompt_path),
        "--provider",
        provider,
        "--max-tokens",
        str(max_tokens),
        "--timeout",
        str(timeout),
    ]
    if audit_dir is not None:
        cmd.extend(["--audit-dir", str(audit_dir)])
    if operator_live_network_consent:
        cmd.append("--operator-live-network-consent")
    env = os.environ.copy()
    if not operator_live_network_consent:
        for key in ("AUDITOOOR_LLM_NETWORK_CONSENT", "ADVERSARIAL_LIVE_CONSENT"):
            env.pop(key, None)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"subprocess-timeout: {exc}"
    except OSError as exc:
        return 127, "", f"OSError: {exc}"
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass


def default_cache_path(workspace: pathlib.Path | None) -> pathlib.Path:
    if workspace is not None:
        return workspace / ".auditooor" / "semantic_predicate_gate_cache.json"
    return REPO_ROOT / "agent_outputs" / "semantic_predicate_gate_cache.json"


def evaluate_candidates(
    candidates: list[dict[str, Any]],
    *,
    cache_path: pathlib.Path | None,
    dispatcher: pathlib.Path,
    provider: str,
    max_tokens: int,
    timeout: float,
    audit_dir: pathlib.Path | None,
    max_calls: int,
    max_report_cost_usd: float,
    cost_per_call_usd: float,
    operator_live_network_consent: bool,
    dry_run: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cache = load_cache(cache_path)
    records = cache.setdefault("records", {})
    cost_cap = int((max_report_cost_usd + 1e-9) / cost_per_call_usd)
    effective_cap = max(0, min(max_calls, cost_cap))
    calls_attempted = 0
    calls_succeeded = 0
    cache_hits = 0
    budget_skipped = 0
    verdicts: list[dict[str, Any]] = []

    for candidate in candidates:
        cached = records.get(candidate["cache_key"])
        base = {
            key: candidate[key]
            for key in (
                "candidate_id",
                "entry_index",
                "file_line",
                "cluster_id",
                "predicate_id",
                "predicate_statement",
                "code_hash",
                "predicate_hash",
                "cache_key",
                "warnings",
            )
        }
        if isinstance(cached, dict):
            cache_hits += 1
            verdicts.append(
                {
                    **base,
                    "verdict": normalize_verdict(cached.get("verdict")) or "TOPICAL",
                    "reason": str(cached.get("reason") or ""),
                    "evidence": str(cached.get("evidence") or ""),
                    "source": "cache",
                    "dispatched": False,
                }
            )
            continue
        if dry_run:
            verdicts.append(
                {
                    **base,
                    "verdict": "TOPICAL",
                    "reason": "dry-run: llm-dispatch not invoked",
                    "evidence": "",
                    "source": "dry-run",
                    "dispatched": False,
                }
            )
            continue
        if calls_attempted >= effective_cap:
            budget_skipped += 1
            verdicts.append(
                {
                    **base,
                    "verdict": "TOPICAL",
                    "reason": "budget-skipped: default report cost cap reached",
                    "evidence": "",
                    "source": "budget",
                    "dispatched": False,
                }
            )
            continue

        prompt = build_prompt(candidate)
        calls_attempted += 1
        rc, stdout, stderr = dispatch_llm(
            prompt,
            dispatcher=dispatcher,
            provider=provider,
            max_tokens=max_tokens,
            timeout=timeout,
            audit_dir=audit_dir,
            operator_live_network_consent=operator_live_network_consent,
        )
        if rc != 0:
            parsed = {
                "verdict": "TOPICAL",
                "reason": f"llm-dispatch-failed: rc={rc}",
                "evidence": (stderr or stdout)[:1000],
            }
        else:
            calls_succeeded += 1
            parsed = parse_llm_response(stdout)
        row = {
            **base,
            **parsed,
            "source": "llm",
            "dispatched": True,
            "dispatch_returncode": rc,
        }
        verdicts.append(row)
        if rc == 0:
            records[candidate["cache_key"]] = {
                "verdict": row["verdict"],
                "reason": row["reason"],
                "evidence": row["evidence"],
                "code_hash": candidate["code_hash"],
                "predicate_hash": candidate["predicate_hash"],
                "predicate_id": candidate["predicate_id"],
                "created_at_utc": _utc_now(),
            }

    if not dry_run:
        save_cache(cache_path, cache)
    summary = {
        "effective_call_cap": effective_cap,
        "llm_calls_attempted": calls_attempted,
        "llm_calls_succeeded": calls_succeeded,
        "cache_hits": cache_hits,
        "budget_skipped": budget_skipped,
        "estimated_call_cost_usd": cost_per_call_usd,
        "max_report_cost_usd": max_report_cost_usd,
        "estimated_spend_usd": round(calls_attempted * cost_per_call_usd, 4),
    }
    return verdicts, summary


def build_output(
    *,
    input_path: pathlib.Path,
    workspace: pathlib.Path | None,
    cache_path: pathlib.Path | None,
    candidates: list[dict[str, Any]],
    verdicts: list[dict[str, Any]],
    eval_summary: dict[str, Any],
) -> dict[str, Any]:
    counts = {verdict: 0 for verdict in sorted(VALID_VERDICTS)}
    for row in verdicts:
        verdict = normalize_verdict(row.get("verdict")) or "TOPICAL"
        counts[verdict] = counts.get(verdict, 0) + 1
    return {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": _utc_now(),
        "input": str(input_path),
        "workspace": str(workspace) if workspace is not None else None,
        "cache_path": str(cache_path) if cache_path is not None else None,
        "summary": {
            "stage1_topical_candidates": len(candidates),
            "stage2_verdicts": len(verdicts),
            "verdict_counts": counts,
            **eval_summary,
        },
        "verdicts": verdicts,
        "integration_notes": [
            (
                "Default output remains a standalone sidecar. When --apply-to-report "
                "is set, non-dry-run/cache SEMANTIC verdicts are promoted into "
                "semantic_p1_invariants in the target LIVE_TARGET_REPORT JSON."
            ),
            (
                "TOPICAL verdicts remain topical. FALSE-POSITIVE verdicts are recorded "
                "as append-only semantic_gate_verdicts evidence and are not suppressed "
                "or removed without operator acceptance."
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="live-target report JSON or candidate-list JSON")
    parser.add_argument("--output", default=None, help="write JSON sidecar here; stdout when omitted")
    parser.add_argument("--workspace", default=None, help="target workspace used to hydrate file_line source")
    parser.add_argument("--cache", default=None, help="verdict cache JSON path; default is workspace .auditooor cache")
    parser.add_argument("--provider", default="auto", choices=("auto", "kimi", "minimax", "anthropic"))
    parser.add_argument("--dispatcher", default=str(DEFAULT_DISPATCHER), help="llm-dispatch.py path")
    parser.add_argument("--audit-dir", default=None, help="audit-dir forwarded to llm-dispatch.py")
    parser.add_argument("--max-tokens", type=int, default=400, help="completion token cap per semantic verdict")
    parser.add_argument("--timeout", type=float, default=60.0, help="llm-dispatch timeout seconds")
    parser.add_argument("--max-calls", type=int, default=50, help="hard call cap per report")
    parser.add_argument("--max-report-cost-usd", type=float, default=1.00, help="approximate report spend cap")
    parser.add_argument("--cost-per-call-usd", type=float, default=0.02, help="conservative estimated cost per call")
    parser.add_argument("--context-lines", type=int, default=80, help="source lines around file_line when hydrating code")
    parser.add_argument("--operator-live-network-consent", action="store_true", help="forward consent to llm-dispatch.py")
    parser.add_argument("--dry-run", action="store_true", help="select candidates and emit TOPICAL placeholders without LLM calls")
    parser.add_argument("--apply-to-report", default=None, help="LIVE_TARGET_REPORT JSON to update in-place with non-dry-run/cache verdicts")
    parser.add_argument("--report-markdown-output", default=None, help="optional LIVE_TARGET_REPORT.md path to rerender after applying verdicts")
    parser.add_argument("--include-dry-run-apply", action="store_true", help="also record dry-run TOPICAL placeholders when applying")
    args = parser.parse_args(argv)

    if args.cost_per_call_usd <= 0:
        raise SystemExit("--cost-per-call-usd must be > 0")

    input_path = pathlib.Path(args.input).resolve()
    workspace = pathlib.Path(args.workspace).resolve() if args.workspace else None
    cache_path = pathlib.Path(args.cache).resolve() if args.cache else default_cache_path(workspace)
    audit_dir = pathlib.Path(args.audit_dir).resolve() if args.audit_dir else None
    report = load_json(input_path)
    invariant_index = load_invariant_index()
    candidates = build_candidates(
        report,
        workspace=workspace,
        invariant_index=invariant_index,
        context_lines=max(1, int(args.context_lines)),
    )
    verdicts, eval_summary = evaluate_candidates(
        candidates,
        cache_path=cache_path,
        dispatcher=pathlib.Path(args.dispatcher).resolve(),
        provider=args.provider,
        max_tokens=args.max_tokens,
        timeout=args.timeout,
        audit_dir=audit_dir,
        max_calls=max(0, int(args.max_calls)),
        max_report_cost_usd=max(0.0, float(args.max_report_cost_usd)),
        cost_per_call_usd=float(args.cost_per_call_usd),
        operator_live_network_consent=bool(args.operator_live_network_consent),
        dry_run=bool(args.dry_run),
    )
    payload = build_output(
        input_path=input_path,
        workspace=workspace,
        cache_path=cache_path,
        candidates=candidates,
        verdicts=verdicts,
        eval_summary=eval_summary,
    )
    apply_path = pathlib.Path(args.apply_to_report).resolve() if args.apply_to_report else None
    if apply_path is not None:
        apply_report = load_json(apply_path)
        if not isinstance(apply_report, dict):
            raise SystemExit("--apply-to-report must point at a JSON object report")
        apply_summary = apply_verdicts_to_report(
            apply_report,
            payload,
            include_dry_run=bool(args.include_dry_run_apply),
        )
        write_json(apply_path, apply_report)
        payload["report_application"] = {
            "path": str(apply_path),
            "summary": apply_summary,
        }
        if args.report_markdown_output:
            live_target_mod = _load_live_target_module()
            if live_target_mod is None or not hasattr(live_target_mod, "render_markdown"):
                raise SystemExit("cannot rerender markdown: live-target renderer unavailable")
            md_path = pathlib.Path(args.report_markdown_output).resolve()
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(live_target_mod.render_markdown(apply_report), encoding="utf-8")
            payload["report_application"]["markdown_path"] = str(md_path)
    if args.output:
        write_json(pathlib.Path(args.output).resolve(), payload)
    else:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
