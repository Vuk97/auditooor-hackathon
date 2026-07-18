#!/usr/bin/env python3
"""Classify live provider-assist results into advisory follow-up buckets."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Sequence

CATEGORIES = (
    "candidate_harvest",
    "killed_by_minimax",
    "needs_local_grep",
    "needs_fixture",
    "non_detectorizable",
    "strategic_refusal",
    "malformed",
)
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"

KILL_TOKENS = ("reject", "kill", "not_vulnerable", "not-vulnerable", "false_positive", "wont_fix", "won't fix", "not_actionable", "not actionable")
KEEP_TOKENS = ("keep", "local_verification_required", "keep_for_local_verification", "advisory_candidate")
LOCAL_GREP_TOKENS = ("grep", "rg ", "ripgrep", "local verification", "verify ", "confirm ", "inspect ", "audit ", "check ", "minimum_followup_check")
FIXTURE_TOKENS = ("fixture", "test fixture", "harness", "poc", "forge test", "smoke", "regression test")
NON_DETECTORIZABLE_TOKENS = (
    "non-detectorizable",
    "not detectorizable",
    "not automatable",
    "no automation",
    "not standalone detector",
    "no unique security-relevant",
    "no unique",
    "common pattern",
    "prior-art risk",
    "manual review",
)
REFUSAL_TOKENS = ("strategic refusal", "refusal", "cannot assist", "can't assist", "cannot comply", "decline")
SUPPORTED_CLASSIFICATION_TOKENS = (
    *KILL_TOKENS,
    *KEEP_TOKENS,
    "needs_fixture",
    "needs-local-grep",
    "needs_local_grep",
    "local_grep",
    "fixture_required",
    "source_review_only",
    "non_detectorizable",
    "non-detectorizable",
)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _extract_fenced_blocks(text: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"```(?:json)?\s*(.*?)```", text, flags=re.I | re.S)]


def _extract_balanced_json_objects(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    start: int | None = None
    depth = 0
    in_string = False
    escape = False
    for idx, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
            continue
        if ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                candidate = text[start : idx + 1]
                try:
                    payload = json.loads(candidate)
                except json.JSONDecodeError:
                    start = None
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
                start = None
    return rows


def parse_provider_objects(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Return provider JSON objects plus parse notes for advisory accounting."""
    notes: list[str] = []
    objects: list[dict[str, Any]] = []
    chunks = _extract_fenced_blocks(text)
    chunks.append(text.strip())
    seen: set[str] = set()
    for chunk in chunks:
        if not chunk:
            continue
        parsed = _extract_balanced_json_objects(chunk)
        if not parsed:
            notes.append("no-json-object")
            continue
        for obj in parsed:
            key = json.dumps(obj, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                objects.append(obj)
    return objects, notes


def _provider_path(final_path: Path, raw: str | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else (final_path.parent / path).resolve()


def _read_provider_output(final_path: Path, payload: dict[str, Any], key: str) -> dict[str, Any]:
    path = _provider_path(final_path, payload.get(key))
    if path is None:
        return {"path": "", "exists": False, "objects": [], "text": "", "notes": ["missing-path"]}
    if not path.is_file():
        return {"path": str(path), "exists": False, "objects": [], "text": "", "notes": ["missing-file"]}
    text = path.read_text(encoding="utf-8", errors="replace")
    objects, notes = parse_provider_objects(text)
    return {"path": str(path), "exists": True, "objects": objects, "text": text, "notes": notes}


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        out: list[Any] = []
        for item in value.values():
            out.extend(_as_list(item))
        return out
    return [value]


def _split_checks(value: Any) -> list[str]:
    checks: list[str] = []
    for item in _as_list(value):
        text = str(item).strip()
        if not text or text.lower() in {"true", "false"}:
            continue
        parts = re.split(r";\s+|\(\d+\)\s+", text)
        checks.extend(part.strip(" .") for part in parts if part.strip(" ."))
    return checks


def _unique_text(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _local_check_requirements(objects: Sequence[dict[str, Any]]) -> tuple[list[str], list[str]]:
    required: list[str] = []
    followup: list[str] = []
    for obj in objects:
        required.extend(_split_checks(obj.get("local_checks_required")))
        followup.extend(_split_checks(obj.get("minimum_followup_check")))
    return _unique_text(required), _unique_text(followup)


def _has_actionable_source_facts(objects: Sequence[dict[str, Any]]) -> bool:
    for obj in objects:
        facts = obj.get("extracted_source_facts")
        if not isinstance(facts, dict):
            continue
        if any(isinstance(facts.get(key), str) and facts.get(key).strip() for key in ("file", "source_file", "file_path", "location")):
            return True
        if any(isinstance(facts.get(key), str) and facts.get(key).strip() for key in ("symbol", "source_symbol", "function", "symbol_name")):
            return True
    return False


def _has_actionable_shape(objects: Sequence[dict[str, Any]]) -> bool:
    for obj in objects:
        shape = obj.get("candidate_detector_shape")
        if not isinstance(shape, dict):
            continue
        for key in ("local_verification_grep_patterns", "local_check_targets", "detection_triggers"):
            if _split_checks(shape.get(key)):
                return True
    return False


def _provider_schema_notes(objects: Sequence[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for idx, obj in enumerate(objects, start=1):
        prefix = f"object-{idx}"
        classification = obj.get("classification")
        if classification is not None:
            if not isinstance(classification, str) or not classification.strip():
                notes.append(f"{prefix}:unsupported-classification-type")
            elif not _has_any(classification, SUPPORTED_CLASSIFICATION_TOKENS):
                notes.append(f"{prefix}:unsupported-classification:{classification.strip()[:80]}")
        if "candidate_detector_shape" in obj and not isinstance(obj.get("candidate_detector_shape"), dict):
            notes.append(f"{prefix}:candidate_detector_shape-not-object")
        if "extracted_source_facts" in obj and not isinstance(obj.get("extracted_source_facts"), dict):
            notes.append(f"{prefix}:extracted_source_facts-not-object")
        if "local_checks_required" in obj and not _split_checks(obj.get("local_checks_required")):
            notes.append(f"{prefix}:local_checks_required-empty")
        if "minimum_followup_check" in obj and not _split_checks(obj.get("minimum_followup_check")):
            notes.append(f"{prefix}:minimum_followup_check-empty")
    return notes


def _has_any(haystack: str, needles: Sequence[str]) -> bool:
    low = haystack.lower()
    return any(token in low for token in needles)


def _classifications(objects: Sequence[dict[str, Any]]) -> list[str]:
    return [obj["classification"] for obj in objects if isinstance(obj.get("classification"), str) and obj.get("classification")]


def _minimax_verdict_text(objects: Sequence[dict[str, Any]]) -> str:
    fields = []
    for obj in objects:
        fields.extend(
            str(obj.get(key) or "")
            for key in ("classification", "reason", "contradiction_citation")
        )
    return "\n".join(fields)


def _primary_category(categories: Sequence[str]) -> str:
    for category in ("strategic_refusal", "malformed", "killed_by_minimax", "candidate_harvest", "needs_fixture", "needs_local_grep", "non_detectorizable"):
        if category in categories:
            return category
    return "malformed"


def _reason(primary: str, classifications: Sequence[str], provider_malformed: bool, schema_notes: Sequence[str]) -> str:
    if primary == "malformed" and schema_notes:
        return "provider result row failed closed: " + "; ".join(schema_notes[:4])
    if primary == "malformed" and provider_malformed:
        return "one or more live provider outputs were missing or did not yield parseable JSON objects"
    if classifications:
        return f"Minimax classification(s): {', '.join(classifications)}"
    return f"Advisory heuristic assigned {primary}"


def classify_result(final_path: Path) -> dict[str, Any]:
    payload = _read_json(final_path)
    if payload is None:
        return {
            "task_id": final_path.stem.replace(".provider-assist", ""),
            "final": str(final_path),
            "primary_category": "malformed",
            "categories": ["malformed"],
            "reason": "final provider-assist JSON is missing or malformed",
            "advisory_only": True,
            "evidence_class": GENERATED_EVIDENCE_CLASS,
            "promotion_authority": False,
            "submit_ready": False,
            "submission_posture": "NOT_SUBMIT_READY",
        }

    kimi = _read_provider_output(final_path, payload, "kimi_output")
    minimax = _read_provider_output(final_path, payload, "minimax_output")
    provider_objects = list(kimi["objects"]) + list(minimax["objects"])
    classifications = _classifications(minimax["objects"])
    minimax_verdict_text = _minimax_verdict_text(minimax["objects"])
    local_checks_required, minimum_followup_checks = _local_check_requirements(provider_objects)
    combined_text = "\n".join([_flatten_text(payload), kimi.get("text", ""), minimax.get("text", ""), _flatten_text(provider_objects)])
    categories: list[str] = []
    provider_malformed = (
        not kimi["exists"]
        or not minimax["exists"]
        or not kimi["objects"]
        or not minimax["objects"]
    )
    schema_notes = _provider_schema_notes(provider_objects)
    if provider_malformed:
        categories.append("malformed")
    if schema_notes:
        categories.append("malformed")
    if _has_any(combined_text, REFUSAL_TOKENS):
        categories.append("strategic_refusal")
    if _has_any(minimax_verdict_text, KILL_TOKENS):
        categories.append("killed_by_minimax")
    if _has_any(combined_text, NON_DETECTORIZABLE_TOKENS):
        categories.append("non_detectorizable")
    if _has_any(combined_text, LOCAL_GREP_TOKENS) or payload.get("local_verification_required") is True:
        categories.append("needs_local_grep")
    if _has_any(combined_text, FIXTURE_TOKENS):
        categories.append("needs_fixture")

    has_candidate_shape = any(isinstance(obj.get("candidate_detector_shape"), dict) for obj in provider_objects)
    kept = _has_any(" ".join(classifications), KEEP_TOKENS)
    has_actionable_local_requirement = bool(
        local_checks_required
        or minimum_followup_checks
        or _has_actionable_source_facts(provider_objects)
        or _has_actionable_shape(provider_objects)
    )
    if (has_candidate_shape or kept) and "killed_by_minimax" not in categories and not has_actionable_local_requirement:
        categories.append("malformed")
        schema_notes.append("candidate-without-actionable-local-check")
    if (has_candidate_shape or kept) and "killed_by_minimax" not in categories and "malformed" not in categories:
        categories.append("candidate_harvest")
    if not categories:
        categories.append("malformed")

    primary = _primary_category(categories)
    return {
        "task_id": str(payload.get("task_id") or final_path.stem.replace(".provider-assist", "")),
        "final": str(final_path),
        "primary_category": primary,
        "categories": [c for c in CATEGORIES if c in categories],
        "reason": _reason(primary, classifications, provider_malformed, schema_notes),
        "classifications": classifications,
        "provider_object_count": len(provider_objects),
        "kimi_object_count": len(kimi["objects"]),
        "minimax_object_count": len(minimax["objects"]),
        "kimi_output": kimi["path"],
        "minimax_output": minimax["path"],
        "parse_notes": {"kimi": kimi["notes"], "minimax": minimax["notes"]},
        "provider_schema_notes": schema_notes,
        "local_checks_required": local_checks_required,
        "minimum_followup_checks": minimum_followup_checks,
        "actionable_local_check_count": len(local_checks_required) + len(minimum_followup_checks),
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "local_verification_required": bool(payload.get("local_verification_required")),
        "submit_ready": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }


def discover_final_results(roots: Sequence[Path]) -> list[Path]:
    results: list[Path] = []
    for root in roots:
        if root.is_file() and root.name.endswith(".provider-assist.json"):
            results.append(root)
        elif root.is_dir():
            results.extend(root.glob("**/final/*.provider-assist.json"))
    return sorted(set(p.resolve() for p in results))


def build_triage(roots: Sequence[Path]) -> dict[str, Any]:
    rows = [classify_result(path) for path in discover_final_results(roots)]
    summary = {category: 0 for category in CATEGORIES}
    primary_summary = {category: 0 for category in CATEGORIES}
    for row in rows:
        primary_summary[row["primary_category"]] += 1
        for category in row["categories"]:
            summary[category] += 1
    blockers = [] if rows else ["no-provider-assist-results-found"]
    return {
        "schema": "auditooor.live_provider_result_triage.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "roots": [str(root) for root in roots],
        "result_count": len(rows),
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "submit_ready": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "categories": list(CATEGORIES),
        "summary": summary,
        "primary_summary": primary_summary,
        "blockers": blockers,
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Provider Result Triage",
        "",
        "Advisory categorization of live Kimi/Minimax provider-assist outputs.",
        "",
        "No row is promoted to a detector, finding, submission, severity decision, or PoC.",
        "",
        f"- result count: `{payload['result_count']}`",
        f"- advisory only: `{str(payload['advisory_only']).lower()}`",
        f"- promotion authority: `{str(payload['promotion_authority']).lower()}`",
        f"- blockers: `{', '.join(payload['blockers']) if payload['blockers'] else 'none'}`",
        "",
        "## Category Counts",
        "",
        "| Category | Any-match Count | Primary Count |",
        "|---|---:|---:|",
    ]
    for category in CATEGORIES:
        lines.append(f"| `{category}` | {payload['summary'].get(category, 0)} | {payload['primary_summary'].get(category, 0)} |")
    lines.extend(["", "## Results", "", "| Task | Primary | Categories | Provider JSON Objects | Reason |", "|---|---|---|---:|---|"])
    for row in payload["rows"]:
        cats = ", ".join(f"`{cat}`" for cat in row["categories"])
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(f"| `{row['task_id']}` | `{row['primary_category']}` | {cats} | {row.get('provider_object_count', 0)} | {reason} |")
    return "\n".join(lines) + "\n"


def write_outputs(payload: dict[str, Any], out_json: Path, out_md: Path | None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", type=Path, help="Artifact root or final provider-assist JSON; repeatable.")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    roots = args.root or [Path(".audit_logs/pr560_worker_am"), Path(".auditooor/provider_assist/live_batch")]
    payload = build_triage(roots)
    out_json = args.out_json or Path(".audit_logs/pr560_worker_an/live_provider_result_triage.json")
    out_md = args.out_md if args.out_md is not None else Path(".audit_logs/pr560_worker_an/live_provider_result_triage.md")
    write_outputs(payload, out_json, out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
