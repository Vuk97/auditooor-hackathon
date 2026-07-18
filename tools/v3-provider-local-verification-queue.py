#!/usr/bin/env python3
"""Build local verification queues from Hackerman V3 provider fanout closeouts."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
TRIAGE_TOOL = ROOT / "tools" / "live-provider-result-triage.py"

KILL_TOKENS = (
    "reject_",
    "reject-oos",
    "reject oos",
    "kill_confirmed",
    "not actionable",
    "false_positive",
    "false positive",
    "no_action",
)
FIXTURE_TOKENS = ("fixture", "harness", "poc", "forge test", "regression test", "smoke-fire", "smoke test")
EXTERNAL_SOURCE_TOKENS = (
    "needs_more_source",
    "primary source",
    "source url",
    "source_url",
    "txhash",
    "transaction hash",
    "iso-8601",
    "source-data blocked",
)
BLOCKER_STATUSES = {
    "blocked_no_mcp_receipt",
    "blocked_missing_model",
    "dispatched_no_output",
    "malformed_provider_output",
}
LOCAL_PATH_HINT_RE = re.compile(
    r"\b(?:\.auditooor|tools|docs|reference|audit|audits|agent_outputs|reports|detectors|src|test|tests)/"
    r"[A-Za-z0-9_./-]+(?::\d+(?:-\d+)?)?"
)
TERMINAL_OUTCOMES = (
    "verified_actionable",
    "verified_no_action",
    "rejected_oos",
    "rejected_duplicate",
    "rejected_false_positive",
    "needs_more_source",
    "blocked_missing_receipt",
    "blocked_missing_model",
    "blocked_no_output",
    "blocked_malformed_output",
)
FILE_KEYS = {"file", "files", "path", "paths", "source_file", "file_path", "exact_source_files_lines"}
PATTERN_KEYS = {
    "symbol",
    "source_symbol",
    "function",
    "function_signature",
    "local_verification_grep_patterns",
    "local_check_targets",
    "detection_triggers",
    "detector_concept",
}
CHECK_KEYS = {
    "local_checks_required",
    "minimum_followup_check",
    "required_local_verification",
    "promotion_blockers",
    "missing_fields",
    "fixture_requirements",
    "notes",
}
CLAIM_LIST_KEYS = (
    "advisory_candidates",
    "candidate_predicates",
    "candidates",
    "claims",
    "items",
    "per_candidate_judgments",
    "row_verdicts",
    "rows",
    "tasks",
    "verdicts",
)


def _load_provider_parser() -> Any:
    spec = importlib.util.spec_from_file_location("live_provider_result_triage_for_v3_queue", TRIAGE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load provider parser: {TRIAGE_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PROVIDER_PARSER = _load_provider_parser()


def _default_campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return workspace / ".auditooor" / "provider_fanout" / campaign_id


def _latest_closeout(workspace: Path, campaign_id: str) -> Path:
    runs_dir = _default_campaign_dir(workspace, campaign_id) / "runs"
    candidates = sorted(runs_dir.glob("*/fanout_closeout.json"))
    if not candidates:
        raise SystemExit(f"[v3-provider-local-verification-queue] no closeouts under {runs_dir}")
    return candidates[-1]


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _read_text(path: Path, limit: int = 30000) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated by v3 local verification queue]"


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _flatten(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _flatten(child)
    else:
        yield value


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_items(child)


def _unique(values: Iterable[Any], *, limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        text = re.sub(r"\s+", " ", str(value)).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _extract_local_path_hints(raw: Any) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    return _unique((match.group(0).rstrip(".,;)]}") for match in LOCAL_PATH_HINT_RE.finditer(text)), limit=20)


def _expand_path_hint(raw: Any) -> list[str]:
    hints = _extract_local_path_hints(raw)
    if hints:
        return hints
    text = str(raw or "").strip()
    return [text] if text else []


def _codey(text: str) -> bool:
    return bool(re.search(r"[/_.:]|[A-Za-z_][A-Za-z0-9_]{3,}\(", text)) and len(text) <= 160


def _inside_root_hint(raw: str, root: Path = ROOT) -> bool:
    text = str(raw or "").strip()
    if not text or re.match(r"^[a-z][a-z0-9+.-]*://", text, flags=re.I):
        return True
    text = re.sub(r":\d+(?:-\d+)?$", "", text)
    path = Path(text)
    if not path.is_absolute():
        path = root / path
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _hint_path(raw: str, root: Path = ROOT) -> Path:
    text = re.sub(r":\d+(?:-\d+)?$", "", str(raw or "").strip())
    path = Path(text)
    if not path.is_absolute():
        path = root / path
    return path


def _same_path_hint(left: str | Path | None, right: str | Path | None, root: Path = ROOT) -> bool:
    if left is None or right is None:
        return False
    try:
        left_path = _hint_path(str(left), root).resolve()
        right_path = _hint_path(str(right), root).resolve()
    except OSError:
        return False
    return left_path == right_path


def _strip_line_suffix(raw: str) -> str:
    return re.sub(r":\d+(?:-\d+)?$", "", str(raw or "").strip())


def _unique_path_hints(values: Iterable[str], *, root: Path = ROOT, limit: int = 10) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = str(_hint_path(text, root).resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _looks_like_local_path_arg(token: str, root: Path = ROOT) -> bool:
    text = str(token or "").strip()
    if not text or text.startswith("-") or re.match(r"^[a-z][a-z0-9+.-]*://", text, flags=re.I):
        return False
    if not _inside_root_hint(text, root):
        return False
    path = _hint_path(text, root)
    if path.exists():
        return True
    return bool(
        text.startswith(("./", "../", "/", "tools/", "docs/", "reference/", "audit/", "reports/", "agent_outputs/", ".auditooor/"))
        or "/" in text
    )


def _line_suffix(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    match = re.match(r"^\s*(\d+)(?:\s*-\s*(\d+))?\s*$", value)
    if not match:
        return ""
    return f":{match.group(1)}" + (f"-{match.group(2)}" if match.group(2) else "")


def _provider_objects(output_text: str) -> list[dict[str, Any]]:
    objects, _notes = PROVIDER_PARSER.parse_provider_objects(output_text)
    return [obj for obj in objects if isinstance(obj, dict)]


def _file_hints(objects: Sequence[dict[str, Any]], output_text: str, root: Path = ROOT) -> list[str]:
    raw_hints: list[str] = []
    for obj in objects:
        for key in ("exact_local_files_to_inspect_next", "source_refs", "source_files"):
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        path = item.get("path") or item.get("file") or item.get("source_file")
                        if isinstance(path, str):
                            raw_hints.append(path + _line_suffix(item.get("lines") or item.get("line_range")))
        for key, value in _walk_items(obj):
            if key in FILE_KEYS:
                raw_hints.extend(str(item) for item in _flatten(value))
    raw_hints.extend(_extract_local_path_hints(output_text))
    expanded = (hint for raw in raw_hints for hint in _expand_path_hint(raw))
    return _unique((hint for hint in expanded if ("/" in str(hint) or "." in str(hint)) and _inside_root_hint(str(hint), root)), limit=10)


def _grep_patterns(objects: Sequence[dict[str, Any]], output_text: str) -> list[str]:
    patterns: list[str] = []
    for obj in objects:
        for key, value in _walk_items(obj):
            if key in PATTERN_KEYS:
                patterns.extend(_flatten(value))
            elif key in CHECK_KEYS:
                for item in _flatten(value):
                    if isinstance(item, str):
                        patterns.extend(re.findall(r"[`'\"]([^`'\"]{3,80})[`'\"]", item))
    patterns.extend(re.findall(r"`([^`]{3,80})`", output_text))
    return _unique((pattern for pattern in patterns if _codey(str(pattern))), limit=10)


def _local_checks(objects: Sequence[dict[str, Any]]) -> list[str]:
    checks: list[str] = []
    for obj in objects:
        for key, value in _walk_items(obj):
            if key in CHECK_KEYS:
                checks.extend(_flatten(value))
    return _unique(checks, limit=12)


def _contains_any(text: str, tokens: Sequence[str]) -> bool:
    low = text.lower()
    return any(token in low for token in tokens)


def _route(row: dict[str, Any], objects: Sequence[dict[str, Any]], output_text: str, file_hints: Sequence[str], grep_patterns: Sequence[str]) -> str:
    status = str(row.get("status") or "")
    if status in BLOCKER_STATUSES:
        return "blocked_provider_output"
    if status == "killed_by_minimax" or (row.get("provider") == "minimax" and _contains_any(output_text, KILL_TOKENS)):
        return "kill_review"
    if _contains_any(output_text, EXTERNAL_SOURCE_TOKENS):
        return "external_source_needed"
    if _contains_any(output_text, FIXTURE_TOKENS):
        return "fixture_needed"
    if file_hints or grep_patterns or objects:
        return "local_source_review"
    return "manual_review"


def _next_command(route: str, file_hints: Sequence[str], grep_patterns: Sequence[str], output_path: str, root: Path = ROOT) -> str:
    if route == "blocked_provider_output":
        return "rerun v3-provider-fanout-run for this row; do not use provider output"
    if route == "external_source_needed":
        return "collect primary URL/date/txhash or local source artifact, then rerun closeout"
    if route == "fixture_needed":
        return "create paired vulnerable/clean fixture plus smoke command before any detector promotion"
    if route == "kill_review":
        return f"review {shlex.quote(output_path)} against local source; mark NO_ACTION only with exact citation"
    if grep_patterns:
        regex = "|".join(re.escape(pattern) for pattern in grep_patterns[:4])
        targets = [_strip_line_suffix(hint) for hint in file_hints[:4] if _inside_root_hint(hint, root)] or ["tools", "docs", "reference"]
        return f"rg -n {shlex.quote(regex)} " + " ".join(shlex.quote(target) for target in targets)
    if file_hints:
        return "inspect local source refs: " + ", ".join(file_hints[:4])
    return f"manual source review of {shlex.quote(output_path)}"


def _terminal_options(route: str) -> list[str]:
    return {
        "blocked_provider_output": ["blocked_missing_receipt", "blocked_missing_model", "blocked_no_output", "blocked_malformed_output"],
        "external_source_needed": ["needs_more_source", "verified_no_action"],
        "fixture_needed": ["verified_actionable", "verified_no_action", "needs_more_source"],
        "kill_review": [
            "verified_no_action",
            "rejected_oos",
            "rejected_duplicate",
            "rejected_false_positive",
            "verified_actionable",
            "needs_more_source",
        ],
        "local_source_review": ["verified_actionable", "verified_no_action", "rejected_false_positive", "needs_more_source"],
        "manual_review": ["verified_no_action", "needs_more_source"],
    }[route]


def _claim_objects(output_text: str) -> list[dict[str, Any]]:
    objects = _provider_objects(output_text)
    claims: list[dict[str, Any]] = []
    for obj in objects:
        expanded = False
        for key in CLAIM_LIST_KEYS:
            value = obj.get(key)
            if isinstance(value, list):
                child_claims = [child for child in value if isinstance(child, dict)]
                if child_claims:
                    claims.extend(child_claims)
                    expanded = True
        if not expanded:
            claims.append(obj)
    return claims or [{"provider_text_excerpt": output_text[:800]}]


def _claim_kind(route: str, claim: dict[str, Any], output_text: str) -> str:
    text = json.dumps(claim, sort_keys=True, default=str).lower() + "\n" + output_text[:2000].lower()
    if route == "kill_review":
        return "kill_reason"
    if "triager" in text or "oos" in text or "scope" in text:
        return "triager_objection"
    if "proof" in text or "poc" in text or "harness" in text or "fixture" in text:
        return "proof_obligation"
    if "workflow" in text or "make audit" in text or "closeout" in text:
        return "workflow_gap"
    if "corpus" in text or "solodit" in text or "defimon" in text or "darknavy" in text:
        return "corpus_gap"
    if "source" in text or "primary" in text or "url" in text or "txhash" in text:
        return "source_gap"
    return "lesson_candidate"


def _claim_summary(claim: dict[str, Any], output_text: str) -> str:
    if claim.get("candidate_id") and claim.get("source_surface"):
        summary = f"{claim.get('candidate_id')}: {claim.get('source_surface')}"
        if claim.get("next_action_required"):
            summary += f" — {claim.get('next_action_required')}"
        return summary[:220]
    for key in ("summary", "title", "claim", "reason", "notes", "finding", "candidate", "gap"):
        value = claim.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:220]
    for key in ("missing_fields", "promotion_blockers", "local_checks_required", "minimum_followup_check"):
        value = claim.get(key)
        items = _unique(_flatten(value), limit=2)
        if items:
            return "; ".join(items)[:220]
    text = re.sub(r"\s+", " ", output_text).strip()
    return text[:220] if text else "provider row requires local verification"


def _claim_id(claim: dict[str, Any], task_id: str, ordinal: int) -> str:
    for key in ("candidate_id", "claim_id", "id", "finding_id", "row_id"):
        value = claim.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:80]
    return f"{task_id}-claim-{ordinal:02d}"


def _explicit_needs_more_source_verdict(output_text: str) -> str:
    match = re.search(
        r"(?im)^\s*(?:verdict|classification|status|outcome)\s*[:=]\s*`?\"?(NEEDS?_MORE_SOURCE)\"?`?\b",
        output_text,
    )
    return match.group(1) if match else ""


def _provider_verdict(claim: dict[str, Any], output_text: str = "") -> str:
    for key in ("verdict", "classification", "status", "outcome"):
        value = claim.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:80]
    prose_verdict = _explicit_needs_more_source_verdict(output_text)
    if prose_verdict:
        return prose_verdict[:80]
    return ""


def _source_refs(row: dict[str, Any], file_hints: Sequence[str], output_path: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = [
        {"kind": "provider_output", "path": output_path, "verified": False},
    ]
    for hint in file_hints[:10]:
        ref = {"kind": "provider_suggested_ref", "path": hint, "verified": False}
        start_end = re.search(r":(\d+)(?:-(\d+))?$", hint)
        if start_end:
            ref["line_start"] = int(start_end.group(1))
            ref["line_end"] = int(start_end.group(2) or start_end.group(1))
        refs.append(ref)
    receipt = row.get("mcp_receipt") if isinstance(row.get("mcp_receipt"), dict) else {}
    if receipt.get("path"):
        refs.append(
            {
                "kind": "mcp_receipt",
                "path": receipt.get("path"),
                "sha256_16": receipt.get("sha256_16"),
                "verified": True,
            }
        )
    if row.get("campaign_dispatch_audit_path"):
        refs.append({"kind": "llm_audit", "path": row.get("campaign_dispatch_audit_path"), "verified": True})
    return refs


def _blockers(row: dict[str, Any], route: str, file_hints: Sequence[str], grep_patterns: Sequence[str]) -> list[dict[str, Any]]:
    status = str(row.get("status") or "")
    blockers: list[dict[str, Any]] = []
    if status == "blocked_no_mcp_receipt":
        blockers.append({"code": "blocked_missing_receipt", "detail": "No MCP receipt was present for this provider row.", "blocking": True})
    elif status == "blocked_missing_model":
        blockers.append({"code": "blocked_missing_model", "detail": "Provider model ID is missing from audit metadata.", "blocking": True})
    elif status == "dispatched_no_output":
        blockers.append({"code": "blocked_no_output", "detail": "Provider dispatch produced no usable output.", "blocking": True})
    elif status == "malformed_provider_output":
        blockers.append({"code": "blocked_malformed_output", "detail": "Provider output was not parseable enough for claim extraction.", "blocking": True})
    if route == "external_source_needed":
        blockers.append({"code": "needs_primary_source", "detail": "Collect primary URL/date/txhash or local source artifact before use.", "blocking": True})
    if route == "fixture_needed":
        blockers.append({"code": "needs_test", "detail": "Create a paired vulnerable/clean fixture or proof harness before promotion.", "blocking": True})
    if status not in BLOCKER_STATUSES:
        blockers.append({"code": "needs_source_inspection", "detail": "Resolve provider-suggested refs to exact local file/line or command evidence.", "blocking": True})
    if not file_hints and not grep_patterns and route not in {"external_source_needed", "blocked_provider_output"}:
        blockers.append({"code": "provider_claim_too_broad", "detail": "Provider output has no concrete local refs or grep patterns.", "blocking": True})
    return blockers


def _queue_rows_for_closeout_row(index_start: int, row: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    task_id = str(row.get("task_id") or f"provider-row-{index_start:03d}")
    output_path = str(row.get("provider_output_path") or "")
    output_text = _read_text(Path(output_path)) if output_path else ""
    all_objects = _provider_objects(output_text)
    claims = _claim_objects(output_text)
    files = _file_hints(all_objects, output_text, root)
    patterns = _grep_patterns(all_objects, output_text)
    checks = _local_checks(all_objects)
    route = _route(row, all_objects, output_text, files, patterns)
    out: list[dict[str, Any]] = []
    for offset, claim in enumerate(claims, start=0):
        queue_id = f"V3-LV-{index_start + offset:03d}"
        claim_id = _claim_id(claim, task_id, offset + 1)
        out.append(
            {
                "queue_id": queue_id,
                "row_id": f"{queue_id}-{task_id}",
                "route": route,
                "source_provider_row": {
                    "task_id": task_id,
                    "provider": row.get("provider"),
                    "model": row.get("model"),
                    "template": row.get("template"),
                    "provider_output_path": output_path,
                    "output_shape": row.get("output_shape"),
                    "closeout_status": row.get("status"),
                    "advisory_only": True,
                },
                "claim": {
                    "kind": _claim_kind(route, claim, output_text),
                    "summary": _claim_summary(claim, output_text),
                    "provider_claim_id": claim_id,
                    "provider_verdict": _provider_verdict(claim, output_text),
                },
                "blockers": _blockers(row, route, files, patterns),
                "source_refs": _source_refs(row, files, output_path),
                "verification": {
                    "status": "pending" if route != "blocked_provider_output" else "blocked",
                    "commands": [_next_command(route, files, patterns, output_path, root)],
                    "evidence_refs": [],
                    "verifier_notes": None,
                },
                "terminal_outcome": None,
                "terminal_outcome_options": _terminal_options(route),
                "task_id": task_id,
                "provider": row.get("provider"),
                "model": row.get("model"),
                "tokens_used": int(row.get("tokens_used") or 0),
                "provider_output_bytes": row.get("provider_output_bytes", 0),
                "object_count": len(all_objects),
                "file_hints": files,
                "grep_patterns": patterns,
                "local_checks": checks,
                "next_command": _next_command(route, files, patterns, output_path, root),
                "advisory_only": True,
                "evidence_class": "generated_hypothesis",
                "promotion_authority": False,
                "local_verification_required": True,
                "severity": "none",
                "selected_impact": "",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_ready": False,
            }
        )
    return out


def _backfill_grep_patterns(packet: dict[str, Any]) -> list[str]:
    patterns: list[str] = []
    for cmd in packet.get("suggested_local_commands") or []:
        if not isinstance(cmd, dict) or str(cmd.get("kind") or "") != "rg":
            continue
        command = str(cmd.get("command") or "")
        try:
            parts = shlex.split(command)
        except ValueError:
            continue
        if len(parts) >= 3 and parts[0] == "rg":
            candidate = parts[2] if parts[1] == "-n" else parts[1]
            if candidate:
                patterns.append(candidate)
    return _unique(patterns, limit=6)


def _backfill_file_hints(
    packet: dict[str, Any],
    provider_text: str,
    *,
    source_file: str,
    root: Path = ROOT,
) -> list[str]:
    objects = _provider_objects(provider_text)
    hints = list(_file_hints(objects, provider_text, root))
    for cmd in packet.get("suggested_local_commands") or []:
        if not isinstance(cmd, dict):
            continue
        command = str(cmd.get("command") or "")
        try:
            parts = shlex.split(command)
        except ValueError:
            continue
        for part in parts[1:]:
            if _looks_like_local_path_arg(part, root):
                hints.append(part)
    return _unique_path_hints(
        (
            hint
            for hint in hints
            if not _same_path_hint(hint, source_file, root)
        ),
        root=root,
        limit=10,
    )


def _queue_row_for_backfill_packet(index: int, packet: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    packet_id = str(packet.get("packet_id") or f"KEEP-BACKFILL-{index:03d}")
    source_file = str(packet.get("source_file") or "")
    source_path = Path(source_file).expanduser() if source_file else None
    if source_path is not None and not source_path.is_absolute():
        source_path = root / source_path
    source_exists = bool(source_path and source_path.is_file())
    reason = str(packet.get("missing_verification_reason") or "")
    provider_text = _read_text(source_path) if source_exists and source_path is not None else ""
    file_hints = _backfill_file_hints(packet, provider_text, source_file=source_file, root=root)
    grep_patterns = _unique([*_backfill_grep_patterns(packet), *_grep_patterns(_provider_objects(provider_text), provider_text)], limit=10)
    route = "blocked_provider_output" if not source_file or not source_exists or reason.startswith("missing_provider_output") else "local_source_review"
    if route != "blocked_provider_output" and not file_hints:
        route = "external_source_needed"
    commands = [_next_command(route, file_hints, grep_patterns, source_file, root)]
    blockers = (
        [{"code": "blocked_no_output", "detail": "Provider KEEP backfill source file is missing.", "blocking": True}]
        if route == "blocked_provider_output"
        else [{"code": "needs_primary_source" if route == "external_source_needed" else "needs_source_inspection", "detail": "Provider KEEP backfill requires verifier-owned local evidence.", "blocking": True}]
    )
    return {
        "queue_id": f"V3-LV-{index:03d}",
        "row_id": f"V3-LV-{index:03d}-{packet_id}",
        "route": route,
        "source_provider_row": {
            "task_id": packet_id,
            "provider": packet.get("provider"),
            "model": packet.get("model") or "",
            "template": packet.get("task_type") or "provider-keep-backfill",
            "provider_output_path": source_file,
            "output_shape": "provider_keep_backfill_packet",
            "closeout_status": packet.get("packet_status") or "pending_local_verification_backfill",
            "source_report": packet.get("source_report") or "",
            "advisory_only": True,
        },
        "claim": {
            "kind": "provider_keep_backfill",
            "summary": f"{packet_id}: {reason or 'provider KEEP requires local verification'}",
            "provider_claim_id": packet_id,
            "provider_verdict": "KEEP_FOR_LOCAL_VERIFICATION",
        },
        "blockers": blockers,
        "source_refs": _source_refs({"provider": packet.get("provider")}, file_hints, source_file) if source_file else [],
        "verification": {
            "status": "blocked" if route == "blocked_provider_output" else "pending",
            "commands": commands,
            "evidence_refs": [],
            "verifier_notes": None,
        },
        "terminal_outcome": None,
        "terminal_outcome_options": _terminal_options(route),
        "task_id": packet_id,
        "provider": packet.get("provider") or "unknown",
        "model": packet.get("model") or "",
        "tokens_used": 0,
        "provider_output_bytes": source_path.stat().st_size if source_exists and source_path is not None else 0,
        "object_count": 1,
        "file_hints": file_hints,
        "grep_patterns": grep_patterns,
        "local_checks": [reason] if reason else [],
        "next_command": commands[0],
        "advisory_only": True,
        "evidence_class": "generated_hypothesis",
        "promotion_authority": False,
        "local_verification_required": route != "blocked_provider_output",
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_ready": False,
    }


def _queue_rows_for_backfill(backfill_path: Path | None, index_start: int, root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if backfill_path is None:
        return [], {}
    payload = _read_json(backfill_path)
    rows: list[dict[str, Any]] = []
    for packet in payload.get("packets") or []:
        if isinstance(packet, dict):
            rows.append(_queue_row_for_backfill_packet(index_start + len(rows), packet, root))
    return rows, payload


def build_queue(closeout_path: Path | None, workspace_root: Path | None = None, backfill_path: Path | None = None) -> dict[str, Any]:
    closeout = _read_json(closeout_path) if closeout_path is not None else {}
    root = (workspace_root or ROOT).expanduser().resolve()
    rows: list[dict[str, Any]] = []
    for row in closeout.get("rows", []):
        if not isinstance(row, dict):
            continue
        rows.extend(_queue_rows_for_closeout_row(len(rows) + 1, row, root))
    backfill_rows, backfill_payload = _queue_rows_for_backfill(backfill_path, len(rows) + 1, root)
    rows.extend(backfill_rows)
    by_route = Counter(str(row["route"]) for row in rows)
    by_provider = Counter(str(row["provider"]) for row in rows)
    by_claim_kind = Counter(str(row["claim"]["kind"]) for row in rows)
    return {
        "schema": "auditooor.v3_provider_local_verification_queue.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_closeout": str(closeout_path or ""),
        "source_backfill": str(backfill_path or ""),
        "campaign_id": closeout.get("campaign_id") or backfill_payload.get("schema") or "provider-keep-verification-backfill",
        "run_id": closeout.get("run_id") or "",
        "run_dir": closeout.get("run_dir") or str((backfill_path or Path(".")).parent),
        "advisory_only": True,
        "evidence_class": "generated_hypothesis",
        "promotion_authority": False,
        "local_verification_required": True,
        "submit_ready": False,
        "summary": {
            "total_queue_items": len(rows),
            "by_route": dict(sorted(by_route.items())),
            "by_provider": dict(sorted(by_provider.items())),
            "by_claim_kind": dict(sorted(by_claim_kind.items())),
            "tokens_by_provider": closeout.get("summary", {}).get("tokens_by_provider", {}),
            "total_tokens": closeout.get("summary", {}).get("total_tokens", 0),
            "backfill_packet_rows": len(backfill_rows),
        },
        "terminal_outcomes": list(TERMINAL_OUTCOMES),
        "rows": rows,
        "status": "actionable_verification_queue" if rows else "empty_no_closeout_rows",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# V3 Provider Local Verification Queue",
        "",
        "Every row is advisory-only until local source, primary-source, fixture, or test evidence closes it.",
        "",
        f"- source closeout: `{payload['source_closeout']}`",
        f"- run_id: `{payload.get('run_id') or ''}`",
        f"- total queue items: `{payload['summary']['total_queue_items']}`",
        f"- by_route: `{payload['summary']['by_route']}`",
        f"- tokens_by_provider: `{payload['summary']['tokens_by_provider']}`",
        "",
        "| ID | Provider | Task | Route | Next command |",
        "|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        command = str(row["next_command"]).replace("|", "\\|")
        lines.append(
            f"| `{row['queue_id']}` | `{row['provider']}` | `{row['task_id']}` | "
            f"`{row['route']}` | `{command}` |"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: dict[str, Any], out_json: Path, out_md: Path | None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--closeout", type=Path, default=None)
    parser.add_argument("--backfill-json", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    backfill_path = args.backfill_json.expanduser().resolve() if args.backfill_json else None
    closeout_path = args.closeout.expanduser().resolve() if args.closeout else None
    if closeout_path is None and backfill_path is None:
        closeout_path = _latest_closeout(workspace, args.campaign_id)
    payload = build_queue(closeout_path, workspace, backfill_path=backfill_path)
    run_dir = Path(str(payload.get("run_dir") or (closeout_path.parent if closeout_path else workspace / ".auditooor")))
    out_json = args.out_json.expanduser().resolve() if args.out_json else run_dir / "v3_provider_local_verification_queue.json"
    out_md = args.out_md.expanduser().resolve() if args.out_md else run_dir / "v3_provider_local_verification_queue.md"
    write_outputs(payload, out_json, out_md)
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "out_json": str(out_json)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
