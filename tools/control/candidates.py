#!/usr/bin/env python3
"""Candidate registry discovery and paste-ready validation.

This module intentionally stays stdlib-only.  It indexes the control-plane
candidate rows first, then falls back to existing submission drafts and PoC
execution manifests so old workspaces can be summarized before they are fully
migrated to ``.auditooor/control/candidates``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from pathlib import Path
from typing import Any, Iterable


CONTROL_CANDIDATE_GLOBS = ("*.json", "*.yaml", "*.yml")
SUBMISSION_DIRS = (
    "submissions/cantina_paste",
    "submissions/staging",
    "submissions/ready",
)
POC_MANIFEST_GLOB = "poc_execution/**/execution_manifest.json"


@dataclass
class Candidate:
    id: str
    title: str
    status: str
    severity: str = ""
    likelihood: str = ""
    impact: str = ""
    inline_poc_ready: bool = False
    poc_command: str = ""
    poc_result: str = ""
    oos_checked: bool = False
    proof_state: str = "planned"
    source_paths: list[str] = field(default_factory=list)
    recommended_fix_marker: bool = False
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_candidates(workspace: str | Path) -> list[Candidate]:
    """Discover normalized candidates from a workspace."""

    ws = Path(workspace)
    candidates: list[Candidate] = []
    candidates.extend(_discover_control_candidates(ws))
    candidates.extend(_discover_submission_candidates(ws))
    candidates.extend(_discover_poc_manifest_candidates(ws))
    return _dedupe_candidates(candidates)


def paste_ready_blockers(candidate: Candidate | dict[str, Any]) -> list[str]:
    """Return fail-closed blockers for marking a candidate paste-ready."""

    cand = normalize_candidate(candidate)
    blockers: list[str] = []
    required_strings = (
        ("severity", cand.severity),
        ("likelihood", cand.likelihood),
        ("impact", cand.impact),
        ("poc_command", cand.poc_command),
        ("poc_result", cand.poc_result),
    )
    for name, value in required_strings:
        if not value:
            blockers.append(f"missing_{name}")
    if not cand.oos_checked:
        blockers.append("missing_oos_check")
    if not cand.inline_poc_ready:
        blockers.append("missing_inline_poc")
    if not cand.recommended_fix_marker:
        blockers.append("missing_recommended_fix")
    blockers.extend(cand.blockers)
    return _stable_unique(blockers)


def normalize_candidate(row: Candidate | dict[str, Any]) -> Candidate:
    if isinstance(row, Candidate):
        return row

    oos = _dict_at(row, "oos")
    poc = _dict_at(row, "poc")
    impact_contract = _dict_at(row, "impact_contract")
    source_paths = row.get("source_paths") or row.get("files") or row.get("sources") or []
    if isinstance(source_paths, str):
        source_paths = [source_paths]

    impact = _string(row.get("impact"))
    if not impact:
        impact = _string(impact_contract.get("listed_impact"))

    return Candidate(
        id=_string(row.get("id") or row.get("candidate_id") or row.get("slug") or "candidate"),
        title=_string(row.get("title") or row.get("claim") or row.get("id") or "Untitled candidate"),
        status=_string(row.get("status") or row.get("promotion_status") or "candidate"),
        severity=_string(row.get("severity")),
        likelihood=_string(row.get("likelihood") or row.get("confidence")),
        impact=impact,
        inline_poc_ready=_bool(row.get("inline_poc_ready", poc.get("inline_ready"))),
        poc_command=_string(row.get("poc_command") or poc.get("command")),
        poc_result=_string(row.get("poc_result") or poc.get("result") or poc.get("expected_output")),
        oos_checked=_bool(row.get("oos_checked", oos.get("checked"))),
        proof_state=_string(row.get("proof_state") or _proof_state_from_poc(poc)) or "planned",
        source_paths=[_string(path) for path in source_paths if _string(path)],
        recommended_fix_marker=_has_value(
            row.get("recommended_fix_marker")
            or row.get("recommended_fix")
            or row.get("fix")
            or row.get("recommendation")
        ),
        blockers=list(row.get("blockers") or []),
    )


def _discover_control_candidates(ws: Path) -> list[Candidate]:
    root = ws / ".auditooor" / "control" / "candidates"
    if not root.is_dir():
        return []

    candidates: list[Candidate] = []
    for pattern in CONTROL_CANDIDATE_GLOBS:
        for path in sorted(root.glob(pattern)):
            row, blockers = _load_control_row(path)
            if row is None:
                candidates.append(
                    Candidate(
                        id=_slug(path.stem),
                        title=path.stem,
                        status="blocked",
                        proof_state="blocked",
                        source_paths=[str(path)],
                        blockers=blockers or ["unsupported_candidate_file"],
                    )
                )
                continue
            candidate = normalize_candidate(row)
            candidate.source_paths = _stable_unique(candidate.source_paths + [str(path)])
            candidate.blockers = _stable_unique(candidate.blockers + blockers)
            candidates.append(candidate)
    return candidates


def _discover_submission_candidates(ws: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    for rel_dir in SUBMISSION_DIRS:
        root = ws / rel_dir
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.md")):
            candidates.append(_candidate_from_markdown(path, rel_dir))
    return candidates


def _discover_poc_manifest_candidates(ws: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    for path in sorted(ws.glob(POC_MANIFEST_GLOB)):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            candidates.append(
                Candidate(
                    id=_slug(path.parent.name),
                    title=path.parent.name,
                    status="blocked",
                    proof_state="blocked",
                    source_paths=[str(path)],
                    blockers=[f"invalid_poc_manifest:{exc.__class__.__name__}"],
                )
            )
            continue
        candidates.append(_candidate_from_poc_manifest(path, data))
    return candidates


def _load_control_row(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"unreadable_candidate_file:{exc.__class__.__name__}"]

    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return None, [f"invalid_json:{exc.msg}"]
        if not isinstance(data, dict):
            return None, ["candidate_json_not_object"]
        return data, []

    data = _parse_tiny_yaml(text)
    if data is None:
        return None, ["unsupported_yaml_shape"]
    return data, []


def _parse_tiny_yaml(text: str) -> dict[str, Any] | None:
    """Parse a conservative subset of reviewable key/value YAML."""

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            return None
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if stripped.startswith("- "):
            return None
        if ":" not in stripped:
            return None
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            return None
        current = stack[-1][1]
        if value == "":
            nested: dict[str, Any] = {}
            current[key] = nested
            stack.append((indent, nested))
        else:
            current[key] = _parse_scalar(value)
    return root


def _candidate_from_markdown(path: Path, rel_dir: str) -> Candidate:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = _first_heading(text) or path.stem.replace("-", " ").replace("_", " ").strip()
    candidate = Candidate(
        id=_slug(path.stem),
        title=title,
        status=_status_from_submission(path, rel_dir, text),
        severity=_markdown_field(text, "severity"),
        likelihood=_markdown_field(text, "likelihood"),
        impact=_markdown_impact(text),
        inline_poc_ready=_has_inline_poc(text),
        poc_command=_extract_command(text),
        poc_result=_extract_result(text),
        oos_checked=_has_oos_check(text),
        proof_state="planned",
        source_paths=[str(path)],
        recommended_fix_marker=_has_recommended_fix(text),
    )
    if candidate.poc_command and candidate.poc_result:
        candidate.proof_state = "proved" if _result_looks_passing(candidate.poc_result) else "executed"
    elif candidate.inline_poc_ready:
        candidate.proof_state = "scaffolded"
    return candidate


def _candidate_from_poc_manifest(path: Path, data: dict[str, Any]) -> Candidate:
    result = _string(
        data.get("result")
        or data.get("final_result")
        or data.get("impact_assertion_status")
        or data.get("status")
    )
    command = _string(data.get("command") or data.get("cmd") or data.get("replay_command"))
    candidate_id = _string(data.get("candidate_id") or data.get("id") or path.parent.name)
    proof_state = "proved" if result.lower() in {"proved", "pass", "passed", "success"} else "executed"
    if result.lower() in {"blocked", "failed", "disproved", "killed"}:
        proof_state = result.lower()
    return Candidate(
        id=_slug(candidate_id),
        title=_string(data.get("title") or candidate_id),
        status=_string(data.get("status") or "poc_executed"),
        inline_poc_ready=_bool(data.get("inline_poc_ready")),
        poc_command=command,
        poc_result=result,
        proof_state=proof_state,
        source_paths=[str(path)],
    )


def _dedupe_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    by_id: dict[str, Candidate] = {}
    for candidate in candidates:
        current = by_id.get(candidate.id)
        if current is None:
            by_id[candidate.id] = candidate
            continue
        by_id[candidate.id] = _merge_candidates(current, candidate)
    return [by_id[key] for key in sorted(by_id)]


def _merge_candidates(left: Candidate, right: Candidate) -> Candidate:
    return Candidate(
        id=left.id,
        title=left.title if left.title != "Untitled candidate" else right.title,
        status=_stronger_status(left.status, right.status),
        severity=left.severity or right.severity,
        likelihood=left.likelihood or right.likelihood,
        impact=left.impact or right.impact,
        inline_poc_ready=left.inline_poc_ready or right.inline_poc_ready,
        poc_command=left.poc_command or right.poc_command,
        poc_result=left.poc_result or right.poc_result,
        oos_checked=left.oos_checked or right.oos_checked,
        proof_state=_stronger_proof_state(left.proof_state, right.proof_state),
        source_paths=_stable_unique(left.source_paths + right.source_paths),
        recommended_fix_marker=left.recommended_fix_marker or right.recommended_fix_marker,
        blockers=_stable_unique(left.blockers + right.blockers),
    )


def _stronger_status(left: str, right: str) -> str:
    order = [
        "lead",
        "candidate",
        "poc_planned",
        "poc_executed",
        "impact_mapped",
        "oos_checked",
        "paste_ready",
        "submitted",
        "duplicate",
        "rejected",
        "accepted",
        "paid",
        "killed",
        "blocked",
    ]
    return max((left, right), key=lambda value: order.index(value) if value in order else -1)


def _stronger_proof_state(left: str, right: str) -> str:
    order = ["planned", "scaffolded", "executed", "proved", "killed", "blocked"]
    return max((left, right), key=lambda value: order.index(value) if value in order else -1)


def _status_from_submission(path: Path, rel_dir: str, text: str) -> str:
    lower = text.lower()
    if "submitted" in lower or "report id" in lower or "cantina" in rel_dir:
        return "submitted"
    if path.parent.name == "ready":
        return "paste_ready"
    if path.parent.name == "staging":
        return "candidate"
    return "candidate"


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return match.group(1).strip()
    return ""


def _markdown_field(text: str, name: str) -> str:
    pattern = re.compile(rf"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?{re.escape(name)}(?:\*\*)?\s*:\s*(.+?)\s*$")
    match = pattern.search(text)
    if match:
        return _clean_value(match.group(1))

    heading = re.compile(rf"(?ims)^##+\s*{re.escape(name)}\s*\n+(.+?)(?:\n##+|\Z)")
    match = heading.search(text)
    if match:
        return _clean_value(match.group(1).strip().splitlines()[0])
    return ""


def _markdown_impact(text: str) -> str:
    for name in ("impact", "listed impact", "impact mapping"):
        value = _markdown_field(text, name)
        if value:
            return value
    return ""


def _has_inline_poc(text: str) -> bool:
    lower = text.lower()
    has_poc_section = any(marker in lower for marker in ("proof of concept", "poc", "forge test"))
    has_code = "```" in text
    return has_poc_section and has_code


def _extract_command(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip().strip("`")
        if "forge test" in stripped or stripped.startswith(("make ", "python3 ")):
            return stripped.lstrip("$ ").strip()
    return _markdown_field(text, "command")


def _extract_result(text: str) -> str:
    for name in ("expected output", "output", "result", "poc result"):
        value = _markdown_field(text, name)
        if value:
            return value
    pattern = re.compile(r"(?im)^.*\b\d+\s+passed\b.*$")
    match = pattern.search(text)
    return _clean_value(match.group(0)) if match else ""


def _has_oos_check(text: str) -> bool:
    lower = text.lower()
    if "out of scope" in lower and any(word in lower for word in ("clear", "checked", "not out of scope", "passes")):
        return True
    return bool(re.search(r"(?im)^\s*(?:oos|out[- ]of[- ]scope)\s*:\s*(?:checked|clear|pass|true|yes)\b", text))


def _has_recommended_fix(text: str) -> bool:
    return bool(re.search(r"(?im)^##+\s*(recommended fix|recommendation|mitigation|fix)\b", text)) or bool(
        re.search(r"(?im)^\s*(recommended fix|recommendation|mitigation|fix)\s*:", text)
    )


def _result_looks_passing(value: str) -> bool:
    lower = value.lower()
    return "passed" in lower and "failed" not in lower


def _proof_state_from_poc(poc: dict[str, Any]) -> str:
    result = _string(poc.get("result") or poc.get("expected_output"))
    command = _string(poc.get("command"))
    if result and command:
        return "proved" if _result_looks_passing(result) else "executed"
    if _bool(poc.get("inline_ready")):
        return "scaffolded"
    return "planned"


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"[]", "[ ]"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        body = value[1:-1].strip()
        if not body:
            return []
        return [_clean_value(part) for part in body.split(",")]
    return _clean_value(value)


def _dict_at(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "yes", "true", "checked", "clear", "pass", "passed"}
    return bool(value)


def _has_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).strip()


def _clean_value(value: str) -> str:
    return value.strip().strip("`").strip().strip("*").strip().strip('"').strip("'")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


__all__ = ["Candidate", "discover_candidates", "normalize_candidate", "paste_ready_blockers"]
