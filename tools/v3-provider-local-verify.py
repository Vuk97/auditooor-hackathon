#!/usr/bin/env python3
"""Run bounded local checks for V3 provider local-verification queues.

This verifier is intentionally conservative. It can prove that provider-suggested
local refs exist and that simple patterns appear in local files. It cannot turn a
provider claim into a detector, exploit, severity decision, or submission.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN_ID = "hackerman-v3-8kimi-8minimax"
TEXT_SUFFIXES = {
    ".cfg",
    ".go",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".sol",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_PARTS = {".git", "__pycache__", "node_modules", "target", "vendor"}
LOCAL_PATH_HINT_RE = re.compile(
    r"\b(?:\.auditooor|tools|docs|reference|audit|audits|agent_outputs|reports|detectors|src|test|tests)/"
    r"[A-Za-z0-9_./-]+(?::\d+(?:-\d+)?)?"
)
BLOCKER_TO_TERMINAL = {
    "blocked_missing_receipt": "blocked_missing_receipt",
    "blocked_missing_model": "blocked_missing_model",
    "blocked_no_output": "blocked_no_output",
    "blocked_malformed_output": "blocked_malformed_output",
}
VERIFICATION_STATUSES = {"verified", "no_action", "rejected", "needs_more_source", "blocked", "pending"}
REJECT_VERDICT_TO_TERMINAL = {
    "REJECT_OOS": "rejected_oos",
    "REJECT_DUPLICATE": "rejected_duplicate",
    "REJECT_FALSE_POSITIVE": "rejected_false_positive",
    "REJECT_MISSING_PRODUCTION_PATH": "verified_no_action",
    "REJECT_MOCK_OR_TEST_ONLY": "verified_no_action",
    "REJECT_INSUFFICIENT_IMPACT": "verified_no_action",
    "REJECT_ADMIN_DEPENDENT": "verified_no_action",
    "REJECT_ONE_FIX": "verified_no_action",
    "REJECT_ECONOMICS_WEAK": "verified_no_action",
    "REJECT_PROVIDER_ONLY": "verified_no_action",
}


def _default_campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return workspace / ".auditooor" / "provider_fanout" / campaign_id


def _latest_queue(workspace: Path, campaign_id: str) -> Path:
    runs_dir = _default_campaign_dir(workspace, campaign_id) / "runs"
    candidates = sorted(runs_dir.glob("*/v3_provider_local_verification_queue.json"))
    if not candidates:
        raise SystemExit(f"[v3-provider-local-verify] no local verification queues under {runs_dir}")
    return candidates[-1]


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _unique(values: Iterable[str], *, limit: int = 20) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _parse_ref_path(raw: str, root: Path) -> tuple[Path | None, str, bool]:
    text = str(raw or "").strip()
    if not text:
        return None, "", False
    if re.match(r"^[a-z][a-z0-9+.-]*://", text, flags=re.I):
        return None, text, True
    hints = _extract_local_path_hints(text)
    if hints:
        text = hints[0]
    text = re.sub(r":\d+(?:-\d+)?$", "", text)
    path = Path(text)
    if not path.is_absolute():
        path = root / path
    return path, text, False


def _extract_local_path_hints(raw: str) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    return _unique(match.group(0).rstrip(".,;)]}") for match in LOCAL_PATH_HINT_RE.finditer(text))


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _line_range(raw: str) -> tuple[int | None, int | None]:
    match = re.search(r":(\d+)(?:-(\d+))?$", str(raw or ""))
    if not match:
        return None, None
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    return start, end


def _line_count(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def _is_text_file(path: Path) -> bool:
    return path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in {"Makefile"})


def _candidate_files(path: Path, *, max_files: int = 200) -> list[Path]:
    if _is_text_file(path):
        return [path]
    if not path.is_dir():
        return []
    files: list[Path] = []
    for child in path.rglob("*"):
        if len(files) >= max_files:
            break
        if any(part in SKIP_PARTS for part in child.parts):
            continue
        if _is_text_file(child):
            files.append(child)
    return files


def _pattern_usable(pattern: str) -> bool:
    text = str(pattern or "").strip()
    if not text or len(text) > 120:
        return False
    if text.startswith("/") or text.startswith("#"):
        return False
    return not bool(re.search(r"\s{4,}", text))


def _claim_text(row: dict[str, Any]) -> str:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    parts = [
        claim.get("summary"),
        claim.get("id"),
        claim.get("claim_id"),
        row.get("claim_summary"),
        " ".join(str(item) for item in row.get("grep_patterns") or []),
        " ".join(str(item) for item in (row.get("verification") or {}).get("commands") or []),
    ]
    return "\n".join(str(part) for part in parts if part)


def _derived_grep_patterns(row: dict[str, Any], *, limit: int = 12) -> list[str]:
    """Extract conservative code-like terms from provider rows.

    Provider output remains advisory. These patterns only let the verifier prove
    that an exact local artifact contains a concrete symbol/path mentioned by the
    row, after which a local terminal judgment is still required before learning.
    """
    text = _claim_text(row)
    if not text:
        return []
    candidates: list[str] = []
    candidates.extend(match.group(1).strip() for match in re.finditer(r"`([^`\n]{4,120})`", text))
    candidates.extend(
        match.group(0).strip()
        for match in re.finditer(r"\b[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9][A-Za-z0-9._:/-]*)+\b", text)
    )
    # Include long identifiers that are likely source symbols, but avoid prose.
    candidates.extend(
        match.group(0).strip()
        for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]{8,}\b", text)
        if "_" in match.group(0)
    )
    cleaned: list[str] = []
    for candidate in candidates:
        value = candidate.strip(" \t\r\n.,;:)]}\"'")
        if not value or value.startswith(("http://", "https://")):
            continue
        if value.lower() in {"provider", "workspace", "source", "packet", "verify", "confirm"}:
            continue
        if _pattern_usable(value):
            cleaned.append(value)
    return _unique(cleaned, limit=limit)


def _grep_hits(files: Sequence[Path], patterns: Sequence[str], root: Path, *, max_hits: int = 20) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    usable_patterns = [pattern for pattern in patterns if _pattern_usable(pattern)]
    for path in files:
        if len(hits) >= max_hits:
            break
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            if len(hits) >= max_hits:
                break
            for pattern in usable_patterns:
                if pattern in line:
                    hits.append(
                        {
                            "pattern": pattern,
                            "path": _safe_rel(path, root),
                            "line": line_no,
                            "excerpt": line.strip()[:240],
                        }
                    )
                    break
    return hits


def _check_source_refs(row: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    checks: list[dict[str, Any]] = []
    local_paths: list[Path] = []
    for ref in row.get("source_refs") or []:
        if not isinstance(ref, dict):
            continue
        kind = str(ref.get("kind") or "")
        raw_path = str(ref.get("path") or "")
        if kind not in {"provider_suggested_ref", "local_file"}:
            continue
        path, normalized, is_external = _parse_ref_path(raw_path, root)
        start, end = _line_range(raw_path)
        if is_external:
            checks.append(
                {
                    "kind": kind,
                    "raw_path": raw_path,
                    "normalized_path": normalized,
                    "exists": False,
                    "external": True,
                    "line_range_valid": False,
                }
            )
            continue
        out_of_workspace = bool(path and not _inside_root(path, root))
        count = _line_count(path) if path is not None and not out_of_workspace else None
        line_range_valid = bool(count is not None and start is not None and 1 <= start <= end <= count)
        exists = bool(path and path.exists() and not out_of_workspace)
        if exists and path is not None and (start is None or line_range_valid):
            local_paths.append(path)
        checks.append(
            {
                "kind": kind,
                "raw_path": raw_path,
                "normalized_path": _safe_rel(path, root) if path is not None else normalized,
                "exists": exists,
                "out_of_workspace": out_of_workspace,
                "is_dir": bool(path and path.is_dir()),
                "line_start": start,
                "line_end": end,
                "line_count": count,
                "line_range_valid": line_range_valid,
                "exact_ref_valid": bool(exists and (start is None or line_range_valid)),
                "external": False,
            }
        )
    return checks, local_paths


def _load_terminal_judgments(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        if isinstance(payload.get("judgments"), list):
            rows = payload["judgments"]
        elif isinstance(payload.get("rows"), list):
            rows = payload["rows"]
        else:
            rows = []
            for key, value in payload.items():
                if isinstance(value, dict):
                    row = dict(value)
                    row.setdefault("queue_id", key)
                    rows.append(row)
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in (row.get("queue_id"), row.get("row_id")):
            if key:
                out[str(key)] = row
    return out


def _terminal_judgment_for_row(
    row: dict[str, Any],
    root: Path,
    terminal_judgments: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    judgment = terminal_judgments.get(str(row.get("queue_id") or "")) or terminal_judgments.get(
        str(row.get("row_id") or "")
    )
    if not judgment:
        return None

    outcome = str(judgment.get("terminal_outcome") or "").strip()
    allowed = set(str(item) for item in row.get("terminal_outcome_options") or [])
    reviewer = str(judgment.get("reviewer") or "").strip().lower()
    citation = str(judgment.get("exact_citation") or judgment.get("citation") or "").strip()
    command = str(judgment.get("command") or "").strip()
    errors: list[str] = []

    if reviewer != "local":
        errors.append("reviewer_must_be_local")
    if not outcome or outcome not in allowed:
        errors.append("terminal_outcome_not_allowed")
    if not command:
        errors.append("command_required")
    path, normalized, is_external = _parse_ref_path(citation, root)
    start, end = _line_range(citation)
    count = _line_count(path) if path is not None and not is_external and _inside_root(path, root) else None
    line_range_valid = bool(count is not None and start is not None and 1 <= start <= end <= count)
    if is_external or path is None or not path.exists() or not _inside_root(path, root) or not line_range_valid:
        errors.append("exact_local_line_citation_required")

    return {
        "provided": True,
        "valid": not errors,
        "errors": errors,
        "terminal_outcome": outcome,
        "reviewer": reviewer,
        "command": command,
        "exact_citation": citation,
        "evidence_ref": {
            "kind": "terminal_judgment",
            "path": _safe_rel(path, root) if path is not None else normalized,
            "line": start,
            "line_end": end,
            "verified": not errors,
        },
    }


def _terminal_from_blockers(row: dict[str, Any]) -> str | None:
    for blocker in row.get("blockers") or []:
        if not isinstance(blocker, dict):
            continue
        code = str(blocker.get("code") or "")
        if code in BLOCKER_TO_TERMINAL:
            return BLOCKER_TO_TERMINAL[code]
    return None


def _allowed_terminal(row: dict[str, Any], desired: str | None) -> str | None:
    if desired is None:
        return None
    allowed = set(str(item) for item in row.get("terminal_outcome_options") or [])
    return desired if desired in allowed else None


def _status_for_terminal(terminal: str | None) -> str | None:
    if terminal is None:
        return None
    if terminal.startswith("blocked_"):
        return "blocked"
    if terminal == "needs_more_source":
        return "needs_more_source"
    if terminal == "verified_actionable":
        return "verified"
    if terminal == "verified_no_action":
        return "no_action"
    if terminal.startswith("rejected_"):
        return "rejected"
    return None


def _provider_verdict(row: dict[str, Any]) -> str:
    claim = row.get("claim") if isinstance(row.get("claim"), dict) else {}
    return str(claim.get("provider_verdict") or "").strip().upper()


def _terminal_from_provider_verdict(row: dict[str, Any], route: str) -> str | None:
    verdict = _provider_verdict(row)
    if not verdict:
        return None
    if verdict in {"NEEDS_MORE_SOURCE", "NEED_MORE_SOURCE"}:
        return "needs_more_source"
    if verdict.startswith("KEEP"):
        return None
    if route == "kill_review":
        return REJECT_VERDICT_TO_TERMINAL.get(verdict)
    return None


def _has_claim_specific_evidence(grep_hits: Sequence[dict[str, Any]]) -> bool:
    return bool(grep_hits)


def _desired_terminal(
    row: dict[str, Any],
    route: str,
    *,
    grep_hits: Sequence[dict[str, Any]],
    existing_refs: Sequence[dict[str, Any]],
    missing_refs: Sequence[dict[str, Any]],
    external_refs: Sequence[dict[str, Any]],
) -> str | None:
    blocked = _terminal_from_blockers(row)
    if blocked is not None:
        return blocked
    if route == "external_source_needed":
        return "needs_more_source"
    if route == "fixture_needed":
        return "needs_more_source"
    if route == "local_source_review":
        if missing_refs or (external_refs and not existing_refs):
            return "needs_more_source"
        verdict_terminal = _terminal_from_provider_verdict(row, route)
        if verdict_terminal is not None:
            return verdict_terminal
        if not _has_claim_specific_evidence(grep_hits):
            return "needs_more_source"
        return None
    if route == "kill_review":
        if missing_refs or (external_refs and not existing_refs):
            return "needs_more_source"
        verdict_terminal = _terminal_from_provider_verdict(row, route)
        if verdict_terminal is not None:
            return verdict_terminal
        return None
    if missing_refs or (external_refs and not existing_refs):
        return "needs_more_source"
    return None


def _verify_row(
    row: dict[str, Any],
    root: Path,
    terminal_judgments: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    source_checks, local_paths = _check_source_refs(row, root)
    existing_refs = [check for check in source_checks if check.get("exists")]
    exact_existing_refs = [
        check
        for check in existing_refs
        if check.get("exact_ref_valid")
    ]
    missing_refs = [
        check
        for check in source_checks
        if (not check.get("exists") or (check.get("line_start") is not None and not check.get("line_range_valid")))
        and not check.get("external")
    ]
    external_refs = [check for check in source_checks if check.get("external")]
    candidate_files: list[Path] = []
    for path in local_paths:
        candidate_files.extend(_candidate_files(path))
    candidate_files = list(dict.fromkeys(candidate_files))
    explicit_patterns = _unique(str(pattern) for pattern in row.get("grep_patterns") or [])
    derived_patterns = _derived_grep_patterns(row)
    grep_patterns = _unique([*explicit_patterns, *derived_patterns])
    grep_hits = _grep_hits(candidate_files, grep_patterns, root)
    route = str(row.get("route") or "")
    desired_terminal = _desired_terminal(
        row,
        route,
        grep_hits=grep_hits,
        existing_refs=exact_existing_refs,
        missing_refs=missing_refs,
        external_refs=external_refs,
    )
    judgment = _terminal_judgment_for_row(row, root, terminal_judgments or {})
    if judgment and judgment["valid"]:
        terminal = str(judgment["terminal_outcome"])
    else:
        terminal = _allowed_terminal(row, desired_terminal)
    if terminal is not None:
        status = _status_for_terminal(terminal) or "pending"
    elif desired_terminal is not None:
        status = "pending"
    elif grep_hits or exact_existing_refs:
        status = "verified"
    else:
        status = "pending"

    local_verification_required = status == "pending"
    source_collection_required = status == "needs_more_source"
    terminal_judgment_required = status == "verified" and terminal is None

    return {
        "queue_id": row.get("queue_id"),
        "row_id": row.get("row_id"),
        "task_id": row.get("task_id"),
        "provider": row.get("provider"),
        "model": row.get("model"),
        "route": route,
        "claim": row.get("claim"),
        "source_provider_row": row.get("source_provider_row"),
        "verification_status": status,
        "terminal_outcome": terminal,
        "terminal_outcome_options": row.get("terminal_outcome_options") or [],
        "terminal_safe": terminal is not None,
        "source_ref_checks": source_checks,
        "existing_source_ref_count": len(existing_refs),
        "exact_source_ref_count": len(exact_existing_refs),
        "missing_source_ref_count": len(missing_refs),
        "external_source_ref_count": len(external_refs),
        "candidate_file_count": len(candidate_files),
        "grep_patterns": grep_patterns,
        "derived_grep_patterns": [pattern for pattern in derived_patterns if pattern not in explicit_patterns],
        "grep_hit_count": len(grep_hits),
        "grep_hits": grep_hits,
        "verification": {
            "status": status,
            "commands": list((row.get("verification") or {}).get("commands") or []),
            "evidence_refs": [
                {"kind": "local_file", "path": check["normalized_path"], "verified": True}
                for check in exact_existing_refs[:10]
                if check.get("normalized_path")
            ]
            + [
                {
                    "kind": "grep_hit",
                    "path": hit["path"],
                    "line": hit["line"],
                    "pattern": hit["pattern"],
                    "verified": True,
                }
                for hit in grep_hits[:10]
            ]
            + ([judgment["evidence_ref"]] if judgment and judgment["valid"] else []),
            "verifier_notes": None,
        },
        "terminal_judgment": judgment,
        "local_verification_required": local_verification_required,
        "source_collection_required": source_collection_required,
        "terminal_judgment_required": terminal_judgment_required,
        "advisory_only": True,
        "evidence_class": "generated_hypothesis",
        "promotion_authority": False,
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
        "severity_assigned": False,
        "learning_ledger_ready": terminal is not None,
    }


def build_verification(
    queue_path: Path,
    workspace_root: Path,
    terminal_judgments: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    queue = _read_json(queue_path)
    rows = [
        _verify_row(row, workspace_root, terminal_judgments=terminal_judgments)
        for row in queue.get("rows", [])
        if isinstance(row, dict)
    ]
    by_status = Counter(str(row["verification_status"]) for row in rows)
    by_terminal = Counter(str(row["terminal_outcome"]) for row in rows if row.get("terminal_outcome"))
    return {
        "schema": "auditooor.v3_provider_local_verification_result.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_queue": str(queue_path),
        "campaign_id": queue.get("campaign_id"),
        "run_id": queue.get("run_id"),
        "run_dir": queue.get("run_dir"),
        "advisory_only": True,
        "promotion_authority": False,
        "submit_ready": False,
        "summary": {
            "rows": len(rows),
            "by_status": dict(sorted(by_status.items())),
            "by_terminal_outcome": dict(sorted(by_terminal.items())),
            "learning_ledger_ready_rows": sum(1 for row in rows if row["learning_ledger_ready"]),
            "local_verification_required_rows": sum(1 for row in rows if row["local_verification_required"]),
            "source_collection_required_rows": sum(1 for row in rows if row["source_collection_required"]),
            "terminal_judgment_required_rows": sum(1 for row in rows if row["terminal_judgment_required"]),
            "grep_hit_rows": sum(1 for row in rows if row["grep_hit_count"]),
            "existing_ref_rows": sum(1 for row in rows if row["existing_source_ref_count"]),
            "terminal_judgment_input_rows": sum(1 for row in rows if row.get("terminal_judgment")),
            "invalid_terminal_judgment_rows": sum(
                1 for row in rows if row.get("terminal_judgment") and not row["terminal_judgment"].get("valid")
            ),
        },
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# V3 Provider Local Verification Result",
        "",
        "Mechanical local checks only. This result never promotes provider output to proof, severity, or submission readiness.",
        "",
        f"- source queue: `{payload['source_queue']}`",
        f"- run_id: `{payload.get('run_id') or ''}`",
        f"- rows: `{payload['summary']['rows']}`",
        f"- by_status: `{payload['summary']['by_status']}`",
        f"- by_terminal_outcome: `{payload['summary']['by_terminal_outcome']}`",
        "",
        "| Queue ID | Provider | Status | Terminal | Existing Refs | Grep Hits |",
        "|---|---|---|---|---:|---:|",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| `{row['queue_id']}` | `{row['provider']}` | `{row['verification_status']}` | "
            f"`{row.get('terminal_outcome') or ''}` | {row['existing_source_ref_count']} | {row['grep_hit_count']} |"
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
    parser.add_argument("--queue", type=Path, default=None)
    parser.add_argument("--terminal-judgments", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    queue_path = args.queue.expanduser().resolve() if args.queue else _latest_queue(workspace, args.campaign_id)
    terminal_judgments = (
        _load_terminal_judgments(args.terminal_judgments.expanduser().resolve())
        if args.terminal_judgments
        else {}
    )
    payload = build_verification(queue_path, workspace, terminal_judgments=terminal_judgments)
    run_dir = Path(str(payload.get("run_dir") or queue_path.parent))
    out_json = (
        args.out_json.expanduser().resolve()
        if args.out_json
        else run_dir / "v3_provider_local_verification_result.json"
    )
    out_md = args.out_md.expanduser().resolve() if args.out_md else run_dir / "v3_provider_local_verification_result.md"
    write_outputs(payload, out_json, out_md)
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "out_json": str(out_json)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
