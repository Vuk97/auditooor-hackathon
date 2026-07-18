#!/usr/bin/env python3
"""Guard source-scoped audits from live-state-only terminal decisions.

For source-scoped bounty programs, missing current deployed/live-state evidence
is not a valid reason by itself to kill or block a candidate. Live probes can be
materiality witnesses, but terminal decisions need a source/scope reason unless
the program explicitly requires live/deployed-state proof.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.source_scope_live_proof_guard.v1"
MAX_REFS = 8
MAX_REASONS = 12

SOURCE_SCOPE_HINTS = (
    "github.com/",
    "github",
    "repository",
    "repo url",
    "repo:",
    "codebase",
    "source code",
    "source-code",
    "commit pin",
    "commit:",
    "audit pin",
)

LIVE_REQUIRED_HINTS = (
    "live state required",
    "live proof required",
    "fork proof required",
    "deployed contracts only",
    "deployed contract only",
    "only deployed",
    "mainnet only",
    "production deployment only",
)

LIVE_TERMINAL_PATTERNS = (
    "live_state_currently_blocked",
    "live-state-blocked",
    "live_state_blocked",
    "monitor-live-state",
    "live managers",
    "sampled live",
    "no current live",
    "current live",
    "live-deployment",
    "live deployment",
    "live/governed",
    "live tier",
    "production-registered",
    "current production reachability",
    "tierprice(1..4)=0",
)

TERMINAL_HINTS = (
    "killed",
    "closed",
    "closed_negative",
    "blocked",
    "not_submit_ready",
    "live_state_currently_blocked",
)

PASS_VERDICT_KEYS = (
    "proof_status",
    "proof_verdict",
    "poc_status",
    "poc_verdict",
    "reproduction_status",
    "reproduction_verdict",
    "final_verdict",
    "final_result",
    "finalization_status",
    "finalization_verdict",
    "finalisation_status",
    "finalisation_verdict",
    "submission_posture",
    "quality_gate_status",
    "promotion_status",
    "promotion_verdict",
    "status",
    "verdict",
    "result",
)

PASS_VERDICT_RE = re.compile(
    r"\b(pass|passed|ok|ready|submit_ready|proof[_ -]?ready|proof[_ -]?complete|"
    r"verified|confirmed|reproduced|accepted|complete|promotion[_ -]?allowed)\b",
    re.IGNORECASE,
)
NEGATIVE_VERDICT_RE = re.compile(
    r"\b(blocked|not[_ -]?submit|not[_ -]?ready|not[_ -]?proof|missing|pending|todo|"
    r"needs|advisory|hypothesis|inconclusive|failed|false|no[_ -]?proof|killed|closed_negative)\b",
    re.IGNORECASE,
)

SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "source_citations",
    "source_locations",
    "evidence_refs",
    "root_cause_refs",
    "file_line_refs",
)

SOURCE_REF_PATH_RE = re.compile(
    r"(?P<path>(?:/|\.{0,2}/|workspace:)?[A-Za-z0-9_./@+\-]+?\."
    r"(?:sol|go|rs|move|vy|cairo|py|ts|tsx|js|jsx|yul|huff|c|cpp|h|hpp))"
    r"(?P<line>:\d+)?\b",
    re.IGNORECASE,
)

OUT_OF_SCOPE_PATH_PARTS = (
    ".auditooor/",
    "advisories/",
    "advisory/",
    "audit/corpus_tags/",
    "docs/",
    "prior_audits/",
    "reference/",
    "reports/",
    "submissions/",
)

ADVISORY_ONLY_RE = re.compile(
    r"\b(advisory[_ -]?only|advisory|external[_ -]?only|archive[_ -]?only|"
    r"out[_ -]?of[_ -]?scope|oos|prior[_ -]?audit|known[_ -]?issue|candidate[_ -]?only|"
    r"hypothesis|review[_ -]?only)\b",
    re.IGNORECASE,
)

BLOCKER_KEYS = (
    "blocker",
    "blockers",
    "blocking_reason",
    "blocking_reasons",
    "proof_blockers",
    "proof_blocker",
    "hard_blockers",
    "stop_reason",
    "stop_condition",
)

PROOF_ARTIFACT_PATH_KEYS = (
    "proof_file",
    "proof_path",
    "proof_artifact",
    "proof_artifact_path",
    "poc_path",
    "poc_paths",
    "test_path",
    "test_paths",
    "harness_path",
    "harness_paths",
    "execution_manifest_path",
    "poc_execution_manifest_path",
    "live_proof_path",
    "live_check_path",
    "transcript_path",
    "poc_transcript_path",
)

PROOF_EVIDENCE_TEXT_KEYS = (
    "pass_evidence_lines",
    "poc_pass_evidence",
    "proof_evidence",
    "harness_evidence",
    "live_evidence",
    "reproduction_evidence",
    "test_output",
    "forge_output",
    "go_test_output",
    "proof_transcript",
    "poc_transcript",
    "validation_evidence",
    "finalization_evidence",
)

PASS_EVIDENCE_RE = re.compile(
    r"--- PASS:|Suite result:\s*ok|\bPASS\b|\bpassed\b|\breproduced\b|\bconfirmed\b|\bverified\b",
    re.IGNORECASE,
)

SCAN_DOCS = ("STATUS.md", "FINDINGS.md", "HYPOTHESES.md")
SCAN_JSON_GLOBS = (
    ".auditooor/exploit_queue*.json",
    ".auditooor/impact_contracts.json",
    "source_proofs/**/source_proof.json",
    "poc_execution/**/execution_manifest.json",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(pattern in low for pattern in patterns)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _raw_values(row: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for key in keys:
        value = row.get(key)
        for item in _as_list(value):
            text = str(item or "").strip()
            if text:
                out.append(text)
    return out


def _uniq(values: list[str], limit: int = MAX_REFS) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
        if len(out) >= limit:
            break
    return out


def classify_scope(workspace: Path) -> dict[str, Any]:
    scope_text = "\n".join(
        _read(workspace / name) for name in ("SCOPE.md", "OOS_PASTED.md", "scope.json")
    )
    source_scoped = _contains_any(scope_text, SOURCE_SCOPE_HINTS)
    live_required = _contains_any(scope_text, LIVE_REQUIRED_HINTS)
    source_roots: list[str] = []

    policy_path = workspace / ".auditooor" / "scope_live_proof_policy.json"
    policy = _load_json(policy_path)
    if isinstance(policy, dict):
        if "source_scoped" in policy:
            source_scoped = bool(policy["source_scoped"])
        if "requires_live_proof" in policy:
            live_required = bool(policy["requires_live_proof"])
        for key in ("source_roots", "in_scope_source_roots", "in_scope_paths"):
            for root in _as_list(policy.get(key)):
                text = str(root or "").strip().strip("/")
                if text:
                    source_roots.append(text)

    return {
        "source_scoped": source_scoped,
        "requires_live_proof": live_required,
        "source_roots": _uniq(source_roots, limit=32),
        "policy_path": str(policy_path) if policy_path.is_file() else "",
    }


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    if isinstance(value, list):
        return " ".join(_stringify(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}={_stringify(val)}" for key, val in value.items())
    return str(value)


def _candidate_id(row: dict[str, Any]) -> str:
    for key in ("candidate_id", "lead_id", "id", "row_key", "impact_contract_id"):
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _line_exists(path: Path, line_no: int) -> bool:
    if line_no <= 0:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, _line in enumerate(handle, start=1):
                if index >= line_no:
                    return True
    except OSError:
        return False
    return False


def _display_path(path: Path, workspace: Path) -> str:
    try:
        rel = path.resolve().relative_to(workspace.resolve())
        return rel.as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _strip_line_suffix(value: str) -> str:
    return re.sub(r":\d+(?:-\d+)?$", "", value.strip().strip("`'\"()[]{}.,;"))


def _source_ref_status(ref: str, workspace: Path, source_roots: list[str]) -> tuple[str | None, str | None]:
    text = ref.strip().strip("`'\"()[]{}.,;")
    if text.startswith("[src:") and text.endswith("]"):
        text = text[5:-1].strip()
    if not text or re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        return None, "missing_current_workspace_source_refs"
    match = SOURCE_REF_PATH_RE.search(text)
    if not match:
        return None, "missing_current_workspace_source_refs"

    raw_path = match.group("path")
    line_suffix = match.group("line") or ""
    if raw_path.startswith("workspace:"):
        raw_path = raw_path[len("workspace:") :]
    if raw_path.startswith(f"{workspace.name}/"):
        raw_path = raw_path[len(workspace.name) + 1 :]

    path = Path(raw_path).expanduser()
    try:
        resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return None, "source_ref_outside_current_workspace"

    display = _display_path(resolved, workspace)
    display_low = display.lower()
    if any(display_low.startswith(part) or f"/{part}" in display_low for part in OUT_OF_SCOPE_PATH_PARTS):
        return None, f"out_of_scope_or_advisory_source_ref:{display}"
    if source_roots and not any(display == root or display.startswith(f"{root}/") for root in source_roots):
        return None, f"out_of_scope_or_advisory_source_ref:{display}"
    if not resolved.is_file():
        return None, f"stale_workspace_source_ref:{display}"
    if line_suffix and not _line_exists(resolved, int(line_suffix[1:])):
        return None, f"stale_workspace_source_ref:{display}{line_suffix}"
    return f"{display}{line_suffix}", None


def _current_workspace_source_refs(
    row: dict[str, Any], workspace: Path, source_roots: list[str]
) -> tuple[list[str], list[str]]:
    raw_refs = _raw_values(row, *SOURCE_REF_KEYS)
    if not raw_refs:
        return [], ["missing_current_workspace_source_refs"]

    valid: list[str] = []
    reasons: list[str] = []
    for ref in raw_refs:
        display, reason = _source_ref_status(ref, workspace, source_roots)
        if display:
            valid.append(display)
        if reason:
            reasons.append(reason)
    return _uniq(valid), _uniq(reasons, limit=MAX_REASONS)


def _existing_workspace_paths(row: dict[str, Any], workspace: Path, keys: tuple[str, ...]) -> list[str]:
    values = _raw_values(row, *keys)
    out: list[str] = []
    for value in values:
        cleaned = _strip_line_suffix(value)
        if not cleaned or re.match(r"^[a-z][a-z0-9+.-]*://", cleaned, re.IGNORECASE):
            continue
        candidate = Path(cleaned).expanduser()
        try:
            resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
            resolved.relative_to(workspace)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            out.append(_display_path(resolved, workspace))
    return _uniq(out)


def _proof_text_evidence(row: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for text in _raw_values(row, *PROOF_EVIDENCE_TEXT_KEYS):
        if PASS_EVIDENCE_RE.search(text):
            evidence.append(re.sub(r"\s+", " ", text[:240]).strip())
    return _uniq(evidence)


def _concrete_live_or_harness_evidence(row: dict[str, Any], workspace: Path) -> tuple[list[str], list[str]]:
    artifacts = _existing_workspace_paths(row, workspace, PROOF_ARTIFACT_PATH_KEYS)
    evidence = _proof_text_evidence(row)
    return artifacts, evidence


def _passlike(row: dict[str, Any]) -> bool:
    if row.get("promotion_allowed") is True or row.get("proof_ready") is True:
        return True
    for text in _raw_values(row, *PASS_VERDICT_KEYS):
        if NEGATIVE_VERDICT_RE.search(text):
            continue
        if PASS_VERDICT_RE.search(text):
            return True
    return False


def _advisory_only_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if row.get("advisory_only") is True or row.get("out_of_scope") is True:
        reasons.append("out_of_scope_or_advisory_only_evidence")
    for key, value in row.items():
        if key in SOURCE_REF_KEYS:
            continue
        text = _stringify(value)
        if ADVISORY_ONLY_RE.search(text):
            reasons.append(f"out_of_scope_or_advisory_only_evidence:{key}")
    return _uniq(reasons, limit=MAX_REASONS)


def _blocker_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for key in BLOCKER_KEYS:
        for text in _raw_values(row, key):
            if text:
                reasons.append(f"blocker_present:{key}:{text[:180]}")
    terminal_text = " ".join(_raw_values(row, *PASS_VERDICT_KEYS)).lower()
    if _contains_any(terminal_text, TERMINAL_HINTS) and NEGATIVE_VERDICT_RE.search(terminal_text):
        reasons.append("blocker_present:terminal_status")
    return _uniq(reasons, limit=MAX_REASONS)


def _candidate_payload(row: dict[str, Any]) -> bool:
    if _candidate_id(row):
        return True
    evidence_keys = SOURCE_REF_KEYS + PROOF_ARTIFACT_PATH_KEYS + PROOF_EVIDENCE_TEXT_KEYS + BLOCKER_KEYS
    if any(key in row for key in evidence_keys):
        return True
    text = _stringify(row)
    return _terminalish(row) and _contains_any(text, LIVE_TERMINAL_PATTERNS)


def _row_needs_report(row: dict[str, Any]) -> bool:
    if not _candidate_payload(row):
        return False
    if _passlike(row):
        return True
    if _blocker_reasons(row):
        return True
    text = _stringify(row)
    return _terminalish(row) and _contains_any(text, LIVE_TERMINAL_PATTERNS)


def _terminalish(row: dict[str, Any]) -> bool:
    keys = (
        "proof_status",
        "final_verdict",
        "final_result",
        "submission_posture",
        "status",
        "quality_gate_status",
        "learning_route",
        "stop_condition",
    )
    text = " ".join(str(row.get(key) or "") for key in keys).lower()
    if _contains_any(text, TERMINAL_HINTS):
        return True
    if _contains_any(_stringify(row.get("blockers") or ""), LIVE_TERMINAL_PATTERNS):
        return True
    return False


def _json_rows(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        rows.append(value)
        for child in value.values():
            rows.extend(_json_rows(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(_json_rows(child))
    return rows


def evaluate_row(workspace: Path, rel: str, row: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any] | None:
    if not _row_needs_report(row):
        return None

    reasons: list[str] = []
    passlike = _passlike(row)
    text = _stringify(row)
    if _terminalish(row) and _contains_any(text, LIVE_TERMINAL_PATTERNS):
        reasons.append("live_state_only_terminal_decision")
    reasons.extend(_blocker_reasons(row))
    reasons.extend(_advisory_only_reasons(row))

    source_refs: list[str] = []
    source_ref_reasons: list[str] = []
    proof_artifacts: list[str] = []
    proof_evidence: list[str] = []

    if passlike:
        source_refs, source_ref_reasons = _current_workspace_source_refs(
            row, workspace, list(scope.get("source_roots") or [])
        )
        proof_artifacts, proof_evidence = _concrete_live_or_harness_evidence(row, workspace)
        if not source_refs:
            reasons.extend(source_ref_reasons or ["missing_current_workspace_source_refs"])
        if not proof_artifacts and not proof_evidence:
            reasons.append("missing_concrete_live_or_harness_evidence")

    reasons = _uniq(reasons, limit=MAX_REASONS)
    if passlike and not reasons:
        return None
    if not passlike and not reasons:
        return None

    return {
        "path": rel,
        "candidate_id": _candidate_id(row),
        "kind": "source_scope_live_proof_non_pass",
        "passlike": passlike,
        "typed_reasons": reasons,
        "current_workspace_source_refs": source_refs,
        "source_ref_reasons": source_ref_reasons,
        "proof_artifacts": proof_artifacts,
        "proof_evidence": proof_evidence,
        "snippet": re.sub(r"\s+", " ", text[:500]).strip(),
        "remediation": (
            "Pass-like source-scoped rows need current workspace source refs, "
            "in-scope source evidence, and concrete live proof or harness evidence."
        ),
    }


def scan_json_file(workspace: Path, path: Path) -> list[dict[str, Any]]:
    payload = _load_json(path)
    if payload is None:
        return []
    rel = str(path.relative_to(workspace))
    violations: list[dict[str, Any]] = []
    scope = classify_scope(workspace)
    for row in _json_rows(payload):
        violation = evaluate_row(workspace, rel, row, scope)
        if violation:
            violations.append(violation)
    return violations


def scan_doc_file(workspace: Path, path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rel = str(path.relative_to(workspace))
    violations: list[dict[str, Any]] = []
    for lineno, line in enumerate(_read(path).splitlines(), start=1):
        low = line.lower()
        if not _contains_any(low, LIVE_TERMINAL_PATTERNS):
            continue
        if not _contains_any(low, TERMINAL_HINTS):
            continue
        violations.append(
            {
                "path": rel,
                "line": lineno,
                "candidate_id": "",
                "kind": "doc_terminal_live_gate",
                "typed_reasons": ["live_state_only_terminal_decision"],
                "snippet": line.strip(),
                "remediation": "Terminal source-scoped decisions must cite source/scope evidence, not live-state absence alone.",
            }
        )
    return violations


def build_report(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    scope = classify_scope(workspace)
    violations: list[dict[str, Any]] = []
    if workspace.is_dir() and scope["source_scoped"] and not scope["requires_live_proof"]:
        for name in SCAN_DOCS:
            violations.extend(scan_doc_file(workspace, workspace / name))
        seen: set[Path] = set()
        for pattern in SCAN_JSON_GLOBS:
            for path in workspace.glob(pattern):
                if path in seen or not path.is_file():
                    continue
                seen.add(path)
                violations.extend(scan_json_file(workspace, path))
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "scope": scope,
        "violation_count": len(violations),
        "non_pass_reason_count": sum(len(item.get("typed_reasons") or []) for item in violations),
        "violations": violations,
        "non_pass_reasons": violations,
        "status": "fail" if violations else "pass",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    report = build_report(args.workspace)
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if report["violation_count"]:
        print(
            f"[source-scope-live-proof-guard] {'ERR' if args.strict else 'WARN'} "
            f"{report['violation_count']} source-scope proof issue(s) in source-scoped workspace",
            file=sys.stderr,
        )
    return 1 if args.strict and report["violation_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
