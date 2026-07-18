#!/usr/bin/env python3
# r36-rebuttal: funnel-enforcement-gates-AB
"""Build advisory candidate judgment packets before PoC spend.

This is an aggregator, not a promotion gate. It joins exploit-queue rows with
prefiling stress, severity/scope oracle, and falsification outputs so a High+
candidate has one bounded packet of local judgment facts before proof work.
With --strict, blocked packets fail the command so strict proof workflows stop
before spending harness time on candidates that are locally blocked.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.chain_d4 import has_chain_attacker_control_evidence  # noqa: E402

# ---------------------------------------------------------------------------
# Gate B: Early prior-audit dedup (loaded best-effort; never breaks packets)
# ---------------------------------------------------------------------------
# Kills or flags acknowledged / prior-audited candidates BEFORE draft/PoC work.
# Fills the gap between LLM-hunt emit and late pre-submit R47/R53 checks.
_EARLY_DEDUP_GATE_PATH = TOOLS_DIR / "early-prior-audit-dedup-gate.py"
_EARLY_DEDUP_MOD: Any | None = None


def _load_early_dedup_gate() -> Any | None:
    global _EARLY_DEDUP_MOD
    if _EARLY_DEDUP_MOD is not None:
        return _EARLY_DEDUP_MOD
    if not _EARLY_DEDUP_GATE_PATH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "early_prior_audit_dedup_gate", _EARLY_DEDUP_GATE_PATH
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _EARLY_DEDUP_MOD = mod
        return mod
    except Exception:
        return None


def _early_prior_audit_blocker(
    row: dict[str, Any], workspace: Path | None
) -> dict[str, Any] | None:
    """Return a blocker dict if Gate B fires, or None if the candidate passes.

    Fail-open (returns None) on any import or runtime error so the packet
    pipeline is never broken by a missing gate tool.
    """
    if workspace is None:
        return None
    mod = _load_early_dedup_gate()
    if mod is None:
        return None
    try:
        return mod.candidate_judgment_blocker(row, workspace)
    except Exception:
        return None


# Additive wiring (impact-imagination gap): before a candidate is surfaced or
# dropped, enumerate ALL plausible impact classes for its pattern+function so no
# single benign hypothesis silently closes a multi-impact surface. Generic,
# --workspace-driven; loaded best-effort so a missing tool never breaks packets.
_MIE_PATH = TOOLS_DIR / "multi-impact-enumerator.py"
_MIE_MOD: Any | None = None


def _load_mie() -> Any | None:
    global _MIE_MOD
    if _MIE_MOD is not None:
        return _MIE_MOD
    if not _MIE_PATH.is_file():
        return None
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location("multi_impact_enumerator", _MIE_PATH)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MIE_MOD = mod
        return mod
    except Exception:
        return None


def _impact_enumeration(row: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    """Enumerate every plausible impact class for this candidate's pattern on its
    function so a downstream worker drives ALL hypotheses to a verdict, not just
    the one the author tried. Additive: returns {} on any failure."""
    mie = _load_mie()
    if mie is None:
        return {}
    pattern = _first(row, "attack_class", "detector", "pattern", "class")
    function = _first(row, "function", "function_name", "function_signature", "entrypoint")
    file_line = ""
    for ref in _raw_source_refs(row):
        m = REAL_SOURCE_REF_RE.search(ref)
        if m:
            mm = SOURCE_REF_PATH_RE.search(ref)
            if mm:
                file_line = mm.group("path") + (mm.group("line") or "")
                break
    if not file_line and ":" in function and REAL_SOURCE_REF_RE.search(function):
        file_line = function
    if not pattern and not function and not file_line:
        return {}
    try:
        rows, meta = mie.enumerate_impacts(
            pattern or "", function or file_line or "", workspace, file_line or function or None
        )
    except Exception:
        return {}
    return {
        "tool": getattr(mie, "TOOL", "multi-impact-enumerator"),
        "schema_version": getattr(mie, "SCHEMA_VERSION", ""),
        "pattern": pattern or "",
        "function": function or file_line or "",
        "language": meta.get("language"),
        "pattern_matched": meta.get("pattern_matched"),
        "note": meta.get("note", ""),
        "impact_classes": [r["impact_class"] for r in rows],
        "hypotheses": [
            {
                "impact_class": r["impact_class"],
                "attack_hypothesis": r["attack_hypothesis"],
                "test_to_run": r["test_to_run"],
            }
            for r in rows
        ],
    }


SCHEMA = "auditooor.candidate_judgment_packet.v1"
_TYPED_ENVELOPE_PATH = TOOLS_DIR / "zero-day-proof-envelope-verify.py"
_TYPED_ENVELOPE_MOD: Any | None = None
MAX_REFS = 8
MAX_BLOCKERS = 10
MISSING_VALUES = {"", "unknown", "n/a", "na", "missing", "todo", "not_assessed"}


def _load_typed_envelope_tool() -> Any:
    """Load the shared immutable typed-proof validator fail-closed."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("auditooor_candidate_typed_envelope", _TYPED_ENVELOPE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module
STATUS_TRIPLE_VALUES = {
    "clean",
    "low",
    "medium",
    "high",
    "dupe_risk=low",
    "not_checked",
    "possible_dupe",
    "known_dupe",
    "duplicate",
    "dupe",
}

REQUIRED_FIELDS = (
    "verdict",
    "permissionless_trigger",
    "admin_or_team_dependency",
    "offchain_dependency",
    "exact_rubric_row",
    "dupe_triple",
    "economics_range",
    "capital_lock",
    "gas_slippage_time_cost",
    "attacker_actor",
    "victim_actor",
    "official_source_url_or_hash",
    "execution_window",
)
LOCAL_BLOCKING_STATES = {
    "blocked_missing_truth",
    "blocked_by_scope",
    "blocked_by_dupe",
    "blocked_by_economics",
    "blocked_by_falsification",
    "blocked_intended_actor_mismatch",
    "blocked_admin_gated_or_by_design",
    "blocked_severity_cap",
    "blocked_weak_proof",
    "blocked_prior_disclosure",
}
TERMINAL_QUEUE_PROOF_STATUSES = {
    "killed",
    "kill",
    "drop",
    "dropped",
    "disproved",
    "closed_negative",
    "closed_negative_operator_review",
    "false_positive",
    "false-positive",
    "not_exploitable",
    "not_candidate",
}
TERMINAL_QUEUE_QUALITY_STATUSES = {
    "killed",
    "kill",
    "drop",
    "dropped",
    "disqualified",
    "closed_negative",
    "closed_negative_operator_review",
    "false_positive",
    "false-positive",
    "not_exploitable",
    "advisory_not_candidate",
}

HIGH_PLUS = {"high", "critical"}
NO_LESSON_PACK_REASON_PREFIX = "NO_LESSON_PACK_REASON:"
CHAIN_METADATA_BLOCKER = "chain_causal_evidence_metadata_overlap_only_unproven"
CHAIN_D4_BLOCKERS = (
    "chain_d4_missing_source_anchor",
    "chain_d4_missing_attacker_control_evidence",
    "chain_d4_missing_negative_or_clean_control",
    "chain_d4_missing_harness_or_source_proof_artifact",
)
DUPE_BAD = {"high", "known_dupe", "possible_dupe", "duplicate", "dupe", "not_checked"}
VALUE_CLAIM_RE = re.compile(
    r"\b(theft|drain|steal|loss|funds?|principal|yield|reward|fee evasion|"
    r"value extraction|profit|insolvency|freeze)\b",
    re.IGNORECASE,
)
WINDOW_CLAIM_RE = re.compile(
    r"\b(mev|sandwich|front[- ]?run|frontrun|back[- ]?run|backrun|race|"
    r"same block|mempool|oracle window|execution window|timestamp|liquidation)\b",
    re.IGNORECASE,
)
REAL_SOURCE_REF_RE = re.compile(r"\.(?:sol|go|rs|move|vy|cairo|py|ts|js)(?::\d+)?\b", re.IGNORECASE)
CHAIN_ARTIFACT_REF_RE = re.compile(
    r"\b(chained_attack_plans|chain_unify_payload|swarm/|dsl_pattern|synthetic)\b",
    re.IGNORECASE,
)
PROOF_ARTIFACT_RE = re.compile(r"\.(?:sol|go|rs|move|vy|cairo|py|ts|js|json|sh)(?::\d+)?\b", re.IGNORECASE)
GENERIC_PROOF_SHELLS = {"foundry", "cosmos-production", "solana-program-test", "manual-source"}
PROOF_ARTIFACT_PATH_KEYS = (
    "proof_file",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "execution_manifest_path",
    "poc_execution_manifest_path",
)
PROOF_VERDICT_KEYS = {
    "proof_ready",
    "proof_status",
    "proof_verdict",
    "poc_status",
    "poc_verdict",
    "reproduction_status",
    "reproduction_verdict",
    "finalization_status",
    "finalization_verdict",
    "finalisation_status",
    "finalisation_verdict",
}
PROOF_STATUS_KEY_RE = re.compile(
    r"(?:proof|poc|repro|reproduction|finali[sz]ation).*(?:ready|status|verdict|result|confirmed|passed)",
    re.IGNORECASE,
)
POSITIVE_PROOF_VALUE_RE = re.compile(
    r"\b(pass|passed|ok|proof[_ -]?ready|reproduced|confirmed|verified|finali[sz]ed|"
    r"finali[sz]ation[_ -]?passed|proof[_ -]?complete)\b",
    re.IGNORECASE,
)
NEGATIVE_PROOF_VALUE_RE = re.compile(
    r"\b(advisory|not[_ -]?submit|not[_ -]?proof|blocked|missing|pending|todo|needs|"
    r"inconclusive|disproved|failed|false|no[_ -]?proof|hypothesis)\b",
    re.IGNORECASE,
)
ADVISORY_ONLY_RE = re.compile(
    r"\b(advisory[_ -]?only|not[_ -]?submit[_ -]?ready|not[_ -]?proof[_ -]?ready|"
    r"review[_ -]?only|hypothesis|candidate[_ -]?only)\b",
    re.IGNORECASE,
)
PASS_EVIDENCE_RE = re.compile(
    r"--- PASS:|Suite result:\s*ok|\bPASS\b|\bpassed\b|\breproduced\b|\bconfirmed\b|\bverified\b",
    re.IGNORECASE,
)
PROOF_EVIDENCE_TEXT_KEYS = (
    "pass_evidence_lines",
    "poc_pass_evidence",
    "proof_evidence",
    "reproduction_evidence",
    "test_output",
    "forge_output",
    "go_test_output",
    "proof_transcript",
    "poc_transcript",
    "validation_evidence",
    "finalization_evidence",
)
PROOF_ARTIFACT_INPUT_KEYS = PROOF_ARTIFACT_PATH_KEYS + (
    "proof_artifacts",
    "poc_paths",
    "test_paths",
    "transcript_path",
    "poc_transcript_path",
)
SOURCE_REF_PATH_RE = re.compile(
    r"(?P<path>(?:/|\.{0,2}/)?[A-Za-z0-9_./@+\-]+?\."
    r"(?:sol|go|rs|move|vy|cairo|py|ts|js))(?P<line>:\d+)?\b",
    re.IGNORECASE,
)


def _is_terminal_queue_row(row: dict[str, Any]) -> bool:
    proof_status = str(
        row.get("proof_status")
        or row.get("source_mined_proof_status")
        or row.get("proof_verdict")
        or row.get("status")
        or ""
    ).strip().lower()
    quality_status = str(row.get("quality_gate_status") or "").strip().lower()
    learning_route = str(row.get("learning_route") or row.get("recommended_next_step") or "").strip().lower()
    # A quality-gate rejection is a routing result, not a technical refutation.
    # In particular, ``disqualified`` and a bare ``killed`` are commonly emitted
    # when a candidate could not be auto-proved.  Filtering those rows here would
    # turn unresolved work into an empty queue and let downstream consumers infer
    # "no leads".  Require a concrete negative artifact before suppressing a row.
    negative_control = row.get("negative_control") or row.get("clean_control")
    source_proof_path = row.get("source_proof_path") or row.get("source_proof")
    truth_summary = row.get("truth_table_summary")
    truth_negative = isinstance(truth_summary, dict) and any(
        str(truth_summary.get(key) or "").strip().lower() in {
            "closed_negative",
            "source proof killed candidate",
            "source proof refuted candidate",
        }
        for key in ("source_state", "clean_control", "next_action")
    )
    evidence_backed_negative = bool(
        source_proof_path
        or truth_negative
        or (isinstance(negative_control, str) and negative_control.strip())
    )

    if proof_status in {"closed_negative", "disproved", "false_positive", "not_exploitable", "not_candidate"}:
        return evidence_backed_negative
    if quality_status in {"closed_negative", "closed_negative_source_proof", "false_positive", "not_exploitable"}:
        return evidence_backed_negative
    if learning_route in {"drop", "dropped", "closed-negative", "closed_negative"}:
        return evidence_backed_negative

    # ``killed`` / ``disqualified`` remain visible unless the row carries the
    # same explicit negative evidence.  This is deliberately fail-closed.
    if proof_status in TERMINAL_QUEUE_PROOF_STATUSES or quality_status in TERMINAL_QUEUE_QUALITY_STATUSES:
        return evidence_backed_negative and proof_status not in {"killed", "kill"}
    return False


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _display_path(path: Path | None, workspace: Path | None = None) -> str:
    if path is None:
        return ""
    expanded = path.expanduser()
    try:
        resolved = expanded.resolve()
    except OSError:
        resolved = expanded
    if workspace is not None:
        try:
            workspace_resolved = workspace.expanduser().resolve()
            rel = resolved.relative_to(workspace_resolved)
            return f"{workspace_resolved.name}/{rel.as_posix()}"
        except (OSError, ValueError):
            pass
    if resolved.is_absolute():
        return resolved.name
    return resolved.as_posix()


_LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:])"
    r"(?P<path>/(?:Users|home|tmp|var|private|Volumes)/[^\s`'\"\),\]}]+)"
)


def _sanitize_local_paths(text: str, workspace: Path | None = None) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group("path")
        suffix = ""
        path_text = raw
        line_match = re.match(r"^(?P<path>.+?)(?P<suffix>:\d+(?::\d+)?)$", raw)
        if line_match:
            path_text = line_match.group("path")
            suffix = line_match.group("suffix")
        return f"{_display_path(Path(path_text), workspace)}{suffix}"

    return _LOCAL_PATH_RE.sub(repl, text)


def _norm(value: Any, *, limit: int = 320) -> str:
    if isinstance(value, (list, tuple)):
        value = "; ".join(_norm(v, limit=limit) for v in value if _norm(v, limit=limit))
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        text = _norm(value)
        if text and text.lower() not in MISSING_VALUES:
            return text
    return ""


def _severity(row: dict[str, Any]) -> str:
    raw = _first(row, "likely_severity", "claimed_severity", "severity", "severity_tier").lower()
    for sev in ("critical", "high", "medium", "low"):
        if sev in raw:
            return sev
    return "unknown"


def _candidate_id(row: dict[str, Any]) -> str:
    return _first(row, "lead_id", "candidate_id", "id", "title") or "candidate"


def _source_refs(row: dict[str, Any], workspace: Path | None = None) -> list[str]:
    refs: list[str] = []
    for key in ("source_refs", "source_ref", "evidence_refs", "proof_artifact_precedent_refs", "metric_integrity_refs"):
        value = row.get(key)
        if isinstance(value, list):
            refs.extend(_norm(v) for v in value)
        elif value:
            refs.append(_norm(value))
    out: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        ref = _sanitize_local_paths(ref, workspace)
        if ref and ref not in seen:
            out.append(ref)
            seen.add(ref)
    return out[:MAX_REFS]


def _source_anchor_refs(row: dict[str, Any], workspace: Path | None = None) -> list[str]:
    refs: list[str] = []
    for key in ("source_refs", "source_ref", "evidence_refs", "source_citations"):
        value = row.get(key)
        if isinstance(value, list):
            refs.extend(_norm(v) for v in value)
        elif value:
            refs.append(_norm(value))
    out: list[str] = []
    for ref in refs:
        ref = _sanitize_local_paths(ref, workspace)
        if ref and not CHAIN_ARTIFACT_REF_RE.search(ref) and REAL_SOURCE_REF_RE.search(ref):
            out.append(ref)
    return out[:MAX_REFS]


def _raw_values(payload: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            out.extend(_norm(v, limit=1000) for v in value if _norm(v, limit=1000))
        elif value:
            out.append(_norm(value, limit=1000))
    return out


def _raw_source_refs(row: dict[str, Any]) -> list[str]:
    return _raw_values(row, "source_refs", "source_ref", "evidence_refs", "source_citations")


def _line_exists(path: Path, line_no: int) -> bool:
    if line_no <= 0:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, _line in enumerate(handle, 1):
                if index >= line_no:
                    return True
    except OSError:
        return False
    return False


def _local_ref_status(ref: str, workspace: Path) -> tuple[str | None, str | None]:
    text = _norm(ref, limit=1000).strip("`'\"()[]{}.,;")
    if not text or re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        return None, f"missing_current_workspace_source_ref:{text or 'empty'}"
    match = SOURCE_REF_PATH_RE.search(text)
    if not match:
        return None, f"missing_current_workspace_source_ref:{_sanitize_local_paths(text, workspace)}"
    raw_path = match.group("path")
    line_suffix = match.group("line") or ""
    if raw_path.startswith(f"{workspace.name}/"):
        raw_path = raw_path[len(workspace.name) + 1 :]
    path = Path(raw_path).expanduser()
    try:
        resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return None, f"source_ref_outside_current_workspace:{_sanitize_local_paths(text, workspace)}"
    display = f"{_display_path(resolved, workspace)}{line_suffix}"
    if not resolved.is_file():
        return None, f"stale_workspace_source_ref:{display}"
    if line_suffix:
        line_no = int(line_suffix[1:])
        if not _line_exists(resolved, line_no):
            return None, f"stale_workspace_source_ref:{display}"
    return display, None


def _current_workspace_source_refs(row: dict[str, Any], workspace: Path | None) -> tuple[list[str], list[str]]:
    if workspace is None:
        return [], ["missing_current_workspace_source_ref"]
    raw_refs = _raw_source_refs(row)
    if not raw_refs:
        return [], ["missing_current_workspace_source_ref"]
    valid: list[str] = []
    reasons: list[str] = []
    seen_valid: set[str] = set()
    seen_reasons: set[str] = set()
    for ref in raw_refs:
        display, reason = _local_ref_status(ref, workspace)
        if display and display not in seen_valid:
            valid.append(display)
            seen_valid.add(display)
        if reason and reason not in seen_reasons:
            reasons.append(reason)
            seen_reasons.add(reason)
    return valid[:MAX_REFS], reasons[:MAX_BLOCKERS]


def _strip_line_suffix(value: str) -> str:
    return re.sub(r":\d+(?:-\d+)?$", "", value.strip().strip("`'\""))


def _has_existing_chain_proof_artifact(row: dict[str, Any], workspace: Path | None) -> bool:
    if workspace is None:
        return False
    values: list[str] = []
    for key in PROOF_ARTIFACT_PATH_KEYS:
        raw = row.get(key)
        if isinstance(raw, str):
            values.append(raw)
    for key in ("proof_artifact_precedent_refs", "proof_artifacts", "poc_paths", "test_paths"):
        raw = row.get(key)
        if isinstance(raw, list):
            values.extend(_norm(item) for item in raw)
    proof_path = _norm(row.get("proof_path"))
    if proof_path:
        values.append(proof_path)

    for value in values:
        cleaned = _strip_line_suffix(value)
        lowered = cleaned.lower()
        if not cleaned or lowered in MISSING_VALUES or lowered in GENERIC_PROOF_SHELLS:
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*://", cleaned, re.IGNORECASE):
            continue
        if not PROOF_ARTIFACT_RE.search(cleaned):
            continue
        candidate = Path(cleaned).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        if candidate.is_file():
            return True
    return False


def _iter_named_payloads(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    payloads = [
        ("exploit_queue", row),
        ("prefiling_stress_test", prefiling),
        ("severity_oracle", oracle),
        ("falsification", falsification),
    ]
    return [(name, payload) for name, payload in payloads if isinstance(payload, dict) and payload]


def _explicit_proof_claims(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
) -> list[dict[str, str]]:
    claims: list[dict[str, str]] = []
    for artifact, payload in _iter_named_payloads(row, prefiling, oracle, falsification):
        for key, value in payload.items():
            key_s = str(key)
            if key_s not in PROOF_VERDICT_KEYS and not PROOF_STATUS_KEY_RE.search(key_s):
                continue
            text = _norm(value, limit=240)
            if text:
                claims.append({"artifact": artifact, "field": key_s, "value": text})
    return claims[:MAX_REFS]


def _has_positive_proof_claim(claims: list[dict[str, str]]) -> bool:
    for claim in claims:
        value = claim.get("value", "")
        if NEGATIVE_PROOF_VALUE_RE.search(value):
            continue
        if value.lower() == "true" or POSITIVE_PROOF_VALUE_RE.search(value):
            return True
    return False


def _advisory_only_reasons(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    for artifact, payload in _iter_named_payloads(row, prefiling, oracle, falsification):
        if payload.get("advisory_only") is True:
            reasons.append(f"advisory_only_candidate:{artifact}.advisory_only")
        for key in (
            "status",
            "candidate_status",
            "submission_posture",
            "posture",
            "proof_status",
            "proof_verdict",
            "poc_status",
            "poc_verdict",
            "finalization_status",
            "finalization_verdict",
        ):
            text = _norm(payload.get(key), limit=240)
            if text and ADVISORY_ONLY_RE.search(text):
                reasons.append(f"advisory_only_candidate:{artifact}.{key}")
    out: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason not in seen:
            out.append(reason)
            seen.add(reason)
    return out[:MAX_BLOCKERS]


def _existing_proof_artifacts(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
    workspace: Path | None,
) -> list[str]:
    if workspace is None:
        return []
    values: list[str] = []
    for _artifact, payload in _iter_named_payloads(row, prefiling, oracle, falsification):
        values.extend(_raw_values(payload, *PROOF_ARTIFACT_INPUT_KEYS))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = _strip_line_suffix(value)
        lowered = cleaned.lower()
        if not cleaned or lowered in MISSING_VALUES or lowered in GENERIC_PROOF_SHELLS:
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*://", cleaned, re.IGNORECASE):
            continue
        if not PROOF_ARTIFACT_RE.search(cleaned):
            continue
        candidate = Path(cleaned).expanduser()
        try:
            resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
            resolved.relative_to(workspace)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            display = _display_path(resolved, workspace)
            if display not in seen:
                out.append(display)
                seen.add(display)
    return out[:MAX_REFS]


def _proof_signal_evidence(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for artifact, payload in _iter_named_payloads(row, prefiling, oracle, falsification):
        for key in PROOF_EVIDENCE_TEXT_KEYS:
            for text in _raw_values(payload, key):
                if PASS_EVIDENCE_RE.search(text):
                    evidence.append({"artifact": artifact, "field": key, "value": text[:240]})
    return evidence[:MAX_REFS]


def _proof_readiness(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
    state: str,
    blockers: list[str],
    workspace: Path | None = None,
) -> dict[str, Any]:
    claims = _explicit_proof_claims(row, prefiling, oracle, falsification)
    positive_claim = _has_positive_proof_claim(claims)
    source_refs, source_reasons = _current_workspace_source_refs(row, workspace)
    proof_artifacts = _existing_proof_artifacts(row, prefiling, oracle, falsification, workspace)
    proof_evidence = _proof_signal_evidence(row, prefiling, oracle, falsification)
    advisory_reasons = _advisory_only_reasons(row, prefiling, oracle, falsification)

    if state in LOCAL_BLOCKING_STATES:
        return {
            "state": "blocked",
            "claimed_positive_proof": positive_claim,
            "positive_claims": claims,
            "current_workspace_source_refs": source_refs,
            "proof_artifacts": proof_artifacts,
            "proof_evidence": proof_evidence,
            "typed_reasons": [f"blocked_candidate:{state}", *blockers[:MAX_BLOCKERS]][:MAX_BLOCKERS],
        }
    if advisory_reasons:
        return {
            "state": "advisory_only",
            "claimed_positive_proof": positive_claim,
            "positive_claims": claims,
            "current_workspace_source_refs": source_refs,
            "proof_artifacts": proof_artifacts,
            "proof_evidence": proof_evidence,
            "typed_reasons": advisory_reasons,
        }
    if not positive_claim:
        return {
            "state": "not_claimed",
            "claimed_positive_proof": False,
            "positive_claims": claims,
            "current_workspace_source_refs": source_refs,
            "proof_artifacts": proof_artifacts,
            "proof_evidence": proof_evidence,
            "typed_reasons": ["no_positive_proof_or_finalization_verdict"],
        }

    reasons: list[str] = []
    if not source_refs:
        reasons.extend(source_reasons or ["missing_current_workspace_source_ref"])
    if not proof_artifacts:
        reasons.append("missing_current_workspace_proof_artifact")
    if not proof_evidence:
        reasons.append("missing_concrete_reproduction_or_proof_evidence")
    return {
        "state": "not_proof_ready" if reasons else "proof_ready",
        "claimed_positive_proof": True,
        "positive_claims": claims,
        "current_workspace_source_refs": source_refs,
        "proof_artifacts": proof_artifacts,
        "proof_evidence": proof_evidence,
        "typed_reasons": reasons[:MAX_BLOCKERS],
    }


def _chain_d4_closure_gaps(row: dict[str, Any], workspace: Path | None = None) -> list[str]:
    if not row.get("chain_id"):
        return []
    gaps: list[str] = []
    if not _source_anchor_refs(row, workspace):
        gaps.append(CHAIN_D4_BLOCKERS[0])

    attacker = _first(row, "attacker_control", "attacker_actor", "attacker_role", "required_control").lower()
    if not has_chain_attacker_control_evidence(attacker):
        gaps.append(CHAIN_D4_BLOCKERS[1])

    generic_default = "run identical scenario without the bug path and confirm clean state"
    negative = _first(row, "negative_control", "required_control_test").lower()
    kills = row.get("kill_conditions")
    fals = row.get("falsification_requirements")
    clean_control = ""
    tt = row.get("truth_table_summary") if isinstance(row.get("truth_table_summary"), dict) else {}
    if isinstance(tt, dict):
        clean_control = _norm(tt.get("clean_control")).lower()
    has_control = bool(negative and negative not in MISSING_VALUES and negative != generic_default)
    has_control = has_control or (isinstance(kills, list) and any(_norm(item) for item in kills))
    has_control = has_control or (isinstance(fals, list) and any("control" in _norm(item).lower() for item in fals))
    has_control = has_control or bool(clean_control and clean_control not in MISSING_VALUES)
    if not has_control:
        gaps.append(CHAIN_D4_BLOCKERS[2])

    has_artifact = _has_existing_chain_proof_artifact(row, workspace)
    if not has_artifact:
        gaps.append(CHAIN_D4_BLOCKERS[3])
    return gaps


def _list_field(row: dict[str, Any], *keys: str, workspace: Path | None = None) -> list[str]:
    out: list[str] = []
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            out.extend(_norm(v) for v in value)
        elif value:
            out.append(_norm(value))
    return [_sanitize_local_paths(v, workspace) for v in out if v][:MAX_REFS]


def _rows_from_queue(
    payload: Any, *, workspace: Path | None = None, queue_path: Path | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    typed_entries: dict[str, dict[str, Any]] | None = None
    if "zero_day_proof_admission" in payload:
        if payload.get("entries") not in (None, []):
            raise ValueError("typed_proof_envelope_legacy_entries_present")
        if workspace is None or queue_path is None:
            raise ValueError("typed_proof_envelope_workspace_required")
        try:
            _load_typed_envelope_tool().verify_persisted(workspace, queue_path)
        except Exception as exc:
            raise ValueError(f"typed_proof_envelope_invalid:{exc}") from exc
        envelope = _load_typed_envelope_tool().build_envelope(payload)
        typed_entries = {
            entry["lead_id"]: entry
            for entry in envelope["entries"]
            if isinstance(entry, dict) and isinstance(entry.get("lead_id"), str)
        }
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    keys = ("queue",) if typed_entries is not None else ("queue", "entries", "rows")
    for key in keys:
        bucket = payload.get(key)
        if not isinstance(bucket, list):
            continue
        for row in bucket:
            if not isinstance(row, dict):
                continue
            lead_id = str(row.get("lead_id") or "").strip()
            if typed_entries is not None and lead_id not in typed_entries:
                raise ValueError("typed_proof_envelope_row_missing")
            if _is_terminal_queue_row(row):
                continue
            marker = id(row)
            if marker in seen:
                continue
            seen.add(marker)
            selected = dict(row)
            if typed_entries is not None:
                selected["zero_day_proof_envelope"] = typed_entries[lead_id]
            rows.append(selected)
    return rows


def _artifact_meta(path: Path | None, present: bool, row_count: int = 0, workspace: Path | None = None) -> dict[str, Any]:
    return {
        "path": _display_path(path, workspace),
        "present": bool(present),
        "row_count": row_count,
    }


def _prefiling_map(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("results")
    if isinstance(rows, list):
        return {
            str(row.get("candidate_id") or ""): row
            for row in rows
            if isinstance(row, dict) and row.get("candidate_id")
        }
    cid = payload.get("candidate_id")
    if cid:
        return {str(cid): payload}
    return {}


def _result_map(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}
    for key in ("results", "rows", "oracles", "falsification_results"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return {
                str(row.get("candidate_id") or row.get("lead_id") or row.get("id") or ""): row
                for row in rows
                if isinstance(row, dict) and (row.get("candidate_id") or row.get("lead_id") or row.get("id"))
            }
    cid = payload.get("candidate_id") or payload.get("lead_id") or payload.get("id")
    if cid:
        return {str(cid): payload}
    return {}


def _question_answer(prefiling: dict[str, Any], name: str) -> str:
    questions = prefiling.get("questions")
    if not isinstance(questions, dict):
        return ""
    q = questions.get(name)
    if isinstance(q, dict):
        return _first(q, "answer", "status")
    return _norm(q)


def _prior_status(prefiling: dict[str, Any]) -> str:
    questions = prefiling.get("questions")
    if isinstance(questions, dict):
        prior = questions.get("prior_disclosure")
        if isinstance(prior, dict):
            return _norm(prior.get("status")).lower()
    return ""


def _dupe_risk(row: dict[str, Any], oracle: dict[str, Any] | None = None) -> str:
    risks = [
        _first(row, "dupe_risk", "prior_disclosure_status").lower(),
        _first(oracle or {}, "dupe_risk", "prior_disclosure_status").lower(),
    ]
    for bad in ("known_dupe", "possible_dupe", "duplicate", "dupe", "not_checked", "high"):
        if bad in risks:
            return bad
    for risk in ("medium", "low", "clean"):
        if risk in risks:
            return risk
    return ""


def _prefiling_evidence_class(prefiling: dict[str, Any]) -> str:
    plan = prefiling.get("evidence_plan")
    if isinstance(plan, dict):
        req = plan.get("required_evidence_class")
        if isinstance(req, list):
            return "; ".join(_norm(v, limit=120) for v in req if _norm(v, limit=120))[:320]
        text = _norm(req)
        if text:
            return text
    return ""


def _required_evidence_class(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    workspace: Path | None = None,
) -> str:
    evidence_class = (
        _prefiling_evidence_class(prefiling)
        or _first(row, "required_evidence_class", "evidence_class", "required_proof_path", "proof_path")
        or _first(oracle, "required_proof_to_defend", "required_proof_upgrades")
    )
    return _sanitize_local_paths(evidence_class, workspace)


def _dupe_triple(row: dict[str, Any]) -> str:
    explicit = _first(row, "dupe_triple", "prior_disclosure_triple")
    if explicit and explicit.lower() not in STATUS_TRIPLE_VALUES:
        return explicit
    contract = _first(row, "contract", "contract_name", "production_path", "file_path", "source_path")
    function = _first(row, "function", "function_name", "function_signature", "entrypoint")
    attack_class = _first(row, "attack_class")
    if contract and function and attack_class:
        return f"contract={contract} | function={function} | attack_class={attack_class}"
    return ""


def _execution_window(row: dict[str, Any], workspace: Path | None = None) -> str:
    explicit = _first(row, "execution_window", "execution_environment", "execution_window_oos", "ordering_window")
    if explicit:
        return _sanitize_local_paths(explicit, workspace)
    text = _row_haystack(row)
    if WINDOW_CLAIM_RE.search(text):
        return ""
    refs = _source_refs(row, workspace)
    if refs:
        return f"NO_EXECUTION_WINDOW_RELEVANCE: no ordering/MEV/race keyword in candidate text; anchor={refs[0]}"
    return ""


def _field_anchor(
    field: str,
    row: dict[str, Any],
    prefiling: dict[str, Any],
    answer: str,
    workspace: Path | None = None,
) -> list[dict[str, str]]:
    if not answer:
        return []
    cid = _candidate_id(row)
    anchors: list[dict[str, str]] = []
    queue_key_map = {
        "permissionless_trigger": ("permissionless_action", "attacker_action", "trigger"),
        "admin_or_team_dependency": ("admin_or_team_dependency", "admin_dependency", "team_dependency"),
        "offchain_dependency": ("offchain_dependency", "offchain_oracle_dependency", "offchain_dependency_status"),
        "exact_rubric_row": ("rubric_row", "selected_impact", "severity_row"),
        "dupe_triple": ("dupe_triple", "prior_disclosure_triple", "contract", "function_name", "attack_class"),
        "economics_range": ("economics_range", "profit_loss", "affected_amount_basis", "market_cap_basis"),
        "capital_lock": ("capital_lock", "capital_lock_or_cost", "attacker_capital"),
        "gas_slippage_time_cost": ("gas_slippage_time_cost", "gas_cost", "slippage_cost", "time_cost"),
        "attacker_actor": ("attacker_actor", "attacker_role", "attacker_control"),
        "victim_actor": ("victim_actor", "victim_role", "asset_at_risk"),
        "official_source_url_or_hash": ("official_source_url_or_hash", "source_hash", "source_refs"),
        "execution_window": ("execution_window", "execution_environment", "execution_window_oos", "ordering_window"),
    }
    for key in queue_key_map.get(field, (field,)):
        if row.get(key):
            anchors.append({"artifact": "exploit_queue", "field": key, "candidate_id": cid})
            break
    if not anchors and prefiling:
        anchors.append({"artifact": "prefiling_stress_test", "field": field, "candidate_id": cid})
    refs = _source_refs(row, workspace)
    for ref in refs[:2]:
        anchors.append({"artifact": "source_ref", "field": field, "ref": ref})
    return anchors[:3]


def _field_answers(row: dict[str, Any], prefiling: dict[str, Any], workspace: Path | None = None) -> dict[str, str]:
    src_refs = _source_refs(row, workspace)
    prior = _prior_status(prefiling)
    dupe_risk = _dupe_risk(row)
    if not dupe_risk and prior:
        dupe_risk = prior

    admin_flags = ""
    questions = prefiling.get("questions") if isinstance(prefiling.get("questions"), dict) else {}
    priv = questions.get("privileged_or_mock_dependency") if isinstance(questions, dict) else None
    if isinstance(priv, dict):
        flags = priv.get("flags")
        status = _norm(priv.get("status"))
        admin_flags = "none_observed" if status == "pass" and not flags else _norm(flags or status)

    economics = questions.get("economics") if isinstance(questions, dict) else None
    econ_status = ""
    if isinstance(economics, dict):
        econ_status = _norm(economics.get("status"))

    fields = {
        "permissionless_trigger": _first(row, "permissionless_action", "attacker_action", "trigger")
        or _question_answer(prefiling, "permissionless_action"),
        "admin_or_team_dependency": _first(row, "admin_or_team_dependency", "admin_dependency", "team_dependency")
        or admin_flags
        or "not_assessed",
        "offchain_dependency": _first(row, "offchain_dependency", "offchain_oracle_dependency", "offchain_dependency_status")
        or "not_assessed",
        "exact_rubric_row": _first(row, "rubric_row", "selected_impact", "severity_row")
        or _question_answer(prefiling, "rubric_row"),
        "dupe_triple": _dupe_triple(row),
        "economics_range": _first(row, "economics_range", "profit_loss", "affected_amount_basis", "market_cap_basis")
        or ("prefiling_economics=pass" if econ_status == "pass" else ""),
        "capital_lock": _first(row, "capital_lock", "capital_lock_or_cost", "attacker_capital")
        or ("prefiling_economics=pass" if econ_status == "pass" else ""),
        "gas_slippage_time_cost": _first(row, "gas_slippage_time_cost", "gas_cost", "slippage_cost", "time_cost")
        or ("prefiling_economics=pass" if econ_status == "pass" else ""),
        "attacker_actor": _first(row, "attacker_actor", "attacker_role", "attacker_control"),
        "victim_actor": _first(row, "victim_actor", "victim_role", "asset_at_risk"),
        "official_source_url_or_hash": _first(row, "official_source_url_or_hash", "source_hash")
        or (src_refs[0] if src_refs else ""),
        "execution_window": _execution_window(row, workspace),
    }
    return {key: _sanitize_local_paths(value, workspace) for key, value in fields.items()}


def _row_haystack(row: dict[str, Any]) -> str:
    parts = []
    for key in (
        "title",
        "attack_class",
        "impact_path",
        "root_cause_hypothesis",
        "selected_impact",
        "rubric_row",
        "likely_triager_objection",
        "blockers",
        "tags",
        "shape_tags",
    ):
        parts.append(_norm(row.get(key), limit=500))
    return " ".join(parts)


def _is_explicit_non_proof_row(row: dict[str, Any]) -> bool:
    """Return whether the upstream queue explicitly excluded this row from proof.

    Coverage and completeness fuel can remain in the shared queue, but an
    explicit non-proof disposition is not an open exploit lead. It must remain
    visible in the packet artifact while being excluded from strict PoC
    authorization, otherwise coverage fuel falsely blocks every real lead.
    """
    status = _norm(row.get("proof_relevance_status")).lower()
    if status in {"skipped_non_proof", "non_proof", "not_proof_relevant"}:
        return True
    return row.get("proof_relevance") is False


def _missing_fields(row: dict[str, Any], fields: dict[str, str], prefiling: dict[str, Any]) -> list[str]:
    sev = _severity(row)
    if sev not in HIGH_PLUS:
        return []
    missing = []
    base_required = [
        "permissionless_trigger",
        "admin_or_team_dependency",
        "offchain_dependency",
        "exact_rubric_row",
        "dupe_triple",
        "attacker_actor",
        "victim_actor",
        "official_source_url_or_hash",
        "execution_window",
    ]
    for key in base_required:
        if str(fields.get(key, "")).strip().lower() in MISSING_VALUES:
            missing.append(key)

    text = _row_haystack(row)
    if VALUE_CLAIM_RE.search(text):
        questions = prefiling.get("questions") if isinstance(prefiling.get("questions"), dict) else {}
        econ = questions.get("economics") if isinstance(questions, dict) else None
        econ_missing = econ.get("missing_fields") if isinstance(econ, dict) else []
        for key in ("economics_range", "capital_lock", "gas_slippage_time_cost"):
            if str(fields.get(key, "")).strip().lower() in MISSING_VALUES:
                missing.append(key)
        if econ_missing:
            missing.extend(f"economics.{_norm(item, limit=80)}" for item in econ_missing[:4])

    blocked = prefiling.get("blocked_reasons")
    if isinstance(blocked, list):
        for reason in blocked:
            reason_s = _norm(reason, limit=120)
            if reason_s.startswith("missing_"):
                missing.append(f"prefiling.{reason_s}")

    out: list[str] = []
    seen: set[str] = set()
    for item in missing:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _packet_state(
    row: dict[str, Any],
    fields: dict[str, str],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
    workspace: Path | None = None,
) -> tuple[str, list[str]]:
    blockers: list[str] = []

    # Gate B: early prior-audit dedup - runs FIRST, before any draft/PoC work.
    # Kills candidates whose root cause is acknowledged in prior_audits/ or
    # SCOPE.md acknowledged-by-design clauses.  Fail-open: if the gate tool is
    # unavailable the packet proceeds normally (pre-submit R47/R53 still fire).
    _early_dedup = _early_prior_audit_blocker(row, workspace)
    if _early_dedup is not None:
        blockers.append(_early_dedup["blocker_code"])
        return "blocked_prior_disclosure", blockers[:MAX_BLOCKERS]

    scope_status = _norm(oracle.get("scope_status")).lower()
    fals_verdict = _norm(falsification.get("falsification_result") or falsification.get("verdict")).lower()
    dupe_risk = _dupe_risk(row, oracle)
    prior = _prior_status(prefiling)
    prefiling_verdict = _norm(prefiling.get("verdict")).lower()
    fals_blockers = []
    for key in ("open_blockers", "remaining_triager_questions", "required_negative_controls_missing"):
        value = falsification.get(key)
        if isinstance(value, list):
            fals_blockers.extend(_norm(item, limit=120) for item in value if _norm(item, limit=120))
        elif value:
            fals_blockers.append(_norm(value, limit=120))
    combined_text = " ".join(
        [
            _row_haystack(row),
            _norm(oracle.get("likely_triager_objections"), limit=800),
            _norm(oracle.get("required_proof_upgrades"), limit=800),
            _norm(prefiling.get("blocked_reasons"), limit=800),
            _norm(prefiling.get("warnings"), limit=800),
        ]
    ).lower()
    causal = _norm(row.get("causal_evidence_level") or row.get("impact_probe"), limit=300).lower()
    metadata_overlap_only_chain = bool(row.get("chain_id")) and (
        bool(row.get("metadata_overlap_only")) or "metadata" in causal or "unproven" in causal
    )

    if scope_status == "oos_risk" or fals_verdict == "not_in_scope":
        blockers.append("scope_status_oos_risk")
        return "blocked_by_scope", blockers[:MAX_BLOCKERS]
    if fals_verdict == "disproved":
        blockers.append("falsification_disproved")
        return "blocked_by_falsification", blockers[:MAX_BLOCKERS]
    if fals_verdict in {"needs_harness", "inconclusive"} and fals_blockers:
        blockers.extend(f"falsification:{blocker}" for blocker in fals_blockers[:MAX_BLOCKERS])
        return "blocked_weak_proof", blockers[:MAX_BLOCKERS]
    if dupe_risk in DUPE_BAD or prior in DUPE_BAD:
        blockers.append(f"duplicate_risk={dupe_risk or prior}")
        return "blocked_prior_disclosure", blockers[:MAX_BLOCKERS]
    if "intended actor" in combined_text or "wrong actor" in combined_text:
        blockers.append("intended_actor_mismatch")
        return "blocked_intended_actor_mismatch", blockers[:MAX_BLOCKERS]
    if re.search(r"\b(admin[- ]?gated|onlyowner|only owner|privileged|by[- ]design|documented design)\b", combined_text):
        blockers.append("admin_gated_or_by_design")
        return "blocked_admin_gated_or_by_design", blockers[:MAX_BLOCKERS]
    if re.search(r"\b(severity cap|capped at|low severity|medium severity|economically unviable|not economically viable)\b", combined_text):
        blockers.append("severity_cap_or_economics")
        return "blocked_severity_cap", blockers[:MAX_BLOCKERS]
    if re.search(r"\b(weak proof|mock-only|fixture-only|synthetic state|missing negative control|production path)\b", combined_text):
        blockers.append("weak_or_synthetic_proof")
        return "blocked_weak_proof", blockers[:MAX_BLOCKERS]
    if metadata_overlap_only_chain:
        blockers.append(CHAIN_METADATA_BLOCKER)
        return "blocked_weak_proof", blockers[:MAX_BLOCKERS]
    chain_d4_gaps = _chain_d4_closure_gaps(row, workspace)
    if chain_d4_gaps:
        blockers.extend(chain_d4_gaps[:MAX_BLOCKERS])
        return "blocked_weak_proof", blockers[:MAX_BLOCKERS]

    missing = _missing_fields(row, fields, prefiling)
    if missing:
        blockers.extend(f"missing:{item}" for item in missing)
        return "blocked_missing_truth", blockers[:MAX_BLOCKERS]

    econ_q = {}
    questions = prefiling.get("questions") if isinstance(prefiling.get("questions"), dict) else {}
    if isinstance(questions, dict) and isinstance(questions.get("economics"), dict):
        econ_q = questions["economics"]
    if _norm(econ_q.get("status")).lower() == "fail":
        blockers.append("economics_question_failed")
        return "blocked_by_economics", blockers[:MAX_BLOCKERS]

    if prefiling_verdict == "fail":
        blockers.extend(_norm(item, limit=120) for item in prefiling.get("blocked_reasons", [])[:MAX_BLOCKERS])
        return "blocked_missing_truth", blockers[:MAX_BLOCKERS]

    return "ready_for_poc_planning", []


def _local_verdict(state: str) -> str:
    if state == "ready_for_poc_planning":
        return "ready_for_poc_planning"
    if state in LOCAL_BLOCKING_STATES:
        return "blocked_before_poc"
    return "needs_local_judgment"


def _worker_receipts(
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    workspace: Path | None = None,
) -> dict[str, Any]:
    no_lesson_pack_reasons = _list_field(
        row,
        "no_lesson_pack_reason",
        "no_lesson_pack_reasons",
        "lesson_pack_skip_reason",
        "lesson_pack_skip_reasons",
        workspace=workspace,
    )
    typed_no_lesson_pack_reasons = [
        reason for reason in no_lesson_pack_reasons if reason.startswith(NO_LESSON_PACK_REASON_PREFIX)
    ][:MAX_REFS]
    # Source-mined rows have already passed the source-artifact producer and
    # carry current file/line citations.  Treat that exact, bounded evidence as
    # a typed primary-source receipt when no separate lesson pack exists.  This
    # removes a workflow-order false block without making any exploitability or
    # promotion claim.
    if (
        not typed_no_lesson_pack_reasons
        and not no_lesson_pack_reasons
        and bool(row.get("source_artifacts_complete"))
        and _source_refs(row, workspace)
    ):
        typed_no_lesson_pack_reasons = [
            "NO_LESSON_PACK_REASON: source-mined artifact with current source citations is the primary read receipt"
        ]
    return {
        "mcp_context_ids": _list_field(row, "mcp_context_ids", "mcp_context_id", workspace=workspace),
        "lesson_pack_refs": _list_field(row, "lesson_pack_refs", "lesson_source_refs", "outcome_lesson_refs", workspace=workspace),
        "pre_source_read_receipts": _list_field(row, "pre_source_read_receipts", "source_read_receipts", workspace=workspace),
        "typed_no_lesson_pack_reasons": typed_no_lesson_pack_reasons,
        "invalid_no_lesson_pack_reasons": [
            reason for reason in no_lesson_pack_reasons if reason not in typed_no_lesson_pack_reasons
        ][:MAX_REFS],
        "prefiling_artifact_present": bool(prefiling),
        "severity_oracle_artifact_present": bool(oracle),
    }


def _packet(
    index: int,
    row: dict[str, Any],
    prefiling: dict[str, Any],
    oracle: dict[str, Any],
    falsification: dict[str, Any],
    workspace: Path | None = None,
) -> dict[str, Any]:
    fields = _field_answers(row, prefiling, workspace)
    state, blockers = _packet_state(row, fields, prefiling, oracle, falsification, workspace)
    verdict = _local_verdict(state)
    fields = {**fields, "verdict": verdict}
    anchors = {
        field: _field_anchor(field, row, prefiling, fields.get(field, ""), workspace)
        for field in REQUIRED_FIELDS
    }
    cid = _candidate_id(row)
    evidence_class = _required_evidence_class(row, prefiling, oracle, workspace)
    worker_receipts = _worker_receipts(row, prefiling, oracle, workspace)
    if _severity(row) in HIGH_PLUS and not evidence_class:
        blockers = [*blockers, "missing:required_evidence_class"][:MAX_BLOCKERS]
        if state == "ready_for_poc_planning":
            state = "blocked_missing_truth"
            verdict = _local_verdict(state)
            fields["verdict"] = verdict
    if _severity(row) in HIGH_PLUS and not (
        worker_receipts["lesson_pack_refs"]
        or worker_receipts["pre_source_read_receipts"]
        or worker_receipts["typed_no_lesson_pack_reasons"]
    ):
        worker_receipts["missing_worker_receipt_warning"] = True
        if "missing:lesson_pack_or_source_read_receipt" not in blockers:
            blockers = [*blockers, "missing:lesson_pack_or_source_read_receipt"][:MAX_BLOCKERS]
        if state == "ready_for_poc_planning":
            state = "blocked_missing_truth"
            verdict = _local_verdict(state)
            fields["verdict"] = verdict
    proof_readiness = _proof_readiness(row, prefiling, oracle, falsification, state, blockers, workspace)
    if state == "ready_for_poc_planning" and proof_readiness["state"] == "not_proof_ready":
        proof_blockers = [f"proof_readiness:{reason}" for reason in proof_readiness["typed_reasons"]]
        blockers = [*blockers, *proof_blockers][:MAX_BLOCKERS]
        state = "blocked_weak_proof"
        verdict = _local_verdict(state)
        fields["verdict"] = verdict
    next_action = {
        "ready_for_poc_planning": "Use this packet to select the narrow PoC proof class; it is not submission readiness.",
        "blocked_by_scope": "Resolve scope/OOS evidence before PoC spend.",
        "blocked_by_dupe": "Write a concrete duplicate/originality distinction before PoC spend.",
        "blocked_by_falsification": "Treat the candidate as killed unless a new production path invalidates the falsification.",
        "blocked_by_economics": "Quantify realistic economics, costs, and victim loss before PoC spend.",
        "blocked_missing_truth": "Fill missing local judgment fields before assigning harness work.",
        "blocked_intended_actor_mismatch": "Prove the intended victim/actor mismatch is real or kill the candidate.",
        "blocked_admin_gated_or_by_design": "Prove a non-privileged path distinct from documented/admin-gated design.",
        "blocked_severity_cap": "Downgrade, quantify economics, or prove the higher impact row.",
        "blocked_weak_proof": "Replace weak/synthetic proof with production-path evidence and negative controls.",
        "blocked_prior_disclosure": "Write a concrete contract/function/attack-class duplicate distinction.",
        "needs_local_judgment": "Run prefiling stress and local judgment before PoC spend.",
    }.get(state, "Review packet state before proceeding.")

    packet = {
        "packet_id": f"CJP-{index:03d}",
        "candidate_id": cid,
        "title": _sanitize_local_paths(_first(row, "title") or cid, workspace),
        "attack_class": _sanitize_local_paths(_first(row, "attack_class"), workspace),
        "severity_claim": _severity(row),
        "priority_score": row.get("priority_score"),
        "source_refs": _source_refs(row, workspace),
        "verdict": verdict,
        "required_evidence_class": evidence_class,
        "required_judgment_fields": fields,
        "field_source_anchors": anchors,
        "judgment_inputs": {
            "prefiling_verdict": _norm(prefiling.get("verdict")),
            "scope_status": _norm(oracle.get("scope_status")),
            "dupe_risk": _dupe_risk(row, oracle) or _prior_status(prefiling),
            "falsification_verdict": _norm(falsification.get("falsification_result") or falsification.get("verdict")),
            "oracle_selected_severity": _norm(oracle.get("selected_severity")),
            "required_evidence_class": evidence_class,
        },
        "worker_receipts": worker_receipts,
        "packet_state": state,
        "proof_readiness": proof_readiness,
        "promotion_blockers": blockers,
        "next_action": next_action,
        "impact_enumeration": _impact_enumeration(row, workspace),
    }
    typed_envelope = row.get("zero_day_proof_envelope")
    if isinstance(typed_envelope, dict):
        packet["zero_day_proof_envelope"] = typed_envelope
    return packet


def _default_queue(workspace: Path) -> tuple[Path, str | None]:
    canonical = workspace / ".auditooor" / "exploit_queue.json"
    source_mined = workspace / ".auditooor" / "exploit_queue.source_mined.json"
    canonical_exists = canonical.is_file()
    source_exists = source_mined.is_file()

    if canonical_exists and source_exists:
        try:
            canonical_mtime = canonical.stat().st_mtime
            source_mtime = source_mined.stat().st_mtime
        except OSError:
            canonical_mtime = 0.0
            source_mtime = 0.0
        if canonical_mtime >= source_mtime:
            return canonical, (
                "default_queue_selection:canonical_preferred;"
                "exploit_queue.source_mined.json_ignored_as_stale_or_equal_age"
            )
        return source_mined, None
    if canonical_exists:
        return canonical, None
    if source_exists:
        return source_mined, None
    return canonical, None


def build_packet(
    workspace: Path,
    *,
    queue_path: Path | None = None,
    prefiling_path: Path | None = None,
    oracle_path: Path | None = None,
    falsification_path: Path | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    queue_selection_diagnostic: str | None = None
    if queue_path:
        queue_path = queue_path.expanduser().resolve()
    else:
        queue_path, queue_selection_diagnostic = _default_queue(workspace)
    prefiling_path = prefiling_path.expanduser().resolve() if prefiling_path else workspace / ".auditooor" / "prefiling_stress_test.json"
    oracle_path = oracle_path.expanduser().resolve() if oracle_path else workspace / ".auditooor" / "exploit_severity_scope_oracle.json"
    falsification_path = falsification_path.expanduser().resolve() if falsification_path else workspace / ".auditooor" / "poc_falsification_runner.json"

    queue_payload = _read_json(queue_path) if queue_path.is_file() else None
    prefiling_payload = _read_json(prefiling_path) if prefiling_path.is_file() else None
    oracle_payload = _read_json(oracle_path) if oracle_path.is_file() else None
    fals_payload = _read_json(falsification_path) if falsification_path.is_file() else None

    rows = _rows_from_queue(
        queue_payload, workspace=workspace, queue_path=queue_path,
    )
    prefilings = _prefiling_map(prefiling_payload)
    oracles = _result_map(oracle_payload)
    falsifications = _result_map(fals_payload)

    packets = [
        _packet(
            i,
            row,
            prefilings.get(_candidate_id(row), {}),
            oracles.get(_candidate_id(row), {}),
            falsifications.get(_candidate_id(row), {}),
            workspace,
        )
        for i, row in enumerate(rows, 1)
    ]
    states = Counter(p["packet_state"] for p in packets)
    proof_states = Counter(
        p.get("proof_readiness", {}).get("state", "unknown")
        for p in packets
    )
    missing_count = sum(
        1
        for packet in packets
        for value in packet["promotion_blockers"]
        if str(value).startswith("missing:")
    )
    local_blocked_packets = [
        {
            "packet_id": packet["packet_id"],
            "candidate_id": packet["candidate_id"],
            "severity_claim": packet.get("severity_claim", "unknown"),
            "packet_state": packet["packet_state"],
            "promotion_blockers": packet["promotion_blockers"][:MAX_BLOCKERS],
        }
        for packet in packets
        if packet["packet_state"] in LOCAL_BLOCKING_STATES
    ]
    local_blocked_ids = {packet["candidate_id"] for packet in local_blocked_packets}
    strict_blocked_packets = [
        packet
        for row, packet in zip(rows, packets)
        if packet["candidate_id"] in local_blocked_ids
        and str(packet.get("severity_claim") or "").strip().lower() in HIGH_PLUS
        and not _is_explicit_non_proof_row(row)
    ]
    strict_excluded_non_proof_count = sum(
        1
        for row, packet in zip(rows, packets)
        if packet["packet_state"] in LOCAL_BLOCKING_STATES
        and str(packet.get("severity_claim") or "").strip().lower() in HIGH_PLUS
        and _is_explicit_non_proof_row(row)
    )
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": workspace.name,
        "source_artifacts": {
            "exploit_queue": {
                **_artifact_meta(queue_path, queue_path.is_file(), len(rows), workspace),
                **({"selection_diagnostic": queue_selection_diagnostic} if queue_selection_diagnostic else {}),
            },
            "prefiling_stress_test": _artifact_meta(prefiling_path, prefiling_path.is_file(), len(prefilings), workspace),
            "severity_oracle": _artifact_meta(oracle_path, oracle_path.is_file(), len(oracles), workspace),
            "falsification": _artifact_meta(falsification_path, falsification_path.is_file(), len(falsifications), workspace),
        },
        "summary": {
            "queue_rows_seen": len(rows),
            "packets_emitted": len(packets),
            "by_packet_state": dict(sorted(states.items())),
            "by_proof_readiness_state": dict(sorted(proof_states.items())),
            "missing_required_truth_count": missing_count,
            "local_blocked_packet_count": len(local_blocked_packets),
            "blocked_before_poc_count": len(strict_blocked_packets),
            "strict_excluded_non_proof_count": strict_excluded_non_proof_count,
            "ready_for_poc_planning_count": states.get("ready_for_poc_planning", 0),
            "proof_ready_count": proof_states.get("proof_ready", 0),
            "proof_not_ready_count": proof_states.get("not_proof_ready", 0),
            "typed_proof_envelope_packet_count": sum(
                1 for packet in packets if isinstance(packet.get("zero_day_proof_envelope"), dict)
            ),
            "strict_poc_planning_allowed": not strict_blocked_packets,
        },
        "strict_blockers": strict_blocked_packets[:MAX_BLOCKERS],
        "local_blockers": local_blocked_packets[:MAX_BLOCKERS],
        "packets": packets,
        "advisory_only": True,
        "promotion_authority": False,
        "network_used": False,
        "proof_boundary": (
            "This packet aggregates local judgment evidence only. It does not prove exploitability, "
            "assign final severity, clear duplicate/OOS risk, or make a submission ready."
        ),
    }


def render_md(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# Candidate Judgment Packet",
        "",
        f"- Workspace: `{payload.get('workspace', '')}`",
        f"- Packets: {summary.get('packets_emitted', 0)}",
        f"- Missing required truth fields: {summary.get('missing_required_truth_count', 0)}",
        f"- Advisory only: {payload.get('advisory_only')}",
        "",
        "## State Summary",
    ]
    states = summary.get("by_packet_state") if isinstance(summary.get("by_packet_state"), dict) else {}
    if states:
        for state, count in sorted(states.items()):
            lines.append(f"- `{state}`: {count}")
    else:
        lines.append("- No queue rows found.")
    lines.extend(["", "## Packets"])
    for packet in payload.get("packets", []):
        lines.append(f"### {packet.get('packet_id')} - {packet.get('candidate_id')}")
        lines.append(f"- Title: {packet.get('title')}")
        lines.append(f"- State: `{packet.get('packet_state')}`")
        proof_readiness = packet.get("proof_readiness") if isinstance(packet.get("proof_readiness"), dict) else {}
        lines.append(f"- Proof readiness: `{proof_readiness.get('state', 'unknown')}`")
        proof_reasons = proof_readiness.get("typed_reasons") if isinstance(proof_readiness.get("typed_reasons"), list) else []
        if proof_reasons and proof_readiness.get("state") != "proof_ready":
            lines.append("- Proof readiness reasons:")
            for reason in proof_reasons[:MAX_BLOCKERS]:
                lines.append(f"  - `{reason}`")
        lines.append(f"- Severity claim: `{packet.get('severity_claim')}`")
        if packet.get("promotion_blockers"):
            lines.append("- Blockers:")
            for blocker in packet["promotion_blockers"][:MAX_BLOCKERS]:
                lines.append(f"  - `{blocker}`")
        lines.append(f"- Next action: {packet.get('next_action')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path)
    parser.add_argument("--prefiling", type=Path)
    parser.add_argument("--severity-oracle", type=Path)
    parser.add_argument("--falsification", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any packet is blocked before PoC.")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    payload = build_packet(
        workspace,
        queue_path=args.queue,
        prefiling_path=args.prefiling,
        oracle_path=args.severity_oracle,
        falsification_path=args.falsification,
    )
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / ".auditooor" / "candidate_judgment_packet.json"
    out_md = args.out_md.expanduser().resolve() if args.out_md else workspace / ".auditooor" / "candidate_judgment_packet.md"
    payload["artifact_path"] = _display_path(out_json, workspace)
    payload["markdown_path"] = _display_path(out_md, workspace)
    _write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_md(payload), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[candidate-judgment-packet] wrote {_display_path(out_json, workspace)}")
        print(f"[candidate-judgment-packet] wrote {_display_path(out_md, workspace)}")
    if args.strict and payload["summary"]["blocked_before_poc_count"]:
        print(
            "[candidate-judgment-packet] STRICT blocked "
            f"{payload['summary']['blocked_before_poc_count']} packet(s) before PoC; see {_display_path(out_json, workspace)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
