#!/usr/bin/env python3
"""Evaluate draft/workspace text against compiled outcome lesson predicates.

This gate is deterministic and offline-only. It consumes the predicate catalog
from prose-to-lesson-compiler.py and, when provided, the JSON inventory emitted
by lesson-enforcement-inventory.py. It never claims exploitability, severity
correctness, reward eligibility, or submission readiness.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = Path(__file__).resolve().with_name("prose-to-lesson-compiler.py")
SCHEMA = "auditooor.outcome_lesson_gate.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"
DEFAULT_MAX_CHARS = 200_000
DEFAULT_MAX_MATCHES = 32
DEFAULT_MAX_FILES = 40
MAX_SNIPPET_CHARS = 220
SUPPORTED_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt", ".text"}
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
CANDIDATE_FIELDS = (
    "attacker_role",
    "prerequisites",
    "impact_claim",
    "evidence_class",
    "production_path",
    "economics",
    "oos_flags",
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
    "lesson_pack_refs",
    "lesson_source_refs",
    "outcome_lesson_refs",
    "lesson_refs",
    "matched_lessons",
    "case_study_refs",
    "proof_relevance",
    "proof_relevance_status",
    "proof_relevance_skip_reasons",
    "proof_relevant",
    "proof_work",
    "proof_status",
    "source_mined_proof_status",
    "quality_gate_status",
    "learning_route",
    "recommended_next_step",
    "proof_verdict",
    "proof_claim",
    "proof_path",
    "proof_file",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "harness_command",
    "gating_test",
    "forge_run",
    "execution_contract",
    "reproduction",
    "reproduction_command",
    "repro_command",
    "commands_to_reproduce",
    "exact_proof_command",
    "advisory_only",
    "status",
    "state",
    "verdict",
)
CANDIDATE_CONTAINER_KEYS = (
    "candidates",
    "candidate_rows",
    "leads",
    "queue",
    "rows",
    "items",
)


PROOF_OBLIGATIONS = {
    "economic_viability_missing": [
        "Provide a concrete attacker-profit model with capital, fees/gas, liquidity, and extractable value.",
        "Add a negative-control case showing the path is not unprofitable under realistic execution costs.",
    ],
    "future_reward_eligibility_not_accrued_reward_loss": [
        "Identify reward funding time, entrant deposit time, and the intended eligibility boundary.",
        "Show a before/after accounting delta proving rewards accrued before entry were diluted or stolen.",
    ],
    "intended_actor_mismatch": [
        "Bind the exploit actor to the actual protocol-authorized caller or role.",
        "Show the path is reachable by the reported actor without assuming capabilities they do not have.",
    ],
    "ambient_mev_not_protocol_bug": [
        "Prove a protocol invariant violation independent of ordinary mempool ordering, arbitrage, or sandwich behavior.",
        "Separate the protocol fault from ambient market/MEV activity in the impact narrative.",
    ],
    "protocol_bug_amplified_by_mev": [
        "Preserve the protocol root cause and describe MEV only as an amplifier.",
        "Show the underlying contract/protocol fault exists before any MEV-specific ordering advantage.",
    ],
    "documented_mechanics_no_stronger_intent": [
        "Cite implementation/docs and prove a stronger invariant than the documented mechanics alone.",
        "Explain why the observed behavior is not merely expected or by-design behavior.",
    ],
    "low_severity_cap_triggered": [
        "Quantify the maximum impact and align the severity claim with the deterministic cap.",
        "Remove High/Critical framing unless there is proof of material loss beyond the capped impact.",
    ],
    "admin_or_team_action_prerequisite": [
        "Show the path is reachable without privileged admin, team, owner, multisig, or governance action.",
        "If a privileged step is required, prove it is routine/unavoidable and not a trusted-party prerequisite.",
    ],
    "generic_dos_scope_risk": [
        "Prove specific in-scope protocol impact beyond generic DoS, gas griefing, or temporary service degradation.",
        "Bound duration, affected assets/users, and recovery conditions with local evidence.",
    ],
}

SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
)
LESSON_LINKAGE_KEYS = (
    "lesson_pack_refs",
    "lesson_source_refs",
    "outcome_lesson_refs",
    "lesson_refs",
    "matched_lessons",
    "case_study_refs",
)
REPRODUCTION_PATH_KEYS = (
    "proof_file",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "proof_path",
)
REPRODUCTION_COMMAND_KEYS = (
    "harness_command",
    "gating_test",
    "reproduction",
    "reproduction_command",
    "repro_command",
    "commands_to_reproduce",
    "exact_proof_command",
)
PROOF_STATUS_KEYS = (
    "status",
    "state",
    "verdict",
    "proof_status",
    "source_mined_proof_status",
    "quality_gate_status",
    "learning_route",
    "recommended_next_step",
    "proof_verdict",
    "proof_claim",
    "evidence_class",
)
PROOF_BLOCKER_OBLIGATIONS = {
    "missing_source_backed_lesson_linkage": [
        "Attach at least one lesson reference backed by a source path, vault ref, URL, or case-study citation.",
        "Keep proof work advisory until the lesson link can be traced to reviewed source material.",
    ],
    "missing_source_refs": [
        "Add source_refs or file_line entries that point at the current workspace source.",
        "Do not start proof work from provider-only or prose-only candidate text.",
    ],
    "stale_workspace_source_refs": [
        "Refresh source_refs so at least one cited file and line resolves in the current workspace.",
        "Re-mine the candidate if all cited files are missing, outside the workspace, or out of date.",
    ],
    "workspace_context_unavailable": [
        "Run the gate with --workspace or store the queue under <workspace>/.auditooor/ so source refs can be resolved.",
        "Do not treat unresolved source refs as current source evidence.",
    ],
    "proof_without_runnable_harness_evidence": [
        "Attach a concrete reproduction artifact such as an existing PoC file, runnable harness contract, or passing forge_run.",
        "Keep the row advisory until exploit and control evidence are available.",
    ],
    "advisory_only_row": [
        "Leave advisory-only candidates out of proof execution queues.",
        "Promote the row out of advisory status only after source refs, lesson linkage, and reproduction evidence are concrete.",
    ],
}
TERMINAL_NON_PROOF_STATUS_TOKENS = {
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
    "not_candidate",
    "advisory_not_candidate",
}
SOURCE_REF_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./~:@%+,\-]+?\.(?:sol|vy|go|rs|move|cairo|ts|tsx|js|jsx|py|md))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)


def _load_compiler():
    spec = importlib.util.spec_from_file_location("prose_to_lesson_compiler_for_gate", COMPILER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compiler from {COMPILER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _clean_ws(text: str) -> str:
    return " ".join(str(text or "").split())


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


ADMIN_RE = _rx(r"\b(admin|owner|governance|team|multisig|privileged|trusted\s+party|onlyowner|only\s+owner)\b")
ADMIN_NEGATION_RE = _rx(
    r"\b(no|without|does\s+not\s+require|not\s+required|permissionless|non[-\s]?privileged)\b.{0,50}"
    r"\b(admin|owner|governance|team|multisig|privileged)\b"
)
ECONOMIC_IMPACT_RE = _rx(
    r"\b(profit|loss|loses?|drain|theft|steal|extract(?:able|ed|ion)?|funds?|value|bad\s+debt|"
    r"liquidat(?:e|ion)|arbitrage|fees?|revenue|pnl)\b"
)
ECONOMICS_PRESENT_RE = _rx(r"\b(profit|capital|gas|fee|liquidity|value|ev|pnl|roi|cost)\b")
ECONOMICS_MISSING_RE = _rx(
    r"\b(missing|unknown|unmodeled|not\s+modeled|todo|tbd|n/?a|none|null|"
    r"unprofitable|negative\s+ev|cost\s+exceeds|gas\s+exceeds|not\s+economically\s+viable)\b"
)
DOCUMENTED_MECHANICS_RE = _rx(
    r"\b(documented|docs?|by\s+design|intended\s+behavior|expected\s+behavior|documented\s+mechanics?)\b"
)
INTENT_DELTA_RE = _rx(r"\b(intent\s+delta|unintended|invariant\s+break|stronger\s+intent|protocol\s+fault)\b")
FRONTRUN_ONLY_RE = _rx(
    r"\b(front[-\s]?run|frontrun|sandwich|back[-\s]?run|mempool|ambient\s+mev|ordinary\s+mev)\b"
    r".{0,80}\b(only|alone|external|ambient|oos|out\s+of\s+scope)\b|"
    r"\b(front[-\s]?run|frontrun|sandwich|back[-\s]?run)_?only\b"
)
LOW_SEVERITY_RE = _rx(
    r"\b(low|informational|info)\b.{0,45}\b(cap|severity|only)\b|"
    r"\b(dust\s+only|no\s+funds?\s+at\s+risk|no\s+material\s+loss|bounded\s+impact|limited\s+impact|"
    r"low[-_\s]?severity[-_\s]?cap)\b"
)


def _bounded_snippet(compiler: Any, text: str) -> tuple[str, int]:
    sanitized, suppressed = compiler.sanitize_for_output(str(text or ""))
    snippet = _clean_ws(sanitized)
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[: MAX_SNIPPET_CHARS - 3].rstrip() + "..."
    return snippet, suppressed


def _catalog_levels(compiler: Any) -> dict[str, str]:
    return {spec.key: spec.enforcement_level for spec in compiler.PREDICATES}


def _predicate_gate_phase(compiler: Any, predicate: str) -> str | None:
    spec = getattr(compiler, "PREDICATE_BY_KEY", {}).get(predicate)
    return getattr(spec, "gate_phase", None) if spec is not None else None


def load_inventory(path: Path | None, compiler: Any) -> tuple[dict[str, str], dict[str, Any], list[str]]:
    """Return active predicate -> enforcement level from inventory or catalog."""
    catalog = _catalog_levels(compiler)
    if path is None:
        return dict(catalog), {"source": "compiler_catalog", "path": None}, []

    inventory_path = path.expanduser().resolve()
    warnings: list[str] = []
    try:
        payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - malformed local JSON should become a gate error.
        warnings = [f"inventory load failed; no explicit lesson predicates active: {exc}"]
        return {}, {
            "source": "inventory_load_failed",
            "path": str(inventory_path),
            "load_error": str(exc),
            "warnings": warnings,
        }, warnings
    if not isinstance(payload, dict):
        warnings = [
            f"inventory has invalid JSON shape {type(payload).__name__}; no explicit lesson predicates active"
        ]
        return {}, {
            "source": "inventory_invalid_shape",
            "path": str(inventory_path),
            "load_error": f"expected object, got {type(payload).__name__}",
            "warnings": warnings,
        }, warnings

    active: dict[str, str] = {}
    for row in payload.get("enforcement_rows") or []:
        if not isinstance(row, dict):
            continue
        predicate = str(row.get("predicate") or "")
        level = str(row.get("enforcement_level") or "")
        if predicate and level:
            active[predicate] = level
    for row in payload.get("lessons") or []:
        if not isinstance(row, dict):
            continue
        predicate = str(row.get("predicate") or "")
        level = str(row.get("enforcement_level") or "")
        if predicate and level and predicate not in active:
            active[predicate] = level

    if not active:
        warnings.append("inventory contained no predicates; no explicit lesson predicates active")

    return active, {
        "source": "lesson_enforcement_inventory",
        "path": str(inventory_path),
        "schema": payload.get("schema"),
        "schema_version": payload.get("schema_version"),
        "offline_only": bool(payload.get("offline_only")),
        "network_access": bool(payload.get("network_access")),
        "predicate_count": len(active),
        "warnings": warnings,
    }, warnings


def load_source_inventory(path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Load lesson-source coverage metadata.

    Source inventory warnings are advisory for a single draft: they indicate
    unpromoted lesson-bearing sources, not a proven flaw in the current report.
    V3 roadmap accounting treats them as completion blockers.
    """
    if path is None:
        return {"source": "not_provided", "path": None}, [], []
    inventory_path = path.expanduser().resolve()
    try:
        payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - malformed local JSON becomes a helper warning.
        return {"source": "lesson_source_inventory", "path": str(inventory_path)}, [], [
            f"source inventory load failed: {exc}"
        ]
    blockers = [row for row in payload.get("coverage_blockers") or [] if isinstance(row, dict)]
    warnings = [
        {
            "code": "lesson_source_requires_promotion_review",
            "source_kind": str(row.get("source_kind") or "unknown"),
            "path": str(row.get("path") or ""),
            "lesson_candidates": int(row.get("lesson_candidates") or 0),
            "admissibility": str(row.get("admissibility") or ""),
            "gate_role": str(row.get("gate_role") or ""),
            "reason": str(row.get("reason") or ""),
        }
        for row in blockers
    ]
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "source": "lesson_source_inventory",
        "path": str(inventory_path),
        "schema": payload.get("schema"),
        "schema_version": payload.get("schema_version"),
        "status": payload.get("status"),
        "coverage_blocker_count": len(blockers),
        "sources_seen": summary.get("sources_seen", 0),
        "default_enforcement_sources": summary.get("default_enforcement_sources", 0),
        "promotion_candidate_sources": summary.get("promotion_candidate_sources", 0),
    }, warnings, []


def _flatten_candidate_value(value: Any, *, key_hint: str = "") -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return key_hint if value and key_hint else str(value).lower()
    if isinstance(value, (int, float)):
        return f"{key_hint}={value}" if key_hint else str(value)
    if isinstance(value, list):
        return " ".join(filter(None, (_flatten_candidate_value(item, key_hint=key_hint) for item in value)))
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            key_text = str(key)
            flattened = _flatten_candidate_value(item, key_hint=key_text)
            if flattened:
                parts.append(flattened if key_text in flattened else f"{key_text}: {flattened}")
        return " ".join(parts)
    return str(value)


def _candidate_field_text(candidate: dict[str, Any], *keys: str) -> str:
    return _clean_ws(" ".join(_flatten_candidate_value(candidate.get(key), key_hint=key) for key in keys))


def _candidate_value_is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip().lower()
        return not stripped or stripped in {"unknown", "missing", "none", "null", "n/a", "na", "todo", "tbd"}
    if isinstance(value, (list, tuple, set)):
        return not value or all(_candidate_value_is_missing(item) for item in value)
    if isinstance(value, dict):
        return not value or all(_candidate_value_is_missing(item) for item in value.values())
    return False


def _candidate_has_economic_model(value: Any) -> bool:
    if _candidate_value_is_missing(value):
        return False
    text = _flatten_candidate_value(value)
    if ECONOMICS_MISSING_RE.search(text):
        return False
    return bool(ECONOMICS_PRESENT_RE.search(text))


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "proof", "proof_relevant"}
    return False


def _falsey(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value.strip().lower() in {"0", "false", "no", "n", "non_proof", "not_proof"}
    return False


def _candidate_texts(candidate: dict[str, Any], keys: Sequence[str]) -> list[str]:
    texts: list[str] = []
    for key in keys:
        value = candidate.get(key)
        if isinstance(value, list):
            for item in value:
                flattened = _flatten_candidate_value(item, key_hint=key)
                if flattened:
                    texts.append(flattened)
        else:
            flattened = _flatten_candidate_value(value, key_hint=key)
            if flattened:
                texts.append(flattened)
    return texts


def _clean_ref_text(ref: str) -> str:
    return str(ref or "").strip().strip("`'\"()[]{}<>,.;")


def _candidate_ref_values(candidate: dict[str, Any], keys: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    refs: list[str] = []
    for text in _candidate_texts(candidate, keys):
        for part in re.split(r"[\n\r\t ]+", text):
            clean = _clean_ref_text(part)
            if clean and clean not in seen:
                seen.add(clean)
                refs.append(clean)
    return refs


def _parse_source_ref(ref: str) -> tuple[str, int | None] | None:
    if ref.startswith(("http://", "https://", "vault://")):
        return None
    match = SOURCE_REF_RE.search(ref)
    if not match:
        return None
    line = int(match.group("line")) if match.group("line") else None
    return match.group("path"), line


def _path_inside_workspace(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=False)
        root = workspace.expanduser().resolve(strict=False)
        return resolved == root or root in resolved.parents
    except OSError:
        return False


def _resolve_workspace_source_ref(workspace: Path, ref: str) -> dict[str, Any]:
    parsed = _parse_source_ref(ref)
    if parsed is None:
        return {
            "ref": ref,
            "current": False,
            "reason": "not_a_workspace_source_ref",
            "path": "",
            "line": None,
        }
    path_text, line = parsed
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = workspace / path
    if not _path_inside_workspace(path, workspace):
        return {
            "ref": ref,
            "current": False,
            "reason": "outside_workspace",
            "path": str(path),
            "line": line,
        }
    try:
        resolved = path.resolve(strict=False)
        if not resolved.is_file():
            return {
                "ref": ref,
                "current": False,
                "reason": "source_file_missing",
                "path": str(path),
                "line": line,
            }
        if line is not None:
            line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
            if line < 1 or line > line_count:
                return {
                    "ref": ref,
                    "current": False,
                    "reason": "source_line_missing",
                    "path": str(resolved),
                    "line": line,
                }
    except OSError as exc:
        return {
            "ref": ref,
            "current": False,
            "reason": f"source_ref_error:{exc.__class__.__name__}",
            "path": str(path),
            "line": line,
        }
    return {
        "ref": ref,
        "current": True,
        "reason": "current_workspace_source_ref",
        "path": str(resolved),
        "line": line,
    }


def _candidate_source_ref_status(candidate: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    refs = _candidate_ref_values(candidate, SOURCE_REF_KEYS)
    if workspace is None:
        return {
            "raw_refs": refs,
            "resolved_refs": [],
            "current_refs": [],
            "stale_refs": [],
            "workspace_available": False,
        }
    resolved = [_resolve_workspace_source_ref(workspace, ref) for ref in refs]
    current = [item for item in resolved if item["current"]]
    stale = [item for item in resolved if not item["current"]]
    return {
        "raw_refs": refs,
        "resolved_refs": resolved,
        "current_refs": current,
        "stale_refs": stale,
        "workspace_available": True,
    }


def _is_source_backed_lesson_ref(ref: str) -> bool:
    clean = _clean_ref_text(ref)
    if not clean or _candidate_value_is_missing(clean):
        return False
    lower = clean.lower()
    if lower.startswith(("vault://", "http://", "https://")):
        return True
    if lower.startswith(("case_study/", "reference/", "docs/", "audit/", "reports/")):
        return True
    return bool(re.search(r"\.(?:md|json|jsonl|yaml|yml|txt)(?::\d+)?$", lower))


def _candidate_lesson_linkage(candidate: dict[str, Any]) -> dict[str, Any]:
    refs = _candidate_ref_values(candidate, LESSON_LINKAGE_KEYS)
    source_backed = [ref for ref in refs if _is_source_backed_lesson_ref(ref)]
    return {
        "raw_refs": refs,
        "source_backed_refs": source_backed,
        "has_source_backed_lesson_linkage": bool(source_backed),
    }


def _infer_workspace_from_candidate_path(path: Path | None) -> Path | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve(strict=False)
    for parent in resolved.parents:
        if parent.name == ".auditooor":
            return parent.parent
    return None


def _candidate_json_implies_proof_work(path: Path | None) -> bool:
    if path is None:
        return False
    name = path.name.lower()
    return "exploit_queue" in name or "prove_top_leads" in name or "proof_queue" in name


def _candidate_status_text(candidate: dict[str, Any]) -> str:
    return " ".join(_candidate_texts(candidate, PROOF_STATUS_KEYS)).lower()


def _candidate_status_tokens(candidate: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for text in _candidate_texts(candidate, PROOF_STATUS_KEYS):
        lowered = text.lower()
        tokens.update(part for part in re.split(r"[^a-z0-9_]+", lowered) if part)
        for marker in ("proof-backed", "proof_backed", "poc-pass", "poc_pass", "proof_ready"):
            if marker in lowered:
                tokens.add(marker)
        if re.search(r"\bnot[-_\s]+candidate\b", lowered):
            tokens.add("not_candidate")
    return tokens


def _candidate_positive_proof_claim(candidate: dict[str, Any]) -> bool:
    if _truthy(candidate.get("proof_relevant")) or _truthy(candidate.get("proof_work")):
        return True
    status_tokens = _candidate_status_tokens(candidate)
    return bool(
        status_tokens
        & {"proof-backed", "proof_backed", "poc-pass", "poc_pass", "proved", "proof_ready"}
    )


def _candidate_explicit_non_proof(candidate: dict[str, Any]) -> bool:
    if _falsey(candidate.get("proof_relevant")) or _falsey(candidate.get("proof_work")):
        return True
    if _falsey(candidate.get("proof_relevance")):
        return True
    status = str(candidate.get("proof_relevance_status") or "").strip().lower()
    if status in {"skipped_non_proof", "non_proof", "not_proof", "advisory_only"}:
        return True
    status_tokens = _candidate_status_tokens(candidate)
    status_text = _candidate_status_text(candidate)
    if (
        status_tokens & {"unproved", "disproved", *TERMINAL_NON_PROOF_STATUS_TOKENS}
        or "closed_negative" in status_text
        or "advisory_not_candidate" in status_text
    ):
        return True
    return False


def _candidate_is_advisory_only(candidate: dict[str, Any]) -> bool:
    if _truthy(candidate.get("advisory_only")):
        return True
    status_text = _candidate_status_text(candidate)
    return any(marker in status_text for marker in ("advisory_only", "advisory-only", "scanner_or_rerun"))


def _candidate_requests_proof(candidate: dict[str, Any], *, proof_context: bool) -> bool:
    if _candidate_explicit_non_proof(candidate):
        return False
    if proof_context:
        return True
    return _candidate_positive_proof_claim(candidate)


def _candidate_forge_run_is_concrete(candidate: dict[str, Any]) -> bool:
    forge_run = candidate.get("forge_run")
    if not isinstance(forge_run, dict):
        return False
    return (
        forge_run.get("ran") is True
        and forge_run.get("exploit_pass") is True
        and forge_run.get("control_pass") is True
    )


def _candidate_execution_contract_is_concrete(candidate: dict[str, Any]) -> bool:
    contract = candidate.get("execution_contract")
    if not isinstance(contract, dict):
        return False
    return (
        contract.get("claim") == "runnable_harness"
        and contract.get("runnable") is True
        and contract.get("advisory_only") is not True
    )


def _candidate_reproduction_evidence(candidate: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    path_refs = _candidate_ref_values(candidate, REPRODUCTION_PATH_KEYS)
    command_refs = _candidate_ref_values(candidate, REPRODUCTION_COMMAND_KEYS)
    resolved: list[dict[str, Any]] = []
    if workspace is not None:
        for ref in [*path_refs, *command_refs]:
            resolved.append(_resolve_workspace_source_ref(workspace, ref))
    current = [item for item in resolved if item["current"]]
    has_structured = _candidate_forge_run_is_concrete(candidate) or _candidate_execution_contract_is_concrete(candidate)
    return {
        "path_refs": path_refs,
        "command_refs": command_refs,
        "resolved_refs": resolved,
        "current_refs": current,
        "has_concrete_reproduction_evidence": bool(has_structured or current),
        "has_structured_reproduction_evidence": has_structured,
    }


def _iter_candidate_payload(payload: Any, source: str) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for idx, item in enumerate(payload):
            yield from _iter_candidate_payload(item, f"{source}#{idx}")
        return
    if isinstance(payload, dict):
        for key in CANDIDATE_CONTAINER_KEYS:
            rows = payload.get(key)
            if isinstance(rows, list):
                for idx, item in enumerate(rows):
                    yield from _iter_candidate_payload(item, f"{source}#{key}[{idx}]")
                return
        candidate = {field: payload.get(field) for field in CANDIDATE_FIELDS if field in payload}
        extra_fields = {
            key: payload.get(key)
            for key in (
                "id",
                "candidate_id",
                "lead_id",
                "title",
                "severity",
                "intent_delta",
                "protocol_fault",
            )
            if key in payload
        }
        if candidate or extra_fields:
            record_id = payload.get("candidate_id") or payload.get("lead_id") or payload.get("id") or payload.get("title")
            yield {
                "source_ref": f"{source}#{record_id}" if record_id else source,
                "candidate": {**candidate, **extra_fields},
                "field_presence": {field: field in payload for field in CANDIDATE_FIELDS},
            }


def load_candidate_records(path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    if path is None:
        return {"source": "not_provided", "path": None}, [], []
    candidate_path = path.expanduser().resolve()
    try:
        text = candidate_path.read_text(encoding="utf-8")
        if candidate_path.suffix.lower() == ".jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            records = list(_iter_candidate_payload(rows, str(candidate_path)))
        else:
            records = list(_iter_candidate_payload(json.loads(text), str(candidate_path)))
    except Exception as exc:  # noqa: BLE001 - malformed local candidate JSON should become a gate warning.
        return {"source": "candidate_json", "path": str(candidate_path), "loaded": False}, [], [
            f"candidate JSON load failed: {exc}"
        ]
    return {
        "source": "candidate_json",
        "path": str(candidate_path),
        "loaded": True,
        "records": len(records),
        "typed_fields": list(CANDIDATE_FIELDS),
    }, records, []


def _iter_workspace_files(workspace: Path, *, max_files: int) -> tuple[list[Path], bool]:
    files: list[Path] = []
    truncated = False
    for candidate in sorted(workspace.rglob("*")):
        if len(files) >= max_files:
            truncated = True
            break
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in candidate.parts):
            continue
        files.append(candidate)
    return files, truncated


def collect_target_records(
    *,
    draft_paths: Sequence[Path] = (),
    workspace_path: Path | None = None,
    stdin_text: str | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_files: int = DEFAULT_MAX_FILES,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    chars_seen = 0
    workspace_files_truncated = False

    def add_text(source: str, text: str) -> None:
        nonlocal chars_seen
        if chars_seen >= max_chars:
            return
        remaining = max_chars - chars_seen
        bounded = text[:remaining]
        records.append({"source_ref": source, "text": bounded, "chars_truncated": max(0, len(text) - len(bounded))})
        chars_seen += len(bounded)

    for raw in draft_paths:
        path = raw.expanduser().resolve()
        if not path.is_file():
            warnings.append(f"draft path missing: {path}")
            continue
        add_text(str(path), path.read_text(encoding="utf-8", errors="replace"))

    if workspace_path is not None:
        workspace = workspace_path.expanduser().resolve()
        if workspace.is_file():
            add_text(str(workspace), workspace.read_text(encoding="utf-8", errors="replace"))
        elif workspace.is_dir():
            files, workspace_files_truncated = _iter_workspace_files(workspace, max_files=max_files)
            for path in files:
                add_text(str(path), path.read_text(encoding="utf-8", errors="replace"))
        else:
            warnings.append(f"workspace path missing: {workspace}")

    if stdin_text is not None:
        add_text("<stdin>", stdin_text)

    return records, {
        "records": len(records),
        "chars_seen": chars_seen,
        "max_chars": max_chars,
        "max_files": max_files,
        "workspace_files_truncated": workspace_files_truncated,
    }, warnings


def _match_record(
    compiler: Any,
    record: dict[str, Any],
    active_levels: dict[str, str],
) -> tuple[list[dict[str, Any]], int]:
    text = str(record.get("text") or "")
    snippet, suppressed = _bounded_snippet(compiler, text)
    rows: list[dict[str, Any]] = []
    for pred in compiler.classify_text(text):
        predicate = str(pred.get("predicate") or "")
        if predicate not in active_levels:
            continue
        level = active_levels[predicate]
        rows.append(
            {
                "predicate": predicate,
                "enforcement_level": level,
                "gate_phase": pred.get("gate_phase"),
                "confidence": pred.get("confidence"),
                "advisory_only": level == "advisory_worker_context",
                "source_ref": record.get("source_ref"),
                "matched_signals": list(pred.get("matched_signals") or [])[:8],
                "snippet": snippet,
                "suggested_proof_obligations": PROOF_OBLIGATIONS.get(predicate, []),
            }
        )
    return rows, suppressed


def _candidate_match_row(
    compiler: Any,
    *,
    record: dict[str, Any],
    predicate: str,
    matched_signals: list[str],
    candidate_fields: list[str],
    snippet_text: str,
    active_levels: dict[str, str],
) -> dict[str, Any] | None:
    if predicate not in active_levels:
        return None
    snippet, suppressed = _bounded_snippet(compiler, snippet_text)
    return {
        "predicate": predicate,
        "enforcement_level": active_levels[predicate],
        "gate_phase": _predicate_gate_phase(compiler, predicate),
        "confidence": "high" if len(matched_signals) >= 2 else "medium",
        "advisory_only": active_levels[predicate] == "advisory_worker_context",
        "source_ref": record.get("source_ref"),
        "input_kind": "candidate_json",
        "matched_signals": matched_signals[:8],
        "candidate_fields": candidate_fields[:8],
        "snippet": snippet,
        "suggested_proof_obligations": PROOF_OBLIGATIONS.get(predicate, []),
        "_suppressed": suppressed,
    }


def _candidate_snippet(candidate: dict[str, Any], fields: Sequence[str]) -> str:
    parts: list[str] = []
    for field in fields:
        if field in candidate:
            value = _candidate_field_text(candidate, field)
            if value:
                parts.append(f"{field}: {value}")
    return "; ".join(parts)


def _match_candidate_record(
    compiler: Any,
    record: dict[str, Any],
    active_levels: dict[str, str],
) -> tuple[list[dict[str, Any]], int]:
    candidate = record.get("candidate")
    if not isinstance(candidate, dict):
        return [], 0

    rows: list[dict[str, Any]] = []
    suppressed = 0

    prereq_text = _candidate_field_text(candidate, "prerequisites", "attacker_role")
    if ADMIN_RE.search(prereq_text) and not ADMIN_NEGATION_RE.search(prereq_text):
        fields = ["prerequisites", "attacker_role"]
        row = _candidate_match_row(
            compiler,
            record=record,
            predicate="admin_or_team_action_prerequisite",
            matched_signals=["candidate_admin_or_team_prerequisite"],
            candidate_fields=fields,
            snippet_text=_candidate_snippet(candidate, fields),
            active_levels=active_levels,
        )
        if row:
            rows.append(row)

    economics = candidate.get("economics")
    economics_text = _candidate_field_text(candidate, "economics")
    impact_text = _candidate_field_text(candidate, "impact_claim", "evidence_class")
    economics_required = bool(ECONOMIC_IMPACT_RE.search(impact_text) or ECONOMIC_IMPACT_RE.search(economics_text))
    economics_missing = _candidate_value_is_missing(economics) or bool(ECONOMICS_MISSING_RE.search(economics_text))
    if economics_required and (economics_missing or not _candidate_has_economic_model(economics)):
        fields = ["impact_claim", "evidence_class", "economics"]
        row = _candidate_match_row(
            compiler,
            record=record,
            predicate="economic_viability_missing",
            matched_signals=["candidate_economic_impact_without_viability_model"],
            candidate_fields=fields,
            snippet_text=_candidate_snippet(candidate, fields),
            active_levels=active_levels,
        )
        if row:
            rows.append(row)

    documented_text = _candidate_field_text(candidate, "evidence_class", "impact_claim", "production_path")
    intent_text = _candidate_field_text(candidate, "intent_delta", "protocol_fault")
    has_intent_delta = bool(candidate.get("intent_delta")) or bool(candidate.get("protocol_fault")) or bool(
        INTENT_DELTA_RE.search(intent_text)
    )
    intent_delta_missing = not has_intent_delta
    if DOCUMENTED_MECHANICS_RE.search(documented_text) and intent_delta_missing:
        fields = ["evidence_class", "impact_claim", "production_path", "intent_delta"]
        row = _candidate_match_row(
            compiler,
            record=record,
            predicate="documented_mechanics_no_stronger_intent",
            matched_signals=["candidate_documented_mechanics_without_intent_delta"],
            candidate_fields=fields,
            snippet_text=_candidate_snippet(candidate, fields),
            active_levels=active_levels,
        )
        if row:
            rows.append(row)

    mev_text = _candidate_field_text(candidate, "production_path", "evidence_class", "oos_flags")
    if FRONTRUN_ONLY_RE.search(mev_text):
        fields = ["production_path", "evidence_class", "oos_flags"]
        row = _candidate_match_row(
            compiler,
            record=record,
            predicate="ambient_mev_not_protocol_bug",
            matched_signals=["candidate_frontrun_or_sandwich_only_path"],
            candidate_fields=fields,
            snippet_text=_candidate_snippet(candidate, fields),
            active_levels=active_levels,
        )
        if row:
            rows.append(row)

    low_cap_text = _candidate_field_text(candidate, "impact_claim", "evidence_class", "oos_flags", "severity")
    if LOW_SEVERITY_RE.search(low_cap_text):
        fields = ["impact_claim", "evidence_class", "oos_flags", "severity"]
        row = _candidate_match_row(
            compiler,
            record=record,
            predicate="low_severity_cap_triggered",
            matched_signals=["candidate_low_severity_cap"],
            candidate_fields=fields,
            snippet_text=_candidate_snippet(candidate, fields),
            active_levels=active_levels,
        )
        if row:
            rows.append(row)

    cleaned: list[dict[str, Any]] = []
    for row in rows:
        suppressed += int(row.pop("_suppressed", 0))
        cleaned.append(row)
    return cleaned, suppressed


def _proof_blocker_entry(*, record: dict[str, Any], reason: str, fields: list[str], advisory: bool) -> dict[str, Any]:
    level = "advisory_worker_context" if advisory else "hard_pre_poc"
    return {
        "code": f"proof_relevance_{reason}",
        "predicate": reason,
        "enforcement_level": level,
        "source_ref": record.get("source_ref"),
        "input_kind": "candidate_json",
        "matched_signals": [reason],
        "candidate_fields": fields[:8],
        "reason": reason,
        "rejection_reason": reason,
        "suggested_proof_obligations": PROOF_BLOCKER_OBLIGATIONS.get(reason, []),
    }


def _proof_reason_fields(reason: str) -> list[str]:
    if reason == "missing_source_backed_lesson_linkage":
        return list(LESSON_LINKAGE_KEYS)
    if reason in {"missing_source_refs", "stale_workspace_source_refs", "workspace_context_unavailable"}:
        return list(SOURCE_REF_KEYS)
    if reason == "proof_without_runnable_harness_evidence":
        return [*REPRODUCTION_PATH_KEYS, *REPRODUCTION_COMMAND_KEYS, "forge_run", "execution_contract"]
    if reason == "advisory_only_row":
        return ["advisory_only", "status", "state", "verdict"]
    return []


def _assess_candidate_proof_relevance(
    record: dict[str, Any],
    *,
    workspace: Path | None,
    proof_context: bool,
) -> dict[str, Any] | None:
    candidate = record.get("candidate")
    if not isinstance(candidate, dict):
        return None
    proof_relevant = _candidate_requests_proof(candidate, proof_context=proof_context)
    if not proof_relevant:
        return None

    advisory_only = _candidate_is_advisory_only(candidate)
    lesson = _candidate_lesson_linkage(candidate)
    source_status = _candidate_source_ref_status(candidate, workspace)
    reproduction = _candidate_reproduction_evidence(candidate, workspace)

    reasons: list[str] = []
    if advisory_only:
        reasons.append("advisory_only_row")
    if not lesson["has_source_backed_lesson_linkage"]:
        reasons.append("missing_source_backed_lesson_linkage")
    if not source_status["raw_refs"]:
        reasons.append("missing_source_refs")
    elif not source_status["workspace_available"]:
        reasons.append("workspace_context_unavailable")
    elif not source_status["current_refs"]:
        reasons.append("stale_workspace_source_refs")
    if not reproduction["has_concrete_reproduction_evidence"]:
        reasons.append("proof_without_runnable_harness_evidence")

    blocker_reasons = [] if advisory_only else reasons
    advisory_reasons = reasons if advisory_only else []
    if blocker_reasons:
        decision = "blocked"
    elif advisory_reasons:
        decision = "advisory_only"
    else:
        decision = "proof_relevant_pass"

    return {
        "candidate_id": str(
            candidate.get("lead_id")
            or candidate.get("candidate_id")
            or candidate.get("id")
            or candidate.get("title")
            or record.get("source_ref")
            or "unknown"
        ),
        "source_ref": record.get("source_ref"),
        "proof_relevant": True,
        "advisory_only": advisory_only,
        "decision": decision,
        "rejection_reasons": blocker_reasons,
        "advisory_reasons": advisory_reasons,
        "blocker_reasons": blocker_reasons,
        "has_source_backed_lesson_linkage": lesson["has_source_backed_lesson_linkage"],
        "lesson_linkage_refs": lesson["source_backed_refs"],
        "has_current_source_refs": bool(source_status["current_refs"]),
        "current_source_refs": source_status["current_refs"],
        "stale_source_refs": source_status["stale_refs"],
        "has_concrete_reproduction_evidence": reproduction["has_concrete_reproduction_evidence"],
        "reproduction_evidence_refs": reproduction["current_refs"],
        "workspace_available": source_status["workspace_available"],
    }


def evaluate_candidate_proof_relevance(
    candidate_records: Iterable[dict[str, Any]],
    *,
    workspace: Path | None,
    proof_context: bool,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}

    for record in candidate_records:
        row = _assess_candidate_proof_relevance(record, workspace=workspace, proof_context=proof_context)
        if row is None:
            continue
        rows.append(row)
        for reason in row["blocker_reasons"]:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            blockers.append(
                _proof_blocker_entry(
                    record=record,
                    reason=reason,
                    fields=_proof_reason_fields(reason),
                    advisory=False,
                )
            )
        for reason in row["advisory_reasons"]:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            warnings.append(
                _proof_blocker_entry(
                    record=record,
                    reason=reason,
                    fields=_proof_reason_fields(reason),
                    advisory=True,
                )
            )

    status = "fail" if blockers else ("warn" if warnings else "pass")
    return {
        "status": status,
        "workspace": str(workspace) if workspace is not None else "",
        "proof_context": proof_context,
        "rows": rows,
        "blockers": blockers,
        "warnings": warnings,
        "reason_counts": reason_counts,
        "summary": {
            "proof_relevant_count": len(rows),
            "proof_relevance_blocker_count": len(blockers),
            "proof_relevance_warning_count": len(warnings),
        },
    }


def evaluate_records(
    records: Iterable[dict[str, Any]],
    *,
    active_levels: dict[str, str],
    candidate_records: Iterable[dict[str, Any]] = (),
    compiler: Any | None = None,
    max_matches: int = DEFAULT_MAX_MATCHES,
) -> dict[str, Any]:
    compiler = compiler or _load_compiler()
    matched: list[dict[str, Any]] = []
    positive_reward_claim_lines_suppressed = 0
    truncated = False

    seen: set[tuple[str, str, str]] = set()
    for record in records:
        rows, suppressed = _match_record(compiler, record, active_levels)
        positive_reward_claim_lines_suppressed += suppressed
        for row in rows:
            key = (str(row["source_ref"]), str(row["predicate"]), str(row["snippet"]))
            if key in seen:
                continue
            seen.add(key)
            if len(matched) >= max_matches:
                truncated = True
                break
            matched.append(row)
        if truncated:
            break

    if not truncated:
        for record in candidate_records:
            rows, suppressed = _match_candidate_record(compiler, record, active_levels)
            positive_reward_claim_lines_suppressed += suppressed
            for row in rows:
                key = (str(row["source_ref"]), str(row["predicate"]), str(row["snippet"]))
                if key in seen:
                    continue
                seen.add(key)
                if len(matched) >= max_matches:
                    truncated = True
                    break
                matched.append(row)
            if truncated:
                break

    hard = [row for row in matched if not row["advisory_only"] and str(row["enforcement_level"]).startswith("hard_")]
    advisory = [row for row in matched if row["advisory_only"]]
    status = "fail" if hard else ("warn" if advisory else "pass")
    blockers = [
        {
            "code": f"outcome_lesson_{row['predicate']}",
            "predicate": row["predicate"],
            "enforcement_level": row["enforcement_level"],
            "source_ref": row["source_ref"],
            "input_kind": row.get("input_kind", "text"),
            "matched_signals": row["matched_signals"],
            "candidate_fields": row.get("candidate_fields", []),
            "suggested_proof_obligations": row["suggested_proof_obligations"],
        }
        for row in hard
    ]
    warnings = [
        {
            "code": f"outcome_lesson_{row['predicate']}",
            "predicate": row["predicate"],
            "source_ref": row["source_ref"],
            "input_kind": row.get("input_kind", "text"),
            "matched_signals": row["matched_signals"],
            "candidate_fields": row.get("candidate_fields", []),
            "suggested_proof_obligations": row["suggested_proof_obligations"],
        }
        for row in advisory
    ]

    return {
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "matched_predicates": matched,
        "summary": {
            "matched_count": len(matched),
            "hard_blocker_count": len(blockers),
            "advisory_warning_count": len(warnings),
            "truncated": truncated,
            "positive_reward_claim_lines_suppressed": positive_reward_claim_lines_suppressed,
        },
    }


def _inventory_config_blockers(inventory_meta: dict[str, Any]) -> list[dict[str, Any]]:
    source = str(inventory_meta.get("source") or "")
    if source in {"inventory_load_failed", "inventory_invalid_shape"}:
        return [
            {
                "code": "lesson_inventory_unavailable",
                "predicate": "lesson_inventory_unavailable",
                "enforcement_level": "hard_pre_poc",
                "source_ref": str(inventory_meta.get("path") or ""),
                "input_kind": "inventory",
                "matched_signals": inventory_meta.get("warnings") or [str(inventory_meta.get("load_error") or "")],
                "candidate_fields": [],
                "suggested_proof_obligations": [
                    "Regenerate lesson-enforcement inventory before judging this candidate.",
                    "Do not fall back to the compiler catalog for an explicitly requested inventory path.",
                ],
            }
        ]
    if source == "lesson_enforcement_inventory" and int(inventory_meta.get("predicate_count") or 0) == 0:
        return [
            {
                "code": "lesson_inventory_empty",
                "predicate": "lesson_inventory_empty",
                "enforcement_level": "hard_pre_poc",
                "source_ref": str(inventory_meta.get("path") or ""),
                "input_kind": "inventory",
                "matched_signals": inventory_meta.get("warnings") or ["inventory contained no predicates"],
                "candidate_fields": [],
                "suggested_proof_obligations": [
                    "Promote at least one reviewed lesson into the enforcement inventory before relying on this gate.",
                    "If no explicit inventory is intended, omit --inventory and use ad hoc compiler-catalog mode.",
                ],
            }
        ]
    return []


def build_gate(
    *,
    draft_paths: Sequence[Path] = (),
    workspace_path: Path | None = None,
    candidate_json_path: Path | None = None,
    inventory_path: Path | None = None,
    source_inventory_path: Path | None = None,
    stdin_text: str | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_matches: int = DEFAULT_MAX_MATCHES,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    compiler = _load_compiler()
    active_levels, inventory_meta, inventory_warnings = load_inventory(inventory_path, compiler)
    source_inventory_meta, source_inventory_warnings, source_inventory_messages = load_source_inventory(source_inventory_path)
    records, target_summary, target_warnings = collect_target_records(
        draft_paths=draft_paths,
        workspace_path=workspace_path,
        stdin_text=stdin_text,
        max_chars=max_chars,
        max_files=max_files,
    )
    candidate_meta, candidate_records, candidate_warnings = load_candidate_records(candidate_json_path)
    proof_workspace = workspace_path.expanduser().resolve() if workspace_path is not None else _infer_workspace_from_candidate_path(candidate_json_path)
    proof_context = _candidate_json_implies_proof_work(candidate_json_path)
    evaluation = evaluate_records(
        records,
        active_levels=active_levels,
        candidate_records=candidate_records,
        compiler=compiler,
        max_matches=max_matches,
    )
    proof_relevance = evaluate_candidate_proof_relevance(
        candidate_records,
        workspace=proof_workspace,
        proof_context=proof_context,
    )
    inventory_config_blockers = _inventory_config_blockers(inventory_meta)
    if inventory_config_blockers:
        evaluation["status"] = "fail"
        evaluation["blockers"] = inventory_config_blockers + evaluation["blockers"]
        evaluation["summary"]["hard_blocker_count"] = len(evaluation["blockers"])
    if proof_relevance["blockers"]:
        evaluation["status"] = "fail"
        evaluation["blockers"] = evaluation["blockers"] + proof_relevance["blockers"]
        evaluation["summary"]["hard_blocker_count"] = len(evaluation["blockers"])
    if proof_relevance["warnings"]:
        evaluation["warnings"] = evaluation["warnings"] + proof_relevance["warnings"]
        evaluation["summary"]["advisory_warning_count"] = len(evaluation["warnings"])
        if evaluation["status"] == "pass":
            evaluation["status"] = "warn"
    warnings = inventory_warnings + source_inventory_messages + target_warnings + candidate_warnings
    if source_inventory_warnings:
        warnings.append(
            f"lesson-source inventory has {len(source_inventory_warnings)} unpromoted source bucket(s)"
        )
    if not records and not candidate_records:
        warnings.append("no draft/workspace text or candidate JSON was available for evaluation")
        if evaluation["status"] == "pass":
            evaluation["status"] = "warn"

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "offline_only": True,
        "network_access": False,
        "promotion_authority": False,
        "submit_ready": False,
        "submission_ready_claim": False,
        "status": evaluation["status"],
        "verdict": evaluation["status"],
        "inventory": inventory_meta,
        "source_inventory": source_inventory_meta,
        "candidate_json": candidate_meta,
        "proof_relevance": proof_relevance,
        "target_summary": target_summary,
        "blockers": evaluation["blockers"],
        "warnings": evaluation["warnings"],
        "inventory_coverage_warnings": source_inventory_warnings,
        "matched_predicates": evaluation["matched_predicates"],
        "suggested_proof_obligations": {
            row["predicate"]: row["suggested_proof_obligations"]
            for row in evaluation["matched_predicates"]
            if row["suggested_proof_obligations"]
        },
        "summary": {
            **evaluation["summary"],
            "predicate_catalog_count": len(active_levels),
            "candidate_record_count": len(candidate_records),
            "inventory_coverage_warning_count": len(source_inventory_warnings),
            **proof_relevance["summary"],
            "messages": warnings,
        },
        "policy": "Outcome lessons are proof obligations and blockers only; this gate never marks a draft submission-ready.",
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", action="append", type=Path, default=[], help="Draft text/JSON/Markdown file to evaluate.")
    parser.add_argument("--workspace", type=Path, default=None, help="Workspace directory or text file to evaluate.")
    parser.add_argument("--candidate-json", type=Path, default=None, help="Structured candidate JSON/JSONL to evaluate.")
    parser.add_argument("--inventory", type=Path, default=None, help="lesson-enforcement-inventory JSON to consume.")
    parser.add_argument("--source-inventory", type=Path, default=None, help="lesson-source-inventory JSON for coverage warnings.")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    parser.add_argument("--max-matches", type=int, default=DEFAULT_MAX_MATCHES)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument(
        "--format",
        choices=("json",),
        default="json",
        help="Output format. Currently only JSON is supported.",
    )
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when hard blockers are present.")
    parser.add_argument("--stdin", action="store_true", help="Read additional target text from stdin.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stdin_text = (
        sys.stdin.read()
        if args.stdin or (not args.draft and args.workspace is None and args.candidate_json is None)
        else None
    )
    payload = build_gate(
        draft_paths=args.draft,
        workspace_path=args.workspace,
        candidate_json_path=args.candidate_json,
        inventory_path=args.inventory,
        source_inventory_path=args.source_inventory,
        stdin_text=stdin_text,
        max_chars=args.max_chars,
        max_matches=args.max_matches,
        max_files=args.max_files,
    )
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if args.strict and payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
