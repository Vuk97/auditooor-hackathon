#!/usr/bin/env python3
"""Bounded HIGH+ submission gate wrapper.

This wrapper does not replace ``pre-submit-check.sh``. It runs the canonical
gate for a single local draft, then adds a small fail-closed hardening layer for
common HIGH+ footguns: missing production reachability, selected-impact proof,
and live-topology TARGET_PROTOCOL placeholders. It never edits files, calls
GitHub, or submits.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.high_plus_submission_gate.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
PRE_SUBMIT = REPO_ROOT / "tools" / "pre-submit-check.sh"
ORIGINALITY_GATE = REPO_ROOT / "tools" / "originality-before-proof-gate.py"
SEVERITY_CALIBRATION_GATE = REPO_ROOT / "tools" / "severity-calibration-gate.py"
OUTCOME_LESSON_GATE = REPO_ROOT / "tools" / "outcome-lesson-gate.py"
LESSON_ENFORCEMENT_INVENTORY = REPO_ROOT / ".auditooor" / "lesson_enforcement_inventory.json"
CASE_STUDY_MATCHER = REPO_ROOT / "tools" / "case-study-class-matcher.py"
OPPOSED_TRACE_CHECK = REPO_ROOT / "tools" / "opposed-trace-check.py"
TRIAGER_PATTERNS_PATH = REPO_ROOT / "reference" / "triager_patterns.json"
MAX_OUTPUT_CHARS = 12000
MAX_TRIAGER_PATTERN_WARNINGS = 4
MAX_SEVERITY_EVIDENCE_KEYS = 6
MAX_SEVERITY_EVIDENCE_HITS_PER_KEY = 2
MAX_CASE_STUDY_CLASSES = 4
MAX_CASE_STUDY_MATCHES_PER_CLASS = 3
MAX_CASE_STUDY_OBLIGATIONS = 5
MAX_CASE_STUDY_TEXT_CHARS = 260

SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?\s*Severity(?:\s+rating)?(?:\*\*)?\s*[:\-](?:\*\*)?\s*(?:\*\*)?"
    r"(Critical|High|Medium|Low)\b"
)
FILENAME_SEVERITY_RE = re.compile(r"(?:^|[-_])(critical|high|medium|low)(?:[-_.]|$)", re.IGNORECASE)
SELECTED_IMPACT_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?selected[_ -]impact(?:\*\*)?\s*:\s*(.+?)\s*$"
)
PROGRAM_IMPACT_HEADING_RE = re.compile(r"(?im)^\s*##\s+Program Impact Mapping\s*$")
IMPACT_CONTRACT_HEADING_RE = re.compile(r"(?im)^\s*##\s+Impact Contract\s*$")
LIVE_CLAIM_RE = re.compile(
    r"\b(?:live[- ]state|live[- ]topology|deployment topology|deployed at|"
    r"TARGET_PROTOCOL|live_topology_checks\.json|manual proof|"
    r"mainnet\s+(?:state|deployment|address|balance|tvl|asset|contract|route|topology))\b",
    re.IGNORECASE,
)
NEGATED_LIVE_CLAIM_RE = re.compile(
    r"(?:\blive[- ]proof\s+evidence\s*:\s*n/?a\b|"
    r"\b(?:no|not|without)\b.{0,120}\b(?:live[- ]state|live[- ]topology|mainnet|"
    r"deployment[- ]state|manual proof|live[- ]proof)\b)",
    re.IGNORECASE,
)
TARGET_PROTOCOL_PLACEHOLDER_RE = re.compile(
    r"\bTARGET_PROTOCOL\b|<\s*target[_ -]?protocol\s*>|\btarget_protocol\s*[:=]\s*(?:\"\"|''|<|$)",
    re.IGNORECASE,
)
PRODUCTION_REACHABILITY_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?"
    r"(?:production[_ -]reachability|production[_ -]path|reachability[_ -]tier)"
    r"(?:\*\*)?\s*:\s*(.+?)\s*$"
)
PRODUCTION_REACHABILITY_HEADING_RE = re.compile(r"(?im)^\s*##+\s+Production Reachability\s*$")
NEXT_HEADING_RE = re.compile(r"(?m)^\s*##+\s+\S")
NEGATION_HINT_RE = re.compile(
    r"\b(?:not|no|without|unavailable|missing|absent|none|never|disabled|placeholder)\b|"
    r"\b(?:lab|test)\s+only\b|"
    r"\bmock(?:ed)?\b|"
    r"\bsimulat(?:ed|ion)\b",
    re.IGNORECASE,
)
PRODUCTION_REACHABILITY_MODE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "live_production_path",
        re.compile(r"\blive[- ]production[- ]path\b|\blive[- ]deployed[- ]path\b", re.IGNORECASE),
    ),
    (
        "production_profile_lab_path",
        re.compile(
            r"\bproduction[- ]profile[- ]lab[- ]path\b|\bproduction[- ]profile[- ]harness\b",
            re.IGNORECASE,
        ),
    ),
    (
        "non_production_cap",
        re.compile(r"\b(?:explicit[- ])?non[- ]production[- ]cap\b|\bseverity[- ]cap\b", re.IGNORECASE),
    ),
)
PLACEHOLDER_VALUES = {"", "?", "n/a", "na", "none", "null", "tbd", "todo", "unknown", "unset", "<selected_impact>"}
PLACEHOLDER_VALUE_PATTERN = "|".join(re.escape(value) for value in sorted(PLACEHOLDER_VALUES - {""}))
BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|cross[- ]chain|layerzero|lzreceive|oft|vaa|dvn|guardian|validator[- ]set)\b",
    re.IGNORECASE,
)
BRIDGE_RELEASE_OR_QUORUM_RE = re.compile(
    r"\b(?:release[sd]?|unlock[sd]?|mint(?:ed|s)?|withdraw(?:al|s)?|finali[sz]e[sd]?|"
    r"quorum|attestation|signer[- ]threshold|required[-_]?dvn[-_]?count)\b",
    re.IGNORECASE,
)
BRIDGE_RESPONSE_OR_RELEASE_PROOF_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?"
    r"(?:response[-_ ]path|release[-_ ]proof|destination[-_ ]release[-_ ]proof|"
    r"bridge[-_ ]response[-_ ]path|quorum[-_ ]release[-_ ]proof)"
    rf"(?:\*\*)?\s*:\s*(?!\s*(?:{PLACEHOLDER_VALUE_PATTERN})\s*$).+\S\s*$"
)
# A *real* bridge primitive - a cross-chain messaging/attestation mechanism, not
# a generic word ("validator-set", "withdrawal") that also appears in
# single-chain findings. The release/quorum obligation is a bridge obligation
# only when at least one of these primitives is present near the context.
BRIDGE_PRIMITIVE_RE = re.compile(
    r"\b(?:bridge|cross[- ]chain|layerzero|lzreceive|oft|vaa|dvn)\b",
    re.IGNORECASE,
)
# Refutation / disclaimer cue: when the bridge context is explicitly disclaimed
# ("this is not a bridge finding", "no cross-chain release path"), the release/
# quorum obligation must NOT fire.
BRIDGE_DISCLAIMER_RE = re.compile(
    r"(?i)\b(?:not|no|never|without|does\s+not|do\s+not|is\s+not|are\s+not|"
    r"n[o']t\s+a|rules?\s+out|excludes?)\b",
)
CASE_STUDY_CLASS_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("bridge", ("bridge", "cross-chain", "cross chain", "op-stack", "optimismportal", "withdrawal finalization")),
    ("access-control", ("access-control", "access control", "onlyrole", "onlyroles", "grantrole", "role", "permission", "deployment-state", "deployment state", "mainnet role")),
    ("cross-contract-invariant", ("cross-contract", "cross contract", "composition", "invariant", "anchorstate", "finalizewithdrawal")),
)
ROLE_OR_DEPLOYMENT_DRAFT_RE = re.compile(
    r"\b(?:role|rolesof|grantrole|onlyrole|onlyroles|access[- ]control|permission|"
    r"deployment[- ]state)\b",
    re.IGNORECASE,
)
LIVE_ENUMERATION_EVIDENCE_RE = re.compile(
    r"\b(?:cast\s+call|rolesof|role\s+enumeration|live\s+state|fork\s+proof|"
    r"on[- ]chain\s+enumeration|onchain\s+enumeration)\b",
    re.IGNORECASE,
)
BRIDGE_CROSS_CONTRACT_INVARIANT_DRAFT_RE = re.compile(
    r"(?=.*\b(?:bridge|cross[- ]chain|optimismportal|finalizewithdrawal|withdrawal)\b)"
    r"(?=.*\b(?:cross[- ]contract|composition|invariant|anchorstate|predicate)\b)",
    re.IGNORECASE | re.DOTALL,
)
SYMBOLIC_OR_SMT_EVIDENCE_RE = re.compile(
    r"\b(?:smt|symbolic|halmos|solver|z3|counter[- ]?example|counterexample)\b",
    re.IGNORECASE,
)
FUZZ_OR_REACHABILITY_EVIDENCE_RE = re.compile(
    r"\b(?:forge\s+fuzz|invariant\s+fuzz|fuzz(?:ing|ed)?|reachability\s+evidence|"
    r"permissionless\s+reachability|foundry\s+invariant)\b",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _recorded_originality_gate(draft: Path, severity: str | None) -> dict[str, Any]:
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_originality_before_proof_gate_for_high_plus",
            ORIGINALITY_GATE,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {ORIGINALITY_GATE}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module.build_packet(draft, severity=severity)  # type: ignore[attr-defined]
    except Exception as exc:
        return {
            "schema": "auditooor.originality_before_proof_recorded_posture.v1",
            "draft_path": str(draft),
            "severity": str(severity or "").upper(),
            "verdict": "error",
            "code": "recorded-originality-gate-error",
            "message": str(exc),
            "evidence_lines": [],
        }


def _bounded_severity_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    bounded: dict[str, Any] = {}
    keys = sorted(
        evidence,
        key=lambda item: (
            -len(evidence.get(item) if isinstance(evidence.get(item), list) else []),
            str(item),
        ),
    )
    for key in keys[:MAX_SEVERITY_EVIDENCE_KEYS]:
        hits = evidence.get(key)
        if not isinstance(hits, list):
            continue
        bounded[key] = {
            "hit_count": len(hits),
            "sample_hits": [
                {
                    "line": hit.get("line"),
                    "token": str(hit.get("token") or "")[:120],
                    "text": str(hit.get("text") or "")[:180],
                }
                for hit in hits[:MAX_SEVERITY_EVIDENCE_HITS_PER_KEY]
                if isinstance(hit, dict)
            ],
        }
    return bounded


def _severity_calibration_gate(draft: Path, severity: str | None) -> dict[str, Any]:
    if not SEVERITY_CALIBRATION_GATE.is_file():
        return {
            "available": False,
            "verdict": "error",
            "reason": "severity-calibration-gate.py not found",
            "blockers": [],
            "advisory": ["severity_calibration_gate_unavailable"],
        }
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_severity_calibration_gate_for_high_plus",
            SEVERITY_CALIBRATION_GATE,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {SEVERITY_CALIBRATION_GATE}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _, row = module.analyze_file(draft, severity_override=severity)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "verdict": "error",
            "reason": str(exc),
            "blockers": [],
            "advisory": ["severity_calibration_gate_error"],
        }
    return {
        "available": True,
        "schema": row.get("schema"),
        "gate": row.get("gate"),
        "file": row.get("file"),
        "verdict": row.get("verdict"),
        "reason": row.get("reason"),
        "claimed_severity": row.get("claimed_severity"),
        "severity_source": row.get("severity_source"),
        "predicted_triager_tier": row.get("predicted_triager_tier"),
        "impact_kind": row.get("impact_kind"),
        "privileged_precondition": row.get("privileged_precondition"),
        "attacker_path": row.get("attacker_path"),
        "recoverability": row.get("recoverability"),
        "proof_risks": list(row.get("proof_risks") or [])[:8],
        "blockers": list(row.get("blockers") or [])[:8],
        "advisory": list(row.get("advisory") or [])[:8],
        "evidence_summary": _bounded_severity_evidence(row.get("evidence")),
        "remediation_options": list(row.get("remediation_options") or [])[:5],
    }


def _outcome_lesson_gate(draft: Path) -> dict[str, Any]:
    """Consume the shared outcome-lesson classifier (HACKERMAN_V3 Lane J5a).

    This wrapper does not re-encode any lesson logic; it imports and calls
    ``tools/outcome-lesson-gate.py`` so the predicate definitions live in one
    place. Hard predicates (``hard_pre_poc`` / ``hard_pre_submit`` /
    ``hard_paste_ready`` / ``hard_commit_or_dispatch``) become High+ blockers.
    """
    if not OUTCOME_LESSON_GATE.is_file():
        return {
            "available": False,
            "status": "error",
            "reason": "outcome-lesson-gate.py not found",
            "blockers": [],
            "warnings": [],
        }
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_outcome_lesson_gate_for_high_plus",
            OUTCOME_LESSON_GATE,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {OUTCOME_LESSON_GATE}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        inventory = LESSON_ENFORCEMENT_INVENTORY if LESSON_ENFORCEMENT_INVENTORY.is_file() else None
        payload = module.build_gate(draft_paths=[draft], inventory_path=inventory)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "status": "error",
            "reason": str(exc),
            "blockers": [],
            "warnings": [],
        }
    return {
        "available": True,
        "status": payload.get("status"),
        "schema": payload.get("schema"),
        "blockers": list(payload.get("blockers") or [])[:8],
        "warnings": list(payload.get("warnings") or [])[:8],
        "summary": payload.get("summary") or {},
        "suggested_proof_obligations": payload.get("suggested_proof_obligations") or {},
    }


def _opposed_trace_gate(draft: Path, severity: str | None) -> dict[str, Any]:
    """Run the opposed-trace preflight gate (HACKERMAN_V3 Check 83)."""
    if not OPPOSED_TRACE_CHECK.is_file():
        return {
            "available": False,
            "verdict": "error",
            "reason": "opposed-trace-check.py not found",
            "gate_rc": -1,
        }
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_opposed_trace_check_for_high_plus",
            OPPOSED_TRACE_CHECK,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {OPPOSED_TRACE_CHECK}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        rc, payload = module.run(draft, severity=severity)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "verdict": "error",
            "reason": str(exc),
            "gate_rc": -1,
        }
    return {
        "available": True,
        "gate_rc": rc,
        "verdict": payload.get("verdict"),
        "reason": payload.get("reason"),
        "severity": payload.get("severity"),
        "evidence": {
            "trigger_hits": list((payload.get("evidence") or {}).get("trigger_hits") or [])[:4],
            "defense_hits": list((payload.get("evidence") or {}).get("defense_hits") or [])[:4],
            "attacker_wins_hits": list((payload.get("evidence") or {}).get("attacker_wins_hits") or [])[:4],
            "defender_wins_hits": list((payload.get("evidence") or {}).get("defender_wins_hits") or [])[:4],
        },
        "remediation_options": list(payload.get("remediation_options") or [])[:5],
    }


def infer_severity(path: Path, text: str, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit.capitalize()
    match = SEVERITY_RE.search(text)
    if match:
        return match.group(1).capitalize()
    name_match = FILENAME_SEVERITY_RE.search(path.name)
    if name_match:
        return name_match.group(1).capitalize()
    return None


def is_high_plus(severity: str | None) -> bool:
    return str(severity or "").lower() in {"high", "critical"}


def _selected_impact_values(text: str) -> list[str]:
    values: list[str] = []
    for match in SELECTED_IMPACT_RE.finditer(text):
        value = re.sub(r"\s+<!--.*?-->\s*$", "", match.group(1)).strip().strip("`*_ ")
        if value:
            values.append(value)
    return values


def _selected_impact_ok(text: str) -> bool:
    values = _selected_impact_values(text)
    if not values:
        return False
    for value in values:
        normalized = value.strip().lower().strip(" .,:;`*_")
        if normalized not in PLACEHOLDER_VALUES and not normalized.startswith("<"):
            return True
    return False


def _production_reachability_candidates(text: str) -> list[str]:
    candidates = [match.group(1).strip() for match in PRODUCTION_REACHABILITY_FIELD_RE.finditer(text)]
    for match in PRODUCTION_REACHABILITY_HEADING_RE.finditer(text):
        section_start = match.end()
        next_heading = NEXT_HEADING_RE.search(text, section_start)
        section_end = next_heading.start() if next_heading else len(text)
        section = text[section_start:section_end].strip()
        if section:
            candidates.extend(line.strip() for line in section.splitlines() if line.strip())
    return candidates


def _candidate_matches_mode(candidate: str, pattern: re.Pattern[str]) -> bool:
    for match in pattern.finditer(candidate):
        before = candidate[max(0, match.start() - 48):match.start()]
        after = candidate[match.end():min(len(candidate), match.end() + 64)]
        if NEGATION_HINT_RE.search(before) or NEGATION_HINT_RE.search(after):
            continue
        return True
    return False


def _production_reachability_info(text: str) -> dict[str, Any]:
    candidates = _production_reachability_candidates(text)
    for candidate in candidates:
        normalized = candidate.strip().lower().strip(" .,:;`*_")
        if normalized in PLACEHOLDER_VALUES or normalized.startswith("<"):
            continue
        for mode, pattern in PRODUCTION_REACHABILITY_MODE_PATTERNS:
            if _candidate_matches_mode(candidate, pattern):
                return {
                    "declared": True,
                    "mode": mode,
                    "values": candidates[:5],
                }
    return {
        "declared": False,
        "mode": "",
        "values": candidates[:5],
    }


def _has_live_claim(text: str) -> bool:
    for line in text.splitlines():
        if not LIVE_CLAIM_RE.search(line):
            continue
        if NEGATED_LIVE_CLAIM_RE.search(line):
            continue
        return True
    return False


# Per-predicate rebuttal escape hatch for shared outcome-lesson classifier
# false-reds, mirroring the pre-submit-check #79 `r79-rebuttal` mechanism so the
# SAME classifier consumed by two gates offers the SAME author rebuttal path.
# The shared classifier's draft-text predicates are not reliably negation-aware,
# so a griefing/no-profit or unprivileged finding that DISCUSSES economics / admin
# / MEV only to rule them out can trip a hard predicate. An author converts a
# specific predicate from a hard blocker to a rebutted warning with:
#   <!-- outcome-lesson-rebuttal: <predicate>: <reason up to 200 chars> -->
# (the umbrella `r79-rebuttal` marker rebuts ALL matched predicates, matching #79).
_OUTCOME_LESSON_REBUTTAL_RE = re.compile(
    r"<!--\s*outcome-lesson-rebuttal:\s*([a-z0-9_]+)\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
_R79_REBUTTAL_RE = re.compile(r"<!--\s*r79-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)


def _outcome_lesson_rebuttals(text: str) -> tuple[set[str], str | None]:
    """Return (per-predicate rebutted set, umbrella-reason-or-None) parsed from
    the draft. An umbrella `r79-rebuttal` rebuts every matched predicate (as #79
    already treats it); a per-predicate `outcome-lesson-rebuttal: <pred>: ...`
    rebuts only that predicate."""
    per_predicate = {m.group(1).strip().lower() for m in _OUTCOME_LESSON_REBUTTAL_RE.finditer(text or "")}
    umbrella_match = _R79_REBUTTAL_RE.search(text or "")
    umbrella_reason = umbrella_match.group(1).strip()[:200] if umbrella_match else None
    return per_predicate, umbrella_reason


def _has_bridge_release_or_quorum_claim(text: str) -> bool:
    for bridge_match in BRIDGE_CONTEXT_RE.finditer(text):
        start = max(0, bridge_match.start() - 220)
        end = min(len(text), bridge_match.end() + 260)
        window = text[start:end]
        if not BRIDGE_RELEASE_OR_QUORUM_RE.search(window):
            continue
        # Require a *real* bridge primitive in the window - a generic token like
        # "validator-set" or "withdrawal" alone is not a bridge obligation.
        if not BRIDGE_PRIMITIVE_RE.search(window):
            continue
        # Suppress when the bridge context is explicitly disclaimed/refuted in
        # the immediate preceding window (contrast/refutation phrasing).
        disclaimer_prefix = text[max(0, bridge_match.start() - 90) : bridge_match.start()]
        disclaimer_prefix = re.split(r"[\n.;:!?]", disclaimer_prefix)[-1]
        if BRIDGE_DISCLAIMER_RE.search(disclaimer_prefix):
            continue
        return True
    return False


def _has_bridge_response_or_release_proof(text: str) -> bool:
    return bool(BRIDGE_RESPONSE_OR_RELEASE_PROOF_RE.search(text))


def _truncate(value: object, limit: int = MAX_CASE_STUDY_TEXT_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _load_case_study_matcher() -> Any | None:
    if not CASE_STUDY_MATCHER.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_case_study_class_matcher_for_high_plus",
            CASE_STUDY_MATCHER,
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module
    except Exception:  # noqa: BLE001
        return None


def _workspace_class_text(workspace: Path | None) -> str:
    if workspace is None:
        return ""
    chunks: list[str] = [workspace.name]
    for name in ("INTAKE_BASELINE.md", "SCOPE.md", "README.md"):
        path = workspace / name
        if not path.is_file() or path.is_symlink():
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace")[:4000])
        except OSError:
            continue
    return "\n".join(chunks)


def _infer_case_study_classes(text: str, workspace: Path | None) -> list[str]:
    haystack = f"{_workspace_class_text(workspace)}\n{text}".lower()
    classes: list[str] = []
    for class_name, keywords in CASE_STUDY_CLASS_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            classes.append(class_name)
    return classes[:MAX_CASE_STUDY_CLASSES]


def _case_study_enforcement_mode(match: dict[str, Any]) -> str:
    signature = str(match.get("workflow_signature") or "").strip().lower()
    case_id = str(match.get("case_id") or "").strip().lower()
    if signature == "role_permission_finding_without_onchain_state_enumeration" or case_id == "polymarket-cantina-2026":
        return "hard_block_if_role_access_control_without_live_enumeration"
    if signature == "cross_contract_invariant_without_smt_and_fuzz_both" or case_id == "engagement-3-composition-fuzz-2026":
        return "hard_block_if_critical_bridge_invariant_without_smt_and_fuzz"
    return "warning_only"


def _case_study_obligations(text: str, workspace: Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    matcher = _load_case_study_matcher()
    if matcher is None:
        return [], []

    obligations: list[dict[str, Any]] = []
    source_refs = ["tools/case-study-class-matcher.py"]
    seen: set[str] = set()
    for class_name in _infer_case_study_classes(text, workspace):
        try:
            matches = matcher.match_workspace(
                class_name,
                top_n=MAX_CASE_STUDY_MATCHES_PER_CLASS,
            )
        except Exception:  # noqa: BLE001
            continue
        for match in matches:
            d = match.as_dict() if hasattr(match, "as_dict") else dict(vars(match))
            case_id = str(d.get("case_id") or "").strip()
            if not case_id or case_id in seen:
                continue
            seen.add(case_id)
            source_file = str(d.get("source_file") or "")
            if source_file:
                try:
                    source_refs.append(str(Path(source_file).resolve().relative_to(REPO_ROOT)))
                except ValueError:
                    source_refs.append(source_file)
            obligation = {
                "case_id": case_id,
                "matched_class": class_name,
                "class": d.get("class", d.get("class_", "")),
                "severity_class": d.get("severity_class", ""),
                "score": d.get("score", 0.0),
                "workflow_signature": d.get("workflow_signature", ""),
                "loop_back_phase": d.get("loop_back_phase", ""),
                "stop_criterion": _truncate(d.get("stop_criterion")),
                "extracted_lesson": _truncate(d.get("extracted_lesson")),
                "enforcement_mode": _case_study_enforcement_mode(d),
                "source_file": source_file,
            }
            obligations.append(obligation)
            if len(obligations) >= MAX_CASE_STUDY_OBLIGATIONS:
                return obligations, list(dict.fromkeys(source_refs))
    return obligations, list(dict.fromkeys(source_refs))


def _has_role_or_deployment_claim(text: str) -> bool:
    for match in ROLE_OR_DEPLOYMENT_DRAFT_RE.finditer(text):
        before = text[max(0, match.start() - 80):match.start()]
        after = text[match.end():min(len(text), match.end() + 80)]
        if NEGATION_HINT_RE.search(before) or NEGATION_HINT_RE.search(after):
            continue
        return True
    return False


def _split_terms(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for raw in value:
        text = str(raw).strip().strip("`\"'").lower()
        if not text:
            continue
        if len(text) < 4:
            continue
        out.append(text)
    return out


def _read_structured_triager_patterns() -> list[dict[str, Any]]:
    if not TRIAGER_PATTERNS_PATH.is_file():
        return []
    try:
        payload = json.loads(TRIAGER_PATTERNS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    rows = payload.get("rejections", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return []
    parsed: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pattern_id = str(row.get("id") or "").strip()
        if not pattern_id:
            continue
        name = str(row.get("name") or "").strip() or pattern_id
        parsed.append({
            "id": pattern_id,
            "name": name,
            "severity": str(row.get("severity") or "warn").strip().lower(),
            "description": str(row.get("description") or "").strip(),
            "triager_language": _split_terms(row.get("triager_language")),
            "triggers": _split_terms(row.get("triggers")),
            "pre_submit_guard": str(row.get("pre_submit_guard") or "").strip(),
        })
    return parsed


def _triager_pattern_warnings(text: str, patterns: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    if not text:
        return []
    haystack = text.lower()
    if patterns is None:
        patterns = _read_structured_triager_patterns()
    if not patterns:
        return []
    scored: list[tuple[int, str, str, str, list[str], str]] = []
    for pattern in patterns:
        pattern_id = pattern.get("id", "")
        pattern_name = str(pattern.get("name", pattern_id)).strip()
        if not pattern_id or not pattern_name:
            continue
        hits: list[str] = []
        score = 0
        for term in [*pattern.get("triggers", []), *pattern.get("triager_language", [])]:
            if not term or term in {"user", "issue", "proof", "token", "state"}:
                continue
            if term in haystack:
                score += 2
                hits.append(term)
        if score < 2:
            continue
        scored.append((score, pattern_id, pattern_name, pattern.get("pre_submit_guard", ""), hits))
    if not scored:
        return []
    scored.sort(key=lambda item: (-item[0], item[1]))
    warnings: list[dict[str, str]] = []
    for score, pattern_id, pattern_name, guard, hits in scored[:MAX_TRIAGER_PATTERN_WARNINGS]:
        if not hits:
            continue
        first_hit = hits[0]
        guard_text = (guard[:220] + "...") if len(guard) > 223 else guard
        warning = {
            "code": "triager_pattern_match",
            "message": (
                f"Known triager rejection pattern {pattern_id} ({pattern_name}) "
                f"is textually referenced via \"{first_hit}\". This is a "
                "bounded reminder only; no submission verdict is implied. "
                "Add explicit in-scope attacker path and production-grade proof for "
                "the claimed High/Critical impact before filing."
            ),
            "pattern_id": pattern_id,
            "pattern_name": pattern_name,
            "matched_term": first_hit,
            "match_count": str(score),
        }
        if guard_text:
            warning["pre_submit_guard"] = guard_text
        warnings.append(warning)
    return warnings


def _run_pre_submit(draft: Path, severity: str | None) -> dict[str, Any]:
    if not PRE_SUBMIT.is_file():
        return {
            "available": False,
            "argv": ["bash", str(PRE_SUBMIT), str(draft)],
            "exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "pre-submit-check.sh not found",
            "failed_checks": None,
            "warning_checks": None,
        }
    argv = ["bash", str(PRE_SUBMIT), str(draft)]
    if severity:
        argv.extend(["--severity", severity])
    proc = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    failed_match = re.search(r"([0-9]+)\s+check\(s\)\s+failed", proc.stdout)
    warn_match = re.search(r"([0-9]+)\s+warning\(s\)", proc.stdout)
    return {
        "available": True,
        "argv": argv,
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-MAX_OUTPUT_CHARS:],
        "stderr_tail": proc.stderr[-4000:],
        "failed_checks": int(failed_match.group(1)) if failed_match else (1 if proc.returncode else 0),
        "warning_checks": int(warn_match.group(1)) if warn_match else 0,
    }


def evaluate(
    draft: Path,
    *,
    workspace: Path | None = None,
    severity: str | None = None,
    run_pre_submit: bool = True,
) -> dict[str, Any]:
    draft = draft.expanduser().resolve()
    workspace = workspace.expanduser().resolve() if workspace else None
    blockers: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    source_refs = ["tools/high-plus-submission-gate.py", "tools/pre-submit-check.sh"]
    triager_pattern_matches: list[dict[str, str]] = []

    if not draft.is_file():
        blockers.append({"code": "draft_not_found", "message": f"submission draft not found: {draft}"})
        text = ""
    else:
        text = _read(draft)

    inferred_severity = infer_severity(draft, text, severity)
    high_plus = is_high_plus(inferred_severity)
    if not high_plus:
        warnings.append(
            {
                "code": "not_high_plus",
                "message": "wrapper is designed for High/Critical drafts; canonical pre-submit result is still reported",
            }
        )
    if high_plus:
        triager_pattern_matches = _triager_pattern_warnings(text)
        warnings.extend(triager_pattern_matches)

    severity_calibration_gate = _severity_calibration_gate(draft, inferred_severity) if draft.is_file() else {
        "available": False,
        "verdict": "error",
        "reason": "draft is unavailable",
        "blockers": [],
        "advisory": ["draft_unavailable"],
    }
    severity_calibration_blockers = [
        str(code)
        for code in severity_calibration_gate.get("blockers", [])
        if str(code).strip()
    ]
    if high_plus and severity_calibration_blockers:
        predicted = str(severity_calibration_gate.get("predicted_triager_tier") or "unknown")
        for code in severity_calibration_blockers:
            blockers.append(
                {
                    "code": f"severity_calibration_{code}",
                    "message": (
                        "Severity calibration gate found a deterministic High+/Critical "
                        f"overclaim blocker; predicted triager tier is {predicted}."
                    ),
                }
            )
    elif high_plus and severity_calibration_gate.get("verdict") in {"pass-with-advisory", "error"}:
        warnings.append(
            {
                "code": "severity_calibration_advisory",
                "message": str(
                    severity_calibration_gate.get("reason")
                    or "severity calibration gate returned advisory output"
                ),
            }
        )

    originality_gate = _recorded_originality_gate(draft, inferred_severity) if draft.is_file() else {
        "verdict": "error",
        "code": "draft-unavailable",
        "message": "draft is unavailable",
        "evidence_lines": [],
    }
    originality_verdict = str(originality_gate.get("verdict") or "error")
    if high_plus and originality_verdict == "fail":
        blockers.append(
            {
                "code": "high_plus_originality_fail_closed",
                "message": (
                    "High/Critical promotion blocked because the draft records "
                    "an explicit originality FAIL/DUPE posture"
                ),
            }
        )
    elif originality_verdict in {"warn", "error"}:
        warnings.append(
            {
                "code": f"originality_{originality_verdict}",
                "message": str(originality_gate.get("message") or "recorded originality posture is not a bounded pass"),
            }
        )

    if high_plus and not _selected_impact_ok(text):
        blockers.append(
            {
                "code": "selected_impact_missing_or_placeholder",
                "message": "High/Critical draft must carry a non-placeholder selected_impact in Impact Contract or Program Impact Mapping",
            }
        )

    production_reachability = _production_reachability_info(text)
    if high_plus and not production_reachability["declared"]:
        blockers.append(
            {
                "code": "PRODUCTION_REACHABILITY_MISSING",
                "message": (
                    "High/Critical draft must declare production reachability as one of: "
                    "live production path, production-profile lab path, or explicit non-production cap"
                ),
            }
        )

    has_live_claim = _has_live_claim(text)
    target_protocol_env = os.environ.get("TARGET_PROTOCOL", "").strip()
    target_protocol_placeholder = bool(TARGET_PROTOCOL_PLACEHOLDER_RE.search(text))
    has_bridge_release_or_quorum_claim = _has_bridge_release_or_quorum_claim(text)
    has_bridge_response_or_release_proof = _has_bridge_response_or_release_proof(text)
    case_study_obligations, case_study_source_refs = _case_study_obligations(text, workspace)
    has_role_or_deployment_case = any(
        obligation.get("enforcement_mode") == "hard_block_if_role_access_control_without_live_enumeration"
        for obligation in case_study_obligations
    )
    has_bridge_invariant_case = any(
        obligation.get("enforcement_mode") == "hard_block_if_critical_bridge_invariant_without_smt_and_fuzz"
        for obligation in case_study_obligations
    )
    role_or_deployment_claim_detected = _has_role_or_deployment_claim(text)
    live_enumeration_evidence_present = bool(LIVE_ENUMERATION_EVIDENCE_RE.search(text))
    bridge_cross_contract_invariant_claim_detected = bool(BRIDGE_CROSS_CONTRACT_INVARIANT_DRAFT_RE.search(text))
    symbolic_or_smt_evidence_present = bool(SYMBOLIC_OR_SMT_EVIDENCE_RE.search(text))
    fuzz_or_reachability_evidence_present = bool(FUZZ_OR_REACHABILITY_EVIDENCE_RE.search(text))
    if high_plus and has_live_claim and (target_protocol_placeholder or not target_protocol_env):
        blockers.append(
            {
                "code": "target_protocol_live_hardening_missing",
                "message": "High/Critical live-topology claim needs concrete TARGET_PROTOCOL context before live evidence can clear",
            }
        )

    if high_plus and has_live_claim and not (PROGRAM_IMPACT_HEADING_RE.search(text) or IMPACT_CONTRACT_HEADING_RE.search(text)):
        blockers.append(
            {
                "code": "live_claim_missing_impact_section",
                "message": "High/Critical live/deployment claim must bind live evidence to an Impact Contract or Program Impact Mapping section",
            }
        )
    if high_plus and has_bridge_release_or_quorum_claim and not has_bridge_response_or_release_proof:
        blockers.append(
            {
                "code": "bridge_response_or_release_proof_missing",
                "message": (
                    "High/Critical bridge release/quorum claim must include explicit "
                    "response-path or release-proof evidence"
                ),
            }
        )

    if (
        high_plus
        and has_role_or_deployment_case
        and role_or_deployment_claim_detected
        and not live_enumeration_evidence_present
    ):
        blockers.append(
            {
                "code": "case_study_role_live_enumeration_missing",
                "message": (
                    "Matched role/access-control deployment-state case study requires "
                    "live/on-chain state enumeration evidence for High/Critical drafts "
                    "(for example cast call, rolesOf, role enumeration, live state, fork proof, or on-chain enumeration)."
                ),
            }
        )

    if (
        str(inferred_severity or "").lower() == "critical"
        and has_bridge_invariant_case
        and bridge_cross_contract_invariant_claim_detected
        and not (symbolic_or_smt_evidence_present and fuzz_or_reachability_evidence_present)
    ):
        blockers.append(
            {
                "code": "case_study_bridge_invariant_smt_and_fuzz_missing",
                "message": (
                    "Matched bridge/cross-contract invariant case study requires both "
                    "symbolic/SMT evidence and fuzz/reachability evidence before a Critical draft can pass."
                ),
            }
        )

    for obligation in case_study_obligations:
        if obligation.get("enforcement_mode") != "warning_only":
            continue
        warnings.append(
            {
                "code": "case_study_lesson_match",
                "message": (
                    f"Matched case study {obligation.get('case_id')} for class "
                    f"{obligation.get('matched_class')}; review stop criterion before filing."
                ),
                "case_id": str(obligation.get("case_id") or ""),
                "workflow_signature": str(obligation.get("workflow_signature") or ""),
            }
        )

    # HACKERMAN_V3: opposed-trace gate (Check 83)
    opposed_trace = _opposed_trace_gate(draft, inferred_severity) if draft.is_file() else {
        "available": False,
        "verdict": "error",
        "reason": "draft unavailable",
        "gate_rc": -1,
    }
    opposed_verdict = str(opposed_trace.get("verdict") or "error")
    if high_plus and opposed_verdict in ("fail-unopposed-trace", "fail-defender-wins"):
        blockers.append(
            {
                "code": "unopposed_trace_for_direct_loss",
                "message": (
                    f"HACKERMAN_V3 Check 83 ({opposed_verdict}): "
                    "Direct Loss / Permanent Freeze / Theft / Insolvency claimed from an "
                    "unopposed trace (attacker vs empty world). "
                    "Enumerate every protocol-owned defense (watchtower, refund, "
                    "liquidation, slash, pause, challenge, finalize) and show the "
                    "attacker wins DESPITE each one. "
                    "Override: <!-- opposed-trace-rebuttal: <reason up to 200 chars> -->"
                ),
            }
        )

    # HACKERMAN_V3 Lane J5a: shared outcome-lesson classifier as High+ blockers.
    # The lesson predicate logic is NOT re-encoded here - this consumes the
    # single shared classifier in tools/outcome-lesson-gate.py.
    outcome_lesson = _outcome_lesson_gate(draft) if draft.is_file() else {
        "available": False,
        "status": "error",
        "reason": "draft unavailable",
        "blockers": [],
        "warnings": [],
    }
    if high_plus and outcome_lesson.get("available") and outcome_lesson.get("blockers"):
        rebutted_predicates, umbrella_rebuttal_reason = _outcome_lesson_rebuttals(text)
        seen_predicates: set[str] = set()
        for lesson_blocker in outcome_lesson["blockers"]:
            predicate = str(lesson_blocker.get("predicate") or "outcome_lesson")
            if predicate in seen_predicates:
                continue
            seen_predicates.add(predicate)
            obligations = lesson_blocker.get("suggested_proof_obligations") or []
            # Author rebuttal (per-predicate or umbrella r79-rebuttal) converts a
            # hard predicate false-red into a rebutted warning, mirroring #79.
            if predicate in rebutted_predicates or umbrella_rebuttal_reason is not None:
                warnings.append(
                    {
                        "code": f"outcome_lesson_{predicate}_rebutted",
                        "message": (
                            f"outcome-lesson predicate {predicate} rebutted by author marker "
                            "(outcome-lesson-rebuttal / r79-rebuttal); treated as warning, not a blocker."
                        ),
                    }
                )
                continue
            blockers.append(
                {
                    "code": f"outcome_lesson_{predicate}",
                    "message": (
                        "HACKERMAN_V3 Lane J5a: shared outcome-lesson classifier hard "
                        f"predicate {predicate} ({lesson_blocker.get('enforcement_level')}). "
                        + (str(obligations[0]) if obligations else "Resolve the codified outcome lesson before filing High/Critical.")
                    ),
                }
            )
    elif outcome_lesson.get("available") and outcome_lesson.get("warnings"):
        for lesson_warning in outcome_lesson["warnings"][:2]:
            warnings.append(
                {
                    "code": f"outcome_lesson_{lesson_warning.get('predicate') or 'advisory'}",
                    "message": "Shared outcome-lesson classifier advisory predicate matched; review before filing.",
                }
            )
    elif outcome_lesson.get("status") == "error":
        warnings.append(
            {
                "code": "outcome_lesson_gate_unavailable",
                "message": str(outcome_lesson.get("reason") or "shared outcome-lesson classifier unavailable"),
            }
        )

    pre_submit = _run_pre_submit(draft, inferred_severity) if run_pre_submit and draft.is_file() else None
    if pre_submit and pre_submit.get("exit_code") not in (0, None):
        blockers.append(
            {
                "code": "pre_submit_failed",
                "message": f"canonical pre-submit-check.sh exited {pre_submit.get('exit_code')}",
            }
        )
    if pre_submit and not pre_submit.get("available"):
        blockers.append({"code": "pre_submit_unavailable", "message": "canonical pre-submit-check.sh is unavailable"})
    if triager_pattern_matches and "reference/triager_patterns.json" not in source_refs:
        source_refs.append("reference/triager_patterns.json")
    if "tools/severity-calibration-gate.py" not in source_refs:
        source_refs.append("tools/severity-calibration-gate.py")
    if "tools/opposed-trace-check.py" not in source_refs:
        source_refs.append("tools/opposed-trace-check.py")
    if "tools/outcome-lesson-gate.py" not in source_refs:
        source_refs.append("tools/outcome-lesson-gate.py")
    for source_ref in case_study_source_refs:
        if source_ref not in source_refs:
            source_refs.append(source_ref)

    status = "fail" if blockers else "pass"
    posture = "SUBMIT_GATE_PASSED" if status == "pass" and high_plus else "NOT_SUBMIT_READY"
    digest = hashlib.sha256(
        json.dumps(
            {
                "draft": str(draft),
                "workspace": str(workspace or ""),
                "severity": inferred_severity or "",
                "status": status,
                "blockers": blockers,
                "warnings": warnings,
                "pre_submit_exit": None if pre_submit is None else pre_submit.get("exit_code"),
                "severity_calibration": severity_calibration_gate,
                "case_study_obligations": case_study_obligations,
                "opposed_trace_verdict": opposed_verdict,
                "outcome_lesson_status": outcome_lesson.get("status"),
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:high_plus_submission_gate:{digest[:16]}",
        "context_pack_hash": digest,
        "draft_path": str(draft),
        "workspace_path": str(workspace) if workspace else "",
        "severity": inferred_severity,
        "high_plus": high_plus,
        "status": status,
        "submission_posture": posture,
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "blockers": blockers,
        "warnings": warnings,
        "case_study_obligations": case_study_obligations,
        "case_study_enforcement": {
            "classes_considered": _infer_case_study_classes(text, workspace),
            "role_or_deployment_claim_detected": role_or_deployment_claim_detected,
            "live_enumeration_evidence_present": live_enumeration_evidence_present,
            "bridge_cross_contract_invariant_claim_detected": bridge_cross_contract_invariant_claim_detected,
            "symbolic_or_smt_evidence_present": symbolic_or_smt_evidence_present,
            "fuzz_or_reachability_evidence_present": fuzz_or_reachability_evidence_present,
            "matched_obligation_count": len(case_study_obligations),
            "hard_block_modes": [
                mode
                for mode in (
                    "hard_block_if_role_access_control_without_live_enumeration" if has_role_or_deployment_case else "",
                    "hard_block_if_critical_bridge_invariant_without_smt_and_fuzz" if has_bridge_invariant_case else "",
                )
                if mode
            ],
        },
        "triager_pattern_matches": triager_pattern_matches,
        "severity_calibration_gate": severity_calibration_gate,
        "live_hardening": {
            "live_claim_detected": has_live_claim,
            "target_protocol_env_present": bool(target_protocol_env),
            "target_protocol_placeholder_detected": target_protocol_placeholder,
            "selected_impact_present": _selected_impact_ok(text),
            "selected_impact_values": _selected_impact_values(text)[:5],
            "production_reachability_declared": production_reachability["declared"],
            "production_reachability_mode": production_reachability["mode"],
            "production_reachability_values": production_reachability["values"],
            "bridge_release_or_quorum_claim_detected": has_bridge_release_or_quorum_claim,
            "bridge_response_or_release_proof_present": has_bridge_response_or_release_proof,
        },
        "originality_gate": originality_gate,
        "opposed_trace_gate": opposed_trace,
        "outcome_lesson_gate": outcome_lesson,
        "pre_submit": pre_submit,
        "source_refs": [*source_refs, "tools/originality-before-proof-gate.py:build_packet"],
        "generated_at_utc": _utc_now(),
        "privacy_guards": {
            "single_draft_only": True,
            "stdout_tail_bounded_chars": MAX_OUTPUT_CHARS,
            "no_network_or_github": True,
            "no_file_edits": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--workspace", "--workspace-path", dest="workspace", type=Path)
    parser.add_argument("--severity", choices=("Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"))
    parser.add_argument("--skip-pre-submit", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON; default is a compact text summary")
    parser.add_argument("--advisory", action="store_true", help="Always exit 0 after reporting")
    args = parser.parse_args(argv)

    payload = evaluate(
        args.draft,
        workspace=args.workspace,
        severity=args.severity,
        run_pre_submit=not args.skip_pre_submit,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"high-plus-submission-gate {payload['status']}: "
            f"{payload['blocker_count']} blocker(s), {payload['warning_count']} warning(s)"
        )
        for blocker in payload["blockers"]:
            print(f"- {blocker['code']}: {blocker['message']}")
        for warning in payload["warnings"]:
            print(f"- warning {warning['code']}: {warning['message']}")
    return 0 if args.advisory or payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
