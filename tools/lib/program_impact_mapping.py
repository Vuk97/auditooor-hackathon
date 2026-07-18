#!/usr/bin/env python3
"""Shared Program Impact Mapping summary helpers (PR #535 PR 1).

This module wraps the dash-named ``tools/program-impact-mapping-check.py``
gate so multiple promotion surfaces — submission packager, audit-closeout
check, candidate promotion, paste-ready generator — can ask the same
question without re-implementing severity / rubric / mapping parsing.

The single source of truth remains
``tools/program-impact-mapping-check.py`` (Check #31). This module only
exposes thin, deterministic *summaries* of what that gate would say.

Surfaces wired (PR #535 PR 1):
  * ``tools/submission-packager.py`` — embed an ``impact_mapping`` block in
    ``manifest.json``; refuse packaging under
    ``REQUIRE_PROGRAM_IMPACT_MAPPING=1`` when status is bad.
  * ``tools/audit-closeout-check.py`` — emit a ``program-impact-mapping``
    row with 5 counts (mapped / missing_mapping / tier_mismatch /
    proof_artifact_missing / advisory_no_rubric).
  * ``tools/promote-typed-candidate.py`` — downgrade Critical/High/Medium
    candidates without one exact selected program-impact sentence to
    ``impact_unresolved``.
  * ``tools/paste-ready-generator.py`` — copy
    ``not_proven_impacts:`` into a dedicated ``## Not Proven`` section.

Default policy is ADVISORY WARN. Strict mode is opt-in via the
``REQUIRE_PROGRAM_IMPACT_MAPPING`` environment variable — never break
existing workflows.

Stdlib-only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional


# Stable status enum used by every consumer (packager / closeout /
# promotion / paste-ready). The `summarize_*` helpers below always return
# exactly one of these values.
STATUS_NOT_REQUIRED = "not_required"          # severity not reportable and not paste-ready
STATUS_MAPPED = "mapped"                      # block present, fields valid, rubric grounded
STATUS_MISSING_MAPPING = "missing_mapping"    # block missing or required field absent
STATUS_TIER_MISMATCH = "tier_mismatch"        # selected_impact in a different rubric tier
STATUS_PROOF_ARTIFACT_MISSING = "proof_artifact_missing"  # NF1 -- proof_artifact path bad
STATUS_ADVISORY_NO_RUBRIC = "advisory_no_rubric"  # workspace has no SEVERITY*.md / RUBRIC_COVERAGE.md

ALL_STATUSES = (
    STATUS_NOT_REQUIRED,
    STATUS_MAPPED,
    STATUS_MISSING_MAPPING,
    STATUS_TIER_MISMATCH,
    STATUS_PROOF_ARTIFACT_MISSING,
    STATUS_ADVISORY_NO_RUBRIC,
)

STRICT_ENV_VAR = "REQUIRE_PROGRAM_IMPACT_MAPPING"

REPORTABLE_SEVERITIES = frozenset({"Critical", "High", "Medium"})
DIRECT_SUBMIT_POSTURES = frozenset({
    "in_scope_direct_submit",
    "direct_submit",
    "direct-submit",
    "submit_ready",
    "submit-ready",
    "paste_ready",
    "paste-ready",
})

IMPACT_CONTRACT_REQUIRED_FIELDS = (
    "selected_impact",
    "severity_tier",
    "listed_impact_proven",
    "evidence_class",
    "oos_traps",
    "stop_condition",
)

_FIELD_RE = re.compile(r"^\s*(?:[-*]\s*)?([A-Za-z0-9_ -]+)\s*:\s*(.*?)\s*$")
_REPORTABLE_RE = re.compile(r"\b(Critical|High|Medium)\b", re.IGNORECASE)
_DIRECT_SUBMIT_RE = re.compile(
    r"\b(in_scope_direct_submit|direct[-_ ]submit|submit[-_ ]ready|paste[-_ ]ready)\b",
    re.IGNORECASE,
)
_SNAPPY_RE = re.compile(r"\b(snappy|decompress_vec|gossip decode|decode[- ]bomb)\b", re.IGNORECASE)
_MEMPOOL_RE = re.compile(r"\bmempool\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Lazy import of the dash-named gate module. Cached so repeated calls
# from package_submission / closeout don't reload it for every draft.
# ---------------------------------------------------------------------------

_CACHE_KEY = "_program_impact_mapping_gate_module"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_GATE_PATH = _REPO_ROOT / "tools" / "program-impact-mapping-check.py"


def _load_gate():
    cached = sys.modules.get(_CACHE_KEY)
    if cached is not None:
        return cached
    if not _GATE_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location(_CACHE_KEY, _GATE_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[_CACHE_KEY] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(_CACHE_KEY, None)
        return None
    return module


def is_strict_required() -> bool:
    """True iff ``REQUIRE_PROGRAM_IMPACT_MAPPING`` is set to a truthy value."""
    raw = os.environ.get(STRICT_ENV_VAR, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _norm_sentence(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value.strip().strip('"').strip("'").lower())


def _norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "proved", "proven"}
    return False


def _load_rubric_tiers(workspace: Optional[Path]) -> tuple[bool, dict[str, list[str]], str]:
    gate = _load_gate()
    if gate is None or workspace is None:
        return False, {}, ""
    try:
        found, text = gate._load_rubric_text(workspace)  # type: ignore[attr-defined]
        if not found:
            return False, {}, text
        tiers = gate._parse_rubric_tiers(text)  # type: ignore[attr-defined]
        return True, tiers, text
    except Exception:
        return False, {}, ""


def _impact_tier(selected_impact: str, rubric_tiers: dict[str, list[str]]) -> str:
    needle = _norm_sentence(selected_impact)
    if not needle:
        return ""
    for tier, rows in rubric_tiers.items():
        for row in rows or []:
            if needle == _norm_sentence(row):
                return tier
    return ""


def _parse_contract_fields(text: str) -> dict[str, Any]:
    """Parse Impact Contract / Program Impact Mapping style ``key: value`` rows."""
    fields: dict[str, Any] = {}
    active_list_key = ""
    aliases = {
        "severity": "severity_tier",
        "severity_implied": "severity_tier",
        "selected_exact_impact": "selected_impact",
        "selected_impact_text": "selected_impact",
        "listed_impact_selected": "selected_impact",
        "impact": "selected_impact",
        "impact_sentence": "selected_impact",
        "required_proof_class": "proof_contract",
        "evidence_class_required": "evidence_class",
        "required_evidence_class": "evidence_class",
        "current_evidence_class": "evidence_class",
        "proof_requirement": "proof_contract",
        "what_would_prove": "proof_contract",
        "promotion_stop_condition": "stop_condition",
        "stop": "stop_condition",
        "stop_conditions": "stop_condition",
        "forbidden_assumptions": "oos_traps",
        "forbidden_assumption": "oos_traps",
        "oos_trap": "oos_traps",
        "oos_downgrade_risk": "downgrade_clauses",
        "downgrade_clause": "downgrade_clauses",
        "emergency_downgrade_clauses": "downgrade_clauses",
    }
    list_keys = {"oos_traps", "downgrade_clauses", "proof_contract"}
    for raw in text.splitlines():
        line = raw.rstrip()
        match = _FIELD_RE.match(line)
        if match:
            key = aliases.get(_norm_key(match.group(1)), _norm_key(match.group(1)))
            value = match.group(2).strip()
            if key in list_keys:
                if value in {"", "[]"}:
                    fields[key] = []
                    active_list_key = key
                elif value.startswith("[") and value.endswith("]"):
                    inner = value[1:-1].strip()
                    fields[key] = [p.strip().strip('"').strip("'") for p in inner.split(",") if p.strip()]
                    active_list_key = ""
                else:
                    fields[key] = value
                    active_list_key = ""
            else:
                fields[key] = value
                active_list_key = ""
            continue
        if active_list_key and re.match(r"^\s{0,4}[-*]\s+\S", line):
            fields.setdefault(active_list_key, [])
            if isinstance(fields[active_list_key], list):
                fields[active_list_key].append(re.sub(r"^\s*[-*]\s+", "", line).strip())
    return fields


def _extract_named_section(text: str, names: Iterable[str]) -> str:
    names_norm = {_norm_key(n) for n in names}
    heading_re = re.compile(r"^(#{2,6})\s+(.+?)\s*$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    for idx, match in enumerate(matches):
        heading = _norm_key(match.group(2))
        if heading not in names_norm:
            continue
        level = len(match.group(1))
        end = len(text)
        for nxt in matches[idx + 1:]:
            if len(nxt.group(1)) <= level:
                end = nxt.start()
                break
        return text[match.end():end].strip()
    return ""


def _contract_source_text(text: str) -> str:
    contract = _extract_named_section(
        text,
        ("Impact Contract", "Pre-Harness Impact Contract", "Program Impact Contract"),
    )
    if contract:
        return contract
    gate = _load_gate()
    if gate is not None:
        try:
            found, inner, _level = gate._extract_block(text)  # type: ignore[attr-defined]
            if found:
                if isinstance(inner, list):
                    return "\n".join(str(line) for line in inner)
                return str(inner)
        except Exception:
            pass
    return _extract_named_section(text, ("Program Impact Mapping", "Impact Mapping"))


def prompt_claims_reportable_or_direct(text: str) -> bool:
    """Return True when prompt/draft text claims reportable severity or direct-submit posture."""
    if not isinstance(text, str):
        return False
    return bool(_REPORTABLE_RE.search(text) or _DIRECT_SUBMIT_RE.search(text))


def validate_impact_contract_text(
    text: str,
    *,
    workspace: Optional[Path] = None,
    require_contract: bool = False,
) -> dict[str, Any]:
    """Validate the pre-work impact contract required before dispatch/harness/report work.

    The contract may live under ``## Impact Contract`` or inside the existing
    ``## Program Impact Mapping`` block. It is stricter than draft-level mapping:
    the selected impact must be an exact rubric row, the severity tier must
    derive from that row, ``listed_impact_proven`` must be true, and the proof
    contract / OOS traps / downgrade clauses must be locked before downstream
    work proceeds.
    """
    body = _contract_source_text(text or "")
    fields = _parse_contract_fields(body) if body else {}
    rubric_found, rubric_tiers, _rubric_text = _load_rubric_tiers(workspace)
    selected = str(fields.get("selected_impact") or "").strip()
    severity = str(fields.get("severity_tier") or "").strip().rstrip(".,:;").capitalize()
    matched_tier = _impact_tier(selected, rubric_tiers) if rubric_found else ""
    reasons: list[str] = []

    if require_contract and not body:
        reasons.append("impact_contract_missing")
    for key in IMPACT_CONTRACT_REQUIRED_FIELDS:
        value = fields.get(key)
        if key == "listed_impact_proven":
            if not _coerce_bool(value):
                reasons.append("listed_impact_not_proven")
            continue
        if isinstance(value, list):
            if not [v for v in value if str(v).strip()]:
                reasons.append(f"{key}_missing")
        elif not str(value or "").strip():
            reasons.append(f"{key}_missing")

    if selected:
        if not rubric_found:
            reasons.append("rubric_missing_for_exact_impact")
        elif not matched_tier:
            reasons.append("selected_impact_not_exact_listed_sentence")
    if severity:
        if severity not in {"Critical", "High", "Medium", "Low", "Informational"}:
            reasons.append("severity_tier_invalid")
        elif matched_tier and severity != matched_tier:
            reasons.append("severity_tier_mismatch")
    elif selected:
        reasons.append("severity_tier_missing")

    haystack = f"{text}\n{selected}".lower()
    if _SNAPPY_RE.search(haystack) and _MEMPOOL_RE.search(selected):
        reasons.append("snappy_gossip_decode_cannot_select_mempool_impact")

    return {
        "schema_version": "auditooor.impact_contract.v1",
        "ok": not reasons,
        "required": bool(require_contract),
        "fields": fields,
        "selected_impact": selected,
        "severity_tier": severity,
        "matched_rubric_tier": matched_tier,
        "listed_impact_proven": _coerce_bool(fields.get("listed_impact_proven")),
        "rubric_found": rubric_found,
        "reasons": reasons,
    }


def _render_mapping_like_block(payload: dict[str, Any], heading: str = "Impact Contract") -> str:
    lines = [f"## {heading}", ""]
    for key, value in payload.items():
        if isinstance(value, list):
            lines.append(f"- {key}:")
            for item in value:
                if str(item).strip():
                    lines.append(f"  - {str(item).strip()}")
        elif isinstance(value, bool):
            lines.append(f"- {key}: {'true' if value else 'false'}")
        elif value not in (None, "", []):
            lines.append(f"- {key}: {value}")
    return "\n".join(lines) + "\n"


def load_impact_contracts(workspace: Path) -> list[dict[str, Any]]:
    """Load ``<ws>/.auditooor/impact_contracts.json`` contract rows.

    Malformed or missing files are treated as no contracts so upstream
    consumers can mark rows ``in_scope_not_submit_ready`` without failing
    legacy workflows.
    """
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = payload.get("contracts") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _contract_matches(
    row: dict[str, Any],
    *,
    candidate_id: str = "",
    angle_id: str = "",
    contracts: Iterable[str] = (),
) -> bool:
    candidate_id = str(candidate_id or "").strip()
    angle_id = str(angle_id or "").strip()
    contract_set = {str(item).strip() for item in contracts if str(item).strip()}
    if candidate_id and candidate_id in {
        str(row.get("candidate_id") or "").strip(),
        str(row.get("impact_contract_id") or "").strip(),
        str(row.get("benchmark_id") or "").strip(),
        str(row.get("task_id") or "").strip(),
    }:
        return True
    related_angles = {
        str(item).strip()
        for item in row.get("related_angle_ids", [])
        if str(item).strip()
    }
    if angle_id and angle_id in {
        str(row.get("angle_id") or "").strip(),
        str(row.get("candidate_id") or "").strip(),
    } | related_angles:
        return True
    row_contracts = {
        str(row.get(key) or "").strip()
        for key in ("contract", "target_contract", "asset")
        if str(row.get(key) or "").strip()
    }
    raw_contracts = row.get("contracts")
    if isinstance(raw_contracts, list):
        row_contracts.update(str(item).strip() for item in raw_contracts if str(item).strip())
    return bool(contract_set and row_contracts and contract_set & row_contracts)


def find_impact_contract(
    workspace: Path,
    *,
    candidate_id: str = "",
    angle_id: str = "",
    contracts: Iterable[str] = (),
) -> dict[str, Any] | None:
    """Return the first workspace impact contract matching a candidate/angle."""
    for row in load_impact_contracts(workspace):
        if _contract_matches(row, candidate_id=candidate_id, angle_id=angle_id, contracts=contracts):
            return row
    return None


def impact_contract_summary(
    workspace: Path,
    *,
    candidate_id: str = "",
    angle_id: str = "",
    contracts: Iterable[str] = (),
    severity_claim: str = "",
    direct_submit: bool = False,
) -> dict[str, Any]:
    """Summarize the pre-work impact contract for a mining/candidate row.

    Missing or unproved contracts deliberately clear the selected impact in
    the returned summary so downstream artifacts cannot accidentally carry
    reportable framing into harness/report work.
    """
    severity = str(severity_claim or "").strip().capitalize()
    required = severity in REPORTABLE_SEVERITIES or bool(direct_submit)
    row = find_impact_contract(
        workspace,
        candidate_id=candidate_id,
        angle_id=angle_id,
        contracts=contracts,
    )
    if not required:
        return {
            "schema_version": "auditooor.impact_contract_summary.v1",
            "required": False,
            "status": STATUS_NOT_REQUIRED,
            "submission_posture": "not_required",
            "selected_impact": "",
            "severity_tier": severity or "",
            "evidence_class": "",
            "oos_traps": [],
            "stop_condition": "",
            "reasons": [],
        }
    if row is None:
        return {
            "schema_version": "auditooor.impact_contract_summary.v1",
            "required": True,
            "status": "missing_contract",
            "submission_posture": "in_scope_not_submit_ready",
            "selected_impact": "",
            "severity_tier": "none",
            "evidence_class": "",
            "oos_traps": [],
            "stop_condition": "",
            "reasons": ["impact_contract_missing"],
        }

    report = validate_impact_contract_text(
        _render_mapping_like_block(row),
        workspace=workspace,
        require_contract=True,
    )
    fields = report.get("fields", {}) if isinstance(report.get("fields"), dict) else {}
    listed_proven = bool(report.get("listed_impact_proven"))
    ok = bool(report.get("ok"))
    posture = str(row.get("submission_posture") or row.get("verdict") or "").strip()
    if not posture:
        posture = "in_scope_direct_submit" if ok else "in_scope_not_submit_ready"
    selected = str(report.get("selected_impact") or "").strip() if ok and listed_proven else ""
    return {
        "schema_version": "auditooor.impact_contract_summary.v1",
        "required": True,
        "status": STATUS_MAPPED if ok else STATUS_MISSING_MAPPING,
        "impact_contract_id": str(row.get("impact_contract_id") or ""),
        "candidate_id": str(row.get("candidate_id") or candidate_id or ""),
        "submission_posture": posture if ok else "in_scope_not_submit_ready",
        "selected_impact": selected,
        "severity_tier": str(report.get("severity_tier") or ("none" if not ok else severity)),
        "evidence_class": str(fields.get("evidence_class") or ""),
        "oos_traps": fields.get("oos_traps") if isinstance(fields.get("oos_traps"), list) else [],
        "stop_condition": str(fields.get("stop_condition") or ""),
        "listed_impact_proven": listed_proven,
        "rubric_found": bool(report.get("rubric_found")),
        "reasons": list(report.get("reasons") or []),
    }


# ---------------------------------------------------------------------------
# Per-draft summary
# ---------------------------------------------------------------------------


def summarize_draft(
    draft_path: Path,
    *,
    workspace: Optional[Path] = None,
) -> dict[str, Any]:
    """Return a deterministic dict summarising the mapping status of one draft.

    Keys (always present):

    - ``status``                : one of ``ALL_STATUSES``
    - ``requires_mapping``      : bool
    - ``severity_claim``        : str ("Critical"/"High"/"Medium"/"Low"/...)
    - ``paste_ready``           : bool
    - ``has_mapping_block``     : bool
    - ``selected_impact``       : str ("" if absent)
    - ``severity_implied``      : str
    - ``proof_artifact``        : str
    - ``not_proven_impacts``    : list[str]
    - ``errors``                : list[str] (the gate's error rows)
    - ``warnings``              : list[str]
    - ``rubric_found``          : bool

    A draft that does not require mapping (Low/Informational and not
    paste-ready) returns ``status = "not_required"`` and never errors.
    """
    summary: dict[str, Any] = {
        "draft": str(draft_path),
        "status": STATUS_NOT_REQUIRED,
        "requires_mapping": False,
        "severity_claim": "",
        "paste_ready": False,
        "has_mapping_block": False,
        "selected_impact": "",
        "severity_implied": "",
        "proof_artifact": "",
        "not_proven_impacts": [],
        "errors": [],
        "warnings": [],
        "rubric_found": False,
    }

    gate = _load_gate()
    if gate is None or not draft_path.is_file():
        # Best-effort: gate module could not be loaded or draft missing.
        # Treat as advisory non-error to avoid breaking callers in environments
        # where the gate file is intentionally absent (e.g. a stripped CI image).
        summary["status"] = STATUS_ADVISORY_NO_RUBRIC
        return summary

    ws = workspace
    if ws is None:
        try:
            ws = gate._resolve_workspace_for_draft(draft_path)  # type: ignore[attr-defined]
        except Exception:
            ws = None

    rubric_found = False
    rubric_text: str = ""
    rubric_tiers: dict[str, list[str]] = {}
    if ws is not None:
        try:
            rubric_found, rubric_text = gate._load_rubric_text(ws)  # type: ignore[attr-defined]
            if rubric_found:
                rubric_tiers = gate._parse_rubric_tiers(rubric_text)  # type: ignore[attr-defined]
        except Exception:
            rubric_found = False

    summary["rubric_found"] = bool(rubric_found)

    grounding_text = rubric_text if rubric_found else None
    grounding_tiers = rubric_tiers if rubric_found else None

    try:
        report = gate.check_draft(  # type: ignore[attr-defined]
            draft_path, grounding_text, grounding_tiers, workspace=ws
        )
    except Exception as exc:  # pragma: no cover - defensive
        summary["status"] = STATUS_MISSING_MAPPING
        summary["errors"].append(f"gate raised: {exc}")
        return summary

    summary["requires_mapping"] = bool(report.requires_mapping)
    summary["severity_claim"] = str(report.severity_claim or "")
    summary["paste_ready"] = bool(report.paste_ready)
    summary["has_mapping_block"] = bool(report.has_mapping_block)
    summary["errors"] = list(report.errors)
    summary["warnings"] = list(report.warnings)
    # PR #541 follow-up F8: surface the gate's structured error_codes so
    # consumers don't have to substring-match English error prose.
    summary["error_codes"] = list(getattr(report, "error_codes", []) or [])

    if report.block is not None:
        summary["selected_impact"] = str(report.block.selected_impact or "")
        summary["severity_implied"] = str(report.block.severity_implied or "")
        summary["proof_artifact"] = str(report.block.proof_artifact or "")
        summary["not_proven_impacts"] = list(report.block.not_proven_impacts or [])

    # Status classification — order matters; pick the most specific signal
    # so closeout / packager / promotion get exactly ONE bucket per draft.
    if not report.requires_mapping:
        summary["status"] = STATUS_NOT_REQUIRED
        return summary

    if not rubric_found:
        # Reportable draft, no rubric to validate against — advisory.
        # The gate's --workspace path returns rc=2 for this case.
        summary["status"] = STATUS_ADVISORY_NO_RUBRIC
        return summary

    if report.passed():
        summary["status"] = STATUS_MAPPED
        return summary

    # Failed — bucket by the most useful operator signal. Tier-mismatch
    # and proof-artifact-missing get their own buckets (they tell the
    # author exactly what to fix); everything else falls through to
    # missing_mapping.
    #
    # PR #541 follow-up F8 fix: prefer the gate's structured error codes
    # over substring matching against English error prose. Falls back to
    # the legacy substring sniff if the gate is older and didn't emit
    # error_codes (defensive — keeps the lib backward-compatible).
    codes = list(getattr(report, "error_codes", []) or [])
    if codes:
        # Stable code-based dispatch.
        if "tier_mismatch" in codes:
            summary["status"] = STATUS_TIER_MISMATCH
        elif "proof_artifact_missing" in codes or "proof_artifact_invalid" in codes:
            summary["status"] = STATUS_PROOF_ARTIFACT_MISSING
        else:
            summary["status"] = STATUS_MISSING_MAPPING
        return summary
    # Backward-compatible fallback for older gate modules without codes.
    err_blob = " | ".join(report.errors).lower()
    if "tier mismatch" in err_blob:
        summary["status"] = STATUS_TIER_MISMATCH
    elif "proof_artifact" in err_blob:
        summary["status"] = STATUS_PROOF_ARTIFACT_MISSING
    else:
        summary["status"] = STATUS_MISSING_MAPPING
    return summary


# ---------------------------------------------------------------------------
# Workspace-wide rollup (closeout)
# ---------------------------------------------------------------------------


# Default subdirectories under ``submissions/`` that the closeout sweep
# scans. Real workspaces use various layouts:
#   * Cantina/Immunefi staging  -> submissions/staging/
#   * post-package paste-ready  -> submissions/paste-ready/ or paste_ready/
#   * final Cantina paste text  -> submissions/final_cantina_paste/
#   * polymarket / morpho       -> submissions/drafts/
#   * candidate intake          -> submissions/candidates/
#
# PR #541 follow-up F2 fix: the original list ``("staging", "ready",
# "paste-ready")`` returned PASS+total=0 on real polymarket and morpho
# workspaces because the drafts live in ``submissions/drafts/`` -- the
# strict-mode closeout silently bypassed Critical drafts. We now scan a
# broader default and allow operators to override via environment
# variable (``IMPACT_MAPPING_WORKSPACE_DRAFT_DIRS``) for forward-compat.
DEFAULT_WORKSPACE_DRAFT_DIRS: tuple[str, ...] = (
    "staging",
    "ready",
    "paste-ready",
    "paste_ready",
    "final_cantina_paste",
    "drafts",
    "candidates",
)
WORKSPACE_DRAFT_DIRS_ENV = "IMPACT_MAPPING_WORKSPACE_DRAFT_DIRS"


def _resolve_draft_dirs(override: Optional[Iterable[str]] = None) -> tuple[str, ...]:
    """Determine which submissions/<sub>/ directories the sweep enumerates.

    Precedence:
      1. Explicit ``override`` argument (used by tests).
      2. ``IMPACT_MAPPING_WORKSPACE_DRAFT_DIRS`` env var (comma- or
         colon-separated list of subdirectory names).
      3. ``DEFAULT_WORKSPACE_DRAFT_DIRS``.
    """
    if override is not None:
        cleaned = [str(s).strip().strip("/") for s in override if str(s).strip()]
        if cleaned:
            return tuple(dict.fromkeys(cleaned))
    raw = os.environ.get(WORKSPACE_DRAFT_DIRS_ENV, "").strip()
    if raw:
        parts = [s.strip().strip("/") for s in raw.replace(":", ",").split(",")]
        cleaned = [p for p in parts if p]
        if cleaned:
            return tuple(dict.fromkeys(cleaned))
    return DEFAULT_WORKSPACE_DRAFT_DIRS


def _iter_workspace_drafts(
    ws: Path,
    *,
    draft_dirs: Optional[Iterable[str]] = None,
) -> list[Path]:
    """Return all candidate drafts in ``ws/submissions/<sub>/`` for known subs.

    Closeout aggregates over EVERY surface where a draft could be living so
    a stale staging draft can't hide while a packaged copy of the same
    title goes through. Files ending with ``.bak`` are skipped because
    those are explicit author backups.

    PR #541 follow-up F3 fix: the prior ``RETIRED_`` filename-prefix skip
    was a free bypass (rename a flagged Critical draft
    ``Retired_actually_filing_this.md`` and the sweep ignored it). We
    still skip files whose first non-comment line declares
    ``retired: true`` in YAML frontmatter, but we no longer trust the
    filename alone.
    """
    if not ws.is_dir():
        return []
    subs = _resolve_draft_dirs(draft_dirs)
    out: list[Path] = []
    seen: set[Path] = set()
    for sub in subs:
        sub_dir = ws / "submissions" / sub
        if not sub_dir.is_dir():
            continue
        for p in sorted(sub_dir.glob("*.md")):
            try:
                resolved = p.resolve()
            except OSError:
                resolved = p
            if resolved in seen:
                continue
            name = p.name
            if name.endswith(".bak"):
                continue
            upper_name = name.upper()
            if (
                upper_name == "OOS_CHECK.MD"
                or upper_name.startswith("OOS_CHECK_")
                or upper_name.endswith(".OOS_CHECK.MD")
            ):
                continue
            if _draft_declares_retired(p):
                continue
            seen.add(resolved)
            out.append(p)
    return out


def discover_workspace_drafts(
    ws: Path,
    *,
    draft_dirs: Optional[Iterable[str]] = None,
) -> list[Path]:
    """Public workspace draft discovery for quality and closeout surfaces.

    This intentionally mirrors the closeout sweep instead of only scanning
    ``submissions/staging``: paste-ready and final-paste drafts are still
    reportable submissions and must remain visible to quality/pre-submit
    diagnostics. Mutation-oriented stages can pass a narrower ``draft_dirs``
    override to preserve staging-only semantics.
    """
    return _iter_workspace_drafts(ws, draft_dirs=draft_dirs)


_RETIRED_FRONTMATTER_RE = None  # lazily compiled below


def _draft_declares_retired(p: Path) -> bool:
    """Return True iff the draft's content declares ``retired: true``.

    PR #541 follow-up F3: filename-based ``RETIRED_`` skip was bypassable.
    A draft is now retired only when the markdown body itself opts out
    via either:

      * YAML frontmatter ``---\\nretired: true\\n---`` block at the top
      * A first-section meta line ``> retired: true``
    """
    global _RETIRED_FRONTMATTER_RE
    if _RETIRED_FRONTMATTER_RE is None:
        import re as _re
        _RETIRED_FRONTMATTER_RE = _re.compile(
            r"(?m)^\s*(?:>\s*)?retired\s*[:=]\s*true\s*$",
            _re.IGNORECASE,
        )
    try:
        head = p.read_text(encoding="utf-8", errors="replace")[:4096]
    except Exception:
        return False
    return bool(_RETIRED_FRONTMATTER_RE.search(head))


def closeout_counts(
    workspace: Path,
    *,
    draft_dirs: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    """Aggregate mapping status counts across a workspace.

    Returns a dict with stable keys for the closeout row:

    - ``mapped``                  : int
    - ``missing_mapping``         : int
    - ``tier_mismatch``           : int
    - ``proof_artifact_missing``  : int
    - ``advisory_no_rubric``      : int
    - ``not_required``            : int (informational)
    - ``total``                   : int
    - ``draft_summaries``         : list[dict] (one per draft scanned)

    All counts default to 0 when the workspace has no submissions
    directory (the row simply notes 0/0 and stays PASS).
    """
    counts = {key: 0 for key in (
        STATUS_MAPPED,
        STATUS_MISSING_MAPPING,
        STATUS_TIER_MISMATCH,
        STATUS_PROOF_ARTIFACT_MISSING,
        STATUS_ADVISORY_NO_RUBRIC,
        STATUS_NOT_REQUIRED,
    )}
    summaries: list[dict[str, Any]] = []
    for draft in _iter_workspace_drafts(workspace, draft_dirs=draft_dirs):
        s = summarize_draft(draft, workspace=workspace)
        summaries.append(s)
        status = s.get("status", STATUS_NOT_REQUIRED)
        if status not in counts:
            status = STATUS_MISSING_MAPPING
        counts[status] += 1
    counts["total"] = sum(counts[k] for k in counts if k != "total")
    return {
        "counts": counts,
        "draft_summaries": summaries,
    }


# ---------------------------------------------------------------------------
# Surface-specific helpers
# ---------------------------------------------------------------------------


def packager_metadata(
    draft_path: Path,
    workspace: Optional[Path] = None,
) -> dict[str, Any]:
    """Build the ``impact_mapping`` block embedded in a packager manifest.

    The packager calls this once per packaging run and writes the result
    into ``manifest.json``. Under ``REQUIRE_PROGRAM_IMPACT_MAPPING=1``
    the packager treats a non-clean status (anything other than
    ``mapped``, ``not_required``, ``advisory_no_rubric``) as a refusal.
    """
    summary = summarize_draft(draft_path, workspace=workspace)
    # PR #541 follow-up F6: when status is not_required surface any
    # severity-flavoured keywords in the body so the operator notices a
    # title-narrative pattern that would otherwise bypass strict mode.
    flagged: list[str] = []
    if summary.get("status") == STATUS_NOT_REQUIRED:
        try:
            body = draft_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            body = ""
        flagged = flagged_severity_keywords(body)
    return {
        "schema_version": "auditooor.impact_mapping_summary.v1",
        "status": summary["status"],
        "requires_mapping": summary["requires_mapping"],
        "severity_claim": summary["severity_claim"],
        "paste_ready": summary["paste_ready"],
        "has_mapping_block": summary["has_mapping_block"],
        "selected_impact": summary["selected_impact"],
        "severity_implied": summary["severity_implied"],
        "proof_artifact": summary["proof_artifact"],
        "not_proven_impacts": summary["not_proven_impacts"],
        "errors": summary["errors"],
        "warnings": summary["warnings"],
        "rubric_found": summary["rubric_found"],
        "flagged_severity_keywords": flagged,
    }


# Statuses that are "clean enough to ship" — mapped is canonical, but
# not_required (Low/Informational without paste-ready marker) and
# advisory_no_rubric (workspace has no rubric file at all) also pass.
_CLEAN_STATUSES = frozenset({
    STATUS_NOT_REQUIRED,
    STATUS_MAPPED,
    STATUS_ADVISORY_NO_RUBRIC,
})


def is_clean(status: str) -> bool:
    """Return True iff ``status`` is acceptable for shipping (clean lane)."""
    return status in _CLEAN_STATUSES


def packager_should_refuse(metadata: dict[str, Any]) -> tuple[bool, str]:
    """Return (refuse, reason) for the packager.

    Default is advisory: refuse only under STRICT and only when status is
    not in ``_CLEAN_STATUSES``.

    Note (PR #541 follow-up F6): ``not_required`` is treated as clean. A
    draft that hides its severity by avoiding all severity words in title
    + body will receive ``not_required`` and bypass strict refusal even if
    the body narrates Critical-flavoured impacts. The strict-mode contract
    is structurally only triggered when the gate already detects severity;
    operators should rely on the title-narrative pattern hints emitted by
    the packager (see ``flagged_severity_keywords`` in the manifest) for
    the residual case.
    """
    status = str(metadata.get("status") or STATUS_NOT_REQUIRED)
    if is_clean(status):
        return False, ""
    if not is_strict_required():
        return False, ""
    return True, (
        f"impact_mapping_status={status} "
        f"(set under {STRICT_ENV_VAR}=1 — fix the mapping or unset strict mode)"
    )


# Severity-flavoured keywords scanned in not_required drafts. PR #541
# follow-up F6: when a draft narrates severity-tier impacts but does not
# declare a severity claim in title/body, surface a manifest hint so the
# operator notices the pattern. Default policy is advisory only — never
# refuse — so this stays low blast radius.
_FLAGGED_SEVERITY_KEYWORDS: tuple[str, ...] = (
    "direct theft",
    "permanent freezing",
    "hardfork",
    "drain",
    "total network shutdown",
    "chain split",
    "double spend",
    "infinite mint",
    "bridge drain",
)


def flagged_severity_keywords(text: str) -> list[str]:
    """Return severity-flavoured keywords found in ``text`` (lowercased).

    Stable, lowercased, deduplicated. The packager embeds the list in the
    manifest so operators can spot ``not_required``-bypass patterns
    without forking the lib's status enum.
    """
    if not isinstance(text, str) or not text:
        return []
    body = text.lower()
    out: list[str] = []
    for kw in _FLAGGED_SEVERITY_KEYWORDS:
        if kw in body and kw not in out:
            out.append(kw)
    return out


def candidate_promotion_decision(
    severity_claim: str,
    mapping_status: str,
) -> tuple[bool, str]:
    """Return (downgrade?, reason) for candidate promotion.

    A candidate marked Critical/High/Medium whose mapping status is not in
    ``_CLEAN_STATUSES`` should be downgraded to ``impact_unresolved``
    rather than promoted to ``poc_ready``. Severity must derive only from
    the selected rubric row; there is no triage-ask escape hatch for missing
    proof.
    """
    sev = (severity_claim or "").strip().capitalize()
    if sev not in {"Critical", "High", "Medium"}:
        return False, ""
    if is_clean(mapping_status):
        return False, ""
    return True, (
        f"severity_claim={sev} but program_impact_mapping_status={mapping_status} "
        "(downgrade to impact_unresolved until the mapping is provided)"
    )


# ---------------------------------------------------------------------------
# Paste-ready helpers
# ---------------------------------------------------------------------------


def extract_not_proven_lines(text: str) -> list[str]:
    """Pull the ``not_proven_impacts:`` list out of a draft's mapping block.

    Returns ``[]`` if no block is present, the field is missing, or the
    list is explicitly empty. The paste-ready generator uses this to
    populate the ``## Not Proven`` section.
    """
    gate = _load_gate()
    if gate is None:
        return []
    try:
        found, inner, _level = gate._extract_block(text)  # type: ignore[attr-defined]
        if not found:
            return []
        block = gate._parse_block(inner)  # type: ignore[attr-defined]
        return list(block.not_proven_impacts or [])
    except Exception:
        return []


_TIER_ORDER = ("Informational", "Low", "Medium", "High", "Critical")


def _tier_rank(tier: str) -> int:
    """Return ordinal rank where higher == more severe.

    Unknown tiers return -1 so they don't compare as "higher" by accident.
    """
    if not tier:
        return -1
    norm = tier.strip().rstrip(".,:;").strip().capitalize()
    if norm in _TIER_ORDER:
        return _TIER_ORDER.index(norm)
    return -1


def _classify_item_tier(
    item: str,
    rubric_tiers: Optional[dict[str, list[str]]],
) -> str:
    """Determine which rubric tier a not-proven item lives in.

    Uses the same ``_ground_in_tier`` helper as the canonical gate so a
    single source of truth governs both the gate's BC1/BC2 decisions and
    the paste-ready's tier-prefix decisions.

    Returns the tier name (``"Critical"`` etc.) or ``""`` if the item
    grounds in no tier or no rubric was loaded.
    """
    if not rubric_tiers or not item or not item.strip():
        return ""
    gate = _load_gate()
    if gate is None:
        return ""
    for tier in _TIER_ORDER:
        rows = rubric_tiers.get(tier) or []
        if not rows:
            continue
        try:
            ok, _row = gate._ground_in_tier(rows, item)  # noqa: SLF001
        except Exception:
            ok = False
        if ok:
            return tier
    return ""


def render_not_proven_section(
    items: Iterable[str],
    *,
    severity_implied: str = "",
    rubric_tiers: Optional[dict[str, list[str]]] = None,
) -> str:
    """Render the ``## Not Proven`` markdown section body.

    The heading itself is emitted by the paste-ready generator; this
    helper returns just the body so the generator owns whitespace
    sandwiching.

    PR #541 follow-up F4 fix: the prior implementation emitted every
    ``not_proven_impacts:`` entry verbatim. A draft with
    ``severity_implied: High`` and ``not_proven_impacts: ["Direct theft of
    any user funds"]`` (a Critical-tier rubric phrase) would publish a
    paste-ready section that PROMINENTLY lists Critical-tier language under
    a High claim — exactly the FN7 over-framing class the contract was
    designed to prevent.

    When ``rubric_tiers`` is provided, every item is classified by tier and
    those that live above ``severity_implied`` are prefixed with
    ``(higher-tier impact, not claimed by this finding)`` so the operator
    + triager are not misled into reading the listed phrase as part of the
    severity claim.
    """
    items = [s.strip() for s in items if str(s).strip()]
    if not items:
        return (
            "_The mapping block declared `not_proven_impacts: []` — author "
            "asserts every listed impact at this severity tier is covered "
            "by the PoC. Triagers should still verify the proof matches the "
            "selected impact._"
        )
    own_rank = _tier_rank(severity_implied)
    out_lines: list[str] = []
    for item in items:
        item_tier = _classify_item_tier(item, rubric_tiers) if rubric_tiers else ""
        if item_tier and own_rank >= 0:
            item_rank = _tier_rank(item_tier)
            if item_rank > own_rank:
                out_lines.append(
                    f"- (higher-tier impact, not claimed by this finding) {item}"
                )
                continue
        out_lines.append(f"- {item}")
    return "\n".join(out_lines)


def is_higher_tier_overreach(
    items: Iterable[str],
    severity_implied: str,
    rubric_tiers: dict[str, list[str]],
) -> list[str]:
    """Return the subset of ``items`` that belong to a tier above ``severity_implied``.

    Helper for surfaces (paste-ready, packager) that may want to refuse
    publication when a not-proven entry is from a strictly higher tier.
    """
    own_rank = _tier_rank(severity_implied)
    if own_rank < 0:
        return []
    out: list[str] = []
    for item in items:
        if not str(item).strip():
            continue
        item_tier = _classify_item_tier(item, rubric_tiers)
        if not item_tier:
            continue
        if _tier_rank(item_tier) > own_rank:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


__all__ = [
    "STATUS_NOT_REQUIRED",
    "STATUS_MAPPED",
    "STATUS_MISSING_MAPPING",
    "STATUS_TIER_MISMATCH",
    "STATUS_PROOF_ARTIFACT_MISSING",
    "STATUS_ADVISORY_NO_RUBRIC",
    "ALL_STATUSES",
    "STRICT_ENV_VAR",
    "DEFAULT_WORKSPACE_DRAFT_DIRS",
    "WORKSPACE_DRAFT_DIRS_ENV",
    "is_strict_required",
    "summarize_draft",
    "discover_workspace_drafts",
    "closeout_counts",
    "packager_metadata",
    "packager_should_refuse",
    "candidate_promotion_decision",
    "is_clean",
    "prompt_claims_reportable_or_direct",
    "validate_impact_contract_text",
    "load_impact_contracts",
    "find_impact_contract",
    "impact_contract_summary",
    "extract_not_proven_lines",
    "render_not_proven_section",
    "is_higher_tier_overreach",
    "flagged_severity_keywords",
]
