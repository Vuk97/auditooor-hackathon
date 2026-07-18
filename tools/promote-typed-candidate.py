#!/usr/bin/env python3
"""Classify deep_candidate.v1 files into promotion buckets.

This is a narrow bridge between "deep lane emitted something interesting" and
"an operator should spend PoC time on it." It does not approve findings and it
does not infer scope. It runs the existing schema validator, checks that cited
workspace-relative files exist, applies a few conservative precondition-risk
heuristics, and writes a deterministic report with one of:

* ``poc_ready`` — schema-valid high-confidence candidate with source files and
  no obvious precondition-risk flags.
* ``needs_poc`` — schema-valid candidate that still needs replay, production
  path, scope, or citation work.
* ``impact_unresolved`` — otherwise interesting candidate whose claimed
  severity is not backed by one exact selected program-impact sentence.
* ``rejected`` — malformed or not actionable because required source files are
  absent.

Stdlib-only. No provider calls. No network. No workspace mutation unless an
explicit ``--out-json``/``--out-md`` path is provided.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evidence_class as _evidence_class  # noqa: E402

VALIDATOR_PATH = ROOT / "tools" / "validate-deep-candidate.py"
DOSSIER_LIB_PATH = ROOT / "tools" / "lib" / "production_path_dossier.py"
# PR #535 PR 1: shared Program Impact Mapping helper used to downgrade
# Critical/High/Medium candidates to ``impact_unresolved`` when no mapping is
# present.
IMPACT_MAPPING_LIB_PATH = ROOT / "tools" / "lib" / "program_impact_mapping.py"

REPORTABLE_SEVERITIES = {"Critical", "High", "Medium"}

SEVERITY_TOKEN = re.compile(
    r"\b(critical|high|medium)\b",
    re.IGNORECASE,
)

# PR #535 PR 1: detect a Program Impact Mapping block embedded inside a
# typed candidate (some lanes inline mapping prose into ``claim`` or
# ``lane_payload``). The shared helper does the heavy lifting on draft
# markdown, but for typed candidates we accept both inline prose and an
# explicit ``program_impact_mapping`` field on the lane payload.
PIM_HEADING = re.compile(r"##+\s+Program Impact Mapping", re.IGNORECASE)


PRECONDITION_RISK = re.compile(
    r"\b("
    r"admin|guardian|owner|multisig|governance|privileged|blacklist|retire|"
    r"mock|mockverifier|forged?\s+proof|invalid\s+(?:tee|zk)|project\s+inaction|"
    r"base\s+inaction|manual\s+response|compromised\s+(?:key|signer|tee|prover)"
    r")\b",
    re.I,
)
EXPLICIT_REJECT = re.compile(
    r"\b("
    r"out[-\s]?of[-\s]?scope|oos|duplicate|dupe|already\s+submitted|"
    r"known\s+(?:issue|fp|false\s+positive)|false\s+positive|best\s+practice"
    r")\b",
    re.I,
)
DIRECT_SUBMIT_TOKEN = re.compile(
    r"\b("
    r"in_scope_direct_submit|direct[-_\s]?submit|submit[-_\s]?ready|"
    r"paste[-_\s]?ready|ready\s+to\s+paste|ready\s+to\s+file|"
    r"final[-_\s]?paste"
    r")\b",
    re.I,
)
LINE_CITE_RE = re.compile(r"(?:^|[\s(:])L?\d{1,7}(?:-\d{1,7})?(?:\b|$)")
RUNNABLE_RE = re.compile(r"^\s*(forge|cast|anvil|npx|npm|pnpm|yarn|python3?|bash|sh|make)\b")
# Detect candidate prose that claims "direct submit" / "paste ready" /
# "submit ready" / "ready to submit" posture. Used by
# ``_candidate_claims_direct_submit`` to decide whether the candidate must pass
# the impact-contract gate even if no severity_claim was extracted.
DIRECT_SUBMIT_TOKEN = re.compile(
    r"\b("
    r"direct[-_\s]?submit|"
    r"paste[-_\s]?ready|"
    r"ready[-_\s]?to[-_\s]?submit|"
    r"submit[-_\s]?ready|"
    r"submit[-_\s]?immediately|"
    r"file[-_\s]?(?:now|today|directly)|"
    r"poc[-_\s]?ready|"
    r"submission[-_\s]?ready"
    r")\b",
    re.IGNORECASE,
)
PRODUCTION_PATH_OK = {"PROVEN", "EXTERNAL_REACHABLE", "IN_SCOPE_REACHABLE", "PRE_DEPLOYMENT_SOURCE_ONLY"}
PRODUCTION_PATH_REJECT = {"CONTRADICTED", "OOS", "OOS_ONLY", "OUT_OF_SCOPE"}


@dataclass(frozen=True)
class CandidateVerdict:
    path: str
    candidate_id: str
    lane: str
    decision: str
    reasons: list[str]
    missing_files: list[str]
    precondition_risks: list[str]
    has_line_citation: bool
    blocker_categories: list[str]
    next_actions: list[str]
    checks: dict[str, Any]


def _load_validator():
    spec = importlib.util.spec_from_file_location("deep_candidate_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load validator at {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_dossier_lib():
    spec = importlib.util.spec_from_file_location("production_path_dossier", DOSSIER_LIB_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load dossier lib at {DOSSIER_LIB_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_impact_mapping_lib():
    """Lazy loader for the Program Impact Mapping summary helper.

    Returns ``None`` (fail-open) if the lib file is absent — older checkouts
    or stripped CI images stay functional, the candidate just doesn't get
    a mapping downgrade applied.
    """
    if not IMPACT_MAPPING_LIB_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "program_impact_mapping_promote", IMPACT_MAPPING_LIB_PATH
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        return None
    return module


def _candidate_paths(workspace: Path, explicit: Iterable[Path]) -> list[Path]:
    paths = [p.expanduser() for p in explicit]
    if paths:
        return sorted(paths)
    deep_dir = workspace / "deep_candidates"
    if not deep_dir.is_dir():
        return []
    return sorted(deep_dir.glob("*.json"))


def _load_json(path: Path) -> tuple[Any | None, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return None, [f"candidate file not found: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON: {exc}"]


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _has_line_citation(doc: dict[str, Any]) -> bool:
    for rel in doc.get("files", []):
        if isinstance(rel, str) and LINE_CITE_RE.search(rel):
            return True
    payload = doc.get("lane_payload")
    if not isinstance(payload, dict):
        return False
    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if "line" in key_l and item not in (None, "", []):
                    return True
                if walk(item):
                    return True
        elif isinstance(value, list):
            return any(walk(item) for item in value)
        elif isinstance(value, str):
            return bool(LINE_CITE_RE.search(value))
        return False

    for key, value in payload.items():
        key_l = str(key).lower()
        if "line" in key_l and value not in (None, "", []):
            return True
        if isinstance(value, str) and LINE_CITE_RE.search(value):
            return True
        if walk(value):
            return True
    return False


def _precondition_risks(doc: dict[str, Any]) -> list[str]:
    texts = [
        str(doc.get("claim", "")),
        str(doc.get("trigger", "")),
        str(doc.get("impact", "")),
        str(doc.get("reproduction", "")),
    ]
    payload = doc.get("lane_payload")
    if payload is not None:
        texts.extend(_string_values(payload))
    hits = {m.group(1).lower() for text in texts for m in PRECONDITION_RISK.finditer(text)}
    return sorted(hits)


def _candidate_severity_claim(doc: dict[str, Any]) -> str:
    """Return the severity claim implied by a typed candidate, or ''.

    Inspects ``severity``, ``impact``, ``claim`` and ``lane_payload``
    text. A value of ``"Critical"`` / ``"High"`` / ``"Medium"`` triggers
    the promotion-contract downgrade when no exact mapping evidence is present.
    """
    direct = doc.get("severity")
    if isinstance(direct, str):
        s = direct.strip().capitalize()
        if s in REPORTABLE_SEVERITIES:
            return s
    blob_parts: list[str] = []
    for key in ("impact", "claim", "trigger"):
        v = doc.get(key)
        if isinstance(v, str):
            blob_parts.append(v)
    payload = doc.get("lane_payload")
    if isinstance(payload, dict):
        blob_parts.extend(_string_values(payload))
    blob = " ".join(blob_parts).lower()
    if not blob:
        return ""
    # Highest-severity word wins; word-boundary match.
    if re.search(r"\bcritical\b", blob):
        return "Critical"
    if re.search(r"\bhigh\b", blob):
        return "High"
    if re.search(r"\bmedium\b", blob):
        return "Medium"
    return ""


def _candidate_claims_direct_submit(doc: dict[str, Any]) -> bool:
    """Return True if candidate prose or payload claims direct/paste-ready posture."""
    blob_parts: list[str] = []
    for key in ("claim", "impact", "trigger", "reproduction", "promotion_status"):
        v = doc.get(key)
        if isinstance(v, str):
            blob_parts.append(v)
    payload = doc.get("lane_payload")
    if isinstance(payload, dict):
        blob_parts.extend(_string_values(payload))
    return bool(DIRECT_SUBMIT_TOKEN.search("\n".join(blob_parts)))


def _candidate_referenced_draft(
    doc: dict[str, Any],
    candidate_path: Path,
    workspace: Path,
) -> Optional[Path]:
    """Best-effort lookup of a markdown draft referenced by the candidate.

    Some lanes attach a draft path under ``lane_payload.draft`` /
    ``lane_payload.draft_path`` / ``lane_payload.submission_draft`` so the
    promoter can re-use the canonical Check #31 gate. When found we return
    a resolved Path that exists on disk (workspace-relative or absolute).
    """
    payload = doc.get("lane_payload")
    if not isinstance(payload, dict):
        return None
    for key in ("draft", "draft_path", "submission_draft", "draft_md"):
        v = payload.get(key)
        if not isinstance(v, str) or not v.strip():
            continue
        cand = Path(v).expanduser()
        if not cand.is_absolute():
            cand = (workspace / cand)
        if cand.is_file() and cand.suffix.lower() == ".md":
            return cand
    return None


def _synthesize_mapping_markdown(payload_pim: Any) -> str:
    """Render a ``## Program Impact Mapping`` block from the typed-candidate dict.

    The shared lib parses markdown; typed candidates carry the mapping in
    a structured ``lane_payload.program_impact_mapping`` field. This helper
    renders that structured payload into the canonical markdown shape so we
    can feed it through the same ``_extract_block`` / ``_parse_block``
    parser the gate uses — no forked parser.

    Returns ``""`` when the payload is empty or not a mapping/string we can
    render.
    """
    if isinstance(payload_pim, str):
        text = payload_pim.strip()
        if not text:
            return ""
        # If the string already looks like the markdown block, return it
        # verbatim. Otherwise wrap a heading around it so the lib's
        # ``_extract_block`` can find the body.
        if PIM_HEADING.search(text):
            return text
        return "## Program Impact Mapping\n\n" + text + "\n"
    if not isinstance(payload_pim, dict):
        return ""
    lines = ["## Program Impact Mapping", ""]
    for key in (
        "program",
        "asset",
        "selected_impact",
        "severity_implied",
        "proof_artifact",
        "required_evidence_class",
        "evidence_class",
        "stop_condition",
        "listed_impact_proven",
    ):
        val = payload_pim.get(key)
        if isinstance(val, bool):
            lines.append(f"- {key}: {'true' if val else 'false'}")
        elif isinstance(val, str) and val.strip():
            lines.append(f"- {key}: {val.strip()}")
    for key in ("proof_contract", "oos_traps", "downgrade_clauses"):
        val = payload_pim.get(key)
        if isinstance(val, list):
            if val:
                lines.append(f"- {key}:")
                for item in val:
                    if isinstance(item, str) and item.strip():
                        lines.append(f"  - {item.strip()}")
        elif isinstance(val, str) and val.strip():
            lines.append(f"- {key}: {val.strip()}")
    npi = payload_pim.get("not_proven_impacts")
    if isinstance(npi, list):
        if not npi:
            lines.append("- not_proven_impacts: []")
        else:
            lines.append("- not_proven_impacts:")
            for item in npi:
                if isinstance(item, str) and item.strip():
                    lines.append(f"  - {item.strip()}")
    elif isinstance(npi, str) and npi.strip():
        lines.append(f"- not_proven_impacts: {npi.strip()}")
    if len(lines) <= 2:
        return ""
    return "\n".join(lines) + "\n"


def _classify_mapping_status(
    *,
    doc: dict[str, Any],
    candidate_path: Path,
    workspace: Path,
    severity_claim: str,
    impact_mapping_lib: Any | None,
) -> str:
    """Resolve a candidate's mapping status via the shared lib.

    PR #541 follow-up F1 fix: the previous codepath used a regex helper
    that accepted any non-empty string in ``lane_payload.program_impact_mapping``
    (including a single character ``"x"``) as "mapped". This routes the
    decision through the canonical Check #31 gate parser so a Critical/High
    candidate cannot be promoted on the back of a placeholder string.

    Returns one of the shared lib's ``STATUS_*`` values:
      * ``not_required``           — severity not reportable
      * ``mapped``                  — block present, fields valid, rubric grounded
      * ``missing_mapping``         — block missing or required field absent
      * ``tier_mismatch``           — selected_impact in a different rubric tier
      * ``proof_artifact_missing``  — proof_artifact path bad
      * ``advisory_no_rubric``      — workspace has no SEVERITY*.md
    """
    if severity_claim not in REPORTABLE_SEVERITIES:
        return "not_required"

    # Lib unavailable (older checkouts) — fail closed for reportable severity.
    # Without the canonical rubric parser we cannot prove that the selected
    # impact is one exact program row.
    if impact_mapping_lib is None:
        return _fallback_mapping_status(doc)

    # Preferred path: if the candidate references a real markdown draft on
    # disk, run the canonical gate against that draft (identical to what
    # closeout / packager / paste-ready do).
    draft_path = _candidate_referenced_draft(doc, candidate_path, workspace)
    if draft_path is not None:
        try:
            summary = impact_mapping_lib.summarize_draft(
                draft_path, workspace=workspace
            )
            return str(summary.get("status") or "missing_mapping")
        except Exception:
            return "missing_mapping"

    # Fallback path: synthesize a markdown block from the structured
    # lane_payload + parse via the lib's gate parser. Same parser as the
    # canonical gate — no forked logic.
    payload = doc.get("lane_payload")
    pim_payload = payload.get("program_impact_mapping") if isinstance(payload, dict) else None
    synthesized = _synthesize_mapping_markdown(pim_payload)

    # If no structured PIM payload, scrape inlined ## Program Impact Mapping
    # heading text out of the candidate's prose fields.
    if not synthesized:
        prose_parts: list[str] = []
        for key in ("claim", "impact", "reproduction", "trigger"):
            v = doc.get(key)
            if isinstance(v, str):
                prose_parts.append(v)
        if isinstance(payload, dict):
            prose_parts.extend(_string_values(payload))
        prose = "\n".join(prose_parts)
        if PIM_HEADING.search(prose):
            synthesized = prose

    if not synthesized:
        return "missing_mapping"

    # Run the same parser the canonical gate uses.
    try:
        gate = impact_mapping_lib._load_gate()  # noqa: SLF001 -- shared parser
    except Exception:
        gate = None
    if gate is None:
        return _fallback_mapping_status(doc)

    try:
        found, inner, _level = gate._extract_block(synthesized)  # noqa: SLF001
        if not found:
            return "missing_mapping"
        block = gate._parse_block(inner)  # noqa: SLF001
    except Exception:
        return "missing_mapping"

    # Required-field presence check (mirror of the gate's check_draft logic).
    missing_fields: list[str] = []
    if not block.program:
        missing_fields.append("program")
    if not block.asset:
        missing_fields.append("asset")
    if not block.selected_impact:
        missing_fields.append("selected_impact")
    if not block.severity_implied:
        missing_fields.append("severity_implied")
    if not block.proof_artifact:
        missing_fields.append("proof_artifact")
    if not block.not_proven_impacts_present:
        missing_fields.append("not_proven_impacts")
    if missing_fields:
        return "missing_mapping"

    # Exact-row gate compatibility. The canonical parser now accepts short
    # exact rows, but still rejects empty selected_impact.
    min_len = int(getattr(gate, "MIN_IMPACT_LEN", 12))
    if len(str(block.selected_impact).strip()) < min_len:
        return "missing_mapping"

    # Tier consistency: severity_implied must match severity_claim.
    sev_clean = str(block.severity_implied).strip().rstrip(".,:;").strip().capitalize()
    if sev_clean and sev_clean != severity_claim:
        return "tier_mismatch"

    # Rubric grounding (best effort): if a workspace rubric exists, require
    # the selected_impact to ground in the claimed tier.
    try:
        rubric_found, rubric_text = gate._load_rubric_text(workspace)  # noqa: SLF001
    except Exception:
        rubric_found, rubric_text = False, ""
    if not rubric_found:
        return "advisory_no_rubric"
    try:
        rubric_tiers = gate._parse_rubric_tiers(rubric_text)  # noqa: SLF001
    except Exception:
        return "advisory_no_rubric"
    tier_rows = rubric_tiers.get(severity_claim, [])
    candidates = list(getattr(block, "selected_impact_candidates", None)
                      or [block.selected_impact])
    grounded = False
    for cand in candidates:
        try:
            ok, _row = gate._ground_in_tier(tier_rows, cand)  # noqa: SLF001
        except Exception:
            ok = False
        if ok:
            grounded = True
            break
    if grounded:
        return "mapped"
    # Did the candidate ground in a DIFFERENT tier? -> tier_mismatch.
    for cand in candidates:
        for other_tier, rows in rubric_tiers.items():
            if other_tier == severity_claim:
                continue
            try:
                ok, _row = gate._ground_in_tier(rows, cand)  # noqa: SLF001
            except Exception:
                ok = False
            if ok:
                return "tier_mismatch"
    return "missing_mapping"


def _fallback_mapping_status(doc: dict[str, Any]) -> str:
    """Conservative inline fallback when the shared lib is absent.

    Used only when ``tools/lib/program_impact_mapping.py`` cannot be
    loaded. Reportable-severity promotion must fail closed because the
    selected impact cannot be exact-row-checked without the canonical parser.
    """
    return "missing_mapping"


def _candidate_has_mapping_evidence(doc: dict[str, Any]) -> bool:
    """Return True iff the candidate carries any Program Impact Mapping signal.

    Accepts:
      - ``lane_payload.program_impact_mapping`` dict-or-string field
      - ``## Program Impact Mapping`` heading in any string-shaped field
        (``claim``, ``impact``, ``reproduction``, or any string under
        ``lane_payload``)
    """
    payload = doc.get("lane_payload")
    if isinstance(payload, dict):
        pim = payload.get("program_impact_mapping")
        if isinstance(pim, dict) and pim.get("selected_impact"):
            return True
        if isinstance(pim, str) and pim.strip():
            return True
    blob_parts: list[str] = []
    for key in ("claim", "impact", "reproduction", "trigger"):
        v = doc.get(key)
        if isinstance(v, str):
            blob_parts.append(v)
    if isinstance(payload, dict):
        blob_parts.extend(_string_values(payload))
    blob = "\n".join(blob_parts)
    return bool(PIM_HEADING.search(blob))


def _explicit_reject_markers(doc: dict[str, Any]) -> list[str]:
    texts = [
        str(doc.get("claim", "")),
        str(doc.get("trigger", "")),
        str(doc.get("impact", "")),
        str(doc.get("reproduction", "")),
    ]
    payload = doc.get("lane_payload")
    if payload is not None:
        texts.extend(_string_values(payload))
    hits = {m.group(1).lower() for text in texts for m in EXPLICIT_REJECT.finditer(text)}
    return sorted(hits)


def _missing_files(workspace: Path, doc: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for rel in doc.get("files", []):
        if not isinstance(rel, str):
            continue
        rel_path = _strip_line_suffix(rel)
        if not (workspace / rel_path).is_file():
            missing.append(rel)
    return missing


def _strip_line_suffix(value: str) -> str:
    # Accept source-mining style citations such as `src/X.sol:12` and
    # `src/X.sol:12-20` while preserving Windows drive guards enforced by the
    # schema validator (absolute drive paths never reach this helper as valid
    # workspace-relative files).
    return re.sub(r":\d+(?:-\d+)?$", "", value)


def _reproduction_looks_runnable(workspace: Path, reproduction: str) -> bool:
    if RUNNABLE_RE.search(reproduction):
        return True
    for token in re.findall(r"[A-Za-z0-9_./:-]+\.(?:t\.sol|json|md|log)", reproduction):
        if (workspace / token).is_file():
            return True
    return False


def _production_path_verdict(doc: dict[str, Any]) -> str:
    """Extract a conservative candidate-level production-path verdict.

    `deep_candidate.v1` keeps lane-specific payloads free-form on purpose, so
    this accepts a few stable shapes without expanding the schema:

    * lane_payload.production_path.verdict
    * lane_payload.production_path.status
    * lane_payload.production_path_verdict
    * lane_payload.production_path_status
    """
    payload = doc.get("lane_payload")
    if not isinstance(payload, dict):
        return ""

    raw: Any = payload.get("production_path_verdict") or payload.get("production_path_status")
    prod = payload.get("production_path")
    if isinstance(prod, dict):
        raw = raw or prod.get("verdict") or prod.get("status")
    elif isinstance(prod, str):
        raw = raw or prod

    if not isinstance(raw, str):
        return ""
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", raw.strip().upper()).strip("_")
    return normalized


def _dossier_verdict(dossier: dict[str, Any] | None) -> str:
    if not isinstance(dossier, dict):
        return ""
    if dossier.get("submit_verdict") == "unsafe_to_submit":
        return "CONTRADICTED"
    if dossier.get("external_actor_path") == "proven":
        return "PROVEN"
    if dossier.get("external_actor_path") == "source-only":
        return "PRE_DEPLOYMENT_SOURCE_ONLY"
    if dossier.get("external_actor_path") in {"privileged-only", "contradicted"}:
        return "CONTRADICTED"
    return ""


def _candidate_evidence_class(doc: dict[str, Any]) -> str:
    payload = doc.get("lane_payload") if isinstance(doc.get("lane_payload"), dict) else {}
    candidates: list[Any] = [
        doc.get("evidence_class"),
        payload.get("evidence_class"),
    ]
    for key in ("raw_survivor", "raw_candidate", "raw_hit"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            candidates.append(nested.get("evidence_class"))
    for value in candidates:
        if _evidence_class.is_known(value):
            return str(value)
    return ""


def _candidate_origin_requires_proof(doc: dict[str, Any]) -> bool:
    if str(doc.get("lane") or "") == "source_mine":
        return True
    payload = doc.get("lane_payload") if isinstance(doc.get("lane_payload"), dict) else {}
    evidence_class = _candidate_evidence_class(doc)
    if evidence_class in {
        _evidence_class.GENERATED_HYPOTHESIS,
        _evidence_class.SCAFFOLDED_UNVERIFIED,
    }:
        return True
    return any(
        isinstance(payload.get(key), dict)
        for key in ("raw_survivor", "allocation_gate", "outcome_calibrated_routing")
    )


def _source_proof_record(workspace: Path, candidate_id: str) -> dict[str, Any] | None:
    candidates = [workspace / "source_proofs" / _slug(candidate_id) / "source_proof.json"]
    try:
        candidates.extend(sorted(workspace.glob("source_proofs/*/source_proof.json")))
    except OSError:
        pass
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        payload, errs = _load_json(path)
        if errs or not isinstance(payload, dict):
            continue
        if str(payload.get("candidate_id") or "") == candidate_id:
            return payload
    return None


def _execution_manifest_record(workspace: Path, candidate_id: str) -> dict[str, Any] | None:
    try:
        manifests = sorted(workspace.glob("poc_execution/**/execution_manifest.json"))
    except OSError:
        return None
    for path in manifests:
        payload, errs = _load_json(path)
        if errs or not isinstance(payload, dict):
            continue
        if str(payload.get("candidate_id") or "") == candidate_id:
            return payload
    return None


def _proof_evidence_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    source_proof = _source_proof_record(workspace, candidate_id)
    execution_manifest = _execution_manifest_record(workspace, candidate_id)
    source_ok = bool(
        isinstance(source_proof, dict)
        and source_proof.get("final_verdict") == "proved_source_only"
        and source_proof.get("impact_contract_linked") is True
        and str(source_proof.get("oos_status") or "") == "in_scope"
        and int(source_proof.get("valid_source_citation_count") or 0) > 0
    )
    execution_ok = bool(
        isinstance(execution_manifest, dict)
        and _evidence_class.is_at_least(
            execution_manifest.get("evidence_class"),
            _evidence_class.EXECUTED_WITH_MANIFEST,
        )
    )
    return {
        "source_proof_present": isinstance(source_proof, dict),
        "source_proof_ok": source_ok,
        "source_proof_oos_status": (
            str(source_proof.get("oos_status") or "") if isinstance(source_proof, dict) else ""
        ),
        "source_proof_impact_linked": bool(
            isinstance(source_proof, dict) and source_proof.get("impact_contract_linked") is True
        ),
        "execution_manifest_present": isinstance(execution_manifest, dict),
        "execution_manifest_ok": execution_ok,
    }


def _checks(
    *,
    schema_valid: bool,
    files_exist: bool,
    line_cited: bool,
    runnable: bool,
    explicit_markers: list[str],
    production_path_verdict: str,
    production_path_required: bool,
    production_path_dossier: dict[str, Any] | None = None,
    severity_claim: str = "",
    direct_submit_claim: bool = False,
    program_impact_mapping_status: str = "not_applicable",
    impact_contract_status: str = "not_applicable",
    impact_contract_reasons: list[str] | None = None,
    proof_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = {
        "schema_valid": schema_valid,
        "files_exist": files_exist,
        "line_citations_present": line_cited,
        "reproduction_looks_runnable": runnable,
        "explicit_reject_markers": explicit_markers,
        "production_path_verdict": production_path_verdict,
        "production_path_required": production_path_required,
        # PR #535 PR 1: promotion-contract surfacing.
        "severity_claim": severity_claim,
        "direct_submit_claim": direct_submit_claim,
        "program_impact_mapping_status": program_impact_mapping_status,
        "impact_contract_status": impact_contract_status,
        "impact_contract_reasons": impact_contract_reasons or [],
    }
    if proof_evidence:
        out["proof_evidence"] = proof_evidence
    if production_path_dossier:
        out["production_path_dossier"] = production_path_dossier
    return out


def _impact_contract_report(
    doc: dict[str, Any],
    *,
    workspace: Path,
    impact_mapping_lib: Any,
    severity_claim: str,
    contract_required: bool,
) -> dict[str, Any]:
    if not contract_required:
        return {"ok": True, "reasons": [], "status": "not_required"}
    if impact_mapping_lib is None:
        return {
            "ok": False,
            "reasons": ["impact_contract_validator_missing"],
            "status": "missing_mapping",
        }
    payload = doc.get("lane_payload") if isinstance(doc.get("lane_payload"), dict) else {}
    pim_payload = payload.get("program_impact_mapping") if isinstance(payload, dict) else None
    rendered = _synthesize_mapping_markdown(pim_payload)
    contract_text = ""
    if isinstance(payload, dict):
        raw_contract = payload.get("impact_contract")
        if isinstance(raw_contract, dict):
            lines = ["## Impact Contract", ""]
            for key, value in raw_contract.items():
                if isinstance(value, list):
                    lines.append(f"- {key}:")
                    for item in value:
                        lines.append(f"  - {item}")
                else:
                    lines.append(f"- {key}: {value}")
            contract_text = "\n".join(lines)
        elif isinstance(raw_contract, str):
            contract_text = raw_contract
    text = "\n\n".join(p for p in (contract_text, rendered) if p)
    report = impact_mapping_lib.validate_impact_contract_text(
        text,
        workspace=workspace,
        require_contract=True,
    )
    report["status"] = "mapped" if report.get("ok") else "missing_mapping"
    return report


def _workspace_impact_contract_summary(
    *,
    doc: dict[str, Any],
    workspace: Path,
    impact_mapping_lib: Any,
    severity_claim: str,
    direct_submit_claim: bool,
) -> dict[str, Any]:
    if impact_mapping_lib is None or not hasattr(impact_mapping_lib, "impact_contract_summary"):
        required = severity_claim in REPORTABLE_SEVERITIES or direct_submit_claim
        return {
            "required": required,
            "status": "missing_contract" if required else "not_required",
            "selected_impact": "",
            "reasons": ["impact_contract_summary_helper_missing"] if required else [],
        }
    payload = doc.get("lane_payload") if isinstance(doc.get("lane_payload"), dict) else {}
    contracts = payload.get("contracts") if isinstance(payload.get("contracts"), list) else []
    return impact_mapping_lib.impact_contract_summary(
        workspace,
        candidate_id=str(doc.get("candidate_id") or ""),
        angle_id=str(doc.get("candidate_id") or ""),
        contracts=[str(item) for item in contracts if str(item).strip()],
        severity_claim=severity_claim,
        direct_submit=direct_submit_claim,
    )


NEXT_ACTIONS = {
    "schema_invalid": "Fix the typed candidate JSON so it passes deep_candidate.v1 validation.",
    "missing_file": "Attach or correct the cited workspace-relative source file path.",
    "explicit_reject": "Do not promote; resolve the OOS/duplicate/known-FP marker or close the candidate.",
    "missing_line_citation": "Add exact source line citations for every load-bearing claim.",
    "production_path_missing": (
        "Prove external actor -> in-scope precondition -> state transition -> victim impact."
    ),
    "production_path_contradicted": (
        "Do not promote until the contradicted/OOS-only production path is replaced or disproven."
    ),
    "precondition_risk": "Resolve privileged/mock/project-inaction assumptions with code-level evidence.",
    "not_poc_ready": "Keep as investigation until the lane explicitly marks promotion_status=poc_ready.",
    "confidence_not_high": "Raise confidence only after replay/source/scope evidence is verified.",
    "blocking_questions": "Answer or remove every blocking question with cited evidence.",
    "reproduction_missing": "Add a runnable command, replay artifact, or PoC fixture path.",
    "program_impact_mapping_unresolved": (
        "Add a `## Program Impact Mapping` block (or `lane_payload.program_impact_mapping`) "
        "that maps the proof to one exact listed impact sentence in the program rubric. "
        "Severity is derived only from that row; if the proof does not prove it, remove "
        "the impact and keep the candidate NOT_SUBMIT_READY/impact_unresolved."
    ),
}


def _next_actions(categories: list[str]) -> list[str]:
    return [NEXT_ACTIONS[c] for c in categories if c in NEXT_ACTIONS]


def _blocker_counts(verdicts: list[CandidateVerdict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for verdict in verdicts:
        for category in verdict.blocker_categories:
            counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def _work_items(verdicts: list[CandidateVerdict]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for verdict in verdicts:
        if verdict.decision != "needs_poc":
            continue
        items.append(
            {
                "candidate_id": verdict.candidate_id,
                "path": verdict.path,
                "lane": verdict.lane,
                "blocker_categories": verdict.blocker_categories,
                "next_actions": verdict.next_actions,
                "acceptance_checks": [
                    "Re-run promote-typed-candidate on this candidate and confirm blocker clears.",
                    "If a draft is produced, run pre-submit-check and preserve PoC output.",
                    "Do not submit until production path, scope, prior art, and runnable PoC are verified.",
                ],
            }
        )
    return items


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return slug[:120] or "candidate"


def render_tasks_markdown(work_items: list[dict[str, Any]]) -> str:
    lines = [
        "# Candidate PoC Task Queue",
        "",
        "Generated from typed candidate promotion results. These are work items,",
        "not submission approvals.",
        "",
    ]
    if not work_items:
        lines.append("No `needs_poc` work items.")
        lines.append("")
        return "\n".join(lines)
    for idx, item in enumerate(work_items, 1):
        lines.extend([
            f"## {idx}. {item.get('candidate_id') or item.get('path')}",
            "",
            f"- Candidate: `{item.get('path', '')}`",
            f"- Lane: `{item.get('lane', '')}`",
            "- Blockers: " + ", ".join(f"`{b}`" for b in item.get("blocker_categories", [])),
            "- Next actions:",
        ])
        for action in item.get("next_actions", []):
            lines.append(f"  - {action}")
        lines.append("- Acceptance checks:")
        for check in item.get("acceptance_checks", []):
            lines.append(f"  - {check}")
        lines.append("")
    return "\n".join(lines)


def render_dispatch_brief(item: dict[str, Any]) -> str:
    candidate = str(item.get("candidate_id") or item.get("path") or "candidate")
    lines = [
        f"# PoC Dispatch Brief: {candidate}",
        "",
        "This is a work item generated from typed candidate promotion output.",
        "It is not a finding and not submission approval.",
        "",
        "## Candidate",
        "",
        f"- Candidate JSON: `{item.get('path', '')}`",
        f"- Lane: `{item.get('lane', '')}`",
        "- Blockers: " + ", ".join(f"`{b}`" for b in item.get("blocker_categories", [])),
        "",
        "## Model Delegation",
        "",
        "- Claude: build or adapt the smallest runnable PoC/replay and record exact command output.",
        "- Kimi: read the cited source and produce line-cited production-path evidence or explain why it is absent.",
        "- Minimax: adversarially reject OOS, duplicate, mock-only, project-inaction, or missing-impact assumptions.",
        "- Codex: final verifier only; do not submit or mark safe without Codex re-running gates.",
        "",
        "## Required Work",
        "",
    ]
    for action in item.get("next_actions", []):
        lines.append(f"- {action}")
    lines.extend([
        "",
        "## Acceptance Checks",
        "",
    ])
    for check in item.get("acceptance_checks", []):
        lines.append(f"- {check}")
    lines.extend([
        "- Re-run the promotion command and confirm the relevant blocker category is gone.",
        "- Preserve all PoC/replay output in the workspace; do not rely on terminal-only evidence.",
        "",
        "## Guardrails",
        "",
        "- Do not claim bridge/fund impact unless the external production path and victim impact are proven.",
        "- Do not use local-only paths in submission text; inline runnable PoC code when filing.",
        "- If the only path needs admin, guardian, compromised prover, mock verifier, or project inaction, mark UNSAFE_TO_SUBMIT.",
        "",
    ])
    return "\n".join(lines)


def write_dispatch_briefs(work_items: list[dict[str, Any]], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for idx, item in enumerate(work_items, 1):
        candidate = str(item.get("candidate_id") or item.get("path") or f"candidate-{idx}")
        path = out_dir / f"{idx:03d}-{_slug(candidate)}.md"
        path.write_text(render_dispatch_brief(item), encoding="utf-8")
        paths.append(path)
    return paths


def classify(
    path: Path,
    *,
    workspace: Path,
    validator: Any,
    require_line_cite: bool = False,
    require_production_path: bool = False,
    dossier_lib: Any | None = None,
    semantic_graph: dict[str, Any] | None = None,
    impact_mapping_lib: Any | None = None,
) -> CandidateVerdict:
    doc, load_errors = _load_json(path)
    if load_errors or not isinstance(doc, dict):
        return CandidateVerdict(
            path=str(path),
            candidate_id="",
            lane="",
            decision="rejected",
            reasons=load_errors or ["candidate JSON must be an object"],
            missing_files=[],
            precondition_risks=[],
            has_line_citation=False,
            blocker_categories=["schema_invalid"],
            next_actions=_next_actions(["schema_invalid"]),
            checks=_checks(
                schema_valid=False,
                files_exist=False,
                line_cited=False,
                runnable=False,
                explicit_markers=[],
                production_path_verdict="",
                production_path_required=require_production_path,
                production_path_dossier=None,
            ),
        )

    ok, errors = validator.validate(doc)
    dossier: dict[str, Any] | None = None
    if dossier_lib is not None:
        try:
            doc["_path"] = str(path)
            dossier = dossier_lib.build_dossier(doc, workspace=workspace, graph=semantic_graph or {})
        except Exception as exc:  # pragma: no cover - fail-safe advisory path
            dossier = {
                "schema_version": "auditooor.production_path_dossier.v1",
                "candidate_id": str(doc.get("candidate_id", "")),
                "external_actor_path": "contradicted",
                "submit_verdict": "unsafe_to_submit",
                "blockers": ["dossier_build_failed"],
                "error": str(exc),
            }
    cid = str(doc.get("candidate_id", ""))
    lane = str(doc.get("lane", ""))
    if not ok:
        line_cited = _has_line_citation(doc)
        runnable = _reproduction_looks_runnable(workspace, str(doc.get("reproduction", "")))
        explicit_markers = _explicit_reject_markers(doc)
        production_path_verdict = _production_path_verdict(doc)
        production_path_verdict = production_path_verdict or _dossier_verdict(dossier)
        categories = ["schema_invalid"]
        return CandidateVerdict(
            path=str(path),
            candidate_id=cid,
            lane=lane,
            decision="rejected",
            reasons=[f"schema-invalid: {err}" for err in errors],
            missing_files=[],
            precondition_risks=[],
            has_line_citation=line_cited,
            blocker_categories=categories,
            next_actions=_next_actions(categories),
            checks=_checks(
                schema_valid=False,
                files_exist=False,
                line_cited=line_cited,
                runnable=runnable,
                explicit_markers=explicit_markers,
                production_path_verdict=production_path_verdict,
                production_path_required=require_production_path,
                production_path_dossier=dossier,
            ),
        )

    missing = _missing_files(workspace, doc)
    risks = _precondition_risks(doc)
    explicit_markers = _explicit_reject_markers(doc)
    line_cited = _has_line_citation(doc)
    runnable = _reproduction_looks_runnable(workspace, str(doc.get("reproduction", "")))
    production_path_verdict = _production_path_verdict(doc)
    production_path_verdict = production_path_verdict or _dossier_verdict(dossier)

    # PR #535 PR 1: detect reportable severity claims and map them to
    # one of the shared `program_impact_mapping` lib statuses.
    #
    # PR #541 follow-up (Minimax F1): the previous implementation called the
    # inline regex helper ``_candidate_has_mapping_evidence`` which accepted
    # ``lane_payload.program_impact_mapping = "x"`` (a single character) as
    # "mapped". That bypassed the canonical Check #31 gate completely. We now
    # route through the shared ``program_impact_mapping`` lib whenever it is
    # available — same parser as ``program-impact-mapping-check.py``, no
    # forked logic — and only fall back to the conservative inline heuristic
    # when the lib file is absent (older checkouts / stripped CI images).
    severity_claim = _candidate_severity_claim(doc)
    direct_submit_claim = _candidate_claims_direct_submit(doc)
    impact_contract_required = (
        severity_claim in REPORTABLE_SEVERITIES or direct_submit_claim
    )
    program_impact_mapping_status = _classify_mapping_status(
        doc=doc,
        candidate_path=path,
        workspace=workspace,
        severity_claim=severity_claim,
        impact_mapping_lib=impact_mapping_lib,
    )
    impact_contract = _impact_contract_report(
        doc,
        workspace=workspace,
        impact_mapping_lib=impact_mapping_lib,
        severity_claim=severity_claim,
        contract_required=impact_contract_required,
    )
    workspace_impact_contract = _workspace_impact_contract_summary(
        doc=doc,
        workspace=workspace,
        impact_mapping_lib=impact_mapping_lib,
        severity_claim=severity_claim,
        direct_submit_claim=direct_submit_claim,
    )
    impact_contract_status = str(impact_contract.get("status") or "not_applicable")
    impact_contract_reasons = [str(r) for r in impact_contract.get("reasons", [])]
    workspace_impact_contract_status = str(
        workspace_impact_contract.get("status") or "not_applicable"
    )
    workspace_impact_contract_reasons = [
        str(r) for r in workspace_impact_contract.get("reasons", [])
    ]
    proof_evidence = _proof_evidence_status(workspace, cid)

    checks = _checks(
        schema_valid=True,
        files_exist=not missing,
        line_cited=line_cited,
        runnable=runnable,
        explicit_markers=explicit_markers,
        production_path_verdict=production_path_verdict,
        production_path_required=require_production_path,
        production_path_dossier=dossier,
        severity_claim=severity_claim,
        direct_submit_claim=direct_submit_claim,
        program_impact_mapping_status=program_impact_mapping_status,
        impact_contract_status=impact_contract_status,
        impact_contract_reasons=(
            impact_contract_reasons
            + (
                []
                if workspace_impact_contract_status in {"mapped", "not_required"}
                else [f"workspace:{reason}" for reason in workspace_impact_contract_reasons]
            )
        ),
        proof_evidence=proof_evidence,
    )
    reasons: list[str] = []

    if missing:
        categories = ["missing_file"]
        return CandidateVerdict(
            path=str(path),
            candidate_id=cid,
            lane=lane,
            decision="rejected",
            reasons=["candidate cites workspace-relative files that are absent"],
            missing_files=missing,
            precondition_risks=risks,
            has_line_citation=line_cited,
            blocker_categories=categories,
            next_actions=_next_actions(categories),
            checks=checks,
        )

    if explicit_markers:
        categories = ["explicit_reject"]
        return CandidateVerdict(
            path=str(path),
            candidate_id=cid,
            lane=lane,
            decision="rejected",
            reasons=[f"explicit reject marker present: {', '.join(explicit_markers)}"],
            missing_files=missing,
            precondition_risks=risks,
            has_line_citation=line_cited,
            blocker_categories=categories,
            next_actions=_next_actions(categories),
            checks=checks,
        )

    if require_line_cite and not line_cited:
        categories = ["missing_line_citation"]
        return CandidateVerdict(
            path=str(path),
            candidate_id=cid,
            lane=lane,
            decision="rejected",
            reasons=["line citation required but absent"],
            missing_files=missing,
            precondition_risks=risks,
            has_line_citation=line_cited,
            blocker_categories=categories,
            next_actions=_next_actions(categories),
            checks=checks,
        )

    if require_production_path and production_path_verdict in PRODUCTION_PATH_REJECT:
        categories = ["production_path_contradicted"]
        if dossier and dossier.get("submit_verdict") == "unsafe_to_submit":
            categories = sorted(set(categories + [str(b) for b in dossier.get("blockers", [])]))
        return CandidateVerdict(
            path=str(path),
            candidate_id=cid,
            lane=lane,
            decision="rejected",
            reasons=[f"production path verdict is {production_path_verdict}"],
            missing_files=missing,
            precondition_risks=risks,
            has_line_citation=line_cited,
            blocker_categories=categories,
            next_actions=_next_actions(categories),
            checks=checks,
        )

    blocker_categories: list[str] = []
    if lane == "source_mine" and not line_cited:
        blocker_categories.append("missing_line_citation")
        reasons.append("source_mine candidate lacks structured line citation")
    if require_production_path and production_path_verdict not in PRODUCTION_PATH_OK:
        blocker_categories.append("production_path_missing")
        reasons.append(
            "production path not proven at candidate level "
            f"(got {production_path_verdict or 'missing'})"
        )
    if risks:
        blocker_categories.append("precondition_risk")
        reasons.append("precondition-risk terms require explicit scope/production-path review")
    if doc.get("promotion_status") != "poc_ready":
        blocker_categories.append("not_poc_ready")
        reasons.append(f"promotion_status is {doc.get('promotion_status')!r}, not 'poc_ready'")
    if doc.get("confidence") != "high":
        blocker_categories.append("confidence_not_high")
        reasons.append(f"confidence is {doc.get('confidence')!r}, not 'high'")
    if doc.get("blocking_questions"):
        blocker_categories.append("blocking_questions")
        reasons.append("blocking_questions are still open")
    if not runnable:
        blocker_categories.append("reproduction_missing")
        reasons.append("reproduction does not look runnable or artifact-backed")
    if _candidate_origin_requires_proof(doc):
        if not proof_evidence.get("source_proof_ok") and not proof_evidence.get("execution_manifest_ok"):
            blocker_categories.append("source_or_replay_evidence_missing")
            reasons.append(
                "advisory-origin candidate has neither a proved source proof nor an executed replay/harness manifest"
            )
        if proof_evidence.get("source_proof_present") and not proof_evidence.get("source_proof_impact_linked"):
            blocker_categories.append("source_proof_impact_unlinked")
            reasons.append("recorded source proof is not linked to an exact impact contract")
        if proof_evidence.get("source_proof_present") and proof_evidence.get("source_proof_oos_status") != "in_scope":
            blocker_categories.append("source_proof_oos_unresolved")
            reasons.append(
                "recorded source proof is not marked in_scope; OOS status must be resolved before promotion"
            )

    # PR #535 PR 1: reportable candidates without a Program Impact
    # Mapping block are downgraded to ``impact_unresolved`` — a stronger
    # signal than ``needs_poc`` because the proof might be perfectly
    # valid but the severity language is overframed. The operator still
    # has the same `poc_ready`-style detail; the decision label simply
    # tells downstream tooling not to ship severity framing yet.
    impact_unresolved = (
        severity_claim in REPORTABLE_SEVERITIES
        and program_impact_mapping_status != "mapped"
    )
    if impact_unresolved:
        blocker_categories.append("program_impact_mapping_unresolved")
        contract_suffix = ""
        combined_reasons = list(impact_contract_reasons)
        if workspace_impact_contract_status not in {"mapped", "not_required"}:
            combined_reasons.extend(
                f"workspace:{reason}" for reason in workspace_impact_contract_reasons
            )
        if combined_reasons:
            contract_suffix = f"; impact_contract_reasons={','.join(combined_reasons)}"
        reasons.append(
            f"severity_claim={severity_claim} but no Program Impact Mapping "
            f"evidence proving one exact selected impact sentence was found "
            f"(status={program_impact_mapping_status})"
        )

    if impact_unresolved:
        decision = "impact_unresolved"
    elif reasons:
        decision = "needs_poc"
    else:
        decision = "poc_ready"
    if decision == "poc_ready":
        reasons.append("schema-valid high-confidence poc_ready candidate with present source files")

    return CandidateVerdict(
        path=str(path),
        candidate_id=cid,
        lane=lane,
        decision=decision,
        reasons=reasons,
        missing_files=missing,
        precondition_risks=risks,
        has_line_citation=line_cited,
        blocker_categories=blocker_categories,
        next_actions=_next_actions(blocker_categories),
        checks=checks,
    )


def render_markdown(verdicts: list[CandidateVerdict]) -> str:
    lines = [
        "# Typed Candidate Promotion Report",
        "",
        "This report sorts typed deep-lane candidates. It does not approve",
        "submissions; `poc_ready` still requires normal pre-submit gates.",
        "",
        "## Blocker Summary",
        "",
    ]
    counts = _blocker_counts(verdicts)
    if counts:
        for category, count in counts.items():
            lines.append(f"- `{category}`: {count}")
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Candidate Queue",
        "",
        "| Decision | Lane | Candidate | Blockers | Next Actions | Reasons |",
        "|---|---|---|---|---|---|",
    ])
    for item in verdicts:
        reasons = "<br>".join(item.reasons) if item.reasons else ""
        blockers = "<br>".join(f"`{b}`" for b in item.blocker_categories) or ""
        actions = "<br>".join(item.next_actions) or ""
        lines.append(
            f"| {item.decision} | {item.lane or ''} | `{item.candidate_id or item.path}` | "
            f"{blockers} | {actions} | {reasons} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("candidates", nargs="*", type=Path)
    parser.add_argument(
        "--require-line-cite",
        action="store_true",
        help="Reject candidates that do not carry a structured line citation in lane_payload.",
    )
    parser.add_argument(
        "--require-production-path",
        action="store_true",
        help=(
            "Keep otherwise-ready candidates in needs_poc unless lane_payload "
            "contains a proven external/in-scope production-path verdict."
        ),
    )
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-tasks-json", type=Path)
    parser.add_argument("--out-tasks-md", type=Path)
    parser.add_argument(
        "--out-brief-dir",
        type=Path,
        help="Write one dispatch-ready markdown brief per needs_poc work item.",
    )
    parser.add_argument(
        "--out-dossier-dir",
        type=Path,
        help="Write production_path_dossier.json files for each candidate.",
    )
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    validator = _load_validator()
    dossier_lib = _load_dossier_lib()
    semantic_graph = dossier_lib.load_graph(workspace)
    impact_mapping_lib = _load_impact_mapping_lib()
    paths = _candidate_paths(workspace, args.candidates)
    verdicts = [
        classify(
            path,
            workspace=workspace,
            validator=validator,
            require_line_cite=args.require_line_cite,
            require_production_path=args.require_production_path,
            dossier_lib=dossier_lib,
            semantic_graph=semantic_graph,
            impact_mapping_lib=impact_mapping_lib,
        )
        for path in paths
    ]
    work_items = _work_items(verdicts)
    payload = {
        "schema_version": "auditooor.promote_typed_candidate.v1",
        "workspace": str(workspace),
        "candidate_count": len(verdicts),
        "decision_counts": {
            decision: sum(1 for v in verdicts if v.decision == decision)
            for decision in ("poc_ready", "needs_poc", "rejected", "impact_unresolved")
        },
        "blocker_counts": _blocker_counts(verdicts),
        "work_items": work_items,
        "verdicts": [asdict(v) for v in verdicts],
    }

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(verdicts), encoding="utf-8")
    if args.out_tasks_json:
        args.out_tasks_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_tasks_json.write_text(json.dumps(work_items, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_tasks_md:
        args.out_tasks_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_tasks_md.write_text(render_tasks_markdown(work_items), encoding="utf-8")
    if args.out_brief_dir:
        write_dispatch_briefs(work_items, args.out_brief_dir)
    if args.out_dossier_dir:
        args.out_dossier_dir.mkdir(parents=True, exist_ok=True)
        for verdict in verdicts:
            dossier = verdict.checks.get("production_path_dossier")
            if not isinstance(dossier, dict):
                continue
            candidate = verdict.candidate_id or Path(verdict.path).stem
            safe = _slug(candidate)
            (args.out_dossier_dir / f"{safe}.production_path_dossier.json").write_text(
                json.dumps(dossier, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
