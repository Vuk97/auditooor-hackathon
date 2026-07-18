#!/usr/bin/env python3
"""Base critical-candidate matrix generator (PR #544 Phase 1, Lane H).

Reads Base Azul (or any) workspace artifacts and emits a conservative
matrix of Critical-severity candidates. Default-to-kill semantics:
**no row is promoted to ``executable`` unless every gate is satisfied**.

Inputs (best-effort, all optional):
  <ws>/SEVERITY*.md, <ws>/RUBRIC_COVERAGE.md
      Listed Critical-severity impact bullets used to validate
      ``impact_mapping`` for each candidate.
  <ws>/.auditooor/invariant_ledger.json
      Invariant ledger emitted by tools/invariant-ledger.py.
  <ws>/submissions/SUBMISSIONS.md, <ws>/submissions/*.json
      Existing submission ledger; rows already filed are still
      surfaced for traceability but never re-promoted.
  <ws>/critical_hunt/candidates/*.json
      Critical-hunt seed candidates (this is the primary source).
  <ws>/audit/prior-audits/*.md, <ws>/docs/*PRIOR_AUDIT*.md
      Prior-audit ingest documents — surfaced as ``artifact_refs``
      and used to flag pure-restate dupes (warn only).
  <ws>/poc_execution/**/execution_manifest.json
      Required for ``candidate_status=executable``.
  <ws>/.auditooor/closeout_manifest.json,
  <ws>/.auditooor/audit_closeout_manifest.json,
  <ws>/audit/closeout/*.json
      Closeout manifests — surfaced as ``artifact_refs``.

Outputs (under ``<ws>/critical_hunt/``):
  base_critical_candidate_matrix.json
  base_critical_candidate_matrix.md

Hard rules:
  * Default any row without an exact ``impact_mapping`` entry that equals
    one workspace severity-rubric Critical bullet to
    ``candidate_status=kill_or_reframe``.
  * Severity is derived only from that selected impact row. A Critical row
    with ``listed_impact_proven != true`` is NOT_SUBMIT_READY and stays
    ``kill_or_reframe`` even if a component PoC or execution manifest exists.
  * Mock-only evidence (artifacts containing the literal token
    "mock" with no real-component artifact reference) downgrades
    to ``candidate_status=blocked_real_component``.
  * Snappy / gossip decode rows are never Critical or direct-submit-ready
    unless structured evidence proves the exact selected resource-impact
    sentence: >=30% node resource consumption under realistic
    non-bruteforce conditions, or a quantified >=30% node-shutdown
    threshold. Mempool impact is not applicable to Snappy gossip decode.

Stdlib-only. Idempotent. Offline-safe.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.base_critical_candidate_matrix.v1"

REQUIRED_FIELDS = (
    "candidate_id",
    "scope_asset",
    "impact_mapping",
    "candidate_status",
    "production_path",
    "required_proof",
    "artifact_refs",
)

# Wave 6 Worker L (PR #556 §Priority 4) — additive severity-claim discipline
# fields. Every field is optional with a conservative default; legacy rows
# without these fields are still valid and never auto-promoted.
WAVE6L_DISCIPLINE_FIELDS = (
    "listed_impact_selected",
    "listed_impact_proven",
    "network_level_evidence",
    "component_poc_only",
)

VALID_STATUSES = ("executable", "kill_or_reframe", "blocked_real_component")

SEVERITY_FILES = (
    "SEVERITY.md",
    "SEVERITY_SMART_CONTRACTS.md",
    "SEVERITY_BLOCKCHAIN_DLT.md",
    "RUBRIC_COVERAGE.md",
)

CRITICAL_HEADING_RE = re.compile(
    r"^\s*#{1,6}\s*(?:critical|severity:\s*critical)\b",
    re.IGNORECASE,
)
SEVERITY_HEADING_RE = re.compile(r"^\s*#{1,6}\s*(.+?)\s*$")
BULLET_RE = re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
CRITICAL_KEYWORDS = ("critical", "loss of all funds", "permanent freeze")
MOCK_TOKEN_RE = re.compile(r"\bmock(?:-only|\b)", re.IGNORECASE)
REAL_COMPONENT_HINTS = (
    "external/",
    "src/",
    "contracts/",
    "lib/",
    "rust/",
)
SNAPPY_RE = re.compile(
    r"\b(snappy|decompress_vec|gossip decode|decode-bomb|decode bomb)\b",
    re.IGNORECASE,
)
MEMPOOL_RE = re.compile(r"\bmempool\b", re.IGNORECASE)
RESOURCE_IMPACT_RE = re.compile(r"node resource consumption|resource consumption", re.IGNORECASE)
SHUTDOWN_IMPACT_RE = re.compile(r"shutdown.*nodes?|nodes?.*shutdown", re.IGNORECASE)


@dataclass
class Row:
    candidate_id: str
    scope_asset: str
    impact_mapping: str
    candidate_status: str
    production_path: str
    required_proof: str
    artifact_refs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw_severity: str = ""
    has_execution_manifest: bool = False
    has_real_component_artifact: bool = False
    matches_listed_critical: bool = False
    # Wave 6 Worker L (PR #556 §Priority 4) — severity-claim discipline.
    # `listed_impact_selected` is the verbatim impact-line text the
    # candidate claims to map to (typically a row from SEVERITY*.md).
    # `listed_impact_proven` is True only after a network-level PoC has
    # demonstrated the listed impact end-to-end; defaults False.
    # `network_level_evidence` is a path string or "absent".
    # `component_poc_only` is True when only an isolated component-level
    # PoC exists; defaults True (conservative).
    listed_impact_selected: str = ""
    listed_impact_proven: bool = False
    network_level_evidence: str = "absent"
    component_poc_only: bool = True
    exact_impact_sentence_selected: bool = False
    node_resource_consumption_pct: float | None = None
    shutdown_nodes_pct: float | None = None
    realistic_non_bruteforce: bool = False
    severity_claim_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Severity rubric loading
# ---------------------------------------------------------------------------


def load_listed_critical_impacts(workspace: Path) -> list[str]:
    """Return the verbatim bullet text under any Critical heading.

    Looks at every known severity file. Returns lowercase-trimmed
    strings so callers can do case-insensitive containment checks.
    """
    found: list[str] = []
    for name in SEVERITY_FILES:
        path = workspace / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_critical = False
        for raw_line in text.splitlines():
            heading = SEVERITY_HEADING_RE.match(raw_line)
            if heading:
                in_critical = bool(CRITICAL_HEADING_RE.match(raw_line))
                continue
            if not in_critical:
                continue
            bullet = BULLET_RE.match(raw_line)
            if bullet:
                token = bullet.group(1).strip().lower()
                if token:
                    found.append(token)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _norm_sentence(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def matches_listed_critical(impact_mapping: str, listed: list[str]) -> bool:
    """Return True iff ``impact_mapping`` equals one listed Critical bullet."""
    if not impact_mapping or not impact_mapping.strip():
        return False
    if not listed:
        return False
    needle = _norm_sentence(impact_mapping)
    for bullet in listed:
        if not bullet:
            continue
        if needle == _norm_sentence(bullet):
            return True
    return False


# ---------------------------------------------------------------------------
# Candidate loading
# ---------------------------------------------------------------------------


def load_candidates(workspace: Path) -> list[dict[str, Any]]:
    """Return list of raw candidate dicts.

    Looks under <ws>/critical_hunt/candidates/*.json, plus any
    JSON file with a top-level ``candidates: []`` key under
    <ws>/critical_hunt/.
    """
    out: list[dict[str, Any]] = []
    cand_dir = workspace / "critical_hunt" / "candidates"
    if cand_dir.is_dir():
        for path in sorted(cand_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                data.setdefault("_source_path", str(path.relative_to(workspace)))
                out.append(data)
            elif isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        entry.setdefault(
                            "_source_path", str(path.relative_to(workspace))
                        )
                        out.append(entry)
    aggregate = workspace / "critical_hunt" / "candidates.json"
    if aggregate.is_file():
        try:
            data = json.loads(aggregate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            inner = data.get("candidates")
            if isinstance(inner, list):
                for entry in inner:
                    if isinstance(entry, dict):
                        entry.setdefault(
                            "_source_path", "critical_hunt/candidates.json"
                        )
                        out.append(entry)
    return out


def collect_artifact_refs(workspace: Path, candidate: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    explicit = candidate.get("artifact_refs") or candidate.get("artifacts") or []
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, str) and item:
                refs.append(item)
    src = candidate.get("_source_path")
    if isinstance(src, str) and src and src not in refs:
        refs.append(src)
    cand_id = (
        candidate.get("candidate_id")
        or candidate.get("id")
        or candidate.get("title")
        or ""
    )
    if cand_id:
        for manifest in workspace.glob("poc_execution/**/execution_manifest.json"):
            text = manifest.read_text(encoding="utf-8", errors="replace")
            if str(cand_id).lower() in text.lower():
                rel = str(manifest.relative_to(workspace))
                if rel not in refs:
                    refs.append(rel)
    closeouts = (
        workspace / ".auditooor" / "closeout_manifest.json",
        workspace / ".auditooor" / "audit_closeout_manifest.json",
    )
    for path in closeouts:
        if path.is_file():
            rel = str(path.relative_to(workspace))
            if rel not in refs:
                refs.append(rel)
    closeout_dir = workspace / "audit" / "closeout"
    if closeout_dir.is_dir():
        for path in sorted(closeout_dir.glob("*.json")):
            rel = str(path.relative_to(workspace))
            if rel not in refs:
                refs.append(rel)
    prior_dir = workspace / "audit" / "prior-audits"
    if prior_dir.is_dir():
        for path in sorted(prior_dir.glob("*.md")):
            rel = str(path.relative_to(workspace))
            if rel not in refs:
                refs.append(rel)
    docs_dir = workspace / "docs"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.glob("*PRIOR_AUDIT*.md")):
            rel = str(path.relative_to(workspace))
            if rel not in refs:
                refs.append(rel)
    return refs


def has_execution_manifest(workspace: Path, refs: list[str]) -> bool:
    for ref in refs:
        if "poc_execution/" in ref and ref.endswith("execution_manifest.json"):
            full = workspace / ref
            if full.is_file():
                return True
    return False


def has_real_component_artifact(refs: list[str]) -> bool:
    for ref in refs:
        for hint in REAL_COMPONENT_HINTS:
            if ref.startswith(hint) or f"/{hint}" in ref:
                return True
    return False


def has_mock_only_evidence(candidate: dict[str, Any], refs: list[str]) -> bool:
    body = json.dumps(candidate, ensure_ascii=False).lower()
    if MOCK_TOKEN_RE.search(body):
        # Mock tagged in the candidate body.
        if not has_real_component_artifact(refs):
            return True
        # Allow when the candidate explicitly cites a real component artifact too.
        return False
    # Also scan refs themselves for "mock" naming.
    for ref in refs:
        if MOCK_TOKEN_RE.search(ref):
            if not has_real_component_artifact(refs):
                return True
    return False


# ---------------------------------------------------------------------------
# Status decision
# ---------------------------------------------------------------------------


def decide_status(
    candidate: dict[str, Any],
    listed_critical: list[str],
    refs: list[str],
    workspace: Path,
) -> tuple[str, list[str], dict[str, bool]]:
    """Apply the default-to-kill decision tree.

    Returns (status, notes, flags).
    """
    notes: list[str] = []
    impact = (candidate.get("impact_mapping") or candidate.get("impact") or "").strip()
    raw_severity = (candidate.get("severity") or "").strip().lower()
    (
        listed_impact_selected,
        listed_impact_proven,
        _network_level_evidence,
        _component_poc_only,
    ) = extract_discipline_fields(candidate)
    selected_sentence = listed_impact_selected or impact

    matches = matches_listed_critical(impact, listed_critical)
    selected_exact = matches_listed_critical(selected_sentence, listed_critical)
    has_manifest = has_execution_manifest(workspace, refs)
    has_real = has_real_component_artifact(refs)
    is_mock_only = has_mock_only_evidence(candidate, refs)

    flags = {
        "matches_listed_critical": matches,
        "has_execution_manifest": has_manifest,
        "has_real_component_artifact": has_real,
        "is_mock_only": is_mock_only,
        "exact_impact_sentence_selected": selected_exact,
    }

    # 1. No impact mapping at all -> kill_or_reframe.
    if not impact:
        notes.append("default-to-kill: empty impact_mapping")
        return "kill_or_reframe", notes, flags

    # 2. Critical wording but not on the listed Critical rubric -> kill_or_reframe.
    if not matches:
        if any(kw in (impact + " " + raw_severity).lower() for kw in CRITICAL_KEYWORDS):
            notes.append(
                "default-to-kill: claimed Critical wording without exact listed rubric impact sentence"
            )
        else:
            notes.append(
                "default-to-kill: impact_mapping is not an exact Critical bullet"
            )
        return "kill_or_reframe", notes, flags

    # 2b. The selected impact sentence is the severity source of truth.
    if not selected_exact:
        notes.append(
            "NOT_SUBMIT_READY: no exact Base Azul program impact sentence selected; "
            "remove impact/severity framing or select one verbatim row"
        )
        return "kill_or_reframe", notes, flags

    # 3. Mock-only evidence -> blocked_real_component.
    if is_mock_only:
        notes.append("blocked: mock-only evidence; no real-component artifact cited")
        return "blocked_real_component", notes, flags

    # 4. Executable requires execution manifest AND explicit impact AND proof
    # that the exact selected impact sentence was demonstrated.
    if has_manifest and matches:
        if not listed_impact_proven:
            notes.append(
                "NOT_SUBMIT_READY: execution manifest exists but listed_impact_proven "
                "is not true; kill_or_reframe and remove impact until the proof "
                "demonstrates the exact selected sentence"
            )
            return "kill_or_reframe", notes, flags
        notes.append(
            "executable: execution manifest present, exact impact sentence selected, "
            "and listed_impact_proven=true"
        )
        return "executable", notes, flags

    # 5. Otherwise blocked on missing real-component proof.
    notes.append("blocked: no execution manifest; required_proof must be produced")
    return "blocked_real_component", notes, flags


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------


def _coerce_bool(value: Any, default: bool) -> bool:
    """Coerce JSON-ish values to bool. Strings 'true'/'false' map directly.

    Numbers, None, and unrecognised strings fall back to ``default``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n"):
            return False
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def extract_discipline_fields(
    candidate: dict[str, Any],
) -> tuple[str, bool, str, bool]:
    """Return (listed_impact_selected, listed_impact_proven,
    network_level_evidence, component_poc_only).

    Conservative defaults: empty selected, not proven, evidence absent,
    component-only True. Wave 6 Worker L (PR #556 §Priority 4).
    """
    listed_selected_raw = candidate.get("listed_impact_selected")
    listed_selected = (
        listed_selected_raw.strip()
        if isinstance(listed_selected_raw, str)
        else ""
    )
    listed_proven = _coerce_bool(candidate.get("listed_impact_proven"), False)
    nle_raw = candidate.get("network_level_evidence")
    if isinstance(nle_raw, str) and nle_raw.strip():
        network_level_evidence = nle_raw.strip()
    else:
        network_level_evidence = "absent"
    component_only = _coerce_bool(candidate.get("component_poc_only"), True)
    return listed_selected, listed_proven, network_level_evidence, component_only


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().rstrip("%")
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def extract_snappy_measurements(
    candidate: dict[str, Any],
) -> tuple[float | None, float | None, bool]:
    """Return structured node-resource proof fields for Snappy/gossip rows."""
    resource_pct: float | None = None
    for key in (
        "node_resource_consumption_pct",
        "node_resource_consumption_delta_pct",
        "resource_consumption_pct",
        "resource_consumption_delta_pct",
    ):
        resource_pct = _coerce_float(candidate.get(key))
        if resource_pct is not None:
            break
    shutdown_pct: float | None = None
    for key in (
        "shutdown_nodes_pct",
        "node_shutdown_pct",
        "shutdown_threshold_nodes_pct",
    ):
        shutdown_pct = _coerce_float(candidate.get(key))
        if shutdown_pct is not None:
            break
    realistic = _coerce_bool(candidate.get("realistic_non_bruteforce"), False)
    return resource_pct, shutdown_pct, realistic


def snappy_claim_warnings(
    candidate: dict[str, Any],
    severity: str,
    selected_impact: str,
    network_level_evidence: str,
    component_only: bool,
    resource_pct: float | None,
    shutdown_pct: float | None,
    realistic_non_bruteforce: bool,
) -> list[str]:
    """Return hard-rule notes for Snappy/gossip decode impact overclaims."""
    blob = json.dumps(candidate, ensure_ascii=False)
    if not SNAPPY_RE.search(blob):
        return []
    warns: list[str] = []
    if MEMPOOL_RE.search(blob):
        warns.append(
            "NOT_SUBMIT_READY: mempool impact is not applicable to Snappy "
            "gossip decode; remove mempool impact framing"
        )
    if severity.strip().lower() != "critical":
        return warns
    impact_is_resource = bool(RESOURCE_IMPACT_RE.search(selected_impact))
    impact_is_shutdown = bool(SHUTDOWN_IMPACT_RE.search(selected_impact))
    resource_ok = resource_pct is not None and resource_pct >= 30.0
    shutdown_ok = shutdown_pct is not None and shutdown_pct >= 30.0
    if not (impact_is_resource or impact_is_shutdown):
        warns.append(
            "NOT_SUBMIT_READY: Snappy Critical claim must select the exact "
            "node resource consumption or node-shutdown listed impact sentence"
        )
    if not (resource_ok or shutdown_ok):
        warns.append(
            "NOT_SUBMIT_READY: Snappy Critical claim lacks measured >=30% "
            "node resource consumption or quantified >=30% node-shutdown threshold"
        )
    if not realistic_non_bruteforce:
        warns.append(
            "NOT_SUBMIT_READY: Snappy Critical claim lacks realistic "
            "non-bruteforce conditions"
        )
    if component_only or not network_level_evidence or network_level_evidence == "absent":
        warns.append(
            "NOT_SUBMIT_READY: Snappy component PoC is not direct-submit-ready; "
            "network-level evidence is required"
        )
    return warns


def severity_claim_warnings(
    severity: str,
    listed_proven: bool,
    network_level_evidence: str,
    component_only: bool,
) -> list[str]:
    """Per-row Wave 6 L validator.

    Returns a list of warning strings for any Critical row that does
    not yet have `listed_impact_proven=true`. Lower-severity rows do
    not trigger warnings here; only the explicit pre-submit guard
    enforces the claim discipline at submit time.
    """
    warns: list[str] = []
    if severity.strip().lower() != "critical":
        return warns
    if not listed_proven:
        warns.append(
            "wave6L: severity=Critical but listed_impact_proven=false "
            "(NOT_SUBMIT_READY/kill_or_reframe; remove impact until the "
            "exact selected sentence is proven)"
        )
    if component_only and (
        not network_level_evidence or network_level_evidence == "absent"
    ):
        warns.append(
            "wave6L: component_poc_only=true and network_level_evidence absent "
            "for Critical row"
        )
    return warns


def build_row(
    candidate: dict[str, Any],
    listed_critical: list[str],
    workspace: Path,
) -> Row:
    cand_id = str(
        candidate.get("candidate_id")
        or candidate.get("id")
        or candidate.get("title")
        or candidate.get("_source_path")
        or "UNKNOWN"
    )
    scope_asset = str(
        candidate.get("scope_asset")
        or candidate.get("asset")
        or candidate.get("contract")
        or "unknown"
    )
    impact = str(candidate.get("impact_mapping") or candidate.get("impact") or "").strip()
    production_path = str(
        candidate.get("production_path") or candidate.get("path") or ""
    ).strip()
    required_proof = str(
        candidate.get("required_proof")
        or candidate.get("proof_plan")
        or candidate.get("proof")
        or ""
    ).strip()
    if not required_proof:
        required_proof = (
            "Produce a real-component PoC (poc_execution manifest) that "
            "demonstrates the listed Critical impact end-to-end."
        )

    refs = collect_artifact_refs(workspace, candidate)
    status, notes, flags = decide_status(candidate, listed_critical, refs, workspace)

    raw_severity = str(candidate.get("severity") or "")
    (
        listed_impact_selected,
        listed_impact_proven,
        network_level_evidence,
        component_poc_only,
    ) = extract_discipline_fields(candidate)
    selected_sentence = listed_impact_selected or impact
    (
        node_resource_consumption_pct,
        shutdown_nodes_pct,
        realistic_non_bruteforce,
    ) = extract_snappy_measurements(candidate)
    claim_warns = severity_claim_warnings(
        raw_severity,
        listed_impact_proven,
        network_level_evidence,
        component_poc_only,
    )
    snappy_warns = snappy_claim_warnings(
        candidate,
        raw_severity,
        selected_sentence,
        network_level_evidence,
        component_poc_only,
        node_resource_consumption_pct,
        shutdown_nodes_pct,
        realistic_non_bruteforce,
    )
    if snappy_warns and raw_severity.strip().lower() == "critical":
        status = "kill_or_reframe"
    if any("mempool impact is not applicable" in w for w in snappy_warns):
        status = "kill_or_reframe"
    exact_selected = flags.get("exact_impact_sentence_selected", False)
    notes = notes + list(claim_warns) + list(snappy_warns)

    return Row(
        candidate_id=cand_id,
        scope_asset=scope_asset,
        impact_mapping=impact,
        candidate_status=status,
        production_path=production_path,
        required_proof=required_proof,
        artifact_refs=refs,
        notes=notes,
        raw_severity=raw_severity,
        has_execution_manifest=flags["has_execution_manifest"],
        has_real_component_artifact=flags["has_real_component_artifact"],
        matches_listed_critical=flags["matches_listed_critical"],
        listed_impact_selected=listed_impact_selected,
        listed_impact_proven=listed_impact_proven,
        network_level_evidence=network_level_evidence,
        component_poc_only=component_poc_only,
        exact_impact_sentence_selected=exact_selected,
        node_resource_consumption_pct=node_resource_consumption_pct,
        shutdown_nodes_pct=shutdown_nodes_pct,
        realistic_non_bruteforce=realistic_non_bruteforce,
        severity_claim_warnings=list(claim_warns) + list(snappy_warns),
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_markdown(rows: list[Row], listed: list[str]) -> str:
    lines: list[str] = []
    lines.append("# Base Critical-Candidate Matrix")
    lines.append("")
    lines.append(f"_Schema: `{SCHEMA_VERSION}`_")
    lines.append("")
    lines.append(
        "Default semantics: every row without an exact rubric-listed Critical "
        "impact sentence starts as `kill_or_reframe`. Rows are only promoted "
        "to `executable` when an execution manifest exists **and** the impact "
        "matches one of the workspace Critical bullets verbatim **and** "
        "`listed_impact_proven=true`."
    )
    lines.append(
        "Snappy / gossip decode rows are never Critical or direct-submit-ready "
        "from component evidence alone; they need measured >=30% node resource "
        "consumption under realistic non-bruteforce conditions or a quantified "
        ">=30% node-shutdown threshold. Mempool impact is not applicable."
    )
    lines.append("")
    lines.append("## Listed Critical Impacts (Rubric)")
    lines.append("")
    if listed:
        for bullet in listed:
            lines.append(f"- {bullet}")
    else:
        lines.append("- _(none found in SEVERITY*.md / RUBRIC_COVERAGE.md)_")
    lines.append("")
    counts: dict[str, int] = {s: 0 for s in VALID_STATUSES}
    for row in rows:
        counts[row.candidate_status] = counts.get(row.candidate_status, 0) + 1
    lines.append("## Status Counts")
    lines.append("")
    for status in VALID_STATUSES:
        lines.append(f"- `{status}`: {counts.get(status, 0)}")
    lines.append("")
    lines.append("## Candidates")
    lines.append("")
    if not rows:
        lines.append("_No candidates found._")
        return "\n".join(lines) + "\n"
    lines.append(
        "| candidate_id | scope_asset | candidate_status | impact_mapping | "
        "production_path | artifact_refs |"
    )
    lines.append("|---|---|---|---|---|---|")
    for row in rows:
        refs_cell = ", ".join(row.artifact_refs) if row.artifact_refs else "_none_"
        lines.append(
            "| `{cid}` | {asset} | `{status}` | {impact} | {path} | {refs} |".format(
                cid=row.candidate_id,
                asset=row.scope_asset,
                status=row.candidate_status,
                impact=row.impact_mapping or "_(empty)_",
                path=row.production_path or "_(empty)_",
                refs=refs_cell,
            )
        )
    lines.append("")
    lines.append("### Notes per row")
    lines.append("")
    for row in rows:
        lines.append(f"#### `{row.candidate_id}`")
        lines.append("")
        lines.append(f"- required_proof: {row.required_proof}")
        for note in row.notes:
            lines.append(f"- note: {note}")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_outputs(
    workspace: Path,
    rows: list[Row],
    listed: list[str],
) -> tuple[Path, Path]:
    out_dir = workspace / "critical_hunt"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "base_critical_candidate_matrix.json"
    md_path = out_dir / "base_critical_candidate_matrix.md"
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "listed_critical_impacts": listed,
        "status_counts": {
            status: sum(1 for r in rows if r.candidate_status == status)
            for status in VALID_STATUSES
        },
        "rows": [asdict(r) for r in rows],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(rows, listed), encoding="utf-8")
    return json_path, md_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_matrix(workspace: Path) -> tuple[list[Row], list[str]]:
    listed = load_listed_critical_impacts(workspace)
    candidates = load_candidates(workspace)
    rows = [build_row(c, listed, workspace) for c in candidates]
    return rows, listed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-critical-candidate-matrix.py",
        description=(
            "Generate the Base critical-candidate matrix with default-to-kill "
            "semantics. Stdlib-only, idempotent."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Emit the JSON payload to stdout in addition to writing files.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any row carries Critical wording but ends up "
        "kill_or_reframe (useful in CI on a clean workspace).",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[base-critical-candidate-matrix] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows, listed = build_matrix(workspace)
    json_path, md_path = write_outputs(workspace, rows, listed)
    print(f"[base-critical-candidate-matrix] wrote {json_path.relative_to(workspace)}")
    print(f"[base-critical-candidate-matrix] wrote {md_path.relative_to(workspace)}")
    print(
        "[base-critical-candidate-matrix] status counts: "
        + ", ".join(
            f"{s}={sum(1 for r in rows if r.candidate_status == s)}"
            for s in VALID_STATUSES
        )
    )

    if args.print_json:
        sys.stdout.write(json_path.read_text(encoding="utf-8"))

    if args.strict:
        flagged = [
            r
            for r in rows
            if r.candidate_status == "kill_or_reframe"
            and any(
                kw in (r.impact_mapping + " " + r.raw_severity).lower()
                for kw in CRITICAL_KEYWORDS
            )
        ]
        if flagged:
            print(
                "[base-critical-candidate-matrix] STRICT FAIL: "
                f"{len(flagged)} row(s) carried Critical wording without rubric match",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
