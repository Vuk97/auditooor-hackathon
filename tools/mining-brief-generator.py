#!/usr/bin/env python3
"""
mining-brief-generator.py — Generate enhanced mining briefs from prioritized angles

Reads CCIA attack angles + mining-prioritizer scores and produces focused
agent briefs with:
  - Specific contract/function targets
  - Cross-workspace pattern context
  - Prior submission overlap warnings
  - OOS checklist verification points
  - Expected bug class and PoC approach

Usage:
    mining-brief-generator.py <workspace> --top N --out-dir <dir>
    mining-brief-generator.py ~/audits/snowbridge --top 5 --out-dir ~/audits/snowbridge/swarm

Output:
    brief_001_A-REENT.md, brief_002_A-ORACLE.md, ...
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from submission_ledger import load_submission_entries
from submission_paths import find_submission_file
from lib import program_impact_mapping as impact_mapping
from dispatch_oos_preflight import REDUCED_SEVERITY, evaluate_preflight, render_markdown

AUDITOOOR_DIR = Path(__file__).parent.parent


def rust_contract_from_file(file_path: str) -> str:
    parts = file_path.replace("\\", "/").split("/")
    if "contracts" in parts:
        idx = parts.index("contracts")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return parts[-1] if parts else ""


def rust_angle_severity(angle_id: str, confidence: str) -> str:
    if confidence.lower() == "medium" and angle_id in {"A-AUTH", "A-ORACLE"}:
        return "HIGH"
    return "MEDIUM"


def normalize_ccia_rust_angles(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = payload.get("angles", [])
    if not isinstance(rows, list):
        return []

    angles: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        angle_id = str(row.get("angle") or "").strip()
        if not angle_id:
            continue
        file_path = str(row.get("file") or "")
        confidence = str(row.get("confidence") or "")
        contract = rust_contract_from_file(file_path)
        reason = str(row.get("reason") or angle_id)
        title = reason
        if file_path:
            title = f"{reason} ({file_path}:{row.get('line', 0)})"
        angles.append({
            "id": angle_id,
            "severity": rust_angle_severity(angle_id, confidence),
            "title": title,
            "contracts": [contract] if contract else [],
            "source": "ccia-rust",
            "file": file_path,
            "line": row.get("line", 0),
            "confidence": confidence,
            "reason": reason,
            "snippet": row.get("snippet", ""),
        })
    return angles


def load_ccia_rust(ws: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    candidates = [ws / "ccia_rust_report.json"]
    audit_dir = ws / "audit"
    if audit_dir.is_dir():
        candidates.extend(sorted(audit_dir.glob("ccia_rust_*.json"), reverse=True))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(payload, dict):
            continue
        angles = normalize_ccia_rust_angles(payload)
        if angles:
            return {
                "lang": payload.get("lang", "rust"),
                "workspace": payload.get("workspace", str(ws)),
                "total_files_scanned": payload.get("total_files_scanned", 0),
                "source": str(path),
            }, angles
    return {}, []


def load_ccia(ws: Path) -> Tuple[Dict, List[Dict]]:
    """Load CCIA data and attack angles, including Rust/Soroban fallback."""
    json_path = ws / "ccia_report.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        if isinstance(data, dict):
            angles = data.get("attack_angles", [])
            if angles:
                return data.get("ccia", {}), angles
            rust_ccia, rust_angles = load_ccia_rust(ws)
            if rust_angles:
                return rust_ccia, rust_angles
            return data.get("ccia", {}), []
        if isinstance(data, list) and data:
            return {}, data
        rust_ccia, rust_angles = load_ccia_rust(ws)
        if rust_angles:
            return rust_ccia, rust_angles
        return {}, []
    # Prefer the structured angle dossier when the legacy root JSON is absent.
    # Markdown headings omit contract/file identity and can produce unusable
    # UNKNOWN targets that cannot carry proof context downstream.
    angle_path = ws / ".auditooor" / "ccia_attack_angles.json"
    if angle_path.is_file():
        try:
            angle_data = json.loads(angle_path.read_text())
        except (json.JSONDecodeError, OSError):
            angle_data = None
        if isinstance(angle_data, list) and angle_data:
            return {}, angle_data
        if isinstance(angle_data, dict):
            structured_angles = angle_data.get("attack_angles", [])
            if isinstance(structured_angles, list) and structured_angles:
                return angle_data.get("ccia", {}), structured_angles

    md_path = ws / "ccia_report.md"
    if md_path.exists():
        angles = []
        for line in md_path.read_text().splitlines():
            m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
            if m:
                angles.append({"id": m.group(1), "severity": m.group(2), "title": m.group(3)})
        if angles:
            return {}, angles
        rust_ccia, rust_angles = load_ccia_rust(ws)
        if rust_angles:
            return rust_ccia, rust_angles
        return {}, []
    rust_ccia, rust_angles = load_ccia_rust(ws)
    if rust_angles:
        return rust_ccia, rust_angles
    return {}, []


def load_prior_submissions(ws: Path) -> List[Dict]:
    """Load prior submissions from the active workspace ledger, whatever its layout."""
    sub_file = find_submission_file(ws)
    if sub_file is None or not sub_file.exists():
        return []
    return load_submission_entries(sub_file)


# ---------------------------------------------------------------------------
# Suppressed-patterns filter (PR #120 lesson 4)
# ---------------------------------------------------------------------------
#
# Workspace-local fingerprints for pattern-classes that are already-known
# DUP/FP/cleared on this target. Loaded from
#   <ws>/audit/SUPPRESSED_PATTERNS.{yaml,yml,json}      (preferred)
#   <ws>/SUPPRESSED_PATTERNS.{yaml,yml,json}            (fallback)
# Schema:
#   { "suppressions": [
#       { "id": str,
#         "angle_id": str | "" (regex; empty = match any),
#         "contract_regex": str | "",
#         "detector_regex": str | "",
#         "title_regex": str | "",
#         "clearance_cite": str,   # required — humans must be able to verify
#         "reason": str,
#         "scope": "workspace" | "global"  # advisory; suppression always
#                                          # local to this file
#       },
#       ...
#     ]
#   }
#
# Empty patterns are wildcards. A suppression with EVERY pattern empty is
# rejected (would suppress everything). At least one of angle_id /
# contract_regex / detector_regex / title_regex must be non-empty.
#
# Engagement-4 starter set: 6 saturated cluster classes from Polymarket
# (PR #120 lesson 4). Workspace operators can extend / override per audit.

def _suppression_candidate_paths(ws: Path) -> List[Path]:
    base_paths = [
        ws / "audit" / "SUPPRESSED_PATTERNS.yaml",
        ws / "audit" / "SUPPRESSED_PATTERNS.yml",
        ws / "audit" / "SUPPRESSED_PATTERNS.json",
        ws / "SUPPRESSED_PATTERNS.yaml",
        ws / "SUPPRESSED_PATTERNS.yml",
        ws / "SUPPRESSED_PATTERNS.json",
    ]
    return [p for p in base_paths if p.is_file()]


def _load_suppression_file(path: Path) -> Optional[Dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return None
    if path.suffix.lower() == ".json":
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"[brief] WARN: suppression file {path} invalid JSON: {exc}")
            return None
    # YAML — lazy import so missing PyYAML doesn't break the brief generator.
    try:
        import yaml  # type: ignore
    except ImportError:
        print(
            f"[brief] WARN: suppression file {path} is YAML but PyYAML not "
            f"installed — skipping. Install PyYAML or convert to .json."
        )
        return None
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:  # type: ignore[name-defined]
        print(f"[brief] WARN: suppression file {path} invalid YAML: {exc}")
        return None


def load_suppressed_patterns(ws: Path) -> List[Dict]:
    """Load workspace-local suppressed-pattern fingerprints.

    Returns a (possibly empty) list of normalized suppression dicts. Missing
    or unreadable files yield an empty list — never fatal.
    """
    out: List[Dict] = []
    for path in _suppression_candidate_paths(ws):
        data = _load_suppression_file(path)
        if not isinstance(data, dict):
            continue
        items = data.get("suppressions")
        if not isinstance(items, list):
            continue
        for raw in items:
            if not isinstance(raw, dict):
                continue
            entry = {
                "id": str(raw.get("id", "") or "").strip(),
                "angle_id": str(raw.get("angle_id", "") or "").strip(),
                "contract_regex": str(raw.get("contract_regex", "") or "").strip(),
                "detector_regex": str(raw.get("detector_regex", "") or "").strip(),
                "title_regex": str(raw.get("title_regex", "") or "").strip(),
                "clearance_cite": str(raw.get("clearance_cite", "") or "").strip(),
                "reason": str(raw.get("reason", "") or "").strip(),
                "scope": str(raw.get("scope", "workspace") or "workspace").strip(),
                "_source": str(path),
            }
            if not (entry["angle_id"] or entry["contract_regex"]
                    or entry["detector_regex"] or entry["title_regex"]):
                # All-empty patterns would suppress everything — reject.
                print(
                    f"[brief] WARN: suppression {entry.get('id') or '(no id)'} "
                    f"in {path} has no angle/contract/detector/title pattern; "
                    "skipping (would match everything)."
                )
                continue
            if not entry["clearance_cite"]:
                print(
                    f"[brief] WARN: suppression {entry.get('id') or '(no id)'} "
                    f"in {path} has no clearance_cite; humans cannot verify "
                    "the closure rationale. Skipping."
                )
                continue
            out.append(entry)
    return out


def _regex_match(pattern: str, value: str) -> bool:
    """Empty pattern = wildcard match; non-empty must regex-match value.

    Compile errors fall through to a substring containment check so bad
    operator regexes don't silently fail to suppress.
    """
    if not pattern:
        return True
    try:
        return bool(re.search(pattern, value or ""))
    except re.error:
        return pattern in (value or "")


def is_angle_suppressed(angle: Dict, suppressions: List[Dict]) -> Optional[Dict]:
    """Return the matching suppression dict (first hit) or None."""
    if not suppressions:
        return None
    angle_id = str(angle.get("id", "") or "")
    contracts = angle.get("contracts") or []
    if isinstance(contracts, str):
        contracts = [contracts]
    title = str(angle.get("title", "") or "")
    detector = str(angle.get("detector", "") or angle.get("severity", "") or "")
    for entry in suppressions:
        if not _regex_match(entry["angle_id"], angle_id):
            continue
        if entry["contract_regex"]:
            if not any(_regex_match(entry["contract_regex"], str(c)) for c in contracts):
                continue
        if not _regex_match(entry["detector_regex"], detector):
            continue
        if not _regex_match(entry["title_regex"], title):
            continue
        return entry
    return None


def load_cross_ws_patterns(ws_name: str) -> List[Dict]:
    """Load cross-workspace pattern data for context."""
    cross_ws_file = AUDITOOOR_DIR / "reference" / "cross-ws-patterns.md"
    if not cross_ws_file.exists():
        return []
    # Simple parsing: look for pattern sections mentioning this workspace
    patterns = []
    text = cross_ws_file.read_text()
    # Find pattern sections
    for section in text.split("### "):
        if ws_name in section:
            lines = section.splitlines()
            if lines:
                pat_name = lines[0].strip()
                patterns.append({"pattern": pat_name, "context": "\n".join(lines[:10])})
    return patterns


def load_oos_checklist(ws: Path) -> List[str]:
    """Load OOS checklist items."""
    oos_file = ws / "OOS_CHECKLIST.md"
    if not oos_file.exists():
        return []
    items = []
    for line in oos_file.read_text().splitlines():
        line = line.strip()
        if line.startswith("-") or line.startswith("*"):
            items.append(line.lstrip("-* ").strip())
        elif re.match(r'^\d+\.', line):
            items.append(re.sub(r'^\d+\.\s*', '', line))
    return items


def load_topology(ws: Path) -> Dict[str, Dict]:
    """Load deployment topology artifact keyed by contract name."""
    path = ws / "deployment_topology.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    entries = payload.get("entries", [])
    topology: Dict[str, Dict] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                contract = entry.get("contract")
                if isinstance(contract, str) and contract:
                    topology[contract] = entry
    return topology


def live_dossier_state(ws: Path) -> str:
    """Return whether the workspace live dossier is missing, malformed, or present."""
    path = ws / "live_topology_checks.json"
    if not path.exists():
        return "missing"
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return "malformed"
    results = payload.get("results", [])
    return "present" if isinstance(results, list) else "malformed"


def load_live_checks(ws: Path) -> Dict[str, List[Dict]]:
    """Load live topology check dossier keyed by contract."""
    path = ws / "live_topology_checks.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    results = payload.get("results", [])
    live_checks: Dict[str, List[Dict]] = {}
    if isinstance(results, list):
        for result in results:
            if not isinstance(result, dict):
                continue
            contract = result.get("contract")
            if isinstance(contract, str) and contract:
                live_checks.setdefault(contract, []).append(result)
    return live_checks


def load_live_spec_checks(ws: Path) -> Dict[str, List[Dict]]:
    """Load declarative/generated live-check specs keyed by contract."""
    candidates = [
        ws / "monitoring" / "live_checks.generated.json",
        ws / "monitoring" / "live_checks.json",
        AUDITOOOR_DIR / "projects" / ws.name / "live_checks.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        checks = payload.get("checks", []) if isinstance(payload, dict) else []
        live_checks: Dict[str, List[Dict]] = {}
        if isinstance(checks, list):
            for entry in checks:
                if not isinstance(entry, dict):
                    continue
                contract = entry.get("contract")
                if isinstance(contract, str) and contract:
                    live_checks.setdefault(contract, []).append(entry)
        if live_checks:
            return live_checks
    return {}


def relevant_live_entries(angle: Dict, contract: str, live_checks: Dict[str, List[Dict]]) -> List[Dict]:
    angle_id = str(angle.get("id") or "").strip()
    entries = live_checks.get(contract, [])
    related = []
    fallback = []
    for entry in entries:
        angle_links = [
            str(item).strip()
            for item in entry.get("related_angle_ids", [])
            if str(item).strip()
        ]
        if angle_links:
            if angle_id in angle_links:
                related.append(entry)
        else:
            fallback.append(entry)
    selected = related or fallback
    return sorted(
        selected,
        key=lambda entry: (
            0 if str(entry.get("evidence_class") or "") == "topology-relation" else 1,
            0 if str(entry.get("status") or "") == "fail" else 1,
            str(entry.get("id") or ""),
        ),
    )


def choose_focus_contract(
    angle: Dict,
    topology: Dict[str, Dict],
    live_checks: Dict[str, List[Dict]],
    live_spec_checks: Dict[str, List[Dict]],
) -> str:
    contracts = [
        str(contract).strip()
        for contract in angle.get("contracts", [])
        if str(contract).strip()
    ]
    if not contracts:
        return "UNKNOWN"

    live_entries = angle_live_entries(angle, live_checks)
    spec_entries = angle_live_entries(angle, live_spec_checks)
    if not live_entries:
        live_entries = spec_entries

    best_contract = contracts[0]
    best_score = float("-inf")
    for contract in contracts:
        score = 0.0
        topo = topology.get(contract, {})
        if str(topo.get("status") or "") == "resolved":
            score += 1.0
        elif topo.get("candidate_addresses"):
            score += 0.25

        contract_live = relevant_live_entries(angle, contract, live_checks)
        contract_spec = relevant_live_entries(angle, contract, live_spec_checks)
        score += 0.5 * len(contract_live)
        score += 0.25 * len(contract_spec)

        for entry in live_entries:
            evidence_class = str(entry.get("evidence_class") or "").strip()
            is_relation = evidence_class == "topology-relation"
            source_contract = str(entry.get("contract") or "").strip()
            expect_ref = str(entry.get("check", {}).get("expect_ref") or entry.get("expect_ref") or "").strip()
            if source_contract == contract:
                score += 3.0 if is_relation else 1.0
            if expect_ref == contract:
                score += 2.0 if is_relation else 0.5
        if score > best_score:
            best_contract = contract
            best_score = score
    return best_contract


def angle_live_entries(angle: Dict, live_checks: Dict[str, List[Dict]]) -> List[Dict]:
    """Collect angle-linked live entries across all contracts."""
    angle_id = str(angle.get("id") or "").strip()
    seen: set[str] = set()
    entries: List[Dict] = []
    for bucket in live_checks.values():
        for entry in bucket:
            if not isinstance(entry, dict):
                continue
            row_id = str(entry.get("id") or "").strip()
            if row_id and row_id in seen:
                continue
            angle_links = {
                str(item).strip()
                for item in entry.get("related_angle_ids", [])
                if str(item).strip()
            }
            if angle_id in angle_links:
                entries.append(entry)
                if row_id:
                    seen.add(row_id)
    return sorted(
        entries,
        key=lambda entry: (
            0 if str(entry.get("evidence_class") or "") == "topology-relation" else 1,
            0 if str(entry.get("status") or "") == "fail" else 1,
            str(entry.get("id") or ""),
        ),
    )


def expected_proof_pairs(angle: Dict, contract: str, live_checks: Dict[str, List[Dict]]) -> List[Dict[str, object]]:
    """Suggest paired live-proof rows for cross-contract topology angles."""
    angle_id = str(angle.get("id") or "").strip()
    if angle_id not in {"A-RACE", "A-AUTH", "A-ORACLE"}:
        return []
    target = contract.strip()
    entries = [
        entry for entry in angle_live_entries(angle, live_checks)
        if str(entry.get("evidence_class") or "").strip() == "topology-relation"
    ]
    if len(entries) < 2:
        return []
    if target and not any(
        target in {
            str(entry.get("contract") or "").strip(),
            str(entry.get("address_ref") or "").strip(),
            str(entry.get("check", {}).get("expect_ref") or "").strip(),
        }
        for entry in entries
    ):
        return []
    selected: List[Dict] = []
    seen_contracts: set[str] = set()
    for entry in entries:
        contract = str(entry.get("contract") or "").strip()
        if contract and contract in seen_contracts:
            continue
        selected.append(entry)
        if contract:
            seen_contracts.add(contract)
        if len(selected) >= 2:
            break
    if len(selected) < 2:
        return []
    blocks = sorted(
        {
            str(entry.get("block") or "").strip()
            for entry in selected
            if str(entry.get("block") or "").strip()
        }
    )
    pair_label = {
        "A-AUTH": "edge + authority",
        "A-ORACLE": "forward + reciprocal oracle wiring",
        "A-RACE": "paired cross-contract topology",
    }.get(angle_id, "paired topology proof")
    return [{
        "label": pair_label,
        "rows": selected,
        "same_block": len(blocks) == 1 if blocks else False,
        "blocks": blocks,
    }]


def load_ranked_priorities(ws: Path) -> List[Dict]:
    """Load canonical ranked priorities if mine-prioritize already wrote them.

    Accepts both the historical list-of-angles format and the Gap E wrapped
    dict format `{"angles": [...], "per_asset_allocation": {...}}`.
    """
    path = ws / "swarm" / "mining_priorities.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        angles = data.get("angles")
        if isinstance(angles, list):
            return angles
    return []


def _severity_claim(sev: Any) -> str:
    normalized = str(sev or "").strip().capitalize()
    return normalized if normalized in {"Critical", "High", "Medium"} else ""


def summarize_angle_impact_contract(
    ws: Path,
    angle: Dict[str, Any],
    ranked_contract: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if isinstance(ranked_contract, dict) and ranked_contract:
        return ranked_contract
    contracts = angle.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []
    return impact_mapping.impact_contract_summary(
        ws,
        candidate_id=str(angle.get("candidate_id") or angle.get("id") or ""),
        angle_id=str(angle.get("id") or ""),
        contracts=[str(contract) for contract in contracts],
        severity_claim=_severity_claim(angle.get("severity")),
        direct_submit=bool(angle.get("direct_submit") or angle.get("submit_ready")),
    )


def append_impact_contract_section(lines: List[str], contract: Dict[str, Any]) -> None:
    lines.extend(["", "## Impact Contract Gate"])
    required = bool(contract.get("required"))
    status = str(contract.get("status") or "missing_contract")
    posture = str(contract.get("submission_posture") or "in_scope_not_submit_ready")
    lines.append(f"- Required before reportable/direct-submit work: `{str(required).lower()}`")
    lines.append(f"- Status: `{status}`")
    lines.append(f"- Submission posture: `{posture}`")
    selected = str(contract.get("selected_impact") or "").strip()
    lines.append(f"- Exact listed impact: `{selected or 'none'}`")
    evidence_class = str(contract.get("evidence_class") or "").strip()
    lines.append(f"- Required evidence class: `{evidence_class or 'missing'}`")
    stop_condition = str(contract.get("stop_condition") or "").strip()
    lines.append(f"- Stop condition: `{stop_condition or 'missing'}`")
    oos_traps = contract.get("oos_traps") if isinstance(contract.get("oos_traps"), list) else []
    if oos_traps:
        lines.append("- OOS traps:")
        for item in oos_traps[:8]:
            lines.append(f"  - {item}")
    else:
        lines.append("- OOS traps: `missing`")
    reasons = [str(reason) for reason in contract.get("reasons", []) if str(reason).strip()]
    if reasons:
        lines.append("- Gate blockers:")
        for reason in reasons[:8]:
            lines.append(f"  - `{reason}`")
    if required and (status != "mapped" or not selected):
        lines.append(
            "- Conservative route: keep this `in_scope_not_submit_ready`; do not start "
            "direct-submit/high-severity harness, PoC, or report work until the exact "
            "listed impact, evidence class, OOS traps, and stop condition are locked."
        )


def find_angle_for_ranked_row(angles: List[Dict], row: Dict) -> Optional[Dict]:
    row_id = str(row.get("id") or "").strip()
    row_title = str(row.get("title") or "").strip()
    row_contracts = row.get("contracts", [])
    normalized_contracts = [
        str(contract).strip()
        for contract in row_contracts
        if str(contract).strip()
    ] if isinstance(row_contracts, list) else []

    exact_matches = []
    id_matches = []
    for angle in angles:
        angle_id = str(angle.get("id") or "").strip()
        angle_title = str(angle.get("title") or "").strip()
        angle_contracts = [
            str(contract).strip()
            for contract in angle.get("contracts", [])
            if str(contract).strip()
        ] if isinstance(angle.get("contracts", []), list) else []

        if angle_id == row_id:
            id_matches.append(angle)
            if angle_title == row_title and angle_contracts == normalized_contracts:
                exact_matches.append(angle)

    if exact_matches:
        return exact_matches[0]
    if row_title:
        for angle in id_matches:
            if str(angle.get("title") or "").strip() == row_title:
                return angle
    return id_matches[0] if id_matches else None


def ranked_row_requires_impact_contract(row: Dict) -> bool:
    """Return true when a mining-priority row is still impact-contract gated."""
    if bool(row.get("impact_contract_required")):
        return True
    candidate_kind = str(row.get("candidate_kind") or "").lower()
    terminal_state = str(row.get("terminal_state") or "").lower()
    lane = str(row.get("lane") or "").lower()
    return any(
        token in " ".join([candidate_kind, terminal_state, lane])
        for token in ("harness_task", "source-mining-harness-task", "detector_harness")
    )


def impact_contract_id_from_row(row: Dict) -> str:
    """Normalize the currently-known exact impact-contract identifier."""
    for key in ("impact_contract_id", "impact_contract", "program_impact_contract_id"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def check_prior_overlap(angle: Dict, subs: List[Dict]) -> Optional[str]:
    """Check if angle overlaps with prior submissions."""
    angle_kw = set()
    title = angle.get("title", "").lower()
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', title):
        angle_kw.add(m.group(1).lower())
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.', title):
        angle_kw.add(m.group(1).lower())
    
    for sub in subs:
        sub_title = sub.get("title", "").lower()
        sub_kw = set()
        for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', sub_title):
            sub_kw.add(m.group(1).lower())
        for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.', sub_title):
            sub_kw.add(m.group(1).lower())
        
        overlap = angle_kw & sub_kw
        if len(overlap) >= 2:
            status = sub.get("status", "").lower()
            if "dupe" in status or "duplicate" in status:
                return f"⚠️ NEAR-DUPE WARNING: Similar to prior dupe '{sub.get('title', '')[:50]}...'"
            elif "paid" in status or "accept" in status:
                return f"ℹ️ SIMILAR TO PAID: '{sub.get('title', '')[:50]}...' — ensure this is a distinct vector"
    return None


def infer_investigation_steps(angle_id: str, contract: str, func: Optional[str]) -> List[str]:
    """Generate investigation steps based on bug class."""
    steps = {
        "A-REENT": [
            f"1. Confirm {contract}.{func or 'function'} makes an external call before state update",
            f"2. Identify the callback function (onERC1155Received, onERC721Received, etc.)",
            f"3. Trace the reentrant path: which state variables are written after the callback?",
            f"4. Calculate extractable value: can attacker profit from the state mismatch?",
            f"5. Write PoC: implement attacker contract with callback that re-enters",
        ],
        "A-ORACLE": [
            f"1. Confirm {contract}.{func or 'function'} consumes oracle data without staleness check",
            f"2. Identify the oracle source (Chainlink, internal, etc.)",
            f"3. Check heartbeat: what is the expected update frequency?",
            f"4. Determine impact: what arithmetic uses the stale price?",
            f"5. Write PoC: simulate stale oracle and show incorrect valuation",
        ],
        "A-ERC4626": [
            f"1. Confirm {contract} implements ERC4626-style deposit/withdraw/mint/redeem",
            f"2. Check convertToShares/convertToAssets for rounding direction",
            f"3. Test donation attack: direct transfer to vault inflates share price",
            f"4. Test inflation on empty vault: first depositor exploit",
            f"5. Write PoC: show victim receives fewer shares due to price manipulation",
        ],
        "A-AUTH": [
            f"1. Confirm {contract}.{func or 'function'} is public/external with no auth modifier",
            f"2. Identify which state variables are written",
            f"3. Determine impact: what can an attacker achieve by calling this?",
            f"4. Check if there's an intended auth path (e.g., onlyOwner variant)",
            f"5. Write PoC: show unauthorized state modification",
        ],
        "A-DELEGATE": [
            f"1. Confirm {contract}.{func or 'function'} uses delegatecall",
            f"2. Check if delegate target is mutable (storage variable vs immutable)",
            f"3. If mutable: can attacker change target to malicious contract?",
            f"4. If immutable: verify target is trusted and cannot be compromised",
            f"5. Write PoC: show delegatecall to attacker-controlled code",
        ],
        "A-TIMESTAMP": [
            f"1. Confirm {contract}.{func or 'function'} uses block.timestamp in conditional",
            f"2. Check for safeguards: oracle, commit-reveal, block.number?",
            f"3. Determine manipulable window: how much can miner shift timestamp?",
            f"4. Calculate impact: what happens if timestamp is manipulated?",
            f"5. Write PoC: warp timestamp and show bypass",
        ],
        "A-FLASH": [
            f"1. Confirm {contract} has flash loan entry point or callback",
            f"2. Check if callback is reentrancy-guarded",
            f"3. Trace state updates: are they before or after the callback?",
            f"4. Determine extractable value: can attacker profit from reentrant call?",
            f"5. Write PoC: implement flash loan borrower that re-enters",
        ],
        "A-RACE": [
            f"1. Confirm multiple contracts read/write the same state variable",
            f"2. Identify the race window: when can state be inconsistent?",
            f"3. Determine impact: what bad outcome from reading stale state?",
            f"4. Write PoC: interleave two transactions to trigger race condition",
        ],
    }
    return steps.get(angle_id, [
        f"1. Investigate {contract}.{func or 'function'} for the reported pattern",
        f"2. Confirm hypothesis with file:line citations",
        f"3. Determine real-world impact and extractable value",
        f"4. Write PoC demonstrating the vulnerability",
    ])


def generate_brief(
    angle: Dict,
    rank: int,
    score: float,
    ws: Path,
    subs: List[Dict],
    oos_items: List[str],
    cross_ws: List[Dict],
    topology: Dict[str, Dict],
    live_checks: Dict[str, List[Dict]],
    live_spec_checks: Dict[str, List[Dict]],
    live_dossier_status: str,
    priority_rationale: Optional[List[str]] = None,
    impact_contract: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate an enhanced mining brief."""
    angle_id = angle["id"]
    severity = angle.get("severity", "MEDIUM")
    title = angle.get("title", "")
    contracts = angle.get("contracts", [])
    line = angle.get("line", "?")
    oos_candidate = dict(angle)
    oos_candidate["severity"] = severity
    oos_preflight = evaluate_preflight(ws, oos_candidate)
    displayed_severity = (
        f"{REDUCED_SEVERITY} (original: {severity})"
        if oos_preflight.get("verdict") == "needs-extension-distinct-argument"
        else severity
    )
    
    # Extract contract and function from title if contracts list is empty
    if not contracts:
        title_contract_match = re.search(r':\s+([A-Za-z_][A-Za-z0-9_]*)(?:\.(\w+))?\s*$', title)
        if title_contract_match:
            contracts = [title_contract_match.group(1)]
            if title_contract_match.group(2):
                func = title_contract_match.group(2)
    contract = choose_focus_contract(angle, topology, live_checks, live_spec_checks) if contracts else "UNKNOWN"
    # Try to extract function from title
    if 'func' not in dir() or func is None:
        func_match = re.search(r'\.(\w+)\s*$', title)
        func = func_match.group(1) if func_match else None
    
    # Prior overlap warning
    prior_warning = check_prior_overlap(angle, subs)
    topo_entry = topology.get(contract, {})
    live_entries = relevant_live_entries(angle, contract, live_checks)
    proof_pairs = expected_proof_pairs(angle, contract, live_checks)
    if not proof_pairs:
        proof_pairs = expected_proof_pairs(angle, contract, live_spec_checks)
    topology_heavy = angle_id in {"A-RACE", "A-AUTH", "A-ORACLE"} and bool(proof_pairs or live_entries)
    priority_row = angle.get("_ranked_priority_row") if isinstance(angle.get("_ranked_priority_row"), dict) else {}
    impact_contract_required = ranked_row_requires_impact_contract(priority_row) if priority_row else False
    impact_contract_id = impact_contract_id_from_row(priority_row) if priority_row else ""

    # Cross-ws context
    cross_ws_context = ""
    for cw in cross_ws:
        if angle_id in cw.get("pattern", ""):
            cross_ws_context = cw.get("context", "")
            break
    
    # OOS items that might be relevant
    relevant_oos = []
    for item in oos_items:
        item_lower = item.lower()
        if any(k in item_lower for k in ["centralization", "admin", "owner", "governance", "trusted"]):
            if angle_id in ("A-AUTH", "A-DELEGATE"):
                relevant_oos.append(item)
        if "oracle" in item_lower and angle_id == "A-ORACLE":
            relevant_oos.append(item)
        if "reentrancy" in item_lower and angle_id == "A-REENT":
            relevant_oos.append(item)
    
    steps = infer_investigation_steps(angle_id, contract, func)
    impact_contract_summary = summarize_angle_impact_contract(ws, angle, impact_contract)
    
    lines = [
        f"# Mining Brief #{rank:03d} — {angle_id}",
        "",
        f"**Angle:** {title}",
        f"**Severity:** {displayed_severity}",
        f"**Priority score:** {score:.1f}",
        f"**Target:** `{contract}`{f'.{func}' if func else ''} (line {line})",
        f"**Workspace:** {ws.name}",
    ]

    lines.extend(["", render_markdown(oos_preflight).rstrip()])

    append_impact_contract_section(lines, impact_contract_summary)

    lines.extend([
        "",
        "## Prior Submission Check",
    ])
    
    if prior_warning:
        lines.append(f"**{prior_warning}**")
    else:
        lines.append("✅ No significant overlap with prior submissions detected.")

    if impact_contract_required:
        status = "mapped" if impact_contract_id else "blocked_missing_impact_contract"
        lines.extend([
            "",
            "## Impact Contract Gate",
            f"- Status: `{status}`",
        ])
        if impact_contract_id:
            lines.append(f"- Impact contract: `{impact_contract_id}`")
            lines.append("- Source-mining dispatch may proceed, but preserve this exact impact mapping in any harness task.")
        else:
            lines.append("- Impact contract: `MISSING`")
            lines.append("- Do not dispatch agent, harness, PoC, severity, or report work until one exact program impact sentence is selected.")
            lines.append(
                f"- Next command: `make source-proof-record WS={ws} CANDIDATE={angle_id} "
                "VERDICT=blocked_missing_impact_contract`"
            )

    lines.extend([
        "",
        "## Deployment / Live Topology",
    ])
    if topo_entry:
        lines.append(f"- Topology status: `{topo_entry.get('status', 'unknown')}`")
        resolved = topo_entry.get("resolved_address")
        if resolved:
            lines.append(f"- Resolved address: `{resolved}`")
            lines.append(
                f"- Suggested next proof: "
                f"`python3 tools/live-state-checker.py --workspace {ws} --address {resolved} --network <network> --call \"<getter>\" --expect <value>`"
            )
        else:
            candidates = topo_entry.get("candidate_addresses", [])
            if candidates:
                lines.append("- Candidate addresses:")
                for candidate in candidates[:5]:
                    lines.append(f"  - `{candidate}`")
                if len(candidates) > 5:
                    lines.append(f"  - ... and {len(candidates) - 5} more")
            else:
                lines.append("- No candidate deployment addresses resolved yet.")
        match_counts = topo_entry.get("match_counts", {})
        if match_counts:
            counts = ", ".join(f"{k}={v}" for k, v in match_counts.items())
            lines.append(f"- Evidence counts: {counts}")
    else:
        lines.append("No deployment topology artifact found for this contract yet.")

    lines.extend([
        "",
        "## Live Check Evidence",
    ])
    if live_entries:
        for entry in live_entries[:5]:
            status = entry.get("status", "unknown")
            title = entry.get("title", entry.get("id", "live-check"))
            expr = entry.get("check", {}).get("expression", "unknown-check")
            lines.append(f"- `{status}` {title} — `{expr}`")
            evidence_class = entry.get("evidence_class")
            if evidence_class:
                lines.append(f"  class: `{evidence_class}`")
            if bool(entry.get("generated")) or str(entry.get("spec_source") or "") == "generated-relation":
                lines.append("  source: `generated-relation` (source-backed semantic live edge)")
            if entry.get("related_angle_ids"):
                lines.append(
                    "  related angles: "
                    + ", ".join(f"`{angle_id}`" for angle_id in entry.get("related_angle_ids", [])[:4])
                )
            implication = entry.get("implication_if_match")
            if implication:
                lines.append(f"  implication: {implication}")
    else:
        if live_dossier_status == "missing":
            if topology_heavy:
                lines.append("⚠️ PROOF-POOR: workspace live_topology_checks.json is missing for this topology-heavy angle.")
                lines.append("Recommended next step: run `engage.py --stage live-checks` before drafting a live-dependent finding.")
            else:
                lines.append("Workspace live_topology_checks.json is missing; run `engage.py --stage live-checks` if this angle needs deploy-state proof.")
        elif live_dossier_status == "malformed":
            lines.append("⚠️ PROOF-POOR: workspace live_topology_checks.json is malformed, so live topology evidence cannot be trusted yet.")
        elif topology_heavy:
            lines.append("⚠️ PROOF-POOR: no angle-relevant live dossier rows found for this topology-heavy angle yet.")
            lines.append("Treat this brief as source-only until live checks confirm the deploy/config edge.")
        else:
            lines.append("No live topology dossier rows found for this contract yet.")

    if proof_pairs:
        lines.extend([
            "",
            "## Expected Paired Live Proof",
        ])
        for pair in proof_pairs:
            label = str(pair.get("label") or "paired topology proof")
            blocks = pair.get("blocks") or []
            same_block = bool(pair.get("same_block"))
            lines.append(f"- `{label}`")
            if blocks:
                block_text = ", ".join(f"`{block}`" for block in blocks)
                if same_block:
                    lines.append(f"  pinned block: {block_text}")
                else:
                    lines.append(f"  pinned blocks: {block_text} (re-run at one shared block before submission)")
            else:
                lines.append("  pinned block: capture both rows at one shared block before submission")
            for row in pair.get("rows", [])[:2]:
                if not isinstance(row, dict):
                    continue
                row_id = str(row.get("id") or "live-check")
                row_title = str(row.get("title") or row_id)
                contract_name = str(row.get("contract") or "unknown")
                implication = str(row.get("implication_if_match") or "").strip()
                lines.append(f"  - `{row_id}` ({contract_name}) — {row_title}")
                if implication:
                    lines.append(f"    implication: {implication}")
            lines.append("  why: collect both halves before drafting a live-dependent cross-contract topology finding.")

    exploit_goal_lines: List[str] = []
    if proof_pairs:
        if angle_id == "A-RACE":
            exploit_goal_lines.append(
                "Use the confirmed live cross-contract edges to hunt an interleaving bug, not just a generic race."
            )
            exploit_goal_lines.append(
                "Trace which contract writes or prepares shared state first, then identify which downstream contract consumes stale or precondition-sensitive state over the paired live edge."
            )
        elif angle_id == "A-AUTH":
            exploit_goal_lines.append(
                "Use the paired live topology proof to show that an unauthorized call reaches a real privileged or state-bearing downstream edge."
            )
        elif angle_id == "A-ORACLE":
            exploit_goal_lines.append(
                "Use the paired live topology proof to show that oracle-side state reaches the real downstream consumer on the deployed path."
            )

        pair_contracts = {
            str(row.get("contract") or "").strip()
            for pair in proof_pairs
            for row in pair.get("rows", [])
            if isinstance(row, dict) and str(row.get("contract") or "").strip()
        }
        if {"NegRiskOperator", "NegRiskAdapter"} & pair_contracts:
            exploit_goal_lines.append(
                "For Polymarket NegRisk specifically: test whether `prepareMarket` / `prepareQuestion` / `resolveQuestion` can be interleaved or desynced across the live `NegRiskOperator -> NegRiskAdapter` path."
            )
        if {"NegRiskCtfCollateralAdapter", "NegRiskAdapter"} <= pair_contracts:
            exploit_goal_lines.append(
                "Also test whether adapter-side position conversion/redemption can observe or propagate stale NegRisk state across the live `NegRiskCtfCollateralAdapter -> NegRiskAdapter` edge."
            )

    if exploit_goal_lines:
        lines.extend([
            "",
            "## Exploit Goal",
        ])
        for item in exploit_goal_lines:
            lines.append(f"- {item}")

    if priority_rationale:
        lines.extend([
            "",
            "## Priority Rationale",
        ])
        for item in priority_rationale:
            lines.append(f"- {item}")

    lines.extend([
        "",
        "## Cross-Workspace Context",
    ])
    if cross_ws_context:
        lines.append(f"This pattern also appears in other workspaces:\n{cross_ws_context}")
    else:
        lines.append("No cross-workspace data available. Run cross-ws-pattern-mapper.py to generate.")
    
    if relevant_oos:
        lines.extend([
            "",
            "## Relevant OOS Items",
            "Verify these do NOT apply before mining:",
        ])
        for item in relevant_oos[:5]:
            lines.append(f"- {item}")
    
    lines.extend([
        "",
        "## Investigation Steps",
    ])
    for step in steps:
        lines.append(step)
    
    lines.extend([
        "",
        "## Deliverables",
        "- [ ] CONFIRM or REFUTE hypothesis with file:line citations",
        "- [ ] Read existing PoCs/tests/submission-status notes before writing a new harness",
        "- [ ] If CONFIRMED: run auto-draft-generator.py to create submission draft",
        "- [ ] If CONFIRMED: run poc-scaffold.py to generate PoC test",
        "- [ ] Run pre-submit-check.sh on draft before submission",
        "",
        "## Time Budget",
        "900 seconds (15 minutes) — if no concrete exploit path found, mark as FP and move on.",
        "",
        "---",
        f"*Generated by mining-brief-generator.py for {ws.name}*",
    ])
    
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mining brief generator")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--top", type=int, default=10, help="Generate briefs for top N angles")
    parser.add_argument("--out-dir", help="Output directory for briefs")
    parser.add_argument("--min-score", type=float, default=0, help="Minimum priority score")
    parser.add_argument("--unmined-only", action="store_true", help="Skip angles near prior submissions")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[brief] Workspace not found: {ws}")
        sys.exit(1)

    ccia, angles = load_ccia(ws)
    if not angles:
        print(f"[brief] No CCIA angles found. Run CCIA first.")
        sys.exit(1)

    subs = load_prior_submissions(ws)
    oos_items = load_oos_checklist(ws)
    cross_ws = load_cross_ws_patterns(ws.name)
    topology = load_topology(ws)
    live_checks = load_live_checks(ws)
    live_spec_checks = load_live_spec_checks(ws)
    dossier_status = live_dossier_state(ws)
    ranked = load_ranked_priorities(ws)
    suppressions = load_suppressed_patterns(ws)

    print(
        f"[brief] Loaded {len(angles)} angles, {len(subs)} prior subs, "
        f"{len(oos_items)} OOS items, {len(topology)} topology entrie(s), "
        f"{sum(len(v) for v in live_checks.values())} live check row(s), "
        f"{len(ranked)} ranked priority row(s), "
        f"{len(suppressions)} suppression rule(s)"
    )

    scored: List[Tuple[float, Dict, List[str], Dict[str, Any]]] = []
    if ranked:
        for row in ranked:
            angle = find_angle_for_ranked_row(angles, row)
            if not angle:
                continue
            angle = dict(angle)
            angle["_ranked_priority_row"] = row
            score = float(row.get("score", 0))
            if score < args.min_score:
                continue
            rationale = row.get("rationale", [])
            if args.unmined_only and any("prior overlap" in str(item) for item in rationale):
                continue
            ranked_contract = row.get("impact_contract") if isinstance(row.get("impact_contract"), dict) else {}
            scored.append((score, angle, rationale if isinstance(rationale, list) else [], ranked_contract))
    else:
        # Fallback scoring when mine-prioritize has not run yet.
        for angle in angles:
            sev = angle.get("severity", "MEDIUM")
            score = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 2, "LOW": 1}.get(sev.upper(), 1)

            angle_id = angle.get("id", "")
            bonuses = {"A-REENT": 3, "A-AUTH": 3, "A-DELEGATE": 3, "A-FLASH": 3,
                       "A-ORACLE": 2, "A-ERC4626": 2, "A-TIMESTAMP": 1}
            score += bonuses.get(angle_id, 0)

            prior = check_prior_overlap(angle, subs)
            if prior and "NEAR-DUPE" in prior:
                score -= 3
            elif prior:
                score -= 1

            if score >= args.min_score:
                if not args.unmined_only or not prior or "NEAR-DUPE" not in prior:
                    scored.append((score, angle, [], {}))

        scored.sort(key=lambda x: x[0], reverse=True)

    out_dir = Path(args.out_dir) if args.out_dir else ws / "swarm" / "mining_briefs"
    out_dir.mkdir(parents=True, exist_ok=True)

    suppressed_records: List[Dict] = []
    generated = 0
    rank_index = 0
    candidates = list(scored)
    while generated < args.top and rank_index < len(candidates):
        score, angle, rationale, ranked_contract = candidates[rank_index]
        rank_index += 1
        # PR #120 lesson 4: skip already-known DUP/FP pattern classes via
        # workspace-local SUPPRESSED_PATTERNS.{yaml,yml,json}. Skipped angles
        # are recorded under swarm/suppressed_mining_briefs.json so the
        # closure rationale is auditable.
        suppression_hit = is_angle_suppressed(angle, suppressions)
        if suppression_hit:
            suppressed_records.append({
                "rank": rank_index,
                "score": score,
                "angle_id": angle.get("id"),
                "title": angle.get("title"),
                "contracts": angle.get("contracts"),
                "suppression_id": suppression_hit.get("id"),
                "clearance_cite": suppression_hit.get("clearance_cite"),
                "reason": suppression_hit.get("reason"),
                "source": suppression_hit.get("_source"),
            })
            print(
                f"[brief] SUPPRESSED #{rank_index} ({score:.0f} pts) "
                f"angle={angle.get('id')} title={angle.get('title','')[:40]!r} "
                f"by={suppression_hit.get('id')} cite={suppression_hit.get('clearance_cite')}"
            )
            continue
        i = generated + 1
        brief = generate_brief(
            angle,
            i,
            score,
            ws,
            subs,
            oos_items,
            cross_ws,
            topology,
            live_checks,
            live_spec_checks,
            dossier_status,
            rationale,
            ranked_contract,
        )
        angle_id = angle["id"]
        safe_title = re.sub(r'[^\w\-]', '_', angle.get("title", ""))[:40]
        filename = f"brief_{i:03d}_{angle_id}_{safe_title}.md"
        out_path = out_dir / filename
        out_path.write_text(brief)
        print(f"[brief] #{i} ({score:.0f} pts) → {out_path.name}")
        generated += 1

    print(f"[brief] Generated {generated} brief(s) in {out_dir}")

    if suppressions or suppressed_records:
        ledger_path = ws / "swarm" / "suppressed_mining_briefs.json"
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_path.write_text(json.dumps({
            "rules_loaded": len(suppressions),
            "suppressed_count": len(suppressed_records),
            "suppressed": suppressed_records,
        }, indent=2))
        print(
            f"[brief] Suppression ledger → {ledger_path} "
            f"({len(suppressed_records)} angle(s) suppressed by "
            f"{len(suppressions)} rule(s))"
        )


if __name__ == "__main__":
    main()
