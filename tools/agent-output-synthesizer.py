#!/usr/bin/env python3
"""
agent-output-synthesizer.py — Extract structured findings from agent outputs

Reads agent output files (from agent_outputs/ or swarm/) and extracts:
  - VERDICT lines (TP/FP/NEEDS-VERIFY)
  - File:line citations
  - Severity assessments
  - Attack paths
  - Recommended actions

Produces a structured synthesis report for close-out review and optional
proof-rich candidate-plan artifacts for PoC scaffolding.

Usage:
    agent-output-synthesizer.py <workspace> [--out synthesis.json]
    agent-output-synthesizer.py ~/audits/<project> --out ~/audits/<project>/swarm/synthesis.json
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Local import: every brief candidate stamps a default ``evidence_class``
# so downstream consumers (poc-scaffold, audit-closeout-check, the
# evidence-class-validator) can refuse to count generated hypotheses as
# proof. See docs/EVIDENCE_CLASS_SCHEMA.md.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402  (module-style import after path tweak)


SCANNER_PROMOTION_ADVISORY_SCHEMA = "auditooor.scanner_promotion_advisories.v1"
SCANNER_PROMOTION_ADVISORY_NAME = "scanner_promotion_advisories.json"
DETECTOR_ENVIRONMENT_MANIFEST_NAME = "detector_environment_manifest.json"


def _diagnostic(path: Path, code: str, message: str) -> Dict[str, str]:
    return {"path": str(path), "code": code, "message": message}


def load_asset_coverage(ws: Path) -> Tuple[List[str], Dict[str, List[str]]]:
    """Return (assets_in_scope, roots_by_asset).

    Reads INTAKE_BASELINE.json. Missing or malformed baseline yields empty
    values so callers treat per-asset bucketing as opt-in.
    """
    path = ws / "INTAKE_BASELINE.json"
    if not path.is_file():
        return [], {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return [], {}
    assets = payload.get("assets_in_scope") or []
    plan = payload.get("asset_coverage_plan") or {}
    roots_by_asset: Dict[str, List[str]] = {}
    for asset in assets:
        entry = plan.get(asset, {}) if isinstance(plan, dict) else {}
        if not isinstance(entry, dict):
            continue
        roots = entry.get("roots") or []
        roots_by_asset[asset] = [str(r) for r in roots if r]
    return list(assets), roots_by_asset


def _candidate_root_signals(candidate: Dict) -> List[str]:
    """Gather all file-path-ish strings from a candidate for asset bucketing."""
    signals: List[str] = []
    for key in ("source_file", "contract", "exploit_goal"):
        val = candidate.get(key)
        if isinstance(val, str):
            signals.append(val)
    for citation in candidate.get("citations") or []:
        if isinstance(citation, dict) and citation.get("file"):
            signals.append(str(citation["file"]))
    for name in candidate.get("matched_mining_briefs") or []:
        signals.append(str(name))
    return signals


def bucket_candidates_by_asset(
    candidates: List[Dict], assets: List[str], roots_by_asset: Dict[str, List[str]]
) -> Dict[str, int]:
    """Return a per-asset candidate count for a list of candidates.

    A candidate is attributed to every asset whose root prefixes match any of
    its citations / source_file / matched briefs. When assets share a root
    prefix (rare), both get a hit — dedup is not attempted because the gate's
    goal is to detect zero-coverage assets, not perfect attribution.
    """
    counts: Dict[str, int] = {asset: 0 for asset in assets}
    if not assets:
        return counts
    for candidate in candidates:
        signals = _candidate_root_signals(candidate)
        if not signals:
            continue
        for asset in assets:
            roots = roots_by_asset.get(asset) or []
            if not roots:
                continue
            for root in roots:
                if any(root and root in sig for sig in signals):
                    counts[asset] = counts.get(asset, 0) + 1
                    break
    return counts


def _safe_workspace_rglob(ws: Path, pattern: str) -> List[Path]:
    try:
        return sorted(ws.rglob(pattern))
    except OSError:
        return []


def discover_scanner_promotion_advisory_paths(ws: Path) -> List[Path]:
    """Find scanner promotion advisory artifacts, including custom scan out dirs."""
    paths: List[Path] = [
        ws / SCANNER_PROMOTION_ADVISORY_NAME,
        ws / "scanners" / SCANNER_PROMOTION_ADVISORY_NAME,
    ]

    for manifest_path in _safe_workspace_rglob(ws, DETECTOR_ENVIRONMENT_MANIFEST_NAME):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        block = manifest.get("scanner_promotion_advisories")
        if not isinstance(block, dict):
            continue
        candidates: List[Path] = []
        artifact_path = block.get("artifact_path")
        if isinstance(artifact_path, str) and artifact_path:
            candidates.append(Path(artifact_path))
        artifact_rel = block.get("artifact_relative_to_manifest") or block.get("artifact")
        if isinstance(artifact_rel, str) and artifact_rel:
            rel_path = Path(artifact_rel)
            candidates.append(rel_path if rel_path.is_absolute() else manifest_path.parent / rel_path)
        paths.extend(candidates)

    deduped: List[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.expanduser().resolve() if path.exists() else path.expanduser())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def load_scanner_promotion_advisories_with_diagnostics(
    ws: Path,
) -> Tuple[List[Dict[str, Any]], Optional[Path], List[Dict[str, str]]]:
    """Load conservative LOW-hit advisories plus artifact path and diagnostics.

    Schema/version mismatches are surfaced as diagnostics, but useful
    ``advisories`` rows are still loaded so advisory-only follow-up is not lost.
    """
    paths = discover_scanner_promotion_advisory_paths(ws)
    diagnostics: List[Dict[str, str]] = []
    all_rows: List[Dict[str, Any]] = []
    first_source: Optional[Path] = None
    seen_ids: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        if first_source is None:
            first_source = path
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            diagnostics.append(_diagnostic(path, "invalid_json", str(exc)))
            continue
        except OSError as exc:
            diagnostics.append(_diagnostic(path, "read_error", str(exc)))
            continue
        if not isinstance(payload, dict):
            diagnostics.append(_diagnostic(path, "invalid_payload", "artifact root is not an object"))
            continue
        schema = payload.get("schema_version")
        if schema != SCANNER_PROMOTION_ADVISORY_SCHEMA:
            diagnostics.append(
                _diagnostic(
                    path,
                    "schema_version_mismatch",
                    f"expected {SCANNER_PROMOTION_ADVISORY_SCHEMA}, got {schema or 'missing'}",
                )
            )
        rows = payload.get("advisories") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            diagnostics.append(_diagnostic(path, "missing_advisories", "artifact has no advisories list"))
            continue
        useful_rows: List[Dict[str, Any]] = []
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                diagnostics.append(
                    _diagnostic(path, "invalid_advisory_row", f"advisories[{idx}] is not an object")
                )
                continue
            row_copy = dict(row)
            row_schema = row_copy.get("schema_version")
            if row_schema not in (None, SCANNER_PROMOTION_ADVISORY_SCHEMA):
                diagnostics.append(
                    _diagnostic(
                        path,
                        "row_schema_version_mismatch",
                        f"advisories[{idx}] expected {SCANNER_PROMOTION_ADVISORY_SCHEMA}, got {row_schema}",
                    )
                )
            row_copy.setdefault("schema_version", SCANNER_PROMOTION_ADVISORY_SCHEMA)
            row_copy.setdefault("kind", "capability_gap")
            row_copy.setdefault("promotion_status", "needs_poc")
            row_copy.setdefault("severity_floor", "LOW")
            row_copy.setdefault("severity_promotion_allowed", False)
            row_copy["artifact_source"] = str(path)
            row_id = str(row_copy.get("id") or f"{path}:{idx}")
            if row_id in seen_ids:
                diagnostics.append(_diagnostic(path, "duplicate_advisory_id", row_id))
                continue
            seen_ids.add(row_id)
            useful_rows.append(row_copy)
            all_rows.append(row_copy)
        expected_count = payload.get("advisory_count")
        if isinstance(expected_count, int) and expected_count != len(useful_rows):
            diagnostics.append(
                _diagnostic(
                    path,
                    "advisory_count_mismatch",
                    f"advisory_count={expected_count}, loaded_rows={len(useful_rows)}",
                )
            )
    return all_rows, first_source, diagnostics


def load_scanner_promotion_advisories_with_source(ws: Path) -> Tuple[List[Dict[str, Any]], Optional[Path]]:
    """Load conservative LOW-hit promotion advisories plus the artifact path."""
    rows, source, _diagnostics = load_scanner_promotion_advisories_with_diagnostics(ws)
    return rows, source


def load_scanner_promotion_advisories(ws: Path) -> List[Dict[str, Any]]:
    """Load conservative LOW-hit promotion advisories emitted by scan orchestration."""
    rows, _source = load_scanner_promotion_advisories_with_source(ws)
    return rows


def scanner_advisory_to_candidate(row: Dict[str, Any], source_path: Path) -> Dict[str, Any]:
    contract = str(row.get("contract") or "UnknownContract")
    reason = str(row.get("reason") or "LOW scanner hit needs PoC triage.")
    next_step = str(row.get("recommended_next_step") or "Build a concrete PoC before severity promotion.")
    return {
        "source_file": str(source_path),
        "kind": "capability_gap",
        "contract": contract,
        "angle_id": "A-CAPABILITY-GAP",
        "angle_title": "LOW scanner hit may control pool/hook liveness",
        "matched_mining_briefs": [],
        "proof_poor": True,
        "paired_live_row_ids": [],
        "paired_contracts": [],
        "involved_contracts": [contract],
        "executed_live_rows": False,
        "suggested_functions": [],
        "exploit_goal": reason,
        "recommended_next_step": next_step,
        "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
        "promotion_status": "needs_poc",
        "capability_gap": True,
        "scanner_advisory_id": row.get("id"),
        "severity_floor": row.get("severity_floor") or "LOW",
        "severity_promotion_allowed": False,
        "source_citation": {
            "file": row.get("file"),
            "line": row.get("line"),
        },
        "shape": row.get("shape"),
        "signals": row.get("signals") or [],
        "matched_low_detectors": row.get("matched_low_detectors") or [],
    }


def scanner_advisory_to_needs_verify(row: Dict[str, Any], source_path: Path) -> Dict[str, Any]:
    citation = []
    if row.get("file") and row.get("line"):
        citation = [{"file": row.get("file"), "line": row.get("line")}]
    return {
        "source": str(source_path),
        "verdict": "NEEDS-VERIFY",
        "severity": row.get("severity_floor") or "Low",
        "details": row.get("reason") or "LOW scanner hit needs PoC triage.",
        "citations": citation,
        "attack_paths": [],
        "kind": "capability_gap",
        "promotion_status": "needs_poc",
        "capability_gap": True,
        "scanner_advisory_id": row.get("id"),
        "severity_floor": row.get("severity_floor") or "LOW",
        "severity_promotion_allowed": False,
        "source_citation": {
            "file": row.get("file"),
            "line": row.get("line"),
        },
        "shape": row.get("shape"),
        "signals": row.get("signals") or [],
        "matched_low_detectors": row.get("matched_low_detectors") or [],
        "recommended_next_step": row.get("recommended_next_step"),
        "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
    }


def find_agent_outputs(ws: Path) -> List[Path]:
    """Find all agent output files in workspace."""
    files = []
    for dir_name in ("agent_outputs", "swarm"):
        d = ws / dir_name
        if d.exists():
            for f in d.rglob("*.md"):
                rel = f.relative_to(ws)
                if f.name.endswith(".brief.md") or f.name.startswith("brief_"):
                    continue
                if "mining_briefs" in rel.parts:
                    continue
                files.append(f)
    return sorted(files)


def extract_verdicts(text: str) -> List[Dict]:
    """Extract VERDICT lines from agent output."""
    verdicts = []
    for line in text.splitlines():
        # Pattern: VERDICT: TP severity-MEDIUM | FP <reason> | NEEDS-VERIFY <next>
        m = re.search(r'VERDICT:\s*(TP|FP|NEEDS-VERIFY)\s*(.*)', line, re.I)
        if m:
            verdict_type = m.group(1).upper()
            details = m.group(2).strip()
            severity = None
            if verdict_type == "TP":
                sev_match = re.search(r'severity-?(\w+)', details, re.I)
                if sev_match:
                    severity = sev_match.group(1).capitalize()
            verdicts.append({
                "type": verdict_type,
                "details": details,
                "severity": severity,
                "raw": line.strip(),
            })
    return verdicts


def extract_citations(text: str) -> List[Dict]:
    """Extract file:line citations."""
    citations = []
    pattern = re.compile(r'`?([A-Za-z_][A-Za-z0-9_]*\.sol)(?::|#L)?(\d+)`?')
    for m in pattern.finditer(text):
        citations.append({
            "file": m.group(1),
            "line": int(m.group(2)),
        })
    return citations


def extract_attack_paths(text: str) -> List[str]:
    """Extract attack path descriptions."""
    paths = []
    # Look for numbered steps or attack sequences
    for line in text.splitlines():
        if re.match(r'\s*(?:Step\s+\d+|Attack\s+sequence|\d+\.\s+Attacker)', line, re.I):
            paths.append(line.strip())
    return paths


def extract_confidence(text: str) -> Optional[str]:
    """Extract confidence level."""
    for line in text.splitlines():
        m = re.search(r'confidence:\s*(high|medium|low)', line, re.I)
        if m:
            return m.group(1).lower()
    return None


def parse_agent_output(filepath: Path) -> Dict:
    """Parse a single agent output file."""
    text = filepath.read_text()
    
    return {
        "source_file": str(filepath),
        "verdicts": extract_verdicts(text),
        "citations": extract_citations(text),
        "attack_paths": extract_attack_paths(text),
        "confidence": extract_confidence(text),
        "word_count": len(text.split()),
    }


def find_swarm_briefs(ws: Path) -> List[Path]:
    """Find swarm-dispatch agent briefs, excluding mining briefs."""
    swarm = ws / "swarm"
    if not swarm.exists():
        return []
    files = []
    for f in swarm.rglob("brief_*.md"):
        rel = f.relative_to(ws)
        if "mining_briefs" in rel.parts:
            continue
        files.append(f)
    return sorted(files)


def _load_impact_contract_module():
    tool_path = Path(__file__).resolve().parent / "impact-contract-preflight.py"
    spec = importlib.util.spec_from_file_location("impact_contract_preflight", tool_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {tool_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IMPACT_CONTRACT = _load_impact_contract_module()


def extract_markdown_section(text: str, heading: str) -> str:
    capture = False
    lines: List[str] = []
    for line in text.splitlines():
        if re.match(rf"^##\s+{re.escape(heading)}\s*$", line):
            capture = True
            lines.append(line)
            continue
        if capture and line.startswith("## "):
            break
        if capture:
            lines.append(line)
    return "\n".join(lines).strip()


def extract_target_contract(text: str) -> Optional[str]:
    match = re.search(r"^\*\*Contract:\*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", text, re.MULTILINE)
    if match:
        return match.group(1)
    return None


def extract_angle_specs(text: str) -> List[Dict[str, str]]:
    specs: List[Dict[str, str]] = []
    current_id: Optional[str] = None
    current_title: Optional[str] = None
    for line in text.splitlines():
        m = re.match(r"^###\s+(A-[A-Z0-9-]+)\s+—\s+\w+", line)
        if m:
            current_id = m.group(1)
            current_title = None
            continue
        if current_id:
            title_match = re.match(r"^\*\*Title:\*\*\s+(.+)$", line)
            if title_match:
                current_title = title_match.group(1).strip()
                specs.append({"id": current_id, "title": current_title})
                current_id = None
                current_title = None
    return specs


def extract_matched_briefs(text: str) -> List[str]:
    return re.findall(r"\*\*Matched mining brief:\*\*\s*`([^`]+)`", text)


def extract_paired_row_ids(pair_section: str) -> List[str]:
    return re.findall(r"-\s+`([^`]+)`\s+\(", pair_section)


def extract_paired_contracts(pair_section: str) -> List[str]:
    contracts: List[str] = []
    seen = set()
    for contract in re.findall(r"-\s+`[^`]+`\s+\(([A-Za-z_][A-Za-z0-9_]*)\)\s+—", pair_section):
        if contract in seen:
            continue
        seen.add(contract)
        contracts.append(contract)
    return contracts


def extract_backtick_terms(text: str) -> List[str]:
    terms: List[str] = []
    seen = set()
    for term in re.findall(r"`([^`]+)`", text):
        cleaned = term.strip()
        if not cleaned or "->" in cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        terms.append(cleaned)
    return terms


def live_section_has_executed_rows(live_section: str) -> bool:
    statuses = re.findall(r"-\s+`(pass|fail|dry_run|blocked_[^`]+|error)`", live_section, re.IGNORECASE)
    lowered = {status.lower() for status in statuses}
    return bool(lowered & {"pass", "fail"})


def candidate_kind(
    proof_poor: bool,
    exploit_goal: str,
    pair_ids: List[str],
    executed_live_rows: bool,
    impact_contract_packet: Dict[str, Any],
) -> str:
    impact_contract = impact_contract_packet.get("impact_contract") or {}
    if (
        not proof_poor
        and exploit_goal
        and pair_ids
        and executed_live_rows
        and bool(impact_contract.get("explicit"))
    ):
        return "candidate_finding"
    return "poc_plan"


def extract_candidate_plans_from_brief(filepath: Path) -> List[Dict[str, Any]]:
    text = filepath.read_text()
    contract = extract_target_contract(text)
    if not contract:
        return []
    exploit_goal_section = extract_markdown_section(text, "Exploit Goal")
    if not exploit_goal_section:
        return []
    live_section = extract_markdown_section(text, "Live Check Evidence")
    pair_section = extract_markdown_section(text, "Expected Paired Live Proof")
    proof_poor = "PROOF-POOR" in text
    matched_briefs = extract_matched_briefs(text)
    pair_ids = extract_paired_row_ids(pair_section)
    paired_contracts = extract_paired_contracts(pair_section)
    executed = live_section_has_executed_rows(live_section)
    impact_contract_packet = IMPACT_CONTRACT.build_packet(
        path=filepath,
        text=text,
        route="promotion",
    )
    suggested_functions = [
        term for term in extract_backtick_terms(exploit_goal_section)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", term)
    ]

    candidates: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str]] = set()
    for angle in extract_angle_specs(text):
        key = (contract, angle["id"], exploit_goal_section)
        if key in seen:
            continue
        seen.add(key)
        kind = candidate_kind(
            proof_poor,
            exploit_goal_section,
            pair_ids,
            executed,
            impact_contract_packet,
        )
        next_step = (
            "execute live checks / pin block / turn exploit goal into a concrete interleaving PoC plan"
            if kind == "poc_plan"
            else "draft finding and scaffold PoC from validated exploit path"
        )
        if (
            kind == "poc_plan"
            and not (impact_contract_packet.get("impact_contract") or {}).get("explicit")
        ):
            next_step = (
                next_step
                + "; add `## Impact Contract` with victim/protocol/asset plus "
                + "source-proof / harness-scaffold / exploit-memory evidence"
            )
        candidates.append({
            "source_file": str(filepath),
            "kind": kind,
            "contract": contract,
            "angle_id": angle["id"],
            "angle_title": angle["title"],
            "matched_mining_briefs": matched_briefs,
            "proof_poor": proof_poor,
            "paired_live_row_ids": pair_ids,
            "paired_contracts": paired_contracts,
            "involved_contracts": [contract, *[name for name in paired_contracts if name != contract]],
            "executed_live_rows": executed,
            "impact_contract": impact_contract_packet,
            "suggested_functions": suggested_functions,
            "exploit_goal": exploit_goal_section,
            "recommended_next_step": next_step,
            # Item #14: a brief candidate is a generated hypothesis until a
            # scaffold/replay exists. poc-scaffold.py raises this to
            # ``scaffolded_unverified`` and poc-execution-record.py raises
            # it to ``executed_with_manifest``.
            "evidence_class": _evidence_class.GENERATED_HYPOTHESIS,
        })
    return candidates


def synthesize_brief_candidates(ws: Path) -> Dict[str, Any]:
    briefs = find_swarm_briefs(ws)
    candidates: List[Dict[str, Any]] = []
    for brief in briefs:
        candidates.extend(extract_candidate_plans_from_brief(brief))

    scanner_advisories, discovered_advisory_path, advisory_diagnostics = (
        load_scanner_promotion_advisories_with_diagnostics(ws)
    )
    scanner_advisory_path = discovered_advisory_path or ws / SCANNER_PROMOTION_ADVISORY_NAME
    for row in scanner_advisories:
        row_source = Path(str(row.get("artifact_source") or scanner_advisory_path))
        candidates.append(scanner_advisory_to_candidate(row, row_source))

    deduped: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str, Tuple[str, ...]]] = set()
    for candidate in candidates:
        key = (
            candidate["contract"],
            candidate["angle_id"],
            candidate["exploit_goal"],
            tuple(candidate.get("paired_live_row_ids", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)

    assets, roots_by_asset = load_asset_coverage(ws)
    candidates_by_asset = bucket_candidates_by_asset(deduped, assets, roots_by_asset)

    return {
        "summary": {
            "total_briefs": len(briefs),
            "candidate_count": len(deduped),
            "candidate_findings": sum(1 for item in deduped if item["kind"] == "candidate_finding"),
            "poc_plans": sum(1 for item in deduped if item["kind"] == "poc_plan"),
            "capability_gaps": sum(1 for item in deduped if item["kind"] == "capability_gap"),
            "scanner_promotion_advisories": len(scanner_advisories),
            "scanner_promotion_advisory_diagnostics": len(advisory_diagnostics),
        },
        "assets_in_scope": assets,
        "candidates_by_asset": candidates_by_asset,
        "scanner_promotion_advisory_source": str(scanner_advisory_path) if scanner_advisories else None,
        "scanner_promotion_advisory_diagnostics": advisory_diagnostics,
        "candidates": deduped,
    }


def synthesize_findings(parsed: List[Dict], ws: Optional[Path] = None) -> Dict:
    """Synthesize all agent outputs into a summary."""
    tp_findings = []
    fp_findings = []
    needs_verify = []

    for p in parsed:
        for v in p["verdicts"]:
            finding = {
                "source": p["source_file"],
                "verdict": v["type"],
                "severity": v.get("severity"),
                "details": v["details"],
                "citations": p["citations"],
                "attack_paths": p["attack_paths"],
            }
            if v["type"] == "TP":
                tp_findings.append(finding)
            elif v["type"] == "FP":
                fp_findings.append(finding)
            else:
                needs_verify.append(finding)

    # r36-rebuttal: bugfix-inventory-claude-20260610
    # Capture the parser-sourced needs_verify count BEFORE appending scanner advisories,
    # so that the summary can distinguish the two populations without double-counting.
    needs_verify_count_from_parsers = len(needs_verify)

    scanner_advisories: List[Dict[str, Any]] = []
    scanner_advisory_path: Optional[Path] = None
    scanner_advisory_diagnostics: List[Dict[str, str]] = []
    if ws is not None:
        scanner_advisories, scanner_advisory_path, scanner_advisory_diagnostics = (
            load_scanner_promotion_advisories_with_diagnostics(ws)
        )
        scanner_advisory_path = scanner_advisory_path or ws / SCANNER_PROMOTION_ADVISORY_NAME
        for row in scanner_advisories:
            row_source = Path(str(row.get("artifact_source") or scanner_advisory_path))
            needs_verify.append(scanner_advisory_to_needs_verify(row, row_source))

    # Group TP findings by severity
    by_severity = {}
    for f in tp_findings:
        sev = f.get("severity") or "Unknown"
        by_severity.setdefault(sev, []).append(f)

    assets: List[str] = []
    roots_by_asset: Dict[str, List[str]] = {}
    if ws is not None:
        assets, roots_by_asset = load_asset_coverage(ws)
    all_findings = tp_findings + needs_verify + fp_findings
    candidates_by_asset = bucket_candidates_by_asset(
        [{
            "source_file": f.get("source", ""),
            "contract": "",
            "exploit_goal": f.get("details", ""),
            "citations": f.get("citations", []),
        } for f in all_findings],
        assets, roots_by_asset,
    )

    # needs_verify_count is the total (parser items + scanner advisories).
    # needs_verify_count_from_parsers is the parser-only sub-count.
    # scanner_promotion_advisories count is NOT in the summary dict: it is a strict sub-set of
    # needs_verify_count (those items are already appended to the needs_verify list above),
    # so including it in summary would cause consumers who naively sum it with needs_verify_count
    # to overcount. The full scanner advisory list lives at the top-level key below.
    return {
        "summary": {
            "total_files": len(parsed),
            "total_words": sum(p["word_count"] for p in parsed),
            "tp_count": len(tp_findings),
            "fp_count": len(fp_findings),
            "needs_verify_count": len(needs_verify),
            "needs_verify_count_from_parsers": needs_verify_count_from_parsers,
            "scanner_promotion_advisory_diagnostics": len(scanner_advisory_diagnostics),
        },
        "assets_in_scope": assets,
        "candidates_by_asset": candidates_by_asset,
        "scanner_promotion_advisory_source": str(scanner_advisory_path) if scanner_advisories else None,
        "scanner_promotion_advisory_diagnostics": scanner_advisory_diagnostics,
        "scanner_promotion_advisories": scanner_advisories,
        "tp_findings": tp_findings,
        "fp_findings": fp_findings,
        "needs_verify": needs_verify,
        "by_severity": by_severity,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent output synthesizer")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--out", help="Output JSON file")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--brief-candidates", action="store_true",
                        help="Synthesize candidate findings / PoC plans from proof-rich swarm briefs")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[synth] Workspace not found: {ws}")
        sys.exit(1)

    if args.brief_candidates:
        synthesis = synthesize_brief_candidates(ws)
        print(f"[synth] Found {synthesis['summary']['total_briefs']} swarm brief(s)", file=sys.stderr)
    else:
        files = find_agent_outputs(ws)
        print(f"[synth] Found {len(files)} agent output file(s)", file=sys.stderr)
        parsed = [parse_agent_output(f) for f in files]
        synthesis = synthesize_findings(parsed, ws)

    if args.format == "json":
        output = json.dumps(synthesis, indent=2)
    else:
        if args.brief_candidates:
            lines = ["# Swarm Candidate Plans", ""]
            lines.append(f"**Briefs analyzed:** {synthesis['summary']['total_briefs']}")
            lines.append(f"**Candidate artifacts:** {synthesis['summary']['candidate_count']}")
            lines.append(f"**Candidate findings:** {synthesis['summary']['candidate_findings']}")
            lines.append(f"**PoC plans:** {synthesis['summary']['poc_plans']}")
            lines.append(f"**Capability gaps:** {synthesis['summary'].get('capability_gaps', 0)}")
            lines.append(f"**Scanner promotion advisories:** {synthesis['summary'].get('scanner_promotion_advisories', 0)}")
            lines.append(f"**Scanner advisory diagnostics:** {synthesis['summary'].get('scanner_promotion_advisory_diagnostics', 0)}")
            lines.append("")
            for item in synthesis["candidates"]:
                lines.append(f"## {item['kind']} — {item['angle_id']} — {item['contract']}")
                lines.append(f"- **Title:** {item['angle_title']}")
                lines.append(f"- **Source:** {Path(item['source_file']).name}")
                if item.get("scanner_advisory_id"):
                    lines.append(f"- **Scanner advisory:** `{item['scanner_advisory_id']}`")
                if item.get("promotion_status"):
                    lines.append(f"- **Promotion status:** `{item['promotion_status']}`")
                if item.get("matched_mining_briefs"):
                    lines.append(
                        "- **Matched mining briefs:** " +
                        ", ".join(f"`{path}`" for path in item["matched_mining_briefs"])
                    )
                if item.get("paired_live_row_ids"):
                    lines.append(
                        "- **Paired live rows:** " +
                        ", ".join(f"`{row}`" for row in item["paired_live_row_ids"])
                    )
                lines.append(f"- **Executed live rows:** {'yes' if item.get('executed_live_rows') else 'no'}")
                lines.append(f"- **Proof-poor:** {'yes' if item.get('proof_poor') else 'no'}")
                lines.append(f"- **Recommended next step:** {item['recommended_next_step']}")
                lines.append("")
                lines.append(item["exploit_goal"])
                lines.append("")
        else:
            lines = ["# Agent Output Synthesis"]
            lines.append("")
            lines.append(f"**Files analyzed:** {synthesis['summary']['total_files']}")
            lines.append(f"**TP findings:** {synthesis['summary']['tp_count']}")
            lines.append(f"**FP findings:** {synthesis['summary']['fp_count']}")
            lines.append(f"**Needs verify:** {synthesis['summary']['needs_verify_count']}")
            lines.append(f"**Scanner promotion advisories:** {synthesis['summary'].get('scanner_promotion_advisories', 0)}")
            lines.append(f"**Scanner advisory diagnostics:** {synthesis['summary'].get('scanner_promotion_advisory_diagnostics', 0)}")
            lines.append("")

            if synthesis["tp_findings"]:
                lines.append("## Confirmed Findings (TP)")
                for f in synthesis["tp_findings"]:
                    sev = f.get("severity", "?")
                    lines.append(f"### {sev}: {f['details'][:80]}")
                    lines.append(f"- **Source:** {Path(f['source']).name}")
                    if f["citations"]:
                        citation_text = ", ".join(f"{c['file']}:{c['line']}" for c in f["citations"])
                        lines.append(f"- **Citations:** {citation_text}")
                    lines.append("")

            if synthesis["needs_verify"]:
                lines.append("## Needs Verification")
                for f in synthesis["needs_verify"]:
                    lines.append(f"- {f['details'][:80]} ({Path(f['source']).name})")
                lines.append("")

        output = "\n".join(lines)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(output)
        print(f"[synth] Written: {out_path}")
    else:
        print(output)


if __name__ == "__main__":
    main()
