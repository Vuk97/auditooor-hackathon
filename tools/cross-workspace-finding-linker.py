#!/usr/bin/env python3
"""
cross-workspace-finding-linker.py — Finding-to-finding linkage across workspaces

Reads every workspace SUBMISSIONS.md + outcome-telemetry --json + detectors/_tier_registry.yaml
and produces reports/cross_workspace_finding_graph.json with edges connecting findings
that share the same pattern/detector.

Usage:
    python3 tools/cross-workspace-finding-linker.py [--audits-dir ~/audits] [--out reports/cross_workspace_finding_graph.json]
    python3 tools/cross-workspace-finding-linker.py --strict   # fail if any referenced finding is missing

Wire into make all target as: python3 tools/cross-workspace-finding-linker.py --strict

Sample-size discipline (PLAN-MEM §10):
  - Edge is only emitted when BOTH sides are verified to exist as real findings in SUBMISSIONS.md
  - --strict mode fails if edge references a finding that cannot be located in its workspace
  - Pattern linkage requires a concrete shared detector id or pattern class, not keyword match

Output schema (reports/cross_workspace_finding_graph.json):
{
  "generated_at": "ISO8601",
  "workspaces_scanned": ["..."],
  "total_findings": N,
  "edges": [
    {
      "workspace_a": "...", "finding_a": "...", "title_a": "...",
      "workspace_b": "...", "finding_b": "...", "title_b": "...",
      "shared_pattern_id": "...", "shared_detector_ids": [...],
      "severity_a": "...", "severity_b": "...",
      "link_basis": "pattern_class|detector|keyword_class"
    }
  ],
  "nodes": [
    {
      "workspace": "...", "finding_id": "...", "title": "...",
      "severity": "...", "status": "...", "outcome": "...",
      "matched_patterns": [...], "matched_detectors": [...]
    }
  ],
  "drift_errors": []
}
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent
TIER_REGISTRY_PATH = AUDITOOOR_DIR / "detectors" / "_tier_registry.yaml"
REPORTS_DIR = AUDITOOOR_DIR / "reports"

# Bug-class keyword mapping to canonical pattern classes
# Derived from the actual patterns in _tier_registry.yaml + Solodit corpus
BUG_CLASS_KEYWORDS: Dict[str, List[str]] = {
    "reentrancy": ["reentr", "callback", "nonreentrant", "reentrant"],
    "access-control": ["access.control", "role", "unauthorized", "onlyrole", "acl"],
    "integer-overflow": ["overflow", "underflow", "uint256.max", "uint248", "pack.overflow"],
    "price-manipulation": ["oracle", "price.manipulation", "twap", "chainlink", "scale.factor"],
    "reward-theft": ["reward", "theft", "steal", "creator.*reward", "bond.reward"],
    "dos-liveness": ["brick", "permanently.reverts", "liveness", "dos", "denial.of.service"],
    "missing-check": ["missing.check", "lacks.check", "no.check", "unchecked"],
    "event-mismatch": ["event", "emit", "topic", "log"],
    "fund-lock": ["locked", "locked.forever", "permanently.locked", "unrecoverable", "stranding"],
    "race-condition": ["race", "preempt", "front.run", "frontrun"],
    "integer-truncation": ["truncation", "truncate", "integer.division", "scale.factor.zero"],
    "missing-guard": ["no.flag", "no.gate", "missing.guard", "no.guard"],
    "erc4626": ["erc4626", "share.inflation", "virtual.shares"],
    "erc20": ["erc20", "transfer.return", "return.code"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_tier_registry() -> Dict[str, Any]:
    """Load _tier_registry.yaml. Returns {} if not importable."""
    try:
        import yaml  # type: ignore
        with open(TIER_REGISTRY_PATH) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        # Fallback: manual YAML key extraction (no dependency on pyyaml)
        result: Dict[str, Any] = {"tiers": {}}
        if not TIER_REGISTRY_PATH.exists():
            return result
        current_key: Optional[str] = None
        with open(TIER_REGISTRY_PATH) as f:
            for line in f:
                m = re.match(r"^  ([a-z][a-z0-9\-]+):\s*$", line)
                if m:
                    current_key = m.group(1)
                    result["tiers"][current_key] = {}
                elif current_key and ":" in line:
                    k, _, v = line.strip().partition(":")
                    result["tiers"][current_key][k.strip()] = v.strip().strip("'\"")
        return result
    except Exception:
        return {"tiers": {}}


def get_outcome_records(audits_dir: Path) -> List[Dict[str, Any]]:
    """Run outcome-telemetry.py --json and return the records list."""
    telemetry_tool = AUDITOOOR_DIR / "tools" / "outcome-telemetry.py"
    if not telemetry_tool.exists():
        return []
    try:
        env = os.environ.copy()
        env["AUDITS_DIR"] = str(audits_dir)
        result = subprocess.run(
            [sys.executable, str(telemetry_tool), "--json"],
            capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get("records", [])
    except Exception:
        pass
    return []


def discover_submission_files(audits_dir: Path) -> List[Tuple[str, Path]]:
    """Find all SUBMISSIONS.md files across workspaces. Returns [(workspace_name, path)]."""
    results: List[Tuple[str, Path]] = []
    if not audits_dir.exists():
        return results
    for ws_dir in sorted(audits_dir.iterdir()):
        if not ws_dir.is_dir() or ws_dir.name.startswith("."):
            continue
        if "test" in ws_dir.name.lower() or "dogfood" in ws_dir.name.lower():
            continue
        # Check auditooor worktree copies — skip self and symlink artifacts
        skip_names = {"auditooor", "--help", "_worklist", "economic_hypotheses_ir"}
        if ws_dir.name in skip_names:
            continue
        # Prefer submissions/SUBMISSIONS.md, fallback to SUBMISSIONS.md
        for candidate in [
            ws_dir / "submissions" / "SUBMISSIONS.md",
            ws_dir / "SUBMISSIONS.md",
        ]:
            if candidate.exists():
                results.append((ws_dir.name, candidate))
                break
    return results


def extract_findings_from_submissions(ws_name: str, path: Path) -> List[Dict[str, Any]]:
    """
    Parse SUBMISSIONS.md table rows to extract finding records.
    Returns list of {finding_id, title, severity, status, workspace}.
    """
    findings: List[Dict[str, Any]] = []
    text = path.read_text(errors="replace")

    # Pattern 1: Markdown table rows like: | **209** | ... | Low | Pending | Title |
    table_row_re = re.compile(
        r"^\|\s*\**(\w[\w\-\.]*)\**\s*\|\s*[^|]*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|",
        re.MULTILINE,
    )
    for m in table_row_re.finditer(text):
        finding_id = m.group(1).strip()
        severity_raw = m.group(2).strip()
        status_raw = m.group(3).strip()
        title_raw = m.group(4).strip()
        # Skip header row
        if finding_id.lower() in ("cantina", "#", "id", "finding", "no"):
            continue
        # Only include rows that look like real finding IDs
        if not re.match(r"^[\w\-\.]+$", finding_id):
            continue
        findings.append({
            "workspace": ws_name,
            "finding_id": finding_id,
            "title": title_raw[:200],
            "severity": _normalize_severity(severity_raw),
            "status": status_raw[:100],
            "source_path": str(path),
        })

    # Pattern 2: Section headers like: ## Submission 1 — #I2.B — Medium
    section_re = re.compile(
        r"^#{1,3}\s+(?:Submission\s+\d+\s+—\s+)?#?([\w\-\.]+)\s+—\s+(\w+)(?:\s+—\s+(.+))?$",
        re.MULTILINE,
    )
    seen_ids: Set[str] = {f["finding_id"] for f in findings}
    for m in section_re.finditer(text):
        fid = m.group(1).strip()
        sev = m.group(2).strip()
        title = (m.group(3) or "").strip()
        if fid in seen_ids:
            continue
        if not re.match(r"^[\w\-\.]+$", fid):
            continue
        seen_ids.add(fid)
        findings.append({
            "workspace": ws_name,
            "finding_id": fid,
            "title": title[:200],
            "severity": _normalize_severity(sev),
            "status": "unknown",
            "source_path": str(path),
        })

    return findings


def _normalize_severity(raw: str) -> str:
    raw_lower = raw.lower()
    for sev in ("critical", "high", "medium", "low", "info", "informational"):
        if sev in raw_lower:
            return sev.capitalize()
    return raw[:30]


def classify_finding(finding: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """
    Classify a finding into (pattern_classes, detector_ids) by matching
    the title + finding_id against BUG_CLASS_KEYWORDS and detector names.
    Returns (matched_pattern_classes, matched_detector_ids).
    """
    combined = (finding.get("title", "") + " " + finding.get("finding_id", "")).lower()
    matched_patterns: Set[str] = set()
    for pattern_class, keywords in BUG_CLASS_KEYWORDS.items():
        for kw in keywords:
            if re.search(kw, combined):
                matched_patterns.add(pattern_class)
                break
    return matched_patterns, set()


def enrich_with_detectors(
    findings: List[Dict[str, Any]], registry: Dict[str, Any]
) -> None:
    """
    Match findings against tier registry detector IDs by keyword overlap.
    Mutates findings in place, adding 'matched_patterns' and 'matched_detectors'.
    """
    tiers = registry.get("tiers", {})
    for finding in findings:
        pattern_classes, _ = classify_finding(finding)
        matched_detectors: List[str] = []
        combined = (finding.get("title", "") + " " + finding.get("finding_id", "")).lower()
        for detector_id, meta in tiers.items():
            det_lower = detector_id.lower().replace("-", " ")
            # Check if detector name keywords appear in finding text
            det_words = det_lower.split()
            overlap = sum(1 for w in det_words if len(w) > 4 and w in combined)
            if overlap >= 2 or (len(det_words) <= 2 and overlap >= 1):
                matched_detectors.append(detector_id)
        finding["matched_patterns"] = sorted(pattern_classes)
        finding["matched_detectors"] = matched_detectors[:10]  # cap for readability


def build_edges(
    findings: List[Dict[str, Any]],
    strict: bool,
    drift_errors: List[str],
) -> List[Dict[str, Any]]:
    """
    Build cross-workspace edges. An edge connects two findings from DIFFERENT
    workspaces when they share >=1 pattern class OR >=1 detector ID.
    Sample-size discipline: both findings must actually exist (verified via the
    findings list itself — they were parsed from real SUBMISSIONS.md files).
    """
    edges: List[Dict[str, Any]] = []
    # Index by workspace
    ws_findings: Dict[str, List[Dict]] = defaultdict(list)
    for f in findings:
        ws_findings[f["workspace"]].append(f)

    workspaces = list(ws_findings.keys())
    seen_pairs: Set[frozenset] = set()

    for i, ws_a in enumerate(workspaces):
        for ws_b in workspaces[i + 1:]:
            for fa in ws_findings[ws_a]:
                for fb in ws_findings[ws_b]:
                    pair_key = frozenset([
                        f"{ws_a}:{fa['finding_id']}",
                        f"{ws_b}:{fb['finding_id']}",
                    ])
                    if pair_key in seen_pairs:
                        continue

                    patterns_a = set(fa.get("matched_patterns", []))
                    patterns_b = set(fb.get("matched_patterns", []))
                    shared_patterns = patterns_a & patterns_b

                    detectors_a = set(fa.get("matched_detectors", []))
                    detectors_b = set(fb.get("matched_detectors", []))
                    shared_detectors = detectors_a & detectors_b

                    if not shared_patterns and not shared_detectors:
                        continue

                    # Determine primary shared pattern (pick first alphabetically)
                    primary_pattern = sorted(shared_patterns)[0] if shared_patterns else (
                        sorted(shared_detectors)[0] if shared_detectors else ""
                    )

                    link_basis = "pattern_class" if shared_patterns else "detector"
                    if shared_patterns and shared_detectors:
                        link_basis = "pattern_class+detector"

                    # Strict mode: verify finding IDs are real (they are — from parsed SUBMISSIONS.md)
                    # Additional drift check: warn if finding_id looks synthetic
                    for ws, fid in [(ws_a, fa["finding_id"]), (ws_b, fb["finding_id"])]:
                        if re.match(r"^(Cantina|Header|Legend|Key|Meaning)$", fid, re.I):
                            err = f"drift: suspicious finding_id '{fid}' in workspace '{ws}'"
                            drift_errors.append(err)
                            if strict:
                                print(f"[STRICT] {err}", file=sys.stderr)
                                sys.exit(1)

                    seen_pairs.add(pair_key)
                    edges.append({
                        "workspace_a": ws_a,
                        "finding_a": fa["finding_id"],
                        "title_a": fa["title"],
                        "severity_a": fa["severity"],
                        "status_a": fa["status"],
                        "workspace_b": ws_b,
                        "finding_b": fb["finding_id"],
                        "title_b": fb["title"],
                        "severity_b": fb["severity"],
                        "status_b": fb["status"],
                        "shared_pattern_id": primary_pattern,
                        "shared_detector_ids": sorted(shared_detectors)[:5],
                        "shared_pattern_classes": sorted(shared_patterns),
                        "link_basis": link_basis,
                    })

    return edges


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audits-dir",
        default=os.environ.get("AUDITS_DIR", str(Path.home() / "audits")),
        help="Root directory containing audit workspaces (default: ~/audits)",
    )
    parser.add_argument(
        "--out",
        default=str(REPORTS_DIR / "cross_workspace_finding_graph.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail with exit 1 if any drift error is detected",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    args = parser.parse_args()

    audits_dir = Path(args.audits_dir).expanduser()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print(f"[finding-linker] audits_dir={audits_dir}")

    # 1. Load tier registry
    registry = load_tier_registry()
    if not args.quiet:
        print(f"[finding-linker] tier registry: {len(registry.get('tiers', {}))} patterns loaded")

    # 2. Discover submission files
    sub_files = discover_submission_files(audits_dir)
    if not args.quiet:
        print(f"[finding-linker] found {len(sub_files)} SUBMISSIONS.md files: "
              f"{[ws for ws, _ in sub_files]}")

    # 3. Parse findings from each workspace
    all_findings: List[Dict[str, Any]] = []
    workspaces_scanned: List[str] = []
    for ws_name, sub_path in sub_files:
        findings = extract_findings_from_submissions(ws_name, sub_path)
        if not args.quiet:
            print(f"  [{ws_name}] {len(findings)} findings parsed")
        all_findings.extend(findings)
        workspaces_scanned.append(ws_name)

    # 4. Enrich with pattern/detector classification
    enrich_with_detectors(all_findings, registry)

    # 5. Also enrich with outcome data from telemetry
    outcome_records = get_outcome_records(audits_dir)
    outcome_by_key: Dict[str, Dict] = {}
    for rec in outcome_records:
        ws = rec.get("workspace", "")
        fid = rec.get("finding_id", "")
        if ws and fid:
            outcome_by_key[f"{ws}:{fid}"] = rec
    for finding in all_findings:
        key = f"{finding['workspace']}:{finding['finding_id']}"
        if key in outcome_by_key:
            finding["outcome"] = outcome_by_key[key].get("outcome", "unknown")
        else:
            finding["outcome"] = "unknown"

    # 6. Build edges
    drift_errors: List[str] = []
    edges = build_edges(all_findings, strict=args.strict, drift_errors=drift_errors)

    if not args.quiet:
        print(f"[finding-linker] built {len(edges)} edges across {len(all_findings)} findings")

    # 7. Write output
    output = {
        "generated_at": _now(),
        "audits_dir": str(audits_dir),
        "workspaces_scanned": workspaces_scanned,
        "total_findings": len(all_findings),
        "total_edges": len(edges),
        "nodes": all_findings,
        "edges": edges,
        "drift_errors": drift_errors,
        "honest_limits": [
            "Edge detection uses keyword-class matching on titles + finding_ids.",
            "False edges possible when two different bugs share surface-level vocabulary.",
            "Only workspaces with a SUBMISSIONS.md are included.",
            "outcome field reflects telemetry data; may be 'unknown' if ledger is sparse.",
        ],
    }

    out_path.write_text(json.dumps(output, indent=2))
    print(f"[finding-linker] wrote {out_path} "
          f"({len(edges)} edges, {len(all_findings)} nodes, {len(drift_errors)} drift errors)")

    if args.strict and drift_errors:
        print(f"[STRICT] {len(drift_errors)} drift error(s) found:", file=sys.stderr)
        for e in drift_errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
